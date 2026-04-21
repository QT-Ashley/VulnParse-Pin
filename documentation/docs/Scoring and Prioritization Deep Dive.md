# Scoring and Prioritization Deep Dive

This page details how VulnParse-Pin computes risk, executes the scoring pass, and performs TopN asset/finding prioritization with inference.

## Scope

Primary implementation files:

- `src/vulnparse_pin/core/passes/Scoring/scoringPass.py`
- `src/vulnparse_pin/core/classes/scoring_pol.py`
- `src/vulnparse_pin/core/passes/TopN/topn_pass.py`
- `src/vulnparse_pin/core/passes/TopN/TN_triage_semantics.py`
- `src/vulnparse_pin/core/passes/TopN/TN_triage_config.py`
- `src/vulnparse_pin/core/classes/pass_classes.py`
- `src/vulnparse_pin/resources/scoring.json`
- `src/vulnparse_pin/resources/tn_triage.json`

## Triage methodology baseline

VulnParse-Pin applies a real-world impact probability first triage model by default:

- prioritize findings and assets with the highest near-term likelihood of meaningful operational impact
- treat exploitability and exposure evidence as first-order decision signals
- use chain/pathway context as decision support, with bounded influence

This baseline should be tuned for your environment. Adjust scoring and TopN policy to match business goals, risk tolerance, and regulatory obligations.

## Pass dependency chain

Default pass order:

1. `Scoring@2.0`
2. `TopN@1.0`
3. `Summary@1.0`

`TopNPass` depends on `ScoringPass` output from derived context. If scoring output is missing, TopN cannot rank.

## Scoring policy model

`ScoringPolicyV1` is loaded from `scoring.json` using `load_score_policy(...)` and supplemented by `nmap_ctx.scoring_port_bonus` from `config.yaml`.

Core policy groups:

- EPSS normalization (`scale`, `min`, `max`)
- evidence points (`kev`, `exploit`)
- band thresholds (`critical`, `high`, `medium`, `low`)
- weights (`epss_high`, `epss_medium`, `kev`, `exploit`)
- risk ceiling (`max_raw_risk`, `max_operational_risk`)
- finding-level CVE aggregation (`finding_cve_score`, `finding_cve_decay`, `finding_cve_max_contributors`)
- Nmap context (`nmap_port_bonus`, default `0.0`)

Bootstrap validates monotonic bands and non-negative constraints before pass execution.

## Scoring calculation mechanics

Scoring computation in `scoringPass.py`:

1. Build a per-CVE preview for every retained `finding.cve_analysis` record using CVSS, EPSS, KEV, and exploit signals.
2. Sort contributor CVEs by descending raw preview score.
3. Aggregate contributor raw scores with bounded decay (`1.0`, `decay`, `decay^2`, ...) up to `finding_cve_max_contributors`.
4. Fall back to scanner/enrichment rollup fields when no per-CVE analysis is present.
5. Add Nmap port bonus when a confirmed open port matches the finding's service port and `scoring_port_bonus > 0`.

`raw_score` is the composite pre-normalization score.

`operational_score` is normalized by `max_raw_risk` and clamped to `max_operational_risk`.

Risk band is assigned from raw score thresholds.

`score_trace` captures the full contributor list, per-CVE contribution weights, display CVE, union flags, and final scoring summary. This trace is stored in both `assets[].findings[].score_trace` and `derived["Scoring@2.0"].scored_findings[*].score_trace`.

## Scoring execution strategy and thresholds

`ScoringPass` selects execution path by workload:

- sequential mode for small workloads
- thread-pool mode above `parallel_threshold` (default `100`)
- process-pool mode above `process_pool_threshold` (default `20_000`)

Additional controls:

- `min_findings_per_worker` (default `50`)
- optional worker override via `process_workers`

## Scoring optimizations

- Plugin attribute cache (`_build_plugin_cache`) avoids repeated attribute lookups.
- Signature memo cache reuses repeated score computations for equivalent signal tuples.
- Process worker payloads are serialization-safe plain structures.

These are performance optimizations only; output semantics remain deterministic.

## Whole-of-CVEs trace model

For findings that carry `cve_analysis`, `ScoringPass` no longer uses the display or authoritative CVE as the score source. Instead:

- `display_cve` remains presentation-oriented and is retained in the trace for operator continuity.
- `primary_cve` is the highest-impact contributor after sorting.
- `contributors[*].raw_contribution` shows the exact bounded impact of each CVE on the final finding score.
- `contributors[*].aggregation_weight` shows the decay weight applied to that CVE.

This preserves auditability without requiring downstream consumers to recompute the aggregation logic.

## TopN configuration model

TopN policy is loaded from `tn_triage.json` and normalized into `TNTriageConfig`.

`TopNConfig` controls:

- `rank_basis` (`raw` or `operational`)
- `decay` vector
- `k` (derived from decay length)
- `max_assets`
- `max_findings_per_asset`
- `include_global_top_findings`
- `global_top_findings_max`

`InferenceConfig` controls:

- confidence thresholds (`low < medium < high`)
- `public_service_ports`
- `allow_predicates`
- rule set

Semantic validation enforces invariants and rejects invalid structures.

## Nmap context tiebreak

When `nmap_ctx.port_tiebreak_enabled` is `true` (default), TopN ranking injects an `nmap_hit` flag into all three sort key positions:

- Finding sort within asset: `(-score, -nmap_hit, finding_id)`
- Asset sort: `(-score, -crit_high, -crit_rank, -scorable_count, -nmap_confirmed, asset_id)`
- Global finding sort: `(-score, -nmap_hit, asset_id, finding_id)`

This promotes findings and assets with confirmed open ports within equal-score groups without altering numeric scores. The tiebreak is disabled when the pass returns an empty port index (no `--nmap-ctx` provided, or `port_tiebreak_enabled: false`).

See [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md) for full configuration details and operational guidance.

## TopN ranking flow

TopN processing stages:

1. Load scoring output.
2. Build per-asset finding index (backed by `PostEnrichmentIndex` for O(1) lookups when available).
3. Collect per-asset observations including IP, open ports, hostname, and criticality.
4. Compute exposure inference per asset.
5. Rank findings per asset using rank basis.
6. Rank assets with top-k/decay weighting and criticality tie-breaking.
7. Build optional global top findings.
8. Trim to configured max assets and finding limits.

## Inference semantics

Inference rules are predicate-driven and weighted. Predicates can include port- and token-based evidence.

Confidence tiering is based on cumulative weighted evidence and configured thresholds.

Public service port configuration is central to externally exposed asset inference.

Supported predicate forms:

- `ip_is_public` — matches assets with a routable IP address
- `ip_is_private` — matches RFC 1918 / private IP addresses
- `any_port_in_public_list` — matches if any open port appears in the `public_service_ports` list
- `port_in:[p1,p2,...]` — matches if any open port is in the supplied list
- `hostname_contains_any:[t1,t2,...]` — matches if the hostname contains any of the supplied tokens
- `criticality_is:[extreme|high|medium|low]` — matches based on the asset’s enriched criticality classification

Criticality is sourced from `asset.criticality` and is populated at index-build time via `PostEnrichmentIndex`.
Assets with `extreme` or `high` criticality receive additional exposure weighting from the built-in `critical_asset_hint` rule.

## TopN execution strategy

`TopNPass` uses process-pool parallelism when total findings exceed `process_pool_threshold` (default `20_000`).

Parallel workers process serializable chunks and return ranked/inference payloads for merge.

## Output contract

Scoring output includes:

- per-finding scored records
- per-asset score map
- coverage metrics and aggregate summaries

TopN output includes:

- ranked assets
- ranked findings by asset
- optional global top findings
- rank basis, decay, and k metadata

Derived outputs are append-only under versioned pass keys.

## Tuning guidance

- Adjust scoring bands and weights only with representative dataset validation.
- Keep `decay[0] == 1.0` and a monotonic non-increasing decay profile.
- Prefer `rank_basis = operational` for policy-normalized triage workflows.
- Increase process-pool thresholds only when profiling confirms overhead dominates.

## Related pages

- [Configs](Configs.md)
- [Pass Phases](Pass%20Phases.md)
- [Pipeline System](Pipeline%20System.md)
- [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md)
- [ACI Feature Explanation](ACI%20Feature%20Explanation.md)
- [ACI Rule Authoring Tutorial](ACI%20Rule%20Authoring%20Tutorial.md)
- [ACI Technical Deep Dive](ACI%20Technical%20Deep%20Dive.md)
- [CVSS vs VulnParse-Pin: Technical Scoring Comparison](CVSS_vs_VulnParse_Scoring_Comparison.md)
