# Scoring and Prioritization Deep Dive

This page details how VulnParse-Pin v2.0 (`Apache-2.0`) computes dual-track risk scores, evaluates CISA BOD 26-04 / SSVC triage decisions, ranks assets and findings in DuckDB, and detects cross-run priority drift.

## Scope and Primary Implementation Files

- `src/vulnparse_pin/core/passes/__init__.py` (`run_v2_duckdb_pipeline`)
- `src/vulnparse_pin/core/passes/Scoring/scoringPass.py` (`ScoringV3Pass` / `Scoring@3.0`, plus legacy `ScoringPass` / `Scoring@2.0`)
- `src/vulnparse_pin/utils/cvss_utils.py` (clean-room Apache-2.0 CVSS v2.0 / v3.0 / v3.1 / v4.0 calculator & `resolve_effective_cvss_fields`)
- `src/vulnparse_pin/core/passes/Triage/triage_pass.py` (`TriageDecisionPass` / `Triage@2.0`)
- `src/vulnparse_pin/core/passes/TopN/topn_pass.py` (`TopNV2Pass` / `TopN@2.0`, plus legacy `TopNPass` / `TopN@1.0`)
- `src/vulnparse_pin/core/passes/Summary/summary_pass.py` (`SummaryV2Pass` / `Summary@2.0`, plus legacy `SummaryPass` / `Summary@1.0`)
- `src/vulnparse_pin/core/diff_engine.py` (`DiffEngine`, `evaluate_fail_gate`)
- `src/vulnparse_pin/core/config_projector.py` & `src/vulnparse_pin/core/config_validator.py`
- `src/vulnparse_pin/resources/config.yaml`, `src/vulnparse_pin/resources/scoring.json`, `src/vulnparse_pin/resources/tn_triage.json`

## Triage Methodology Baseline

VulnParse-Pin applies a real-world exploitation and exposure-first triage model:

- Prioritize findings and assets with verified active exploitation (CISA KEV, verified exploit), high EPSS v5 probability/percentile, and internet-facing exposure.
- Separate CVE-backed vulnerabilities (**Track A: `cve_threat`**) from non-CVE misconfigurations, SAST rules, and exposed-service findings (**Track B: `exposure_weakness`**).
- Weight Track B risk and triage eligibility by scanner `detection_mode` (`signal_reliability`) and enforce fail-closed guardrails on uncorroborated static SAST findings.
- Support both the `default` operational triage profile and the federal `bod-26-04` SSVC decision profile.

## v2.0 DuckDB Pass Pipeline

`run_v2_duckdb_pipeline()` executes the canonical DuckDB-first pass DAG via `PassRunner`:

1. `NmapAdapter@1.0` *(optional, when `--nmap` / `--nmap-ctx` is provided)*
2. `ACI@2.0` (`ACIV2Pass`) → persists `aci_signals`
3. `Scoring@3.0` (`ScoringV3Pass`) → persists `scores`, updates `findings.signal_reliability` and `assets.derived_criticality`
4. `Triage@2.0` (`TriageDecisionPass`) → persists `triage_decisions`
5. `TopN@2.0` (`TopNV2Pass`) → unified SQL CTE asset & finding ranking
6. `Summary@2.0` (`SummaryV2Pass`) → unified SQL summary aggregation

> [!NOTE]
> Legacy in-memory `ScanResult` passes (`Scoring@2.0`, `ACI@1.0`, `TopN@1.0`, `Summary@1.0`) remain available only for backward-compatible Python API callers; all v2.0 CLI subcommands (`vpp scan`, `vpp demo`, `vpp diff`, `vpp export`, `vpp ui`) execute the DuckDB v2 pipeline.

## Clean-Room Apache-2.0 CVSS Engine & Provenance

In v2.0.0, VulnParse-Pin removes the LGPL `cvss` runtime dependency and implements a clean-room, Python standard-library-only CVSS calculator in `src/vulnparse_pin/utils/cvss_utils.py`:

- **Supported Specifications:** Official FIRST formulas and MacroVector lookup tables for **CVSS v2.0**, **CVSS v3.0**, **CVSS v3.1**, and **CVSS v4.0** (all 270 valid EQ1–EQ6 MacroVectors).
- **Authoritative Precedence (`_CVSS_PROVENANCE_RANK`):**
  `NVD (5) > CNA (4) > GHSA (3) > OSV (2) > Scanner-Supplied (1) > Missing (0)`
- **Safe Effective Resolution (`resolve_effective_cvss_fields`):**
  Used across DuckDB repositories, dossier/roadmap renderers, JSON/CSV exporters, `DiffEngine`, and the Textual TUI so that a `"Missing"` enrichment snapshot never shadows a valid `"Scanner-Supplied"` score/vector, and missing CVSS never leaks as a synthetic `0.0`.

## Scoring@3.0: Dual-Track Vectorized Scoring

`ScoringV3Pass` reads joined `findings`, `assets`, `aci_signals`, and `enrichment_snapshots` rows from `.vpp.db`, memoizes equivalent signal signatures, and writes `scores` via DuckDB `appender`.

### Track A: `cve_threat` (CVE-Backed Findings)

Selected when a finding carries one or more CVE IDs and `scoring_track != "exposure_weakness"`.

For each associated CVE on the finding:

1. **CVSS Base Score (`0.0–10.0`):** Resolved using `NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing` (`0.0` in numeric calculation if missing, while `score_trace.cvss_provenance` stays `"Missing"`).
2. **EPSS v5 Monotonic Piecewise Cutoffs (`_epss_v5_points`):**
   Computes strictly monotonic piecewise-linear points (`0.0–5.0`) over `epss_score` using the default `scoring.json` breakpoints:

   | EPSS Probability | EPSS Points |
   | --- | --- |
   | `0.00` | `0.0` |
   | `0.04` (4%) | `1.8` |
   | `0.10` (10%) | `3.0` |
   | `0.50` (50%) | `4.2` |
   | `1.00` (100%) | `5.0` |

   FIRST `epss_percentile` (`0.0–1.0`) is stored alongside `epss_score`, formatted in `epss_display` (for example `12.3% / 95th`), and evaluated directly in `Triage@2.0` (`>= 0.90` and `>= 0.95`).
3. **KEV & Verified Exploit (Non-Double-Counting):**
   - `in_kev == True`: `+4.5` (`kev_points`)
   - `verified_exploit == True`: `+2.0` (`verified_exploit_points`) when *not* in KEV, or `+0.5` (`verified_exploit_with_kev_points`) when *already* in KEV
   - `heuristic_exploit_mention == True`: `+0.0` (`heuristic_exploit_points`; preserved as trace metadata only so unverified advisory mentions do not inflate scores)
4. **Multi-CVE Stacked Decay:**
   Per-CVE raw scores (`cve_raw = cvss + epss_points + kev_points + exp_points`) are sorted descending by `(cve_raw, cve_id)` and summed with exponential decay `decay ** idx` (`finding_cve_decay = 0.35`, `finding_cve_max_contributors = 8`).
5. **Asset Context Modifiers & Normalization:**
   - `exposure_bonus`: `+1.25` when `internet_facing` is `true`
   - `criticality_bonuses`: `critical: +1.0`, `high: +0.5`, `medium: 0.0`, `low: -0.25`
   - Clamped to `max_raw_risk = 16.0` and scaled to `operational_score = (raw_score / 16.0) * 10.0` (`0.0–10.0`).

### Track B: `exposure_weakness` (Non-CVE Findings)

Selected when a finding has no CVEs (e.g., Nuclei misconfigurations/default logins, Semgrep SAST findings, exposed admin panels, or network service checks).

1. **Base Score:** `scanner_cvss_score` (or base score computed from `scanner_cvss_vector`, provenance `"Scanner-Supplied"`); otherwise `exposure_track.severity_base`: `critical: 8.5`, `high: 7.0`, `medium: 4.5`, `low: 2.0`, `informational/info: 0.5` (provenance `"Missing"`).
2. **Additive Capability & Context Bonuses:**
   - ACI capability bonus: `+3.5` (`aci_high_impact_bonus`) if any capability is in `{remote_execution, command_execution, auth_bypass, sql_injection, privilege_escalation, initial_access, deserialization, ssrf}`, else `+2.0` (`aci_exposure_bonus`) if any other ACI capability is present.
   - ACI chain bonus: `+1.0` (`aci_chain_bonus`) when `aci_chains` is non-empty.
   - High-impact CWE bonus: `+1.5` (`cwe_high_impact_bonus`) for high-impact CWEs (`CWE-22`, `CWE-77`, `CWE-78`, `CWE-79`, `CWE-89`, `CWE-94`, `CWE-250`, `CWE-269`, `CWE-287`, `CWE-306`, `CWE-434`, `CWE-502`, `CWE-798`, `CWE-918`).
   - Exposure bonus: `+1.5` (`exposure_bonus`) when `internet_facing` is `true`.
3. **Signal Reliability Weighting:**
   `weighted_raw = unweighted_raw * signal_reliability`, clamped to `16.0` and normalized to `0.0–10.0`.

### Signal Reliability (`detection_mode`)

Configured in `config.yaml` and `scoring.json` under `signal_reliability`:

| `detection_mode` | Default Weight | Typical Sources |
| --- | ---: | --- |
| `credentialed_host` | `1.00` | Credentialed Nessus / OpenVAS / Qualys host checks |
| `active_dast` | `1.00` | Active Nuclei probes |
| `sca_container` | `0.90` | Trivy / Grype package & container SARIF |
| `uncredentialed_banner` | `0.85` | Uncredentialed network/service banner checks |
| `network_probe` | `0.80` | Nmap service/script probes |
| `static_sast` | `0.55` | Semgrep / CodeQL static analysis |

If `detection_mode` is unmapped, `SignalReliabilityPolicy.weight_for` falls back to explicit finding reliability (clamped `[0.0, 2.0]`), then `ingestion_confidence` (clamped `[0.0, 1.0]`), then `0.70`.

### Risk Bands & Asset Criticality

Raw-score risk bands (`scoring.json`):

- `Critical`: `raw_score >= 12.8` (operational `>= 8.0`)
- `High`: `raw_score >= 9.6` (operational `>= 6.0`)
- `Medium`: `raw_score >= 6.4` (operational `>= 4.0`)
- `Low`: `raw_score >= 3.2` (operational `>= 2.0`)
- `Informational`: `raw_score < 3.2`

`ScoringV3Pass` also derives `assets.derived_criticality`: `Extreme` (`>= 3` Critical findings), `High` (`>= 1` Critical or `>= 2` High), `Medium` (`>= 1` High or `>= 5` Medium), else `Low`.

## Triage@2.0: `default` vs `--profile bod-26-04`

`TriageDecisionPass` evaluates every finding in `scores` under either `default` or `bod-26-04` (`--profile bod-26-04`) and reconciles explicit deferrals/acceptances/mitigations from `DecisionsRegistry` (`decisions.yaml` or inline `assets.yaml`).

### SSVC Inputs (`bod-26-04`)

`_compute_ssvc_inputs()` derives four SSVC decision points:

- `publicly_exposed`: `bool(internet_facing)`
- `exploitation`:
  - `"active"` if `in_kev` OR (`scoring_track == "exposure_weakness"` and `signal_reliability >= 0.90` and active exposure ACI capability/token such as `remote_execution`, `command_execution`, `auth_bypass`, `default-login`, `rce`)
  - `"poc"` if `verified_exploit` OR `epss >= 0.10` OR `epss_percentile >= 0.95`
  - `"none"` otherwise
- `automatable`: `true` if CVSS vector has `AV:N` and `AC:L` with no/low privilege & no user interaction, OR ACI indicates `remote_execution`/`command_execution`/`auth_bypass`/default-login/RCE tokens
- `technical_impact`: `"total"` if CVSS reflects total CIA impact (`C:H/I:H/A:H`, v2 `C:C/I:C/A:C`, v3 `S:C`, or v4 `VC:H/VI:H` or `SC:H/SI:H`) OR ACI detects `remote_execution`, `command_execution`, `auth_bypass`, `privilege_escalation`, or `sql_injection`; else `"partial"`

### Profile Decision & SLA Matrix

| Profile | Priority Tier | OAL Compat | SSVC Action | SLA Bucket (`sla_days`) | Trigger Conditions |
| --- | --- | --- | --- | --- | --- |
| `bod-26-04` | `P1` | `OAL-1` | `Act` | `3-day + Forensic Triage` (`3`) | `publicly_exposed` AND `exploitation == "active"` |
| `bod-26-04` | `P1` | `OAL-1` | `Act` | `14-day` (`14`) | Internal `exploitation == "active"`, OR `publicly_exposed` + (`automatable & total` OR `epss_pct >= 0.95` OR reliable Track B `total`) |
| `bod-26-04` | `P2` | `OAL-2` | `Attend` | `60-day` (`60`) | `epss_pct >= 0.90` OR `epss >= 0.04` OR (`automatable & total`) OR `aci_chains` OR (`static_sast` + `total`) OR SAST P1-cap applied |
| `bod-26-04` | `P3` / `P4` | `OAL-3` | `Track` | `Fix on Upgrade` (`None`) | Remainder (`P3` if `operational_score >= 3.5`, else `P4`) |
| `default` | `P1` | `OAL-1` | `Act` | `3-day + Forensic Triage` (`3`) or `14-day` (`14`) | `3-day + Forensic Triage` when `in_kev` & `internet_facing`; `14-day` for internal KEV (`critical`/`high` asset), `epss >= 0.10`/`pct >= 0.95` & exposed, reliable Track B high-impact/`>= 8.5` on exposed/critical asset, or `op_score >= 9.0` & `sig_rel >= 0.85` |
| `default` | `P2` | `OAL-2` | `Attend` | `14-day` (`14`) | `in_kev`, `epss >= 0.04`, `epss_pct >= 0.90`, `aci_chains`, `operational_score >= 6.5`, or SAST P1-cap applied |
| `default` | `P3` | `OAL-3` | `Track*` | `60-day` (`60`) | `operational_score >= 3.5` |
| `default` | `P4` | `OAL-3` | `Track` | `Fix on Upgrade` (`None`) | Remainder |

### Static SAST P1-Cap Guardrail

When `triage.static_sast_p1_cap: true` (default), a `detection_mode == "static_sast"` finding is blocked from entering `P1` unless `_is_high_conf_sast_corroborated()` passes:

- `internet_facing == True`, AND
- `scanner_severity` is `"high"` or `"critical"`, AND
- at least one of: high-impact SAST CWE (`CWE-78`, `CWE-89`, `CWE-94`, `CWE-287`, `CWE-306`, `CWE-434`, `CWE-502`, `CWE-798`, `CWE-918`), high-impact ACI capability/chain, or high-confidence rule keyword (`rce`, `sqli`, `command-injection`, `auth-bypass`, `deserialization`, `hardcoded-secret`, `ssrf`, etc.).

Uncorroborated SAST `P1` candidates are capped at `P2` (`60-day` under `bod-26-04`; `14-day` under `default`) with `sast_p1_capped = true` recorded in `assumed_state_json`.

### Decision Registry Reconciliation & Invalidated Deferrals

When `decisions.yaml` (or inline `assets.yaml` `decisions:`) matches a finding, `DecisionsRegistry.evaluate()` checks all assumption predicates (`expires_at`, `in_kev`, `max_epss`, `max_epss_percentile`, `internet_facing`, `max_cvss`):

- Valid match → `deferred_valid`, `accepted_valid`, or `mitigated` (suppressed from active remediation queues).
- Any violated predicate → `deferred_invalidated` or `accepted_invalidated` (immediately re-elevated into Decision Defense Dossiers and `DiffEngine` stale-assumption alerts).

## TopN@2.0 & Summary@2.0

- **`TopNV2Pass` (`TopN@2.0`):** Uses parameterized DuckDB SQL window functions (`ROW_NUMBER() OVER (PARTITION BY f.asset_id ...)`) ordering by `(priority_tier ASC, operational_score DESC, epss_score DESC, aci.uplift_score DESC, finding_id ASC)` so sequential, single-node, and UI queries never diverge from `ProcessPoolExecutor` ordering. Top-K assets are scored by weighted decay (`[1.0, 0.5, 0.25]` default in `TopNV2Pass`; bounded to `k = summary.top_n_findings`, default `20`).
- **`SummaryV2Pass` (`Summary@2.0`):** Computes all summary KPIs (`overview`, `asset_summary`, `finding_summary`, `risk_distribution`, `top_risks`, `enrichment_metrics`, `remediation_priorities`, `decision_trace_summary`) directly via DuckDB SQL aggregations.

## `DiffEngine` & Fail-Closed `stale-assumption` Gate

`DiffEngine` (`src/vulnparse_pin/core/diff_engine.py`, `vpp diff`) performs a `FULL OUTER JOIN` across `base_run_id` and `target_run_id` in `.vpp.db` to track:

1. `newly_introduced_high_risk` (`P1`/`P2` or `Critical`/`High` new findings) + `newly_introduced_all`
2. `threat_intel_escalated` (KEV additions, EPSS crossing `0.04`/`0.10` or `90th`/`95th` percentile, CVSS delta `>= 1.0`, provenance upgrade from `Missing`, or `internet_facing` flipping to `true`)
3. `verified_remediated` (distinguishing `patched` when the asset remains present vs `asset_missing`)
4. `invalidated_assumptions`:
   - **Explicit invalidation:** `decisions.yaml` assumptions violated or expired.
   - **Implicit baseline drift (`_detect_implicit_baseline_drift`):** A persisting finding that was previously in a baseline/deferred posture (`P3`, `P4`, `Fix on Upgrade`, or `60-day`) and escalated to `P1`/`P2` (`14-day` or `3-day + Forensic Triage`) driven by KEV flip, EPSS increase, CVSS increase, exposure flip, or verified exploit addition.
5. `shadow_assets_delta`: newly observed, resolved, or became-shadow unmatched assets.

`evaluate_fail_gate(report, fail_on)` returns exit code `2` on policy breach:

- `--fail-on stale-assumption`: fails closed (`exit 2`) whenever `invalidated_assumptions > 0` (covering both explicit `decisions.yaml` invalidations and `60-day -> 14-day/3-day` implicit baseline drift).
- `--fail-on p1`: fails on active new `P1`, escalation to `P1`, or invalidated assumption escalating to `P1`.
- `--fail-on p2`: fails on active new `P1`/`P2`, escalation into `P1`/`P2`, or invalidated assumption escalating into `P1`/`P2`.
- `--fail-on kev`: fails on active new KEV findings or persisting findings newly entering KEV.

## Related Pages

- [CVSS vs VulnParse-Pin: Technical Scoring Comparison](CVSS_vs_VulnParse_Scoring_Comparison.md)
- [ACI Feature Explanation](ACI%20Feature%20Explanation.md)
- [ACI Technical Deep Dive](ACI%20Technical%20Deep%20Dive.md)
- [Configs](Configs.md)
- [Pass Phases](Pass%20Phases.md)
- [Output Interpretation](Output%20Interpretation.md)
