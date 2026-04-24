# Configs

This page is the technical reference for configuring VulnParse-Pin policy behavior.

## Configuration surfaces

VulnParse-Pin behavior is driven by three policy files plus runtime flags and optional environment variables.

Policy files:

- `src/vulnparse_pin/resources/config.yaml`
- `src/vulnparse_pin/resources/scoring.json`
- `src/vulnparse_pin/resources/tn_triage.json`

Runtime controls:

- CLI flags from `src/vulnparse_pin/cli/args.py`
- env vars used by cache integrity modules

Defaults are materialized into user config locations during bootstrap if missing.

## Config location and mode behavior

Path layout is resolved by `AppPaths` (`src/vulnparse_pin/core/apppaths.py`).

- System mode (default): platform app-data directories.
- Portable mode (`--portable`): project-local data tree for config/cache/log/output.

## `config.yaml` reference

`config.yaml` controls feed cache policy, NVD feed policy, enrichment policy (including GHSA), Nmap context policy, and summary options.

### Webhook controls

`webhook` controls signed scan-complete event delivery over HTTPS.

Canonical keys:

- `enabled`
- `signing_key_env`
- `key_id`
- `timeout_seconds`
- `connect_timeout_seconds`
- `read_timeout_seconds`
- `max_retries`
- `max_payload_bytes`
- `replay_window_seconds`
- `allow_spool`
- `spool_subdir`
- `endpoints[]` with `url`, `enabled`, `oal_filter`, `format`

Validation and safety rules:

- Endpoints must use `https://`.
- Embedded credentials in endpoint URLs are rejected.
- `timeout_seconds` must be greater than or equal to `max(connect_timeout_seconds, read_timeout_seconds)`.
- When `enabled: true`, at least one endpoint must be enabled.
- `oal_filter` values: `all`, `P1`, `P1b`, `P2`.

Runtime notes:

- Signature header uses HMAC-SHA256 with the secret from the env var named by `signing_key_env`.
- Failures can spool payloads under `<output_dir>/<spool_subdir>/` when `allow_spool: true`.
- CLI `--webhook-endpoint` enables one-off webhook delivery without editing config files.
- CLI `--webhook-oal-filter` overrides lane filtering (`all`, `P1`, `P1b`, `P2`).

### Feed TTL controls

- `feed_cache.defaults.ttl_hours`
- `feed_cache.ttl_hours.kev`
- `feed_cache.ttl_hours.epss`
- `feed_cache.ttl_hours.exploit_db`
- `feed_cache.ttl_hours.nvd_yearly`
- `feed_cache.ttl_hours.nvd_modified`

These are consumed by `build_feed_cache_policy(...)` and `FeedCacheManager.is_fresh()`.

TTL semantics:

- `0`: always stale.
- `< 0`: never expires.
- `> 0`: valid while age is within TTL hours.

### NVD policy controls

Canonical keys under `feed_cache.feeds.nvd`:

- `enabled`
- `start_year`
- `end_year`
- `ttl_yearly`
- `ttl_modified`
- `sqlite_enforce_permissions`
- `sqlite_file_mode`
- `sqlite_max_age_hours`
- `sqlite_max_rows`

These are normalized by `nvd_policy_from_config(...)`.

### Summary controls

- `summary.top_n_findings`

Used by `SummaryPass` configuration during runtime bootstrap.

## `enrichment` section in `config.yaml`

The `enrichment` block controls GHSA enrichment source selection, online lookup budgets, SQLite cache retention, and confidence scoring policy. Qualys parser findings flow through the same confidence model as all other scanner outputs — there are no Qualys-specific config keys.

### `enrichment.ghsa_source`

- Type: string or null, values `null` / `"online"` / `"offline"`, default `null`
- Config-level GHSA source hint. At runtime this is overridden by the `--ghsa` CLI flag if present.
- `null`: GHSA enrichment disabled unless `--ghsa` is passed at runtime.
- `"online"`: prefetch advisory data via the GitHub Advisories API.
- `"offline"`: load from a local advisory database directory (requires `--ghsa <path>` at runtime).

### `enrichment.ghsa_online_prefetch_budget`

- Type: integer, default `25`
- Maximum number of distinct CVEs queried against the GitHub Advisories API during a single online GHSA prefetch run.
- Override at runtime with `--ghsa-budget <COUNT>` (online mode only; rejected if offline mode is active).

### `enrichment.ghsa_token_env`

- Type: string, default `VP_GHSA_TK`
- Name of the environment variable that holds a GitHub personal access token for authenticated advisory API requests.
- Falls back to `GITHUB_TOKEN` if the primary env var is absent.
- If neither variable is set, requests are unauthenticated (subject to lower rate limits).

### `enrichment.ghsa_cache`

Controls GHSA SQLite cache (`ghsa_cache.sqlite3`) retention policy.

- `sqlite_max_age_hours` (integer, default `336`): rows older than this are pruned during init and post-upsert.
- `sqlite_max_rows` (integer, default `500000`): row cap; excess rows are pruned by age (oldest first).

Cache integrity: SHA-256 signature sidecar by default; HMAC-SHA-256 when `VP_SQLITE_HMAC_KEY` is set. Tamper-detected files are quarantined and a clean index is rebuilt automatically.

### `enrichment.confidence`

Controls the enrichment confidence scoring model applied to all findings regardless of scanner source (Nessus, OpenVAS, Qualys, etc.).

- `model_version`: schema version identifier, currently `v1`.
- `max_score` (integer, default `100`): confidence score ceiling.
- `base_scanner` (integer, default `35`): baseline confidence contributed by scanner-reported data alone.

#### `enrichment.confidence.weights`

Per-source confidence contribution weights:

| Key | Default | Source |
|---|---|---|
| `nvd` | `25` | NVD CVE record presence |
| `kev` | `15` | CISA KEV hit |
| `epss` | `10` | EPSS probability record |
| `exploitdb` | `10` | Exploit-DB entry |
| `ghsa` | `15` | GHSA advisory hit |

#### `enrichment.confidence.ghsa_signals`

GHSA-specific confidence tuning applied on top of the base GHSA weight:

- `advisory_confidence_bonus` (integer, default `3`): per-advisory bonus added when a GHSA advisory matches a finding.
- `max_advisory_confidence_bonus` (integer, default `9`): cumulative cap on advisory bonuses across all matched advisories for a single finding.
- `exploit_signal_on_high_severity` (boolean, default `false`): when `true`, a GHSA advisory match on a high-severity finding promotes an additional exploit signal.
- `exploit_signal_confidence_bonus` (integer, default `5`): confidence bonus applied when the exploit signal promotion triggers.

## `scoring.json` reference

`scoring.json` maps to `ScoringPolicyV1`.

Key sections:

- `epss`: normalization and scaling (`scale`, `min`, `max`)
- `evidence_points`: KEV and exploit evidence contributions
- `bands`: risk band boundaries
- `weights`: contribution multipliers
- `risk_ceiling`: operational normalization bounds
- `aggregation`: asset-level aggregation mode

Bootstrap validation enforces:

- non-negative weight/evidence values
- monotonic risk bands (`critical > high > medium > low >= 0`)
- EPSS scaling and ordering constraints

### Raw vs operational score

- `raw_score`: composite finding score for ranking behavior.
- `operational_score`: normalized/clamped score for policy-facing risk reporting.

These are intentionally different metrics.

## `tn_triage.json` reference

`tn_triage.json` controls TopN and inference policy.

### `topn` section

- `rank_basis`: `raw` or `operational`
- `decay`: top-k weighting vector
- `max_assets`
- `max_findings_per_asset`
- `include_global_top_findings`
- `global_top_findings_max`

Semantic requirements:

- `decay` must be non-empty
- `decay[0] == 1.0`
- decay values must be non-increasing and in range `[0, 1]`

### `inference` section

- `confidence_thresholds` (`low < medium < high`)
- `public_service_ports`
- `allow_predicates`
- `rules`

Semantic validation rejects invalid threshold ordering, invalid port ranges, empty predicate allow-lists, and malformed rule definitions.

Supported predicate forms in `rules[].when`:

- `ip_is_public`, `ip_is_private`
- `any_port_in_public_list`
- `port_in:[p1,p2,...]`
- `hostname_contains_any:[t1,t2,...]`
- `criticality_is:[extreme|high|medium|low]`

`allow_predicates` controls which predicate forms are permitted in loaded config. Any predicate not in this list causes a validation rejection at startup.

## Environment variable reference

Optional integrity hardening environment variables:

- `VP_FEED_CACHE_HMAC_KEY`: signs feed integrity sidecars in `FeedCacheManager`.
- `VP_SQLITE_HMAC_KEY`: signs NVD and GHSA SQLite signature sidecars (`nvd_cache.sqlite3`, `ghsa_cache.sqlite3`).
- `VP_GHSA_TK`: GitHub personal access token for authenticated GHSA advisory API requests (primary env var; falls back to `GITHUB_TOKEN`).

If `VP_FEED_CACHE_HMAC_KEY` / `VP_SQLITE_HMAC_KEY` are not set, modules fall back to SHA-256 signature-only mode.

## CLI-to-policy mapping

Nmap context:

- `--nmap-ctx` / `-nmap`: path to a Nmap XML file to use as supplementary attack-surface context

GHSA enrichment:

- `--ghsa [PATH|online]`: enable GHSA enrichment; bare flag = online mode, `--ghsa <path>` = offline advisory database directory
- `--ghsa-budget <COUNT>`: override online prefetch CVE budget (online mode only, must be ≥ 1)

Webhook delivery:

- `--webhook-endpoint <HTTPS_URL>`: send signed webhook payloads to a specific endpoint for that run.
- `--webhook-oal-filter <all|P1|P1b|P2>`: restrict webhook payload findings to a specific OAL lane.

Cache and enrichment behavior:

- `--refresh-cache`
- `--allow_regen`
- `--no-kev`
- `--no-epss`
- `--no-exploit`
- `--kev-source`
- `--epss-source`
- `--exploit-source`
- `--kev-feed`
- `--epss-feed`
- `--no-nvd`

Runtime and PFH behavior:

- `--forbid-symlinks-read`
- `--forbid-symlinks-write`
- `--enforce-root-read`
- `--enforce-root-write`
- `--file-mode`
- `--dir-mode`
- `--debug-path-policy`

Logging behavior:

- `--log-file`
- `--log-level`

## Configuration workflow guidance

1. Start from version-controlled defaults.
2. Change one policy area at a time (cache, scoring, or TopN).
3. Re-run representative datasets.
4. Compare score distribution, TopN output shape, and cache/runtime logs.
5. Promote only validated changes.

## `nmap_ctx` section in `config.yaml`

`nmap_ctx` controls Nmap context adapter behavior. Both keys are optional; defaults apply if the section is omitted.

### `port_tiebreak_enabled`

- Type: boolean, default `true`
- Gates the TopN ranking tiebreak. When `true`, equal-score findings and assets with a confirmed Nmap open port rank above those without.
- Setting to `false` reverts TopN tiebreak to ID-only ordering.
- Does not affect numeric scores.

### `scoring_port_bonus`

- Type: float, range `0.0–5.0`, default `0.0`
- When `> 0`, adds to `raw_score` for any finding whose service port is confirmed open in the Nmap output.
- Applied before operational score normalization.
- Schema validation rejects values outside `[0.0, 5.0]`.

See [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md) for full configuration and operational guidance.

## Related deep dives

- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Runtime Policy Deep Dive](Runtime%20Policy%20Deep%20Dive.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [ACI Feature Explanation](ACI%20Feature%20Explanation.md)
- [ACI Rule Authoring Tutorial](ACI%20Rule%20Authoring%20Tutorial.md)
- [ACI Technical Deep Dive](ACI%20Technical%20Deep%20Dive.md)
- [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md)
- [Enrichment Deep Dive](Enrichment%20Deep%20Dive.md)
