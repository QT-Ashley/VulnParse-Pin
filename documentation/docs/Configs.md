# Configs

This page is the technical reference for VulnParse-Pin v2.0.0 configuration files, workspace context YAML (`assets.yaml` and `decisions.yaml`), environment variables, and CLI policy overrides.

## Configuration Surfaces

VulnParse-Pin separates **engine policy** (user/system defaults) from **engagement context** (per-workspace inventory & triage decisions):

1. **Engine policy files** (`src/vulnparse_pin/resources/` provisioned into `paths.config_dir`):
   - `config.yaml` (`version: v2`) — runtime profile, `signal_reliability`, `triage`, `feed_cache`, `enrichment`, `nmap_ctx`, `summary`, `webhook`
   - `scoring.json` (`version: v2`) — EPSS v5 breakpoints, Track A/B evidence points, risk bands, multi-CVE decay
   - `tn_triage.json` (`version: v2`) — `topn` decay/limits, `inference` predicates, and `aci` token rules
2. **Workspace context configs** (supplied via `--assets` and `--decisions`):
   - `assets.yaml` (`src/vulnparse_pin/core/schemas/assets.schema.json`) — inventory matching rules (`aliases`, `cidrs`, `hostnames`, `uris`, `images`, `repos`), `criticality`, `internet_facing`, `owner`, `env`, `tags`, and optional inline `decisions`
   - `decisions.yaml` (`src/vulnparse_pin/core/schemas/decisions.schema.json`) — audit-defensible `deferred`, `accepted`, and `mitigated` entries with expiration and assumption predicates (`vpp defer`)
3. **Runtime controls:** CLI flags (`src/vulnparse_pin/cli/args.py`) and integrity/token environment variables.

> [!NOTE]
> `ConfigValidator` accepts legacy `version: v1` `config.yaml` and `scoring.json` files and auto-projects them to `v2` defaults with a warning.

## Config Location and Mode Behavior (`AppPaths`)

Path layout is resolved by `AppPaths.resolve()` (`src/vulnparse_pin/core/apppaths.py`):

- **System mode (default):** OS-native app data directory via `platformdirs.user_data_dir("VulnParse-Pin")`.
- **Portable mode (`--portable` / `-P` or `VULNPARSE_PIN_PORTABLE=1`):** Project-local `./data/` tree for config, cache, logs, and outputs.

## `config.yaml` Reference (`version: v2`)

### Top-level & Triage Policy

- `version`: `"v2"` (or legacy `"v1"` auto-projected)
- `profile`: `"default"` or `"bod-26-04"`
- `signal_reliability`:
  - `enabled`: `true`
  - `weights`: `active_dast: 1.0`, `credentialed_host: 1.0`, `sca_container: 0.90`, `uncredentialed_banner: 0.85`, `static_sast: 0.55`, `network_probe: 0.80`
- `triage`:
  - `default_profile`: `"default"` (or `"bod_26_04"`)
  - `static_sast_p1_cap`: `true` (prevents uncorroborated SAST findings from triggering `P1`)

### Feed TTL & NVD / OSV Controls

- `feed_cache.defaults.ttl_hours` (`24`) and per-feed `feed_cache.ttl_hours.{exploit_db,kev,epss,nvd_yearly,nvd_modified,osv,ghsa}` (`0` = always stale, `< 0` = never expires, `> 0` = TTL hours).
- `feed_cache.feeds.nvd`: `enabled`, `start_year` (`2002`), `end_year` (`null`), `ttl_yearly`, `ttl_modified`, `sqlite_enforce_permissions` (`true`), `sqlite_file_mode` (`"0o600"`), `sqlite_max_age_hours` (`336`), `sqlite_max_rows` (`500000`).
- `feed_cache.feeds.osv`: `enabled`, `ttl_hours` (`24`).

### Enrichment & Confidence (`enrichment`)

- `ghsa_source`: `null` | `"online"` | `"offline"` (CLI `--ghsa` overrides; config alone does not auto-enable online lookups)
- `ghsa_online_prefetch_budget`: `25` (overridden by `--ghsa-budget`)
- `ghsa_token_env`: `"VP_GHSA_TK"` (falls back to `GITHUB_TOKEN`; validated env name and GitHub token prefix)
- `ghsa_cache`: `sqlite_max_age_hours: 336`, `sqlite_max_rows: 500000`
- `osv_source`: `null` (overridden by `--osv <PATH>`)
- `confidence`:
  - `model_version`: `"v2"`
  - `max_score`: `100`, `base_scanner`: `35`
  - `weights`: `nvd: 25`, `kev: 15`, `epss: 10`, `exploitdb: 10`, `ghsa: 15`, `osv: 15`
  - `ghsa_signals`: `advisory_confidence_bonus: 3`, `max_advisory_confidence_bonus: 9`, `exploit_signal_on_high_severity: false`, `exploit_signal_confidence_bonus: 5`

### Nmap Context (`nmap_ctx`) & Summary (`summary`)

- `nmap_ctx.port_tiebreak_enabled`: `true`
- `nmap_ctx.scoring_port_bonus`: `0.0` (schema-bounded `0.0–5.0`)
- `summary.top_n_findings`: `20`

### Signed Webhooks (`webhook`)

- `enabled`, `signing_key_env` (`"VP_WEBHOOK_HMAC_KEY"`), `key_id` (`"primary"`), `timeout_seconds` (`5`), `connect_timeout_seconds` (`3`), `read_timeout_seconds` (`5`), `max_retries` (`2`), `max_payload_bytes` (`262144`), `replay_window_seconds` (`300`), `allow_spool` (`true`), `spool_subdir` (`"webhook_spool"`), `endpoints[]` (`url`, `enabled`, `oal_filter` in `all|P1|P1b|P2`, `format`).
- Endpoints must use `https://` without embedded credentials, and `timeout_seconds >= max(connect_timeout_seconds, read_timeout_seconds)`.

## `scoring.json` Reference (`version: v2`)

Maps to `ScoringPolicyV2` (`src/vulnparse_pin/core/config_projector.py`):

- `epss`: monotonic piecewise `breakpoints` (`[[0.0, 0.0], [0.04, 1.8], [0.10, 3.0], [0.50, 4.2], [1.0, 5.0]]`), `use_percentile: true`, cutoffs (`0.04`/`0.10`, percentile `0.90`/`0.95`).
- `evidence_points`: `kev` (`4.5`), `verified_exploit` (`2.0`), `verified_exploit_with_kev` (`0.5`), `heuristic_exploit` (`0.0`).
- `bands`: strictly monotonic `critical` (`12.8`) > `high` (`9.6`) > `medium` (`6.4`) > `low` (`3.2`) >= `0`.
- `risk_ceiling`: `max_raw_risk` (`16.0`), `max_operational_risk` (`10.0`).
- `aggregation`: `cve_aggregation_mode` (`"stacked_decay"`), `cve_aggregation_decay` (`0.35`), `cve_aggregation_max_contributors` (`8`).
- `exposure_track`: Track B (`exposure_weakness`) severity base and `ACI@2.0` uplift parameters.

## `tn_triage.json` Reference (`version: v2`)

Controls `TopN@2.0` / `TopNPass` (`decay` starting at `1.0`, non-increasing in `[0, 1]`), exposure inference `rules[].when` predicates validated against `allow_predicates`, and `aci` token/uplift settings (`token_mode`, `disabled_core_tokens`, `min_confidence`, `max_uplift`, `asset_uplift_weight`).

## `assets.yaml` Reference (`assets.schema.json`)

Passed via `vpp scan --assets <PATH>` (or `vpp diff --assets <PATH>`):

- `version`: `"v1"` | `"v2"`
- `defaults`: fallback `criticality` (`critical|high|medium|low`), `internet_facing`, `owner`, `env`, `tags`
- `rules[]`: ordered pattern entries (`id` required; optional `asset_id`, `aliases[]`, `cidrs[]`, `hostnames[]`, `uris[]`, `images[]`, `repos[]`, `internet_facing`, `criticality`, `owner`, `env`, `tags`) matched via 5-tier precedence (`alias` -> `exact` -> longest-prefix `cidr` -> `glob` -> `unmatched_shadow`)
- `decisions[]`: optional inline decision entries evaluated alongside `decisions.yaml`

## `decisions.yaml` Reference (`decisions.schema.json`)

Passed via `vpp scan --decisions <PATH>`, `vpp diff --decisions <PATH>`, `vpp ui --decisions <PATH>`, or updated via `vpp defer`:

- `version`: `"v1"` | `"v2"`
- `decisions[]`: entries with `id`, `cve_or_rule_id`, `status` (`deferred|accepted|mitigated`), `rationale`, optional `asset_id` / `asset_pattern` (glob), `owner`, `created_at`, `expires_at`, and `assumptions`:
  - `in_kev` (`boolean | null`)
  - `max_epss` (`0.0–1.0`)
  - `max_epss_percentile` (`0.0–1.0`)
  - `internet_facing` (`boolean | null`)
  - `max_cvss` (`0.0–10.0`)

## Environment Variable Reference

| Variable | Purpose |
| --- | --- |
| `VP_FEED_CACHE_HMAC_KEY` | HMAC-SHA256 key for `FeedCacheManager` `.integrity.json` sidecars |
| `VP_SQLITE_HMAC_KEY` | HMAC-SHA256 key for all 5 SQLite `.sig.json` caches (`nvd`, `epss`, `kev`, `ghsa`, `osv`) |
| `VP_GHSA_TK` / `GITHUB_TOKEN` | GitHub PAT for online GHSA advisory prefetch |
| `VP_WEBHOOK_HMAC_KEY` | Default HMAC-SHA256 signing key for webhook deliveries (`signing_key_env`) |
| `VULNPARSE_PIN_PORTABLE` | Truthy (`1`/`true`/`yes`/`on`) enables `--portable` `./data/` layout |

## Related deep dives

- [Config Seam Contract](Config%20Seam%20Contract.md)
- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Runtime Policy Deep Dive](Runtime%20Policy%20Deep%20Dive.md)
- [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md)
- [Enrichment Deep Dive](Enrichment%20Deep%20Dive.md)
