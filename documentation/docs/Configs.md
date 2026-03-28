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

`config.yaml` controls feed cache policy, NVD feed policy, and summary options.

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

## Environment variable reference

Optional integrity hardening environment variables:

- `VP_FEED_CACHE_HMAC_KEY`: signs feed integrity sidecars in `FeedCacheManager`.
- `VP_SQLITE_HMAC_KEY`: signs NVD SQLite signature sidecar in `NVDFeedCache`.

If not set, modules fall back to SHA256 signature mode.

## CLI-to-policy mapping

Cache and enrichment behavior:

- `--mode`
- `--refresh-cache`
- `--allow_regen`
- `--enrich-kev`
- `--enrich-epss`
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

## Related deep dives

- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Runtime Policy Deep Dive](Runtime%20Policy%20Deep%20Dive.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
