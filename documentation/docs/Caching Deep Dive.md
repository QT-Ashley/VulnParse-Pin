# Caching Deep Dive

This page describes how VulnParse-Pin caches enrichment feeds, validates cache integrity, applies TTL policy, and uses the NVD SQLite index for warm-run acceleration.

## Scope

Primary implementation files:

- `src/vulnparse_pin/utils/feed_cache.py`
- `src/vulnparse_pin/utils/nvdcacher.py`
- `src/vulnparse_pin/app/runtime_helpers.py`
- `src/vulnparse_pin/app/bootstrap.py`
- `src/vulnparse_pin/resources/config.yaml`

## Cache architecture

VulnParse-Pin uses two cache systems:

1. Feed cache files managed by `FeedCacheManager`.
2. Optional NVD SQLite index managed by `NVDFeedCache`.

The feed cache is authoritative for downloaded KEV, EPSS, Exploit-DB, and NVD feed archives. The SQLite index is a performance layer built from NVD feed data.

## Feed cache internals (`FeedCacheManager`)

`FeedCacheManager` is instantiated in bootstrap via `FeedCacheManager.from_ctx(...)` and receives:

- `cache_dir`
- PFH instance (`ctx.pfh`) for path-safe I/O
- logger
- feed specs
- feed TTL policy (`FeedCachePolicy`)

### Feed identity and path model

For non-NVD feeds, each feed key resolves to:

- data file (for example `epss_cache.csv`)
- checksum sidecar (`.sha256`)
- metadata sidecar (`.meta.json`)
- integrity sidecar (`.integrity.json`)

For NVD feeds, keys use the namespace:

- `nvd.modified`
- `nvd.year.YYYY`

### Sidecar purpose

- `.sha256`: canonical content digest for the data file.
- `.meta.json`: timestamps and source/validation metadata (`created_at`, `last_updated`, source URL, validation status).
- `.integrity.json`: digest signature envelope (`mode`, `digest`, `signature`, `updated_at`).

### Integrity modes for feed files

`FeedCacheManager` supports two integrity modes for `.integrity.json`:

1. `sha256` mode: `signature == digest`
2. `hmac-sha256` mode: signature is `HMAC(secret, digest)`

The mode is controlled by environment variable presence.

## HMAC environment variables

### `VP_FEED_CACHE_HMAC_KEY`

- Used by `FeedCacheManager._feed_integrity_secret()`.
- If set, feed integrity sidecars are signed with HMAC-SHA256.
- If unset, feed integrity falls back to plain SHA256 signature mode.

### `VP_SQLITE_HMAC_KEY`

- Used by `NVDFeedCache._sqlite_secret()`.
- If set, SQLite signature sidecar is HMAC-SHA256.
- If unset, SQLite signature mode remains plain SHA256.

### Operational recommendation

In production, set both variables to high-entropy secrets and rotate with standard secret-management policy.

## TTL behavior

TTL is derived from `FeedCachePolicy` created by `build_feed_cache_policy(config)`.

### Global structure (`config.yaml`)

- `feed_cache.defaults.ttl_hours`
- `feed_cache.ttl_hours.<feed_key>`

Examples of feed keys in `ttl_hours`:

- `kev`
- `epss`
- `exploit_db`
- `nvd_yearly`
- `nvd_modified`

### TTL semantics in `FeedCacheManager.is_fresh()`

- `ttl == 0`: always stale.
- `ttl < 0`: never expires.
- `ttl > 0`: cache is fresh when age in hours is less than or equal to TTL.

`age` is calculated from `.meta.json` using `last_updated` (fallback `created_at`).

### Failure cases

`is_fresh()` returns stale when:

- metadata file is missing
- metadata timestamp is missing
- timestamp parsing fails

## Checksum and integrity lifecycle

`ensure_feed_checksum(key, allow_regen=...)` validates or regenerates feed state:

1. Validate `.sha256` against current data digest.
2. Validate `.integrity.json` digest and signature.
3. If files are missing or invalid and `allow_regen` is true, regenerate local state.
4. If hard mismatch and `allow_regen` is false, fail fast.

This supports strict integrity workflows in offline mode and best-effort recovery when explicitly enabled.

## NVD feed policy and plan

NVD settings are normalized by `nvd_policy_from_config(config)`.

Policy fields include:

- `enabled`
- `ttl_yearly`
- `ttl_modified`
- `start_year`
- `end_year`
- `sqlite_enforce_permissions`
- `sqlite_max_age_hours`
- `sqlite_max_rows`

`nvd_feed_plan(config)` emits feed plan entries:

1. Modified feed (`nvd.modified`)
2. Yearly feeds from `start_year` through `end_year`

NVD policy loader also supports legacy key fallbacks and bounds invalid ranges.

## NVD SQLite index (`NVDFeedCache`)

`NVDFeedCache` initializes in bootstrap unless `--no-nvd` is set.

### Index files

- SQLite DB: `nvd_cache.sqlite3`
- Signature sidecar: `nvd_cache.sqlite3.sig.json`

### Security controls

- Signature verification at startup (`_sqlite_verify_signature`).
- Optional HMAC signatures via `VP_SQLITE_HMAC_KEY`.
- Permission checks/hardening via `_sqlite_harden_permissions`.
- CVE ID validation regex before lookup/upsert paths.
- Quarantine and reset on integrity failure (`_sqlite_quarantine_and_reset`).

### Quarantine behavior

On tamper or signature failure, the index and signature files are moved to timestamped `.tampered.<UTCSTAMP>` files, then a clean index is rebuilt.

### Pruning policy

`_sqlite_prune()` enforces:

- max row age (`sqlite_max_age_hours`)
- max retained rows (`sqlite_max_rows`)

This keeps warm cache size bounded over long runtimes.

## NVD parsing and performance

NVD feed parsing uses:

- `ijson` streaming when available
- `json.load` fallback if `ijson` is unavailable

Feed processing can run in parallel for multi-feed operations and is filtered by target CVEs and year ranges to reduce parse overhead.

## CLI controls that impact cache behavior

- `--refresh-cache`
- `--allow_regen`
- `--no-kev`
- `--no-epss`
- `--no-exploit`
- `--kev-source online|offline`
- `--epss-source online|offline`
- `--exploit-source online|offline`
- `--kev-feed [PATH|URL]`
- `--epss-feed [PATH|URL]`
- `--no-nvd`

## Failure modes and expected behavior

- Missing cache in offline mode: fail with explicit missing-feed error.
- Corrupt feed sidecar: regenerated only when allowed by `--allow_regen`.
- SQLite signature mismatch: quarantine and rebuild path is triggered.
- Remote NVD metadata unavailable: local cache can still be used depending on freshness and mode.

## Related pages

- [Configs](Configs.md)
- [Security Features](Security%20Features.md)
- [Performance Optimizations](Performance%20Optimizations.md)
- [Pipeline System](Pipeline%20System.md)
