# Caching Deep Dive

This page describes how VulnParse-Pin v2.0.0 caches all 6 threat-intelligence feeds, enforces fail-closed HMAC integrity and anti-downgrade rules, bounds remote HTTPS downloads and offline `.zip` archives, and supports read-only health inspection via `vpp intel status`.

## Scope

Primary implementation files:

- `src/vulnparse_pin/utils/feed_cache.py` (`FeedCacheManager`, `_open_https_stream`, `stream_https_get_bytes`)
- `src/vulnparse_pin/utils/nvdcacher.py` (`NVDFeedCache`)
- `src/vulnparse_pin/utils/enricher.py` (`_SignedSQLiteFeedCache`, `EPSSFeedCache`, `KEVFeedCache`)
- `src/vulnparse_pin/utils/ghsa_enrichment.py` (`GHSAEnrichmentSource`)
- `src/vulnparse_pin/utils/osv_enrichment.py` (`OSVEnrichmentSource`)
- `src/vulnparse_pin/utils/exploit_enrichment_service.py` (Exploit-DB `files_exploit.csv`)
- `src/vulnparse_pin/cli/commands.py` (`run_intel_command`, `_verify_sqlite_sig_ro`)

## Cache Architecture

VulnParse-Pin maintains two complementary cache tiers inside `paths.cache_dir`:

1. **Raw feed cache files (`FeedCacheManager`):**
   - `kev/kev_cache.json`
   - `epss/epss_cache.csv`
   - `exploit_db/files_exploit.csv`
   - `nvd/feeds/nvdcve-2.0-<year|modified>.json.gz` (and `.meta`)
   Each managed feed file has `.sha256`, `.meta.json`, and `.integrity.json` sidecars.
2. **Signed SQLite warm indexes (`0o600` POSIX mode, `.sig.json` sidecars):**
   - `nvd_cache.sqlite3` (`NVDFeedCache`)
   - `epss_cache.sqlite3` (`EPSSFeedCache`)
   - `kev_cache.sqlite3` (`KEVFeedCache`)
   - `ghsa_cache.sqlite3` (`GHSAEnrichmentSource`)
   - `osv_cache.sqlite3` (`OSVEnrichmentSource`)

## HMAC Environment Variables & Anti-Downgrade Rules

| Env Var | Scope | Behavior When Set |
| --- | --- | --- |
| `VP_FEED_CACHE_HMAC_KEY` | `FeedCacheManager` `.integrity.json` sidecars | Requires `mode == "hmac-sha256"` (`HMAC-SHA256(secret, digest)`). |
| `VP_SQLITE_HMAC_KEY` | All 5 SQLite `.sig.json` sidecars (`nvd`, `epss`, `kev`, `ghsa`, `osv`) | Requires `mode == "hmac-sha256"` (`HMAC-SHA256(secret, digest)`). |

### Fail-closed anti-downgrade & zero auto-resign guarantees

- **No silent SHA-256 downgrade:** When `VP_FEED_CACHE_HMAC_KEY` or `VP_SQLITE_HMAC_KEY` is set, any pre-existing or attacker-replaced sidecar claiming `mode: "sha256"` is rejected immediately (`_verify_feed_integrity` returns `False`, `_verify_signature` returns `False`).
- **Zero auto-resign on unsigned/tampered SQLite DBs:** All 5 SQLite caches verify `.sig.json` before trusting an existing database. Missing `.sig.json`, world-writable permissions (`stat.S_IWOTH`), digest mismatches, or HMAC mismatches never auto-resign the existing DB; instead, the cache quarantines both DB and sidecar to timestamped `.tampered.<UTCSTAMP>` backups and rebuilds an empty index.
- **Feed quarantine on mismatch:** When `allow_regen=False` (the default), `FeedCacheManager.ensure_feed_checksum()` quarantines mismatched data/sidecars and raises `FeedChecksumError`. Sidecar regeneration happens only when `--allow-regen` (`allow_regen=True`) is explicitly requested.

## Read-Only `vpp intel status` vs `vpp intel sync`

- **`vpp intel status [--feed ...] [--json]`:** Strictly read-only inspection (`_inspect_sqlite_health`, `_verify_sqlite_sig_ro`, `_check_feed_health`). Opens SQLite caches with `?mode=ro` URI mode, verifies `.sig.json` and `.integrity.json` with `allow_regen=False`, detects symlinks (`health="symlink"`), world-writable files (`health="world-writable"`), missing signatures (`health="no-signature"`), or tampering (`health="tampered"`), and reports row counts and freshness without modifying any cache file.
- **`vpp intel sync [--feed all|nvd|epss|kev|exploit_db|ghsa|osv] [--refresh]`:** Fetches/imports feeds and updates local caches and SQLite indexes.

## Remote HTTPS Streaming & Size Caps

All remote feed downloads (`FeedCacheManager`, NVD, KEV, EPSS, Exploit-DB) use `_open_https_stream()` / `stream_https_get_bytes()` (`src/vulnparse_pin/utils/feed_cache.py`):

- **Per-hop redirect validation:** Calls `requests.get(..., allow_redirects=False, stream=True)` and validates every `301`/`302`/`303`/`307`/`308` `Location` target against `https://` with a non-empty host (up to `max_redirects = 5`), failing closed on any HTTP downgrade.
- **Bounded byte limits:**
  - `MAX_NVD_META_BYTES = 1 MiB` (`1024 * 1024`) for NVD `.meta` files
  - `MAX_REMOTE_FEED_BYTES = 200 MiB` (`200 * 1024 * 1024`) for compressed remote feed downloads
  - `MAX_DECOMPRESSED_FEED_BYTES = 2 GiB` (`2 * 1024 * 1024 * 1024`) for `.gz` decompression

## OSV Offline Archive Guards (`osv_enrichment.py`)

When loading OSV `.zip` bundles (`--osv <bundle.zip>`), `OSVEnrichmentSource._validate_zip_member()` enforces strict fail-closed checks (`OSVSecurityError`):

- Rejects NUL bytes, leading `/` or `\`, backslashes, drive/colon prefixes (`:`), and `..` path-traversal segments.
- Rejects POSIX symlink entries (`stat.S_IFLNK` in `external_attr >> 16`).
- Bounds zip size: `DEFAULT_MAX_ZIP_ENTRIES = 250_000`, `DEFAULT_MAX_ZIP_ENTRY_BYTES = 50 MiB`, `DEFAULT_MAX_ZIP_TOTAL_BYTES = 2 GiB`, and `DEFAULT_MAX_ZIP_RATIO = 500` (for entries `> 10 MiB`).

## TTL Policy (`config.yaml`)

`FeedCacheManager.is_fresh()` evaluates `feed_cache.ttl_hours` (and `feed_cache.feeds.<feed>`):

- `ttl == 0`: always stale.
- `ttl < 0`: never expires.
- `ttl > 0`: fresh while age since `.meta.json` `last_updated` (or `created_at`) `<= ttl`.

## Related pages

- [Enrichment Deep Dive](Enrichment%20Deep%20Dive.md)
- [Configs](Configs.md)
- [Security Features](Security%20Features.md)
- [Threat Model](Threat%20Model.md)
