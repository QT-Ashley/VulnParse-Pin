# Security Features

VulnParse-Pin v2.0.0 (`Apache-2.0`) enforces fail-closed security controls across filesystem I/O, DuckDB storage, XML/SARIF/ZIP parsing, threat-intel caches, reporting templates, CSV exports, and RunManifest verification.

## Security Goals

- Prevent path traversal, ancestor symlink escapes, and DuckDB WAL/temp symlink attacks
- Prevent XXE, DTD/entity expansion, JSON/SARIF memory exhaustion, and OSV zip-bomb/traversal attacks
- Detect tampering and prevent silent HMAC-to-SHA256 downgrades in threat-intel caches
- Protect downstream readers from HTML/Markdown XSS/injection and CSV formula injection
- Keep `vpp verify` and `vpp intel status` strictly read-only by default

## File I/O, `_UMASK_LOCK`, and DuckDB Path Hardening

- **PFH (`src/vulnparse_pin/io/pfhandler.py`):** Defaults in `build_pfh()` are `forbid_symlinks_read=True` (opt-out via `--allow-symlinks-read`), `forbid_symlinks_write=True`, `enforce_roots_on_write=True`, `enforce_roots_on_read=False` (opt-in via `--enforce-root-read`), `file_mode=0o600`, and `dir_mode=0o700`.
- **Ancestor symlink & loop checks (`_check_no_symlinks_or_loops`):** Validates every path segment from root to leaf against `stat.S_ISLNK` and `errno.ELOOP`.
- **Thread-safe restricted umask (`_UMASK_LOCK`):** `ensure_safe_dir_non_pfh()` and `open_for_write_non_pfh()` (`src/vulnparse_pin/storage/db.py`) acquire `_UMASK_LOCK` around `os.umask()` so staging temp files and directories are created `0o600`/`0o700` atomically before `os.replace()`.
- **DuckDB workspace guards (`VppDatabase`):** `_validate_duckdb_paths()` checks `.vpp.db`, its `.wal` and `.tmp` sidecars, and all parent segments against symlinks; `duckdb.connect()` and transactions run under `umask(0o177)` + `_UMASK_LOCK` with `_chmod_0600_if_exists()`.
- **Read-only `vpp verify` (`_build_verify_pfh`):** Verifies RunManifest JSON, SHA-256 ledger hash chains, and listed output artifact hashes without writing to `$HOME`/`XDG_*` directories unless a custom `--log-file` is passed.

## XML, SARIF, JSONL, and Input Validation Hardening

- **Hardened `lxml` XML parsing (NO `defusedxml`):** `src/vulnparse_pin/parsers/_xml_security.py` replaces `defusedxml` with `safe_iterparse()` and `sniff_xml_head_events()` backed by `lxml.etree` (`resolve_entities=False`, `no_network=True`, `load_dtd=False`, `dtd_validation=False`, `huge_tree=False`).
  - `inspect_xml_prolog()` inspects up to `MAX_XML_PROLOG_BYTES = 1 MiB` before the root element, handling UTF-8 BOM, UTF-16 BOM, UTF-32, and **BOM-less UTF-16LE/BE**, and rejecting `<!ENTITY`, `SYSTEM`, `PUBLIC`, parameter entities (`%`), internal DTD subsets, and NUL bytes.
  - `safe_iterparse()` iterates all elements internally (even when `tag=` is specified) and runs `assert_no_entity_nodes()` across subtrees so entity nodes outside filtered tags cannot evade rejection.
- **Bounded input validation (`FileInputValidator`):** 500 MiB default cap (up to 50 GiB with `--allow-large`), 64 KiB `SchemaDetector` head read, 8 MiB max JSONL line, and 32 MiB CSV field cap (`_MAX_CSV_FIELD_BYTES`).
- **Chunked SARIF streaming:** `_FastSarifStreamReader` (`sarif_parser.py`) decodes 4 MiB chunks incrementally via `json.JSONDecoder.raw_decode` and skips unrelated values in O(1) memory.

## Clean-Room Apache-2.0 CVSS Engine

`src/vulnparse_pin/utils/cvss_utils.py` implements FIRST CVSS v2.0, v3.0, v3.1, and v4.0 validation and base-score calculation using Python standard library modules only (`Decimal`, `Fraction`), removing the legacy LGPL `cvss` dependency.

## Threat-Intel Cache, Network & OSV Zip Security

- **Strict HMAC anti-downgrade:** When `VP_FEED_CACHE_HMAC_KEY` (`FeedCacheManager`) or `VP_SQLITE_HMAC_KEY` (`nvd_cache.sqlite3`, `epss_cache.sqlite3`, `kev_cache.sqlite3`, `ghsa_cache.sqlite3`, `osv_cache.sqlite3`) is set, plain `sha256` downgrade sidecars or unsigned pre-existing DBs fail closed with zero auto-resign; tampered SQLite files are quarantined to `.tampered.<UTCSTAMP>`.
- **World-writable rejection:** Caches and sidecars with `stat.S_IWOTH` are rejected immediately.
- **Per-hop HTTPS redirect validation:** `_open_https_stream()` uses `allow_redirects=False` and validates every redirect `Location` to `https://` (`MAX_NVD_META_BYTES = 1 MiB`, `MAX_REMOTE_FEED_BYTES = 200 MiB`, `MAX_DECOMPRESSED_FEED_BYTES = 2 GiB`).
- **OSV zip-bomb & traversal guard:** `OSVEnrichmentSource._validate_zip_member()` rejects `..`, absolute/backslash paths, drive prefixes, NUL bytes, POSIX symlinks, entries `> 50 MiB`, total `> 2 GiB`, `> 250,000` entries, and compression ratios `> 500`.
- **GHSA token validation:** Rejects `\r`/`\n` header-unsafe tokens and enforces GitHub token prefixes without logging secrets.

## Reporting, CSV Export, Config & Webhook Hardening

- **Jinja2 `autoescape` & `md_escape`:** `src/vulnparse_pin/reporting/renderer.py` configures Jinja2 `autoescape=select_autoescape(["html", "xml", "j2"])` for HTML Dossiers/Roadmaps and applies `md_escape` across Markdown Dossiers, Roadmaps, PR diff comments, and legacy `markdown_report.py`. Generated HTML contains zero external CDN scripts or stylesheets.
- **CSV formula-injection sanitization:** `csv_exporter.py` neutralizes dangerous prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) and strips control characters by default. Disabling via `--no-csv-sanitize` requires explicit `--confirm-unsafe-csv` (otherwise exits with code `2`).
- **Safe YAML & schema validation:** `config_source.py` and `assets_context.py` load YAML with `ruamel.yaml.YAML(typ="safe", pure=True)` and validate against JSON Schema Draft 2020-12 (`config.schema.json`, `assets.schema.json`, `decisions.schema.json`).
- **Signed HTTPS webhooks:** `webhook_delivery.py` enforces `https://` without embedded credentials, `allow_redirects=False`, bounded payload sizes (`262144` bytes), and HMAC-SHA256 signatures via `VP_WEBHOOK_HMAC_KEY`.

## Related pages

- [Threat Model](Threat%20Model.md)
- [Runtime Policy Deep Dive](Runtime%20Policy%20Deep%20Dive.md)
- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Detection and Parsing](Detection%20and%20Parsing.md)
