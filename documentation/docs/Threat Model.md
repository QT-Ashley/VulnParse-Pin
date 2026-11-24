# Threat Model

This threat model defines the v2.0.0 (`Apache-2.0`) attack surfaces, trust boundaries, mitigations, and residual risks for VulnParse-Pin (`vpp`) deployments.

## Scope

In scope:

- Local workstation, container, Kubernetes/systemd, and CI/CD execution (`vpp scan`, `diff`, `export`, `verify`, `defer`, `intel`, `ui`)
- Streaming ingestion of untrusted scanner files (XML, SARIF 2.1.0, JSONL, CSV, JSON)
- Persistent DuckDB `.vpp.db` workspace and `.wal`/`.tmp` sidecars
- Threat-intelligence feed retrieval (`FeedCacheManager`) and 5 SQLite indexes (`nvd`, `epss`, `kev`, `ghsa`, `osv`)
- Workspace context configs (`assets.yaml`, `decisions.yaml`) and custom Jinja2 `--template-dir`
- Output artifacts (HTML/Markdown Dossiers & Roadmaps, CSV, JSON, `RunManifest`, signed webhooks)

Out of scope:

- Host OS kernel hardening and physical/hypervisor isolation
- Upstream scanner accuracy or compromise of authoritative NVD/CISA/FIRST/GitHub publishers before download
- Consumer browser or spreadsheet security outside VPP's exported artifacts

## Trust Boundaries

- **Untrusted:** Scanner exports (XML, SARIF, JSONL, CSV), inline findings text/titles/locations, OSV offline `.zip` bundles, and external advisory descriptions.
- **Semi-trusted:** Remote HTTPS intelligence mirrors (KEV, EPSS, NVD, Exploit-DB, GHSA API) and local cached files/SQLite DBs on shared filesystems.
- **Configuration / Policy Boundary:** `config.yaml`, `scoring.json`, `tn_triage.json`, `assets.yaml`, `decisions.yaml`, and custom `--template-dir`.
- **Trusted Runtime:** Local Python process, `PermFileHandler` (`0o600`/`0o700`), DuckDB `.vpp.db` workspace, and HMAC keys (`VP_FEED_CACHE_HMAC_KEY`, `VP_SQLITE_HMAC_KEY`, `VP_WEBHOOK_HMAC_KEY`).
- **Output Sinks:** Analyst browsers (HTML Dossiers/Roadmaps), Markdown renderers (GitHub/GitLab PR comments), spreadsheet tools (CSV), and HTTPS webhook receivers.

## Primary Threat Scenarios & v2.0 Mitigations

1. **XXE, DTD Expansion, & Malformed XML / Encoding Smuggling**
   - **Mitigation:** `defusedxml` is absent; `_xml_security.py` runs `inspect_xml_prolog()` (up to 1 MiB, including BOM-less UTF-16LE/BE & UTF-32) rejecting `<!ENTITY`/`SYSTEM`/`PUBLIC`/internal subsets, and `safe_iterparse()` runs `lxml.etree.iterparse` (`resolve_entities=False`, `no_network=True`, `load_dtd=False`, `huge_tree=False`) with full-subtree `assert_no_entity_nodes()`.
2. **Symlink Escapes, Path Traversal, & File Mode Races**
   - **Mitigation:** PFH defaults to `forbid_symlinks_read=True`, `forbid_symlinks_write=True`, `enforce_roots_on_write=True`, `file_mode=0o600`, `dir_mode=0o700`. `VppDatabase` validates `.vpp.db`, `.wal`, `.tmp`, and all ancestors via `_validate_duckdb_paths()`, running `umask(0o177)` and `open_for_write_non_pfh` under `_UMASK_LOCK`.
3. **Cache Tampering & HMAC-to-SHA256 Downgrade Attacks**
   - **Mitigation:** When `VP_FEED_CACHE_HMAC_KEY` or `VP_SQLITE_HMAC_KEY` is set, plain `sha256` sidecars and unsigned SQLite DBs fail closed with zero auto-resign; tampered SQLite caches are quarantined to `.tampered.<UTCSTAMP>`. `vpp intel status` verifies read-only (`?mode=ro`).
4. **HTTP Redirect Downgrade & Decompression / Zip-Bomb DoS**
   - **Mitigation:** `_open_https_stream()` disables auto-redirects (`allow_redirects=False`) and enforces HTTPS per hop (`MAX_NVD_META_BYTES = 1 MiB`, `MAX_REMOTE_FEED_BYTES = 200 MiB`, `MAX_DECOMPRESSED_FEED_BYTES = 2 GiB`). `OSVEnrichmentSource._validate_zip_member()` blocks `..`, symlinks, drive prefixes, and zip-bombs.
5. **HTML XSS, Markdown Table/Link Injection, & CSV Formula Injection**
   - **Mitigation:** `renderer.py` enables Jinja2 `autoescape` for HTML templates (zero external CDNs) and `md_escape` for Markdown templates/reports. `csv_exporter.py` neutralizes formula prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) unless both `--no-csv-sanitize` and `--confirm-unsafe-csv` are passed.
6. **SQL Injection in DuckDB Queries / Textual TUI**
   - **Mitigation:** `storage/repositories.py`, `diff_engine.py`, `renderer.py`, and `ui/app.py` use parameterized DuckDB queries and validated column/table allowlists (`_ALLOWED_SQLITE_TABLES` in `vpp intel status`).
7. **Evidence & Manifest Tampering / Waiver Staleness**
   - **Mitigation:** `RunManifest` v2 hashes inputs, configs, outputs, and SHA-256 hash-chained `ledger_events`. `vpp verify` validates manifests read-only (verifying listed output artifacts + symlinks) without writing to `$HOME`/`XDG_*`. `DecisionsRegistry` + `vpp diff --fail-on stale-assumption` catches expired or assumption-violated deferrals.

## Security Assumptions

- Execution user account and local secret store (`VP_FEED_CACHE_HMAC_KEY`, `VP_SQLITE_HMAC_KEY`, `VP_WEBHOOK_HMAC_KEY`) are protected by host permissions.
- `--template-dir` custom Jinja2 templates and `assets.yaml`/`decisions.yaml` are operator-controlled inputs.
- POSIX `0o600`/`0o700` mode enforcement applies on Linux/macOS; Windows relies on NTFS ACLs.

## Residual Risks

- **Upstream intelligence compromise:** If an authoritative feed publisher (NVD, CISA, FIRST, GitHub, OSV) serves poisoned content over valid TLS before VPP caches it, VPP will faithfully sign and snapshot that content.
- **Operator opt-out flags:** Passing `--allow-symlinks-read`, `--no-csv-sanitize --confirm-unsafe-csv`, or `--allow-regen` intentionally relaxes fail-closed protections.
- **Unrestricted read roots by default:** `--enforce-root-read` is opt-in (`False` by default) so CLI users can pass scan files from arbitrary paths; high-security enclaves should pass `--enforce-root-read`.
- **Untrusted custom `--template-dir`:** Supplying untrusted Jinja2 templates can alter rendered HTML/Markdown output.

## Recommended Controls by Environment

- **Developer workstation:** Keep defaults enabled; install optional `[ui]` in an isolated `pipx`/`uv tool` or virtualenv; avoid `--no-csv-sanitize`.
- **CI/CD pipeline:** Set `VP_FEED_CACHE_HMAC_KEY`, `VP_SQLITE_HMAC_KEY`, and `VP_WEBHOOK_HMAC_KEY`; pass `--offline` against pre-verified caches or run `vpp intel status`; gate PRs with `vpp diff --fail-on stale-assumption` (or `kev`/`p1`); verify artifacts with `vpp verify`.
- **Restricted / air-gapped enclave:** Run as non-root with `readOnlyRootFilesystem`, `--portable` on a dedicated `0o700` volume, `--enforce-root-read`, and `vpp verify` for read-only audit verification.

## Related pages

- [Security Features](Security%20Features.md)
- [Runtime Policy Deep Dive](Runtime%20Policy%20Deep%20Dive.md)
- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Known Limitations](Known%20Limitations.md)
