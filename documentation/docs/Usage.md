# Usage

This is the authoritative **v2.0.0** CLI reference for VulnParse-Pin (`vpp` / `vulnparse-pin`, or `python -m vulnparse_pin`).

For a 5-minute walkthrough, see [Getting Started In 5 Minutes](Getting%20Started%20In%205%20Minutes.md). For complete runnable pipelines, see [Workflow Examples](Workflow%20Examples.md) and [Deployment Options](Deployment%20Options.md).

## Command Overview

```text
vpp [--version | -v] [--help | -h] COMMAND ...
```

| Subcommand | Purpose |
| --- | --- |
| `vpp scan` | Stream, normalize, enrich, score, triage, persist to `.vpp.db`, and export reports |
| `vpp demo` | Run the 100% offline bundled multi-scanner demo pack and optional TUI |
| `vpp diff` | Compare two runs in `.vpp.db` (or two scan files) and evaluate CI fail gates |
| `vpp ui` | Launch the interactive Textual TUI workbench over `.vpp.db` (requires `[ui]` extra) |
| `vpp export` | Export Decision Defense Dossiers, Executive Roadmaps, CSV, or JSON from `.vpp.db` |
| `vpp verify` | Read-only verification of `RunManifest` schema, digest, ledger chain, and listed outputs |
| `vpp defer` | Upsert a deferral, acceptance, or mitigation entry in `decisions.yaml` (and optionally refresh `.vpp.db`) |
| `vpp intel` | Inspect local threat-intel cache integrity/freshness (`status`) or sync feeds (`sync`) |

## Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Success (including `vpp diff` when the `--fail-on` gate passes) |
| `1` | Runtime error, input/parser failure, path/symlink policy error (`FilePathError` / `FilePermissionError`), missing `.vpp.db` or `[ui]` extra, or `vpp verify` integrity failure |
| `2` | CLI argument/usage error, `--no-csv-sanitize` without `--confirm-unsafe-csv`, invalid `--offline` URL override, or `vpp diff --fail-on` policy/drift gate breach (`p1`, `p2`, `kev`, `stale-assumption`) |

## Shared Runtime, Security & Portability Flags

Every subcommand (`scan`, `demo`, `diff`, `ui`, `export`, `verify`, `defer`, `intel`) accepts these shared options:

### General Options

- `--log-file <PATH>`, `-Lf <PATH>`: Log file destination inside the resolved log directory (default: `vulnparse_pin.log`).
- `--log-level <LEVEL>`, `-Ll <LEVEL>`: Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: `INFO`).
- `--version`, `-v`: Show program version and exit.

### Filesystem Security Options (`PermFileHandler`)

- `--forbid-symlinks-read`, `--forbid-symlinks_read`, `-Sr`: Reject symlinks when resolving read paths (default: `True`).
- `--allow-symlinks-read`: Explicitly allow following symlinks during read operations.
- `--forbid-symlinks-write`, `--forbid-symlinks_write`, `-Sw`: Reject symlinks when resolving write paths (default: `True`).
- `--enforce-root-read`, `-err`: Restrict read operations to `PermFileHandler` acceptable roots (default: `False`).
- `--enforce-root-write`, `-erw`: Restrict write operations to `PermFileHandler` acceptable roots (default: `True`; explicit CLI output paths are authorized via `authorize_output_path` without escaping symlink checks).
- `--file-mode <OCTAL>`, `-fm <OCTAL>`: POSIX-only chmod mode for written files (default: `0o600`).
- `--dir-mode <OCTAL>`, `-dm <OCTAL>`: POSIX-only chmod mode for created directories (default: `0o700`).
- `--debug-path-policy`: Print the active `PermFileHandler` path policy and exit.

### Portability

- `--portable`, `-P`: Store config, cache, logs, and default outputs in `./data` relative to the current working directory (or frozen executable directory) instead of OS user data directories. Also enabled by setting `VULNPARSE_PIN_PORTABLE=1` (or `true`/`yes`/`y`/`on`).

---

## Subcommands

### 1. `vpp scan`

Ingest one or more scanner reports into `.vpp.db`, hydrate matched threat intel, run the DuckDB pass DAG (`NmapAdapter@1.0` → `ACI@2.0` → `Scoring@3.0` → `Triage@2.0` → `TopN@2.0` → `Summary@2.0`), optionally diff against a baseline run, and export artifacts.

```bash
vpp scan [OPTIONS] [files ...]
```

#### Scan Inputs & Context

| Flag | Default | Description |
| --- | --- | --- |
| `files` (positional) | `None` | One or more paths to scanner reports (`.nessus`, `.xml`, `.csv`, `.sarif`, `.jsonl`, `.json`). |
| `--file PATH`, `-f PATH` | `None` | Single input scan file (legacy compatibility; combined with `files` if both given). |
| `--db PATH` | `.vpp.db` | DuckDB workspace database path (`0o600` POSIX permissions, symlink-checked). |
| `--assets PATH` | `None` | Asset context inventory YAML (`assets.yaml`) validated against `assets.schema.json`. |
| `--decisions PATH` | `None` | Triage decisions/deferrals YAML (`decisions.yaml`) validated against `decisions.schema.json`. |
| `--profile {default,bod-26-04}` | `default` | Triage decision profile (`default` or CISA BOD 26-04 SSVC). |
| `--run-id ID` | Auto-generated | Explicit run identifier (overwrites if `run_id` already exists in `.vpp.db`). |
| `--baseline-run-id ID` | `None` | Baseline `run_id` in `.vpp.db` for automatic scan-over-scan `DiffEngine` comparison. |
| `--strict-schema` | `False` | Enforce strict schema validation across inputs and configs (also enables strict ingestion). |
| `--allow-large`, `-al` | `False` | Raise input size limit from default `500 MiB` up to `50 GiB`. |
| `--allow-degraded-input` / `--no-allow-degraded-input` | `True` | Allow or reject degraded/partial parser findings during normalization. |
| `--strict-ingestion` | `False` | Fail normalization if degraded findings are present (overrides `--allow-degraded-input`). |
| `--min-ingestion-confidence FLOAT` | `0.0` | Reject findings whose ingestion confidence falls below `[0.0–1.0]`. |
| `--show-ingestion-summary` | `False` | Print ingestion quality summary metrics after normalization. |

#### Enrichment Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--offline` | `False` | Run 100% offline using local SQLite/feed caches and supplied local paths (rejects HTTP/HTTPS feed URLs and online `--ghsa` with exit `2`). |
| `--no-kev` | `False` | Disable CISA KEV enrichment. |
| `--no-epss` | `False` | Disable FIRST EPSS v5 enrichment. |
| `--no-exploit` | `False` | Disable Exploit-DB enrichment. |
| `--no-nvd` | `False` | Disable NVD enrichment. |
| `--kev-source {online,offline}` | `online` | Select CISA KEV source mode. |
| `--epss-source {online,offline}` | `online` | Select FIRST EPSS source mode. |
| `--exploit-source {online,offline}`, `-es` | `online` | Select Exploit-DB source mode (`offline` without `--offline` requires `--exploit-db`). |
| `--kev-feed KEV_FEED`, `--kev` | `None` | Override KEV feed with a local path or HTTPS URL. |
| `--epss-feed EPSS_FEED`, `--epss` | `None` | Override EPSS feed with a local path or HTTPS URL. |
| `--nvd NVD_SOURCE`, `--nvd-source` | `None` | Local NVD 2.0 `.json`, `.json.gz`, or directory of NVD feeds. |
| `--exploit-db PATH`, `-edb PATH` | `None` | Local Exploit-DB CSV file. |
| `--ghsa [PATH\|online]` | `None` (disabled) | Opt-in GHSA enrichment: bare `--ghsa` or `--ghsa online` queries GitHub API; `--ghsa PATH` loads a local advisory directory/cache. |
| `--ghsa-budget COUNT` | `None` (`25` in `config.yaml`) | Positive integer cap on online GHSA CVE lookups (only valid with online `--ghsa`). |
| `--osv PATH` | `None` | Optional offline OSV JSON file, directory, or ZIP archive. |
| `--nmap PATH`, `--nmap-ctx PATH`, `-nmap PATH` | `None` | Optional Nmap `nmaprun` `.xml` file for open-port attack-surface context (`NmapAdapter@1.0`). |
| `--refresh-cache` | `False` | Force refresh of feed caches. |
| `--allow_regen`, `--allow-regen` | `False` | Allow local cache checksum/meta regeneration if missing. |

#### Output Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--template-dir DIR` | `None` | Custom Jinja2 reporting templates directory (symlink-checked). |
| `--output-dossier PATH` | `None` | Write Decision Defense Dossier `.md` and `.html` (file stem or directory). |
| `--output-html PATH` | `None` | Write standalone HTML Decision Defense Dossier. |
| `--output FILE`, `-o FILE`, `--output-json FILE` | `None` | Write normalized + derived JSON output. |
| `--output-csv PATH`, `-oC PATH` | `None` | Write CSV output. |
| `--csv-profile {full,analyst,audit}` | `full` | Select CSV schema (`non-default` profiles require `--output-csv`). |
| `--output-md PATH`, `-oM PATH` | `None` | Write Executive Roadmap Markdown report. |
| `--output-md-technical PATH`, `-oMT PATH` | `None` | Write technical Decision Defense Dossier Markdown report. |
| `--output-runmanifest PATH`, `-oRM PATH` | `None` | Write `RunManifest` v2 JSON artifact (hashes written outputs and updates `runs.manifest_digest` in `.vpp.db`). |
| `--output-all BASENAME`, `--output_all`, `-oA` | `None` | Derive all standard outputs from `BASENAME`: `.json`, `.csv`, `_summary.md`, `_technical.md`, `_dossier.md`/`.html` (unless `--output-html` is set), and `_runmanifest.json`. |
| `--runmanifest-mode {compact,expanded}` | `compact` | Decision detail level in the `RunManifest` ledger. |
| `--pretty-print`, `-pp` | `False` | Pretty-print JSON output (`4`-space indentation). |
| `--presentation` | `False` | Export presentation-friendly JSON view. |
| `--overlay-mode {flatten,namespace}` | `flatten` | Presentation overlay mode (requires `--presentation`). |
| `--no-csv-sanitize`, `-noC` | `False` | Disable CSV cell formula-injection sanitization (requires `--output-csv` and `--confirm-unsafe-csv`, otherwise fails with exit `2`). |
| `--confirm-unsafe-csv` | `False` | Explicit confirmation required to disable CSV sanitization. |
| `--webhook-endpoint URL` | `None` | Override configured webhook target with an HTTPS URL (credentials in URL are rejected). |
| `--webhook-oal-filter {all,P1,P1b,P2}` | `None` | Filter webhook `top_findings` payload by Operational Action Lane. |

Example:

```bash
vpp scan nessus.nessus trivy.sarif nuclei.jsonl \
  --nmap nmap.xml \
  --assets assets.yaml \
  --decisions decisions.yaml \
  --profile bod-26-04 \
  --output-dossier out/dossier \
  --output-md out/roadmap.md \
  --output-runmanifest out/runmanifest.json
```

---

### 2. `vpp demo`

Run the 100% offline end-to-end demo using bundled multi-scanner fixtures (Nessus, Trivy SARIF, Nuclei JSONL, Semgrep SARIF, Nmap XML, `assets.yaml`, `decisions.yaml`, and miniature intel snapshot) without modifying user caches or making network requests.

```bash
vpp demo [OPTIONS]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--db PATH` | `.vpp-demo.db` | Demo DuckDB workspace path. |
| `--profile {default,bod-26-04}` | `default` | Triage decision profile. |
| `--no-ui` | `False` | Skip launching the interactive Textual TUI after exporting demo artifacts (also skipped automatically if stdout is not a TTY or `[ui]` is absent). |
| `--output-dir DIR` | `vpp_demo_output` | Output directory for `dossier.md`, `dossier.html`, `executive_roadmap.html`, and `runmanifest.json`. |
| `--template-dir DIR` | `None` | Custom Jinja2 reporting templates directory. |

---

### 3. `vpp diff`

Compare two runs in `.vpp.db` or two scan files on the fly (`:memory:` DuckDB), report new high-risk findings, threat-intel escalations, verified remediations, shadow-asset deltas, and invalidated deferral assumptions, and evaluate CI fail gates.

```bash
vpp diff [OPTIONS] [base] [target]
```

- **Positional `base` and `target`**: Either two `run_id` strings in `--db` (if omitted, compares the previous run to the latest run in `--db`), or two scan file paths for on-the-fly diffing.

| Flag | Default | Description |
| --- | --- | --- |
| `--db PATH` | `.vpp.db` | DuckDB workspace path when diffing stored runs. |
| `--decisions PATH` | `None` | Decisions registry YAML for stale-assumption checks. |
| `--assets PATH` | `None` | Optional `assets.yaml` when diffing two scan files on the fly. |
| `--profile {default,bod-26-04}` | `default` | Triage profile when ingesting two scan files on the fly. |
| `--offline` | `False` | Offline enrichment mode when ingesting two scan files on the fly. |
| `--fail-on {p1,p2,kev,stale-assumption,none}` | `none` | Exit with code `2` when the specified delta condition triggers. |
| `--output-md PATH` | `None` | Write Markdown diff report. |
| `--output-pr-comment PATH` | `None` | Write concise PR comment Markdown. |
| `--output-json PATH` | `None` | Write structured JSON diff report. |
| `--template-dir DIR` | `None` | Custom Jinja2 templates directory. |

Example CI gate:

```bash
vpp diff --db .vpp.db --decisions decisions.yaml --fail-on stale-assumption --output-pr-comment out/pr_comment.md
```

---

### 4. `vpp ui`

Launch the interactive Textual TUI workbench (`VppApp`) over `.vpp.db` (requires `pip install "vulnparse-pin[ui]"`).

```bash
vpp ui [OPTIONS]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--db PATH` | `.vpp.db` | DuckDB workspace path. |
| `--run-id ID` | Latest run | Target `run_id` to display. |
| `--decisions PATH` | `None` | Optional `decisions.yaml` enabling interactive deferrals (`f` modal). |
| `--output-dir DIR` | `.` | Directory for dossier exports triggered via `e` / `E`. |
| `--template-dir DIR` | `None` | Custom Jinja2 templates directory. |

Keyboard shortcuts inside `vpp ui`:
- `1` / `2` / `3` / `4`: Filter by priority tier `P1` / `P2` / `P3` / `P4`
- `0`: Clear all filters
- `t`: Cycle scoring track (`cve_threat` / `exposure_weakness` / all)
- `k`: Toggle CISA KEV filter
- `u`: Toggle unmatched shadow assets filter
- `/`: Focus search input (`Esc` returns to table)
- `[` / `]`: Previous / next page
- `d`: Switch to **Diff & Stale Assumptions** tab
- `e` / `E`: Export selected finding dossier / full run dossier
- `f`: Open deferral / acceptance / mitigation modal
- `q`: Quit

---

### 5. `vpp export`

Export reports or data views directly from an existing `.vpp.db` run without re-parsing scanner inputs.

```bash
vpp export --format FORMAT [OPTIONS]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--format {dossier-md,dossier-html,roadmap-md,roadmap-html,csv,json}` | **Required** | Artifact format to export. |
| `--db PATH` | `.vpp.db` | DuckDB workspace path. |
| `--run-id ID` | Latest run | Target `run_id`. |
| `--finding-id ID` | `None` | Optional single `finding_id` for `dossier-md` / `dossier-html`. |
| `--output PATH`, `-o PATH` | stdout (`dossier-*`/`roadmap-*`) or `vpp_<run_id>.<ext>` | Output file path. |
| `--template-dir DIR` | `None` | Custom Jinja2 templates directory. |
| `--csv-profile {full,analyst,audit}` | `full` | CSV export column profile (`--format csv`). |
| `--overlay-mode {flatten,namespace}` | `namespace` | JSON presentation mode (`--format json`). |
| `--pretty-print`, `-pp` | `False` | Pretty-print JSON output. |
| `--no-csv-sanitize`, `-noC` | `False` | Disable CSV cell sanitization (requires `--confirm-unsafe-csv`, else exit `2`). |
| `--confirm-unsafe-csv` | `False` | Explicitly confirm disabling CSV sanitization. |

---

### 6. `vpp verify`

Verify a `RunManifest` JSON file's schema, `verification.manifest_digest`, SHA-256 hash-chained decision ledger, and all non-null listed output artifacts (`outputs` + `output_hashes` / `outputs_sha256`).

```bash
vpp verify [OPTIONS] runmanifest
```

- **Positional `runmanifest`**: Path to the `runmanifest.json` file.
- **Strictly Read-Only Default Behavior**: By default, `vpp verify` does **not** create `$HOME` / `XDG_DATA_HOME` / `./data` directories or write log files. Directories and a log file are only created if you explicitly pass a custom `--log-file` (other than the default `vulnparse_pin.log`).
- Honors `--forbid-symlinks-read` (default `True`), `--allow-symlinks-read`, `--enforce-root-read`, and `--portable`.
- Returns `0` on success, `1` if the manifest, ledger chain, or any listed output artifact fails verification or is missing/symlinked.

---

### 7. `vpp defer`

Create or update a deferral, acceptance, or mitigation rule in `decisions.yaml` (preserving YAML comments via `ruamel.yaml`) and optionally re-evaluate triage decisions in `.vpp.db`.

```bash
vpp defer --asset PATTERN --id CVE_OR_RULE --status STATUS --rationale TEXT --owner NAME [OPTIONS]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--asset PATTERN` | **Required** | Asset ID, hostname, IP, CIDR, or glob pattern. |
| `--id CVE_OR_RULE` | **Required** | CVE ID or scanner rule/template ID. |
| `--status {deferred,accepted,mitigated}` | **Required** | Decision status. |
| `--rationale TEXT` | **Required** | Audit-defensible rationale. |
| `--owner NAME` | **Required** | Responsible owner. |
| `--expires YYYY-MM-DD` | `None` | Expiration date (`YYYY-MM-DD` or ISO-8601). |
| `--in-kev true\|false` | `None` | Assumption predicate: whether CVE is in CISA KEV. |
| `--max-epss FLOAT` | `None` | Assumption predicate: max EPSS score `[0.0–1.0]`. |
| `--max-epss-percentile FLOAT` | `None` | Assumption predicate: max EPSS percentile `[0.0–1.0]`. |
| `--internet-facing true\|false` | `None` | Assumption predicate: asset internet exposure state. |
| `--max-cvss FLOAT` | `None` | Assumption predicate: max CVSS base score `[0.0–10.0]`. |
| `--decision-id ID` | Auto-generated | Explicit decision identifier. |
| `--decisions PATH` | `decisions.yaml` | Target decisions YAML path. |
| `--db PATH` | `None` | Optional `.vpp.db` to immediately refresh `triage_decisions` for the latest run. |

---

### 8. `vpp intel`

Inspect local threat-intelligence cache freshness, row counts, and HMAC/SHA-256 integrity (`status`), or sync feeds (`sync`) for connected staging or offline prep.

```bash
vpp intel [status|sync] [OPTIONS]
```

| Flag | Default | Description |
| --- | --- | --- |
| `action` (positional) | `status` | `status` (read-only cache inspection) or `sync` (fetch/hydrate feeds). |
| `--feed {all,nvd,epss,kev,exploit_db,ghsa,osv}` | `all` | Specific feed to inspect or sync. |
| `--refresh` | `False` | Force feed refresh during `sync`. |
| `--allow-regen`, `--allow_regen` | `False` | Allow local checksum regeneration if missing during `sync`. |
| `--kev-feed PATH_OR_URL` | `None` | Custom KEV source for `sync`. |
| `--epss-feed PATH_OR_URL` | `None` | Custom EPSS source for `sync`. |
| `--exploit-db PATH`, `-edb PATH` | `None` | Local Exploit-DB CSV source for `sync`. |
| `--nvd PATH` | `None` | Local NVD JSON / `.json.gz` / directory for `sync`. |
| `--ghsa PATH` | `None` | Local GHSA advisory JSON/directory for `sync`. |
| `--osv PATH` | `None` | Local OSV JSON/directory/zip for `sync`. |
| `--json` | `False` | Print `vpp intel status` output as structured JSON. |

---

## Legacy Compatibility Shim (`v1.x` Flags)

> [!WARNING]
> Top-level legacy flags are deprecated in `v2.0.x` and emit a `[DEPRECATED]` notice to `stderr`. Migrate scripts to v2.0 subcommands before removal in a future release (see [Deprecation and Versioning Policy](Deprecation%20and%20Versioning%20Policy.md)).

| Legacy `v1.x` Invocation | Rewritten v2.0 Command |
| --- | --- |
| `vpp -f scan.nessus -o out.json` / `vpp --file scan.nessus ...` | `vpp scan -f scan.nessus -o out.json` |
| `vpp --demo` | `vpp demo --no-ui` (runs packaged legacy OpenVAS + Nmap demo compatibility flow) |
| `vpp --verify-runmanifest runmanifest.json` | `vpp verify runmanifest.json` |
| `vpp --debug-path-policy` | `vpp scan --debug-path-policy` |

Note: Inside `vpp scan`, `--file` / `-f` and `--nmap-ctx` / `-nmap` continue to work alongside positional `files...` and `--nmap`.

## Related Docs

- [Getting Started In 5 Minutes](Getting%20Started%20In%205%20Minutes.md)
- [Workflow Examples](Workflow%20Examples.md)
- [Deployment Options](Deployment%20Options.md)
- [Upgrade and Migration](Upgrade%20and%20Migration.md)
- [Output Interpretation](Output%20Interpretation.md)
- [Troubleshooting](Troubleshooting.md)
