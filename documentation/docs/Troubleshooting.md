# Troubleshooting

This guide helps diagnose and resolve common runtime, permission, cache, CLI, and TUI issues in VulnParse-Pin **v2.0.0**.

## Fast Triage Flow

1. Run with `--log-level INFO` or `DEBUG` to inspect phase execution.
2. Confirm your `.vpp.db` and cache paths contain no symlinks or world-writable permissions.
3. Run `vpp intel status` to verify local feed/SQLite cache freshness and HMAC/SHA-256 health.
4. Confirm input format, file size (`--allow-large`), and `vpp verify` output paths.

---

## v2.0 Common Issues & Fixes

### 1. DuckDB `.vpp.db` Symlink or Permission (`0o600` / `0o700`) Errors

**Symptoms:**
- `Refusing symlink DuckDB workspace path: ...` or `Refusing symlink DuckDB WAL sidecar: ...`
- `Refusing symlink loop in ...` or `FilePermissionError` / `FilePathError` when opening `.vpp.db`

**Cause:**
- `VppDatabase` (`_validate_duckdb_paths`) checks the `.vpp.db` target, every ancestor directory, and `.wal` / `.tmp` sidecars against symlinks and symlink loops, and enforces `0o600` POSIX permissions on `.vpp.db` / `.wal` files (`0o700` on created directories).

**Fixes:**
- Point `--db` to a real, non-symlinked local path whose parent directories contain no symlinks (for example `/work/vpp.db` instead of a symlinked shortcut).
- If an existing `.vpp.db` or `.vpp.db.wal` has overly permissive modes or belongs to another user, ensure it is owned by the current user with `chmod 600 .vpp.db` (and `chmod 700` on its private state directory).

### 2. Read-Only `$HOME` or `XDG_DATA_HOME` Errors (`--portable`)

**Symptoms:**
- `PermissionError` or path policy errors when running `vpp scan`, `vpp diff`, `vpp export`, or `vpp intel` in containers (`--read-only` rootfs), restricted CI runners, or systemd services where `$HOME` / `~/.local/share` is non-writable.

**Fixes:**
- Pass `--portable` (`-P`) or set `VULNPARSE_PIN_PORTABLE=1` and run inside a writable working directory so VulnParse-Pin writes configs, caches, and logs under `./data`.
- Alternatively, mount a writable volume and set `HOME=/work` or `XDG_DATA_HOME=/work/xdg`.
- Note: `vpp verify <runmanifest.json>` is **strictly read-only by default** and does not write to `$HOME` or `XDG_DATA_HOME` unless you explicitly pass a custom `--log-file`.

### 3. `vpp intel status` HMAC, World-Writable, or Checksum Diagnostics

**Symptoms:**
- `vpp intel status` reports `integrity=world-writable`, `integrity=tampered`, `integrity=no-signature`, `integrity=missing-checksum`, or `integrity=symlink`.

**Diagnosis:**

```bash
vpp intel status
vpp intel status --json
```

| Reported `health` | Meaning & Fix |
| --- | --- |
| `world-writable` | Cache file or `.sig.json` has group/other-writable (`o+w`) permissions. Fix permissions (`chmod 600 <file>`) or delete and re-sync (`vpp intel sync --refresh`). |
| `tampered` | File digest mismatch, or `VP_SQLITE_HMAC_KEY` / `VP_FEED_CACHE_HMAC_KEY` is set/unset differently from when the cache was created. Export the matching key or re-sync with `vpp intel sync --refresh`. |
| `no-signature` / `missing-checksum` | Sidecar `.sig.json` or `.sha256` is missing. Re-sync (`vpp intel sync --refresh`) or pass `--allow-regen` if local sidecar regeneration is acceptable. |
| `symlink` | Cache file or sidecar is a symlink. Replace with a real file via `vpp intel sync --refresh`. |
| `corrupt` | SQLite index table could not be queried. Remove the corrupt `.sqlite3` file and re-run `vpp intel sync --refresh`. |

### 4. Large Scan Rejected (`> 500 MiB` / `--allow-large`)

**Symptoms:**
- `FileInputValidator` or parser rejects a large `.nessus`, `.xml`, `.sarif`, or `.jsonl` file.

**Cause:**
- By default, `FileInputValidator` enforces a `500 MiB` (`max_size_mb=500`) guardrail.

**Fix:**
- Pass `--allow-large` (`-al`) on `vpp scan` to raise the limit up to **`50 GiB`**:

  ```bash
  vpp scan huge_scan.nessus --allow-large --log-level WARNING
  ```

### 5. CSV Export Fails with Exit Code `2` (`--no-csv-sanitize`)

**Symptoms:**
- `[ERROR] Refusing to disable CSV cell sanitization without explicit --confirm-unsafe-csv.` (exit code `2`)

**Cause:**
- Disabling spreadsheet formula-injection protection (`=`, `+`, `-`, `@` prefix neutralization) requires explicit acknowledgment on both `vpp scan` and `vpp export`.

**Fix:**
- Keep default CSV sanitization enabled (recommended), or pass both flags intentionally:

  ```bash
  vpp export --db .vpp.db --format csv --output raw.csv --no-csv-sanitize --confirm-unsafe-csv
  ```

### 6. `vpp diff --fail-on` Exits with Code `2` in CI

**Symptoms:**
- `vpp diff` prints the delta summary and exits with code `2`.

**Cause:**
- Exit code `2` from `vpp diff --fail-on <p1|p2|kev|stale-assumption>` is an intentional **policy/drift gate trigger** (for example, a deferred CVE entered CISA KEV or crossed EPSS thresholds), whereas exit code `1` indicates a runtime, missing-DB, or invalid-run error.

**Fix:**
- Inspect the delta output or `--output-pr-comment` / `--output-json` report to review newly introduced high-risk findings or invalidated deferrals (`decisions.yaml`).
- In CI/cron scripts, branch explicitly on exit code `2` vs `1` (see [Workflow Examples](Workflow%20Examples.md)).

### 7. `vpp verify` Fails on Listed Output Artifacts

**Symptoms:**
- `[FAIL] RunManifest verification failed: ...: Listed output artifact '<key>' is missing: ...`
- `[FAIL] RunManifest verification failed: ...: Output artifact '<key>' digest mismatch: ...`
- `Refusing symlink output artifact '...'`

**Cause:**
- `vpp verify` validates not only `runmanifest.json` and its `ledger_events` SHA-256 chain, but also verifies that every non-null output file recorded under `outputs` exists on disk, is not a symlink (unless `--allow-symlinks-read` is passed), and matches its SHA-256 digest in `output_hashes` (`outputs_sha256`).

**Fixes:**
- Keep exported artifacts (`.json`, `.csv`, `_summary.md`, `_technical.md`, `_dossier.md`/`.html`) at the paths recorded in `runmanifest.json` without post-export editing.
- Do not modify `runmanifest.json` or exported reports after `vpp scan --output-runmanifest` seals them; re-run `vpp scan` or `vpp export` if you need updated outputs.
- If verifying across symlinked artifact directories intentionally, pass `--allow-symlinks-read` (while keeping symlink rejection enabled in untrusted environments).

### 8. `vpp ui` Fails: Missing Textual `[ui]` Dependencies

**Symptoms:**
- `Textual UI dependencies are not installed. Install with: pip install "vulnparse-pin[ui]"` (exit code `1`)

**Fix:**
- Core `vulnparse-pin` intentionally excludes Textual to keep headless CI installs lightweight. Install the `[ui]` extra:

  ```bash
  pipx install --force "vulnparse-pin[ui]"
  # or inside your virtualenv:
  pip install "vulnparse-pin[ui]"
  ```

- For non-interactive `vpp demo` runs without `[ui]`, pass `vpp demo --no-ui`.

---

## General Input & Performance Checks

### Input Not Detected or Unsupported

1. Confirm the file is a supported format (`nessus-xml`, `openvas-xml`, `qualys-xml`, `nmap-xml`, `sarif-2.1.0`, `nuclei-jsonl`, `nessus-csv`, `qualys-csv`).
2. Check for truncated XML/SARIF exports or unexpected root tags.
3. Use `--show-ingestion-summary` and `--log-level INFO` to inspect parser selection and ingestion confidence. See [Detection and Parsing](Detection%20and%20Parsing.md).

### Slow Processing on Large Workloads

1. Pass `--log-level WARNING` or `ERROR` to avoid excessive log I/O on 100k+ findings.
2. Keep local intel caches warm via `vpp intel sync` before running `--offline` scans.
3. Validate host memory and throughput expectations against `benchmarks/bench_scale.py` and [Benchmarks](Benchmarks.md).

## Useful Diagnostic Commands

```bash
vpp --version
vpp scan --debug-path-policy
vpp intel status
vpp demo --no-ui
vpp verify out/runmanifest.json
```

## When Filing an Issue

Include:

1. `vpp --version` output
2. Exact command used (redact sensitive paths, hosts, and tokens)
3. Input format(s) and approximate finding count
4. Relevant `--log-level DEBUG` excerpts and exit code
5. `vpp intel status --json` output (if enrichment-related)

## Related Docs

- [Usage](Usage.md)
- [Installation](Installation.md)
- [Workflow Examples](Workflow%20Examples.md)
- [Deployment Options](Deployment%20Options.md)
- [RunManifest Overview](RunManifest.md)
- [Upgrade and Migration](Upgrade%20and%20Migration.md)
