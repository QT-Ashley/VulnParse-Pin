# RunManifest Technical Deep Dive

This document explains the internal mechanics of `RunManifest` v2 (`manifest_version: "2.0"`): DuckDB construction (`build_runmanifest_from_db`), multi-CVE KEV parity, `--output-all` artifact hashing, `ledger_events` SHA-256 hash chaining, canonical digesting, and strictly read-only `vpp verify` enforcement.

## Primary Implementation Files

- `src/vulnparse_pin/utils/runmanifest.py` (`build_runmanifest_from_db`, `verify_runmanifest`, `verify_runmanifest_file`, `verify_runmanifest_integrity`, `VOLATILE_PATHS`)
- `src/vulnparse_pin/core/classes/execution_manifest.py` (`LedgerService`, `DecisionLedgerEntry`, `EMPTY_LEDGER_ROOT`)
- `src/vulnparse_pin/storage/schema.sql` (`runs`, `ledger_events` tables)
- `src/vulnparse_pin/app/output.py` (`export_v2_outputs`)
- `src/vulnparse_pin/cli/commands.py` (`_build_verify_pfh`, `_verify_listed_manifest_outputs`, `run_verify_command`)
- `src/vulnparse_pin/core/schemas/runManifest.schema.json`

## Architecture & DuckDB Data Flow

During `vpp scan` and `vpp demo`:

1. `LedgerService` appends hash-chained events in memory during ingestion, enrichment, passes, and webhook delivery.
2. `_flush_ledger_to_db(db, run_id, ctx)` persists those entries into DuckDB `ledger_events`.
3. `export_v2_outputs()` writes all requested output files (`json`, `csv`, `executive_markdown`, `technical_markdown`, `dossier_markdown`, `dossier_html`) **before** building the RunManifest so every written artifact exists on disk when hashed.
4. `build_runmanifest_from_db(db, run_id, config_hashes=..., outputs=..., mode=...)` constructs the manifest directly from DuckDB tables (`runs`, `assets`, `findings`, `finding_cves`, `enrichment_snapshots`, `aci_signals`, `scores`, `triage_decisions`, `ledger_events`).
5. `write_runmanifest()` validates the payload against `runManifest.schema.json` and runs `verify_runmanifest_integrity()` before writing to disk.
6. The resulting `verification.manifest_digest` is written back to `runs.manifest_digest` in `.vpp.db` (so subsequent `vpp export` calls embed the sealed digest in dossiers/roadmaps).

## Output Artifact Hashing (`--output-all`)

In `export_v2_outputs()`, `outputs_meta` populates all six exported artifact keys when `--output-all <BASENAME>` is used:

- `json` (`<stem>.json`)
- `csv` (`<stem>.csv`)
- `executive_markdown` (`<stem>_summary.md`)
- `technical_markdown` (`<stem>_technical.md`)
- `dossier_markdown` (`<stem>_dossier.md`)
- `dossier_html` (`<stem>_dossier.html`)

`_collect_output_hashes()` streams each non-null regular file in `1 MiB` chunks (`_HASH_CHUNK_BYTES`), skipping symlinks, and records `"sha256:<hex>"` under `manifest["output_hashes"]`. Input scan files are similarly hashed into `inputs.input_files_sha256` and combined into `inputs.target_sha256`.

## Multi-CVE `kev_findings` Parity in `pass_summaries`

In `_build_db_pass_summaries()`, `Summary@2.0` computes `kev_findings` with full multi-CVE parity across:

1. `enrichment_snapshots` matched on the effective primary CVE (`COALESCE(score_trace.$.primary_cve, f.primary_cve)`),
2. `finding_cves` joined to `enrichment_snapshots` (`BOOL_OR(COALESCE(es.in_kev, FALSE))`), so findings whose *secondary* CVE is in CISA KEV are still counted, and
3. `TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN)`.

This guarantees `pass_summaries[*].metrics.kev_findings` matches `repositories.get_run_summary_counts()`, `SummaryV2Pass`, and Decision Defense Dossiers.

## `ledger_events` SHA-256 Hash Chain

Each `LedgerService` entry is persisted to `ledger_events (run_id, seq, ts, component, event_type, subject_ref, why, evidence_digest, prev_hash, entry_hash)`:

- `EMPTY_LEDGER_ROOT = "sha256:" + sha256("vpp-ledger-empty-root-v1").hexdigest()`
- `evidence_digest = "sha256:" + sha256(_canonical_json(evidence)).hexdigest()`
- `prev_hash` = `EMPTY_LEDGER_ROOT` for `seq == 1`, else previous `entry_hash`
- `entry_hash = "sha256:" + sha256(_canonical_json({seq, ts, component, event_type, subject_ref, why, evidence_digest, prev_hash})).hexdigest()`

`verify_runmanifest_integrity()` verifies:

- `decision_ledger.entry_count == len(entries)` (rejecting booleans or mismatched counts)
- `seq` is contiguous `1..N`
- `prev_hash` matches `expected_prev`
- Recomputed `entry_hash` matches `entry["entry_hash"]`
- `chain_root` equals the final `entry_hash` (or `EMPTY_LEDGER_ROOT` when `N == 0`)

## Canonical `verification.manifest_digest`

`_compute_manifest_digest()` removes `VOLATILE_PATHS`:

- `generated_at_utc`
- `pass_summaries.started_at_utc`
- `pass_summaries.ended_at_utc`
- `decision_ledger.entries.ts`

Sets `verification.manifest_digest = None`, serializes with `_canonical_json()` (`sort_keys=True, separators=(",", ":"), ensure_ascii=True`), and computes `sha256:<hex>`. Note that `ts` remains covered by each ledger entry's `entry_hash`, while `manifest_digest` stays invariant across timestamp-only differences.

## Strictly Read-Only `vpp verify` Enforcement

`run_verify_command()` (`vpp verify <runmanifest.json>`) is strictly read-only by default:

- **`_build_verify_pfh(args)`:** Constructs `PermFileHandler` with a `logging.NullHandler()` logger and does **not** call `paths.ensure_dirs()` or create log files unless the operator explicitly passes a non-default `--log-file <name>` (`!= "vulnparse_pin.log"`). This allows `vpp verify` to run cleanly inside `0o500` / read-only XDG environments and air-gapped CI containers.
- **Symlink & Root Guardrails:**
  - By default (`--forbid-symlinks-read`, `True`), `_check_no_symlinks_or_loops()` rejects symlinks on both the manifest path and every non-null output artifact in `outputs`. Pass `--allow-symlinks-read` only when intentionally verifying symlinked artifacts.
  - Pass `--enforce-root-read` (`-err`) to confine manifest and listed output reads to acceptable `PermFileHandler` roots.
- **Listed Output Verification (`_verify_listed_manifest_outputs`):** For every non-null entry in `outputs` and every recorded digest in `output_hashes`, verifies file existence and checks `hmac.compare_digest(expected_hash, _file_sha256(out_path))`. Any missing file, symlink violation, or digest mismatch exits with code `1`.

## Practical Limits

- `expanded` mode increases manifest and `.vpp.db` size proportionally to logged events.
- SHA-256 hash chains and `manifest_digest` provide **tamper evidence**, not asymmetric cryptographic signatures (combine with CI artifact signing / SLSA attestations for non-repudiation).

## Related Docs

- [RunManifest Overview](RunManifest.md)
- [Output Interpretation](Output%20Interpretation.md)
- [ScanResult & DuckDB Schema](ScanResult_Schema.md)
- [Security Features](Security%20Features.md)
