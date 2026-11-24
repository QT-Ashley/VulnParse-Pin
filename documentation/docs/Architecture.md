# Architecture

VulnParse-Pin (`vpp`) v2.0.0 (`Apache-2.0`) is organized as a DuckDB-backed, streaming vulnerability intelligence and decision-support pipeline with strict seam boundaries between ingestion, persistence, enrichment, derived passes, scan-over-scan diffing, and artifact rendering:

```text
Inputs (XML / SARIF / JSONL / CSV / Nmap)
  -> FileInputValidator + SchemaDetector
  -> Streaming Parsers (iter_batches)
  -> DuckDB Workspace (.vpp.db: ingest_normalized_batches)
  -> Threat Intel Snapshot (populate_enrichment_snapshots)
  -> run_v2_duckdb_pipeline (NmapAdapter@1.0 -> ACI@2.0 -> Scoring@3.0 -> Triage@2.0 -> TopN@2.0 -> Summary@2.0)
  -> DiffEngine (vpp diff) + Reporting / Exports / RunManifest / Textual TUI
```

## High-level module map

- `src/vulnparse_pin/main.py` — Thin CLI entrypoint dispatching `get_args()` to `cli/commands.py` and translating `VppError` to typed exit codes (`0`, `1`, `2`).
- `src/vulnparse_pin/cli/` — Subcommand parser and command handlers:
  - `args.py` — Subcommands (`scan`, `demo`, `diff`, `ui`, `export`, `verify`, `defer`, `intel`) plus legacy compatibility flag rewriting.
  - `commands.py` — End-to-end execution of `vpp` subcommands, DuckDB workspace orchestration, and read-only `vpp verify` enforcement.
  - `errors.py` — Typed `VppError` carrying explicit process exit codes.
- `src/vulnparse_pin/app/` — Application runtime orchestration:
  - `bootstrap.py` — `AppPaths`, `PermFileHandler` (`build_pfh`), config loading, `FeedCacheManager`, `NVDFeedCache`, and `Services` wiring.
  - `normalization.py` — Input validation (`validate_scanner_input`), streaming ingestion gate enforcement (`enforce_batch_ingestion_gates`), and legacy `normalize_input`.
  - `enrichment_source_loader.py`, `enrichment.py`, `enrichment_handoff.py`, `index_builder.py` — Source loading, `populate_enrichment_snapshots()` DuckDB hydration, and enrichment handoff.
  - `output.py`, `io_resolution.py`, `runtime_helpers.py` — PFH-authorized artifact export (`export_v2_outputs`) and runtime policy helpers.
- `src/vulnparse_pin/storage/` — Persistent DuckDB local workspace (`.vpp.db`):
  - `schema.sql` — 12-table columnar schema (`runs`, `assets`, `asset_aliases`, `findings`, `finding_evidence`, `finding_cves`, `enrichment_snapshots`, `aci_signals`, `scores`, `triage_decisions`, `diff_events`, `ledger_events`).
  - `db.py` — `VppDatabase` lifecycle, ancestor/WAL/temp symlink validation, `0o600` POSIX creation under `_UMASK_LOCK`, and safe non-PFH atomic writes (`ensure_safe_dir_non_pfh`, `open_for_write_non_pfh`).
  - `repositories.py` — Columnar Appender ingestion (`ingest_normalized_batches`), cross-scanner deduplication, parameterized UI/export queries, and shadow-asset queries.
- `src/vulnparse_pin/parsers/` — Streaming scanner adapters (`PARSER_SPECS`), hardened `lxml` XML security (`_xml_security.py`), and `BaseParser` normalization contracts.
- `src/vulnparse_pin/core/` — Core domain engines:
  - `id.py` — Canonical v2 identity (`aid_v2_`, `fid_v2_`, `canonicalize_target_key`) and v1 compatibility helpers.
  - `assets_context.py` — `AssetContextMatcher` (`assets.yaml` 5-tier precedence) and `DecisionsRegistry` (`decisions.yaml` predicates & `upsert_decision`).
  - `diff_engine.py` — `DiffEngine` scan-over-scan comparison and `--fail-on` policy gate evaluator (`evaluate_fail_gate`).
  - `schema_detector.py` — Single-read 64 KiB bounded format sniffing and parser confidence scoring.
  - `config_source.py`, `config_validator.py`, `config_projector.py` — 4-stage config pipeline projecting `config.yaml`, `scoring.json`, and `tn_triage.json` into typed `RuntimeConfigBundle` (`VppConfigV2`).
  - `passes/` — `NmapAdapterPass` (`nmap_adapter@1.0`), `ACIV2Pass` (`ACI@2.0`), `ScoringV3Pass` (`Scoring@3.0`), `TriageDecisionPass` (`Triage@2.0`), `TopNV2Pass` (`TopN@2.0`), `SummaryV2Pass` (`Summary@2.0`), and `run_v2_duckdb_pipeline()`.
- `src/vulnparse_pin/reporting/renderer.py` — Sandboxed Jinja2 HTML & Markdown rendering for Decision Defense Dossiers, Executive Roadmaps, and PR diff comments (`autoescape`, `md_escape`).
- `src/vulnparse_pin/ui/app.py` — Optional Textual interactive workbench (`vulnparse-pin[ui]`) backed by parameterized DuckDB queries.
- `src/vulnparse_pin/utils/` — Signed enrichment caches (`feed_cache.py`, `nvdcacher.py`, `enricher.py`, `ghsa_enrichment.py`, `osv_enrichment.py`, `exploit_enrichment_service.py`), clean-room Apache-2.0 CVSS calculator (`cvss_utils.py`), CSV/JSON/Markdown exporters, `RunManifest` builder/verifier (`runmanifest.py`), and HMAC-signed webhooks (`webhook_delivery.py`).
- `src/vulnparse_pin/io/pfhandler.py` — `PermFileHandler` (PFH) path confinement, symlink blocking, and POSIX permission enforcement.

## DuckDB workspace model (`.vpp.db`)

In v2.0.0, `.vpp.db` is the primary workspace store across `scan`, `demo`, `diff`, `ui`, `export`, and `defer`:

| Table | Purpose |
| --- | --- |
| `runs` | Run metadata, SHA-256 config/policy digests, `intel_metadata_json`, `manifest_digest`, `baseline_run_id` |
| `assets` | Canonicalized targets (`aid_v2_...`), criticality, exposure (`internet_facing`), `inventory_status`, `open_ports_json` |
| `asset_aliases` | Observed IP, hostname, URI, image/repo, and `assets.yaml` rule aliases per `asset_id` |
| `findings` | Cross-scanner deduplicated findings (`fid_v2_...`), `scoring_track`, `detection_mode`, `signal_reliability`, `source_count` |
| `finding_evidence` | Append-only raw scanner evidence rows preserved across deduplicated scanners |
| `finding_cves` | Normalized many-to-many CVE links per deduplicated finding |
| `enrichment_snapshots` | Run-scoped NVD/CNA/GHSA/OSV CVSS provenance, EPSS v5 score/percentile/model, KEV metadata, exploit flags |
| `aci_signals` | `ACI@2.0` inferred attack capabilities, chains, matched tokens, confidence, and uplift |
| `scores` | `Scoring@3.0` dual-track `raw_risk_score`, `operational_score`, `risk_band`, and `score_trace_json` |
| `triage_decisions` | `Triage@2.0` priority tier (`P1`/`P1B`/`P2`/`P3`/`P4`), `oal_compat`, `ssvc_action`, SLA bucket, decision status |
| `diff_events` | Persisted `DiffEngine` scan-over-scan deltas and stale-assumption invalidations |
| `ledger_events` | Append-only SHA-256 hash-chained decision provenance events |

## Legacy v1.x in-memory compatibility path

Legacy `ScanResult` / `Asset` / `Finding` dataclasses (`src/vulnparse_pin/core/classes/dataclass.py`) and the in-memory `PassRunner` sequence (`NmapAdapterPass` -> `Scoring@2.0` -> `AttackCapabilityInferencePass` -> `TopN@1.0` -> `Summary@1.0`) remain available for unit tests and legacy `ScanResult` serialization callers, while all v2.0 CLI subcommands execute on the DuckDB pipeline.

## Architectural invariants

- **Deterministic identity:** `aid_v2_` and `fid_v2_` IDs are deterministic SHA-256 prefixes over canonicalized target and deduplication keys.
- **Persistent, auditable provenance:** Raw scanner detections stay intact in `finding_evidence`; enrichment state is snapshotted per `run_id` in `enrichment_snapshots`; decision mutations are hash-chained in `ledger_events` and sealed in `RunManifest`.
- **Policy-driven scoring and triage:** Scoring weights, signal reliability, EPSS breakpoints, and SSVC/BOD 26-04 mappings come from validated configs (`config.yaml`, `scoring.json`, `tn_triage.json`, `assets.yaml`, `decisions.yaml`).
- **Fail-closed security defaults:** Hardened `lxml` XML parsing (`_xml_security.py`), PFH `forbid_symlinks_read=True` and `0o600`/`0o700` file/dir modes, DuckDB `.vpp.db`/`.wal`/`.tmp` symlink checks, read-only `vpp verify`, and anti-downgrade HMAC cache verification.

## Recommended reading order

1. [Detection and Parsing](Detection%20and%20Parsing.md)
2. [Identity Contract](Identity%20Contract.md)
3. [Pipeline System](Pipeline%20System.md)
4. [Pass Phases](Pass%20Phases.md)
5. [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md)
6. [Enrichment Deep Dive](Enrichment%20Deep%20Dive.md)
7. [Caching Deep Dive](Caching%20Deep%20Dive.md)
8. [Runtime Policy Deep Dive](Runtime%20Policy%20Deep%20Dive.md)
9. [Security Features](Security%20Features.md)
10. [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
