# Enrichment Seam Contract

This document defines the v2.0.0 seam contract separating threat-intelligence source loading, finding/snapshot enrichment application, and downstream pipeline handoff.

## Objective

Isolate enrichment concerns across explicit module boundaries:

1. **Source loading & cache verification** (`src/vulnparse_pin/app/enrichment_source_loader.py`)
2. **Enrichment application & DuckDB snapshot hydration** (`src/vulnparse_pin/app/enrichment.py`)
3. **Post-enrichment indexing & handoff** (`src/vulnparse_pin/app/index_builder.py`, `src/vulnparse_pin/app/enrichment_handoff.py`)

## Implemented v2.0 Architecture

### Contract A: Source Loader (`EnrichmentSourceLoader`)

`EnrichmentSourceLoader` (`src/vulnparse_pin/app/enrichment_source_loader.py`) resolves `EnrichmentSourcePlan` from CLI flags and config policy and loads all 6 source families:

- **KEV** (`KEVFeedCache` / `kev_cache.sqlite3`)
- **EPSS v5** (`EPSSFeedCache` / `epss_cache.sqlite3`)
- **Exploit-DB** (`files_exploit.csv` via `FeedCacheManager`)
- **NVD** (`NVDFeedCache` / `nvd_cache.sqlite3`)
- **GHSA** (`GHSAEnrichmentSource` / `ghsa_cache.sqlite3`, opt-in via `--ghsa`)
- **OSV** (`OSVEnrichmentSource` / `osv_cache.sqlite3`, opt-in via `--osv`)

It returns `EnrichmentSourceResult`, encapsulating loaded lookup objects/dicts, source metadata (`epss_model_version`, `kev_catalog_version`, SHA-256 digests), and `nvd_status`.

### Contract B: DuckDB Snapshot Hydration (`populate_enrichment_snapshots`) & `EnrichmentApplicator`

- **v2.0 DuckDB path (`populate_enrichment_snapshots`):** Queries `.vpp.db` (`finding_cves`, `findings`) for only the matched CVEs and `package_purl`s in the active `run_id`, applies `resolve_cvss_with_provenance()` (`NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing`), merges KEV, EPSS v5, and Exploit-DB/negation-aware heuristic flags, and bulk-inserts rows into `enrichment_snapshots` while updating `runs.intel_metadata_json`.
- **Legacy `ScanResult` path (`EnrichmentApplicator.apply`):** Applies loaded sources and `apply_heuristic_exploit_tags_batch()` in-memory for `ScanResult` callers, returning `EnrichmentApplyResult(scan_result, stats_summary)`.

### Contract C: Post-Enrichment Index & Handoff

- `index_builder.py` builds `PostEnrichmentIndex` for `ScanResult` consumers.
- `EnrichmentHandoffBuilder` (`enrichment_handoff.py`) attaches source metadata to `Services` and hands `EnrichmentPipelineState` off cleanly to `PassRunner` / `run_v2_duckdb_pipeline()`.

## Invariants

- **Strict source isolation:** Parsers never fetch network feeds; scoring/triage passes read `enrichment_snapshots` rather than querying external APIs or raw cache files.
- **Fail-closed cache integrity:** `VP_FEED_CACHE_HMAC_KEY` and `VP_SQLITE_HMAC_KEY` anti-downgrade and quarantine rules are enforced inside the source/cache layer before data reaches `enrichment_snapshots`.
- **Deterministic provenance:** Every snapshot records `cvss_provenance`, `sources_json`, `epss_model_version`, and `enrichment_confidence`.

## Blast Radius & Compatibility

Affected modules:

1. `src/vulnparse_pin/app/enrichment_source_loader.py`
2. `src/vulnparse_pin/app/enrichment.py`
3. `src/vulnparse_pin/app/enrichment_handoff.py`
4. `src/vulnparse_pin/app/index_builder.py`
5. `src/vulnparse_pin/utils/{enricher.py,feed_cache.py,nvdcacher.py,ghsa_enrichment.py,osv_enrichment.py,exploit_enrichment_service.py}`

Both `run_enrichment_pipeline()` (for legacy `ScanResult` callers) and `populate_enrichment_snapshots()` (for v2.0 `.vpp.db` pipelines) share `EnrichmentSourceLoader` and `resolve_cvss_with_provenance()`.

## Related Docs

- [Architecture](Architecture.md)
- [Pipeline System](Pipeline%20System.md)
- [Enrichment Deep Dive](Enrichment%20Deep%20Dive.md)
- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [ADR-0002: Enrichment Seam Architecture](adr/ADR-0002-enrichment-seam.md)
