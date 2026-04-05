# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where practical.

## [1.1.1] - 2026-04-05 Governance and Architecture Hardening

### Added

- Strict schema validation for all runtime config files (`config.yaml`, `scoring.json`, `tn_triage.json`) during config load.
- New configuration schemas: `core/schemas/config.schema.json`, `core/schemas/scoring.schema.json`.
- TopN soft no-op dependency artifact when `Scoring@1.0` is unavailable, including explicit error metadata.
- Pass dependency declarations and pipeline dependency/order validation in `PassRunner`.
- RunManifest TopN pass summary metrics now include skip status and error code when applicable.
- Governance guardrail docs: ADR workflow, architecture review checklist, and deprecation/versioning policy.
- Enrichment seam contract: implementation-ready boundary design with staged migration and rollback guidance (`Enrichment Seam Contract.md`).
- Config seam contract: implementation-ready boundary design with staged migration and rollback guidance (`Config Seam Contract.md`).
- Config seam architecture (4-stage refactor) with dedicated `ConfigSource`, `ConfigValidator`, `ConfigProjector` modules and ADR-0001 decision record.
- `--output_all BASENAME` now derives all output artifact paths from a single base name stem: `<base>.json`, `<base>.csv`, `<base>_summary.md`, `<base>_technical.md`, `<base>_runmanifest.json`. Individual output flags still override specific artifacts when provided alongside `--output_all`.

### Changed

- Parser lifecycle metadata now supports `stability` and deprecation markers in parser specs.
- Nessus/OpenVAS JSON parser specs are now explicitly marked as `experimental` and `deprecated`.
- Parser spec `formats` fields were normalized to tuple form for single-format entries.
- Enrichment source summary now reports `exploitdb` enablement truthfully instead of hardcoded true.
- Default global config now includes explicit `version: v1` marker.

### Fixed

- TopN pass contract behavior now remains pass-compatible on missing dependencies by returning a derived artifact rather than a scan object.
- Pass pipelines with missing or misordered declared dependencies now fail fast with explicit validation errors.
- `--output_all` CLI flag redefined as a `BASENAME` string argument; was incorrectly declared as a boolean store-true flag causing argparse to raise "expected one argument" when used.
- Removed spurious f-string with no interpolated variables in `markdown_report.py`.

## [1.1.0] - 2026-03-29 Auditability and Provenance Update

This release introduces comprehensive auditability and provenance tracking for VulnParse-Pin runs. The new Execution Framework captures detailed lifecycle events for each pass and enrichment phase, records input and configuration hashes, and produces a verifiable RunManifest artifact that allows offline integrity and schema validation of the run outputs.  

This ensures that every run can be independently verified for correctness, traceability, and tamper-evidence, providing security teams with confidence in the integrity of the prioritized vulnerability outputs.  

Incident Response, forensics, and compliance teams can now rely on the RunManifest to demonstrate exactly what occurred during a given run, what inputs were used, and how decisions were derived, without needing to rerun the processing pipeline.

### Added

- **RunManifest execution artifact** with embedded decision ledger output via `--output-runmanifest`.
  - Includes runtime metadata, input/config hashes, output references, enrichment summary, pass summaries, and verification block.
- **Decision ledger runtime service** (`LedgerService`) with append-only hash chaining.
  - Pass lifecycle events (`pass_start`, `pass_end`, `pass_error`) now captured during orchestration.
  - Enrichment lifecycle events (`phase_start`, `phase_end`) now captured in the pipeline.
- **RunManifest schema contract** (`core/schemas/runManifest.schema.json`) and runtime schema validation support.
- **RunManifest integrity verification** with chain continuity, entry hash recomputation, and manifest digest verification.
- **Standalone RunManifest verifier command**: `--verify-runmanifest <PATH>` for offline schema/integrity validation without rerunning scan processing.
- **RunManifest mode controls**: `--runmanifest-mode compact|expanded`.
  - `compact` remains default for bounded artifact size.
  - `expanded` emits richer decision detail in Scoring/TopN event emission paths.
- **Decision reason code registry** (`DecisionReasonCodes`) with stable reason identifiers for explainability.
- **Pass-phase metrics in runmanifest** now populated from real pass outputs (Scoring, TopN, Summary) rather than placeholders.
- **New documentation**:
  - `documentation/docs/RunManifest.md`
  - `documentation/docs/RunManifest_Technical.md`
  - Usage updates for generation, mode selection, and verification workflows.
- **RunManifest test suite** covering schema, integrity, tamper detection, reason-code presence, pass metrics, and file verification flows.

### Changed

- Demo output defaults now include `demo_runmanifest.json` when runmanifest output is requested in demo workflow.
- Output orchestration now writes RunManifest alongside JSON/CSV/Markdown artifacts when configured.
- Runtime services container extended with `ledger` and `runmanifest_mode` fields to support explainability and artifact controls.

### Fixed

- Fixed empty `pass_summaries[*].metrics` in RunManifest by deriving metrics from actual pass outputs.
- Reduced analyzer noise in verification flow by narrowing exception handling for verifier path.

## [1.0.3] - 2026-03-28

### Added

- **Derived Asset Criticality Architecture**: Moved asset criticality derivation from parser normalization to the `ScoringPass`, ensuring true derived characteristics are owned by appropriate pass phases.
  - `ScoringPass` now computes `asset_criticality` from risk-band thresholds (`Extreme`, `High`, `Medium`, `Low`).
  - Criticality threshold configuration added to `scoring.json` with sensible defaults.
  - Asset criticality persisted back to `ScanResult.assets[*].criticality` for downstream pass consumption.
  - Removed parser-layer criticality assignment from `NessusParser` and `OpenVASParser` (data normalization scope reduced per architecture principle).
- **TopN Pass Criticality Integration**: Updated asset ranking logic to prioritize current-scan derived criticality over stale index observations.
  - TopN asset ranking now merges current `ScanResult.assets[*].criticality` into parallel pipeline inference state.
  - Asset observations now inherit derived criticality for consistent exposure-management decisions.
- **Enhanced Markdown Reports**:
  - Executive report now includes "Recommended Asset Target List" table showing vulnerable assets with derived criticality, critical/high risk counts, and top CVE per asset.
  - Executive report now includes SLA recommendation note based on criticality distribution.
  - Technical report asset analysis table now displays criticality column for visibility.
  - Both reports now clearly leverage scored risk-band criticality (not scanner severity).
- **Presentation Overlay Criticality Storage**: Asset-level derived criticality and scored risk-band counts now materialized in presentation overlay for both `flatten` and `namespace` modes.
  - Overlay asset entries include: `criticality` (string), derived scoring context (risk-band thresholds and counts).
- **Exploit References Schema Compliance**: Fixed `exploit_references` field emission to conform to schema contract.
  - Changed from non-compliant `exploit_references: {}` object to schema-compliant `exploit_references: [{ "cve": "CVE-xxx" }, ...]` array of dicts.
  - Updated CSV exporter to support both new list-of-dicts format and legacy dict format for backward compatibility.
  - Added regression test (`test_exploit_references_shape.py`) to prevent backsliding.
- **Comprehensive JSON Schema for ScanResult**: Packaged as `core/schemas/scanResult.schema.json` with field-level descriptions, type constraints, and enum validation.
  - Added schema documentation artifact (`ScanResult_Schema.md`) with complete field reference, examples, validation instructions, and common Python patterns.
  - Schema validation included in `pyproject.toml` package resources for runtime contract enforcement.
- **Immutable post-enrichment indexing** (`PostEnrichmentIndex`) with O(1) pass-phase finding lookups.
- **Criticality predicate** (`criticality_is`) added to TopN inference engine for `extreme|high|medium|low` asset classification.
- **Bundled criticality-aware inference rule** (`critical_asset_hint`) in `tn_triage.json` applying +1 exposure weight for `extreme` and `high` criticality assets.
- **New CLI enrichment controls** with online-by-default semantics and explicit disable/source selection:
  - `--no-kev`, `--no-epss`, `--no-exploit`
  - `--kev-source`, `--epss-source`, `--exploit-source`
  - `--kev-feed`, `--epss-feed`
- **Graduated confidence scoring** in `NessusXMLParser.detect_file` and `OpenVASXMLParser.detect_file` returning `(float, list[tuple[str, str]])` instead of a plain `bool`.

### Fixed

- Fixed `asset.criticality` schema definition and documentation to match derived scoring logic (values: `Extreme|High|Medium|Low`).
- Fixed enrichment conditional precedence so KEV/EPSS enrichment execution is evaluated correctly.
- Fixed CSV exporter sentinel handling for `cvss_score`, `epss_score`, and `asset_avg_risk_score` — all now emit `-1.0` when no score data is available.
- Fixed `_sniff_format` to strip leading UTF-8 BOM before format detection so BOM-prefixed XML/JSON inputs are classified correctly.
- Fixed exploit references schema contract violation (now array of dicts, not bare object).

### Changed

- Removed legacy enrichment flags `--enrich-kev`, `--enrich-epss`, and `--enrich-exploit` (hard rename).
- Updated CLI matrix coverage and user documentation for the new enrichment flag model.
- Refactored asset criticality ownership: parser normalization no longer assigns criticality; derived passes own it.
- Updated markdown report generation to use derived scored risk-band criticality (not scanner severity) for asset prioritization and presentation.
- Validated the full OpenVAS XML pipeline against `tests_output/diverse_openvas_mixed.xml`; detection selected `openvas-xml` at `0.95` confidence and successfully generated JSON, CSV, executive Markdown, and technical Markdown artifacts.
- Schema validation on demo output confirmed zero schema errors (including exploit references shape fix).

## [1.0.2] - 2026-03-25

### Added

- Added `--demo` CLI flag for a one-command end-to-end run using a bundled Nessus sample.
- Added automatic demo behavior that forces online enrichment mode and enables all four output artifacts (JSON, CSV, executive Markdown, technical Markdown).
- Added packaged Nessus demo resource support (`resources/*.nessus`) so the demo sample resolves reliably in installed environments.
- Added generated 5k synthetic Nessus benchmark dataset support and tooling (`tests/generate_5k_nessus.py`) with reproducible 10-asset, 5,000-finding coverage.
- Added new value and scoring documentation artifacts: `docs/Value_Proof_Analysis.md`, `docs/CVSS_vs_VulnParse_Scoring_Comparison.md`, and `docs/Value_Proposition_One_Pager.md`.
- Added `--demo` usage instructions to `README.md` and `docs/Usage.md`.

### Fixed

- Fixed CLI summary banner output location rendering to display clean output filenames.

### Changed

- Updated Markdown report templates to clearly separate scanner severity from VulnParse-Pin derived risk bands.
- Updated executive and technical report risk tables with explicit "Primary Drivers" context (KEV, public exploit, EPSS threshold signals).
- Updated benchmark and performance documentation with the 5k demo-derived dataset and measured throughput/runtime snapshot.
- Updated `README.md`, `ROADMAP.md`, and overview docs to reflect demo workflow, prioritization messaging, and current documentation structure.

## [1.0.1] - 2026-03-22

### Added

- Added `ROADMAP.md` with planned milestones for v1.1.0, v1.2.0, and v1.3.0-1.5.0+.

### Fixed

- Fixed a minor documentation typo in `docs/Getting Started In 5 Minutes.md`.

### Changed

- Updated `CHANGELOG.md` with the new roadmap section and minor formatting adjustments.

## [1.0.0] - 2026-03-18

### Added

- CSV export sentinel value (`-1.0`) for findings with no numeric enrichment score, preventing `TypeError` on `round(None)`.
- Five TopN pass contract tests covering asset exhaustiveness, finding completeness, no cross-asset leakage, deterministic index sorting, and score-rank consistency.
- CLI aliases for `--forbid-symlinks_read` and `--forbid-symlinks_write` (underscore variants) alongside the canonical hyphenated forms.
- Stability tier documentation in `docs/Detection and Parsing.md` (XML paths stable, JSON paths experimental).
- Expanded deferred-scope list in `docs/Known Limitations.md` (Shodan enrichment, CVSS v2, extended enrichment, strict schema validation, JSON parser parity).

### Fixed

- CSV exporter no longer raises `TypeError` when exporting findings that have no CVE and therefore no numeric enrichment scores.
- Editable install no longer shadowed by stale `rc1` physical package copy in site-packages.

### Changed

- Removed two `TODO: VERIFY` uncertainty markers from `topn_pass.py` after contract tests confirmed correct behavior.
- `pyproject.toml` classifier updated from `Development Status :: 4 - Beta` to `Development Status :: 5 - Production/Stable`.

## [1.0.0-rc4] - 2026-03-15

### RC4 Added

- GitHub Pages documentation deployment workflow.
- GitHub Pages documentation updates and project favicon.

### RC4 Changed

- CLI argument wording and UX polish for clarity.

## [1.0.0-rc3] - 2026-03-13

### RC3 Fixed

- Packaging resource inclusion for release distributions.

## [1.0.0-rc2] - 2026-03-13

### RC2 Changed

- Release workflow and CI configuration fixes for RC publishing.
- Versioning/release metadata updates for the RC pipeline.

## [1.0.0-rc1] - 2026-03-11

### RC1 Added

- JSON Schema validation support for normalized `ScanResult` data.
- Canonical `asset_id` support on `Asset` objects.
- Post-normalization default schema validation.
- Additional unit tests for schema detection, schema validation, and pass contracts.
- Real-sample validation coverage for Nessus and OpenVAS parsing flows.
- Packaging metadata improvements in `pyproject.toml`.
- `CHANGELOG.md` for release tracking.

### RC1 Changed

- Refactored application startup and orchestration into focused modules under `vulnparse_pin.app`.
- Refactored CLI argument handling into `vulnparse_pin.cli.args`.
- Refactored TopN worker logic into a dedicated module without changing public contracts.
- Updated downstream processing to treat `Asset.asset_id` as the canonical source of truth.
- Improved parser-selection tie-breaking in `SchemaDetector` to honor confidence, priority, then parser name.

### RC1 Fixed

- Corrected XML parser exception handling to use the proper XML `ParseError`.
- Removed unintended dependency path caused by incorrect parse exception usage.
- Fixed asset-to-finding ID consistency issues in parser outputs.
- Fixed downstream scoring/reporting usage of asset identity to avoid relying on finding-level IDs.
- Resolved various unused import and unused variable issues in parser modules.

[Unreleased]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.2
[1.0.1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.1
[1.0.0]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0
[1.0.0-rc4]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc4
[1.0.0-rc3]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc3
[1.0.0-rc2]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc2
[1.0.0-rc1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc1
