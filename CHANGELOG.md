# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where practical.

## [Unreleased]

- See the [ROADMAP](ROADMAP.md) for planned features and improvements in upcoming releases.

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

[Unreleased]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.2
[1.0.1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.1
[1.0.0]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0
[1.0.0-rc4]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc4
[1.0.0-rc3]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc3
[1.0.0-rc2]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc2
[1.0.0-rc1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc1
