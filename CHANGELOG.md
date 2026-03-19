# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where practical.

## [Unreleased]

### Added

- Added `ROADMAP.md` with planned milestones for v1.1.0, v1.2.0, and v1.3.0-1.5.0+.

### Planned

- v1.1.0 focus: output schema validation hardening, execution verification, demo dataset UX, scoring/inference optimization, report polish, and docs improvements.
- v1.2.0 focus: decision ledger and explainability artifacts, expanded scanner/intelligence coverage, aggregated CVE scoring, and integrations.
- v1.3.0-1.5.0+ focus: SQLite-backed historical tracking and additional post-1.2 capabilities.

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

[Unreleased]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0
[1.0.0-rc4]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc4
[1.0.0-rc3]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc3
[1.0.0-rc2]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc2
[1.0.0-rc1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc1
