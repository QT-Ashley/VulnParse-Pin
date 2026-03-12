# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where practical.

## [Unreleased]

### Added
- JSON Schema validation support for normalized `ScanResult` data.
- Canonical `asset_id` support on `Asset` objects.
- Post-normalization default schema validation.
- Additional unit tests for schema detection, schema validation, and pass contracts.
- Real-sample validation coverage for Nessus and OpenVAS parsing flows.
- Packaging metadata improvements in `pyproject.toml`.
- `CHANGELOG.md` for release tracking.

### Changed
- Refactored application startup and orchestration into focused modules under `vulnparse_pin.app`.
- Refactored CLI argument handling into `vulnparse_pin.cli.args`.
- Refactored TopN worker logic into a dedicated module without changing public contracts.
- Updated downstream processing to treat `Asset.asset_id` as the canonical source of truth.
- Improved parser-selection tie-breaking in `SchemaDetector` to honor confidence, priority, then parser name.

### Fixed
- Corrected XML parser exception handling to use the proper XML `ParseError`.
- Removed unintended dependency path caused by incorrect parse exception usage.
- Fixed asset-to-finding ID consistency issues in parser outputs.
- Fixed downstream scoring/reporting usage of asset identity to avoid relying on finding-level IDs.
- Resolved various unused import and unused variable issues in parser modules.

## [1.0.0rc1] - 2026-03-11

### Added
- Initial release candidate for `VulnParse-Pin`.
- Support for parsing Nessus and OpenVAS scan formats.
- Enrichment support for NVD, KEV, EPSS, and exploit intelligence inputs.
- Scoring, TopN triage, summary generation, CSV/JSON/Markdown reporting, and schema-driven output support.

[Unreleased]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.0.0rc1...HEAD
[1.0.0rc1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0rc1