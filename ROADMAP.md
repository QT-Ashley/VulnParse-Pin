# Roadmap

This document outlines planned product milestones after v1.0.0.

## Quarter Focus (Q2 2026)

Delivery focus this quarter is balanced across:

- User and technical documentation hardening
- Architecture guardrails to preserve extensibility
- Verification and release readiness

## v1.1.0 — Released (2026-03-29)

**Status**: Released with follow-on hardening items continuing in v1.2.0

- [done] **JSON Schema validation for ScanResult structure** - Comprehensive schema with field-level descriptions and enum validation (e.g., `asset.criticality: Extreme|High|Medium|Low`) packaged as `core/schemas/scanResult.schema.json` and included in package resources.
- [done] **`vpp --demo` end-to-end workflow** - One-command demo using bundled 5k Nessus sample with automatic online enrichment and all output artifacts (JSON, CSV, executive Markdown, technical Markdown).
- [done] **Performance optimization** - Pre-computed post-enrichment index (`PostEnrichmentIndex`) for O(1) pass-phase finding lookups; process-pool parallelism in Scoring and TopN as needed.
- [done] **Enhanced markdown reports** - Executive report with "Recommended Asset Target List" (criticality, risk counts, top CVE); technical report with criticality column; both reports use derived scored risk-band criticality.
- [done] **Derived asset criticality architecture** - Moved from parser normalization to Scoring pass; integrated with TopN ranking and presentation overlays; properly decoupled concern ownership.
- [done] **Exploit references schema compliance** - Fixed emission from non-compliant object to compliant array-of-dicts; added regression test and backward-compatible CSV support.
- [done] **Verified execution framework (Run Manifest)** - Audit trail and reproducibility verification system capturing execution metadata, enrich decisions, pass evidence, and decision ledger.
- [done] **RunManifest hardening and docs completeness** - Additional usability, verification narrative completion, and explainability documentation completed in v1.1.1.

## v1.1.1 — Released (2026-04-05)

**Status**: Released

- [done] **Documentation hardening** — migration guide, troubleshooting guide, and output interpretation reference.
- [done] **Technical documentation hardening** — contributor/testing guidance and extension playbooks.
- [done] **Governance guardrails** — ADR workflow, deprecation/versioning policy, and architecture review checklist.
- [done] **Enrichment seam contract** — implementation-ready boundary design with staged migration and rollback guidance (`Enrichment Seam Contract.md`, ADR-0002).
- [done] **Config seam contract and implementation** — 4-stage config seam refactor with `ConfigSource`, `ConfigValidator`, `ConfigProjector` modules and ADR-0001 decision record (`Config Seam Contract.md`).
- [done] **Parser lifecycle governance** — explicit `stable`/`experimental`/`deprecated` policy with runtime warnings for non-stable parser selection.
- [done] **Config schema validation** — strict schema validation for all runtime config files at startup.
- [done] **Pass dependency validation** — pipeline dependency/order enforcement with fast-fail on misconfiguration.
- [done] **RunManifest hardening** — pass metrics, skip/error codes, and docs completeness.

### Parser lifecycle timeline (current policy)

- ~~v1.2.x: XML parser paths remain `stable`; JSON parser paths remain `experimental` + `deprecated` and are warning-emitting compatibility paths.~~
- v1.3.x: Re-evaluate JSON parser quality and usage telemetry to decide one of: promote, continue deprecated, or schedule removal.
- v1.4.0+ (earliest removal window): JSON parser removal may be scheduled with advance migration notice if not promoted.

## v1.2.0

**Status**: Planned — feature development

- Decision explainability graph and provenance query tooling (built on RunManifest + DecisionLedger)
- More scanner support (Qualys, Rapid7 InsightVM, NMAP, etc.)
- Expanded intelligence sources (CertCC, threat feeds, GHSA, etc.)
- CVE aggregated scoring (instead of highest-risk CVE per asset)
- Third-party integrations (webhook, API, SIEM forwarding)
- Advanced filtering and custom scoring policies

## v1.3.0-1.5.0+

- SQLite historical tracking and trending
- Comparative risk analysis across multiple scans
- Automated remediation recommendations
- Machine learning-based exposure prediction
- Extended enrichment ecosystem
