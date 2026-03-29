# Roadmap

This document outlines planned product milestones after v1.0.0.

## v1.1.0 — In Progress

**Status**: Partially completed; Run Manifest feature deferred for deeper exploration

- ✅ **JSON Schema validation for ScanResult structure** — Comprehensive schema with field-level descriptions and enum validation (e.g., `asset.criticality: Extreme|High|Medium|Low`) packaged as `core/schemas/scanResult.schema.json` and included in package resources.
- ✅ **`vpp --demo` end-to-end workflow** — One-command demo using bundled 5k Nessus sample with automatic online enrichment and all output artifacts (JSON, CSV, executive Markdown, technical Markdown).
- ✅ **Performance optimization** — Pre-computed post-enrichment index (`PostEnrichmentIndex`) for O(1) pass-phase finding lookups; process-pool parallelism in Scoring and TopN as needed.
- ✅ **Enhanced markdown reports** — Executive report with "Recommended Asset Target List" (criticality, risk counts, top CVE); technical report with criticality column; both reports use derived scored risk-band criticality.
- ✅ **Derived asset criticality architecture** — Moved from parser normalization to Scoring pass; integrated with TopN ranking and presentation overlays; properly decoupled concern ownership.
- ✅ **Exploit references schema compliance** — Fixed emission from non-compliant object to compliant array-of-dicts; added regression test and backward-compatible CSV support.
- 🔄 **Verified execution framework (Run Manifest)** — Audit trail and reproducibility verification system capturing execution metadata, enrich decisions, pass evidence, and decision ledger. Infrastructure ready; design under exploration for v1.1.0 final release.

## v1.2.0

- Decision explainability graph and provenance query tooling (built on v1.1 RunManifest + embedded DecisionLedger)
- More scanner support (Qualys, Rapid7 InsightVM, etc.)
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

