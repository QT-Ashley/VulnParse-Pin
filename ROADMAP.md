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

**Status**: In validation / release hardening

- [done] **Whole-of-CVEs scoring model** — `Scoring@2.0` now aggregates contributor CVEs with bounded decay and persists per-finding `score_trace` for explainability.
- [done] **TopN deterministic parity improvements** — tie-break behavior now includes whole-of-CVEs breadth signals and is aligned between sequential and process-pool worker execution paths.
- [done] **Summary aggregation alignment** — top risks and remediation buckets consume union contributor signals from scoring traces instead of relying on single booleans.
- [done] **RunManifest metric alignment** — pass summaries now capture whole-of-CVEs counters across Scoring, TopN, and Summary for audit/reproducibility.
- [done] **Output presentation upgrade** — CSV profiles (`full`/`analyst`/`audit`), enriched markdown reporting, and output-interpretation guidance for operator workflows.
  - Executive report quality sections delivered: Decision Context, Data Quality Scorecard, Remediation Plan by Time Horizon, and Risk Concentration.
  - Technical report quality sections delivered: Tie-Break Explainability, Analyst Caveats, and Trust and Provenance.
  - Terminology clarity delivered: `Finding Agg CVEs` explicitly denotes finding-level contributor breadth.
- [done] **Attack Capability Inference integration** — `ACI@1.0` pass wired into default pipeline and consumed by TopN as bounded tie-break signal; dependency handling and decision-ledger reason codes added.
- [done] **ACI reporting and diagnostics** — executive/technical markdown now include ACI metrics snapshots, chain/capability distributions, confidence buckets, top-asset capability mapping, runtime-accurate enrichment status, and zero-inference diagnostics.
- [done] **ACI inference guardrails and realism hardening** — reduced protocol/service-only false positives and tightened token semantics to better align outputs with realistic attack pathways.
- [done] **ACI docs and operator guidance** — feature explanation, rule-authoring tutorial, technical deep dive, and tabletop prioritization policy with Operational Action Lane (`OAL`) terminology, including impact-probability-first methodology and policy-tuning guidance.
- [done] **Release-readiness validation pass** — focused ACI/reporting regression suite and dual 5k E2E runs (full + reduced enrichment) completed successfully with reproducible artifacts.
- [done] **ACI phrase-quality benchmark harness** — curated positive/negative phrase benchmark cases added to detect inference drift and guard against regression in semantic precision.
- [done] **Triage policy operationalization (config-backed)** — `triage_policy` controls added to TopN config schema/semantics and surfaced in markdown mapping via per-finding policy lanes.
- [in progress] **Decision explainability graph and provenance query tooling** (built on RunManifest + DecisionLedger).
- [done] **Resilient ingestion guardrails for constrained scanner exports** — minimum-signal contract, deterministic ingestion confidence tiers, and strict/min-confidence normalization gates (`--strict-ingestion`, `--allow-degraded-input`, `--min-ingestion-confidence`, `--show-ingestion-summary`).
- [done] **CSV parser hardening for Nessus + Qualys** — delimiter sniffing, size caps, malformed-row skipping, schema-variant header aliases, and ingestion metadata propagation.
- [done] **Ingestion decision-ledger coverage** — RunManifest now captures ingestion rejection and row-drop/skipped-malformed decision events for auditability.
- [in progress] **More scanner support** (Qualys CSV integrated; Nmap adapter path integrated; additional scanner connectors and parser-quality promotion work pending).
- [in progress] **Expanded intelligence sources** (GHSA integrated with online/offline modes and cache hardening; additional external sources and source-confidence normalization pending).
- [done] **TopN asset context tags in markdown reports** — project asset-level context labels (for example: externally-facing inferred, public-service-port inferred, criticality class, and concentration hints) into executive/technical asset mapping sections.
- [done] **Webhook delivery integration** — HMAC-SHA256 signed scan-complete events over HTTPS with OAL lane filtering, spool fallback, full RunManifest ledger traceability, and `--webhook-endpoint` / `--webhook-oal-filter` CLI overrides.
- [planned] **SIEM forwarding adapters** (Splunk HEC, Elasticsearch / OpenSearch index push, CEF syslog output).
- [planned] **Notification channel adapters** (Slack, Microsoft Teams, and PagerDuty alert routing with severity-gated delivery policy).
- [planned] **Advanced filtering and custom scoring/triage policies**.

### Release validation caveat (v1.2.0 hardening)

- Nessus and Qualys parser hardening in this cycle was validated through targeted synthetic/adversarial fixtures and public-format references.
- A newly bundled Nessus sample and any bundled Qualys sample are deferred; release is shipping with documented parser guardrails and regression coverage instead.

## v1.3.0-1.5.0+

- SQLite historical tracking and trending
- Comparative risk analysis across multiple scans
- Automated remediation recommendations
- Machine learning-based exposure prediction
- Extended enrichment ecosystem
- REST API server mode: expose scan-trigger, status, and result-query endpoints for CI/CD pipeline integration
- Ticketing system adapters: Jira and ServiceNow issue creation from OAL-filtered findings with deduplication and state-sync
- Custom output adapter plugin interface: third-party format targets without patching core output orchestration
- Webhook replay tooling: CLI command to re-deliver spooled payloads with signature refresh and configurable retry policy
