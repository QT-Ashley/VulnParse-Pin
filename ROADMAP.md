# Roadmap

This document tracks shipped milestones and upcoming work for VulnParse-Pin (`vpp`).

## Current Release: v2.0.0 (Apache-2.0, Phase 1 Complete)

**Status**: Shipped (Clean forward relicense from AGPLv3+ to Apache-2.0 starting at `v2.0.0`)

- [done] **Apache-2.0 Forward Cut & Zero-Copyleft Runtime** — Relicense `v2.0.0+` to `Apache-2.0` (`v1.0.0–v1.2.2` remain `AGPL-3.0-or-later`); replace LGPL `cvss` with clean-room Apache-2.0 CVSS v2/v3/v4 calculator; replace `defusedxml` with hardened streaming `lxml`; retire PyInstaller `--onefile` in favor of PEP 639 wheels, SLSA build provenance attestations, and isolated CycloneDX SBOM generation.
- [done] **DuckDB Local Workspace (`.vpp.db`)** — Persistent 12-table columnar workspace (`runs`, `assets`, `asset_aliases`, `findings`, `finding_evidence`, `finding_cves`, `enrichment_snapshots`, `aci_signals`, `scores`, `triage_decisions`, `diff_events`, `ledger_events`) with `0o600` POSIX creation perms, symlink rejection, Appender bulk ingestion, deterministic cross-scanner deduplication, and parameterized paged UI queries.
- [done] **Canonical v2 Identity & Pattern `assets.yaml` / `decisions.yaml`** — `aid_v2_` / `fid_v2_` identity, 5-tier asset matching (`alias`/`asset_id` → exact IP/FQDN/URI/image → longest-prefix CIDR → `fnmatchcase` glob → `unmatched_shadow` alert), and `DecisionsRegistry` predicate validation (`expires_at`, `in_kev`, `max_epss`, `max_epss_percentile`, `internet_facing`, `max_cvss`).
- [done] **Streaming Parsers & Bounded Sniffing** — 64 KB single-read `SchemaDetector` and UTF-8 BOM-safe streaming `FileInputValidator` (`--allow-large` up to 50 GiB); hardened `lxml.etree.iterparse` XML parsers (`nessus-xml`, `openvas-xml`, `qualys-xml`, `nmap-xml`); chunked UTF-8 C `JSONDecoder.raw_decode` + bounded `ijson` sniffing SARIF 2.1.0 (`sarif-2.1.0` for Trivy, Grype, Semgrep, CodeQL); streaming Nuclei JSONL (`nuclei-jsonl`); single-pass header-indexed CSV parsers.
- [done] **Threat Intelligence v2 & Unified Provenance** — NVD CVSS v4.0/v3.1/v3.0/v2.0 with `NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing` provenance; EPSS v5 `#model_version` + raw probability + percentile in signed `epss_cache.sqlite3`; full KEV metadata in `kev_cache.sqlite3`; GHSA `ghsa_package_index` PURL lookup; optional offline OSV cache (`osv_cache.sqlite3` with zip-traversal protection); negation-aware exploit heuristic separation (no KEV/Exploit double-count); DuckDB `populate_enrichment_snapshots()`.
- [done] **Dual-Track Scoring (`Scoring@3.0`), `ACI@2.0`, `Triage@2.0` (`--profile bod-26-04`), `TopN@2.0`, `Summary@2.0`** — Monotonic EPSS v5 piecewise breakpoints, Track A (`cve_threat`) + Track B (`exposure_weakness`) weighted by `detection_mode` Signal Reliability, CISA BOD 26-04 SSVC action/SLA mapping (`3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade`), SAST P1-cap guardrail, and `run_v2_duckdb_pipeline()`.
- [done] **Scan-over-Scan `DiffEngine` (`vpp diff`)** — Full outer join diffing across `.vpp.db` runs for new high-risk findings, threat-intel escalations, verified remediations, shadow-asset deltas, and stale-assumption deferral invalidations (`--fail-on p1|p2|kev|stale-assumption|none`, exit `2` on gate failure).
- [done] **Decision Defense Dossiers, Client Executive Roadmaps & Subcommand CLI / Textual TUI** — Jinja2 self-contained HTML & Markdown Decision Defense Dossiers and Executive Roadmaps (`autoescape`, `md_escape`, zero external CDNs, custom `--template-dir`), streaming DuckDB CSV/JSON exporters, chunked `RunManifest` v2, subcommand CLI (`scan`, `demo`, `diff`, `ui`, `export`, `verify`, `defer`, `intel`) + legacy compat shim, 100% offline `vpp demo` pack, optional `vpp ui` (`vulnparse-pin[ui]`), CI templates (`examples/ci/`), and `benchmarks/bench_scale.py`.

---

## Phase 2 (`v2.1+`) — Planned

- [planned] **CMDB & Cloud Inventory Compilers** — Declarative compilers translating AWS, GCP, Azure, NetBox, and ServiceNow asset exports into validated `assets.yaml` rules and alias mappings.
- [planned] **Extended Threat Intelligence Overlays** — VulnCheck KEV++ exploit timelines and ENISA EUVD regional advisory overlays integrated into `enrichment_snapshots`.
- [planned] **OpenVEX & CycloneDX VEX Ingestion** — Native VEX status parsing (`not_affected`, `affected`, `fixed`, `under_investigation`) with justification provenance fed into `Triage@2.0` and Decision Defense Dossiers.
- [planned] **Air-Gapped Wheelhouse & Cosign-Signed OCI Images** — Reproducible offline wheelhouse archives and Cosign-signed container images (`ghcr.io/qt-ashley/vulnparse-pin`) for restricted enclaves.
- [planned] **`vpp bundle` Offline Evidence & Intel Bundles** — Cryptographically signed, portable archive bundles packaging `.vpp.db`, feed snapshots, and `RunManifest` verification chains for air-gapped handoff.
- [planned] **GRC & Federal Compliance Export Profiles** — Native eMASS and FedRAMP POA&M export templates alongside existing Decision Defense Dossiers and Executive Roadmaps.
- [planned] **Multi-Run Trend Analytics, Ticketing & SIEM Adapters** — Historical SLA burn-down metrics across `.vpp.db` runs, Jira/ServiceNow issue sync, and Splunk HEC / OpenSearch / Slack / Teams / PagerDuty adapters.

---

## Historical v1.x Milestones (AGPL-3.0-or-later)

### v1.2.0 – v1.2.2 — Released (2026-04-24 to 2026-04-27)

- [done] **Whole-of-CVEs scoring (`Scoring@2.0`) & `ACI@1.0`** — Bounded-decay contributor CVE aggregation, per-finding `score_trace`, Attack Capability Inference pass, and phrase-quality benchmark harness.
- [done] **GHSA enrichment & Nmap context (`nmap_adapter@1.0`)** — Opt-in `--ghsa` online/offline enrichment with signed SQLite cache and opt-in `--nmap-ctx` open-port tie-breaks.
- [done] **Resilient ingestion & webhook delivery** — CSV delimiter/malformed-row guardrails, ingestion confidence tiers, and HMAC-SHA256 signed scan-complete webhooks.
- [done] **`v1.2.2` security & regression hardening** — EPSS HTTPS downgrade guard, NVD runtime SQLite policy wiring, webhook retry honoring `max_retries`, and Windows CSV newline fix.

### v1.1.1 — Released (2026-04-05)

- [done] **Config & Enrichment seam contracts** — 4-stage `ConfigSource` / `ConfigValidator` / `ConfigProjector` refactor (ADR-0001), Enrichment Seam Contract (ADR-0002), Draft 2020-12 config schema validation, pass dependency DAG validation, and `--output_all BASENAME`.

### v1.1.0 — Released (2026-03-29)

- [done] **Auditability & provenance (`RunManifest` + `LedgerService`)** — Append-only SHA-256 hash-chained decision ledger, `--verify-runmanifest`, derived asset criticality, and `PostEnrichmentIndex`.
