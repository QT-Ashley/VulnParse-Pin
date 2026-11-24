# Output Interpretation

This guide explains how to generate, read, and interpret all VulnParse-Pin v2.0 (`Apache-2.0`) output artifacts across the subcommand CLI (`vpp scan`, `vpp demo`, `vpp diff`, `vpp ui`, `vpp export`, `vpp verify`).

## v2.0 Output Artifact Types

| Artifact | CLI Flag / Command | Purpose |
| --- | --- | --- |
| **DuckDB Workspace** | `vpp scan --db workspace.vpp.db ...` *(default `.vpp.db`)* | Persistent 12-table columnar workspace backing `vpp ui`, `vpp export`, `vpp diff`, and `vpp defer --db` |
| **Decision Defense Dossier** | `--output-dossier PATH`, `--output-html PATH`, or `vpp export --format dossier-md\|dossier-html` | Audit-ready HTML & Markdown explanation of why findings were prioritized, deferred, invalidated, or deprioritized |
| **Executive Client Roadmap** | `--output-md PATH` or `vpp export --format roadmap-md\|roadmap-html` | Leadership & engineering roadmap grouped by SLA bucket, asset owner, quick wins, and shadow assets |
| **PR Diff Comment** | `vpp diff --output-pr-comment PATH` *(or `--output-md PATH`)* | Concise CI pull-request delta summary + stale-assumption alert |
| **Normalized JSON** | `--output PATH` (`-o`, `--output-json`) or `vpp export --format json` | Streaming machine-readable output (`Scoring@3.0`, `ACI@2.0`, `Triage@2.0`, `TopN@2.0`, `Summary@2.0`, `score_trace`) |
| **CSV** | `--output-csv PATH` (`-oC`) + `--csv-profile full\|analyst\|audit` or `vpp export --format csv` | Formula-sanitized spreadsheet export (`full`, `analyst`, or `audit`) |
| **RunManifest v2** | `--output-runmanifest PATH` (`-oRM`) + `vpp verify <manifest>` | Tamper-evident provenance, output SHA-256 digests, and hash-chained `ledger_events` |
| **6-Artifact Bundle** | `vpp scan ... --output-all <BASENAME>` (`-oA`) | Emits JSON, CSV, Executive Roadmap MD, Technical/Dossier MD, Dossier MD+HTML bundle, and RunManifest v2 in one command |
| **Signed Webhooks** | `config.yaml` (`webhook.*`) / `--webhook-endpoint` / `--webhook-oal-filter` | HMAC-SHA256 signed HTTPS completion event with retry & local spooling |

---

## `--output-all` (`-oA`) Bundle

Running:

```bash
vpp scan scan.nessus --profile bod-26-04 --db workspace.vpp.db --output-all out/prod_scan
```

produces:

- `out/prod_scan.json` — Normalized DuckDB JSON export
- `out/prod_scan.csv` — CSV export (default `--csv-profile full`)
- `out/prod_scan_summary.md` — Executive Client Roadmap Markdown (`executive_markdown`)
- `out/prod_scan_technical.md` — Decision Defense Dossier Markdown (`technical_markdown`)
- `out/prod_scan_dossier.md` & `out/prod_scan_dossier.html` — Decision Defense Dossier bundle (`dossier_markdown`, `dossier_html`) *(unless `--output-html` overrides the HTML path)*
- `out/prod_scan_runmanifest.json` — RunManifest v2 recording SHA-256 digests for all 6 written artifact keys (`json`, `csv`, `executive_markdown`, `technical_markdown`, `dossier_markdown`, `dossier_html`)

---

## Decision Defense Dossier (`dossier.html`, `dossier.md`)

Export on demand from `.vpp.db` for a full run or a single finding:

```bash
vpp export --db workspace.vpp.db --format dossier-html --output out/dossier.html
vpp export --db workspace.vpp.db --format dossier-md --finding-id fid_v2_... --output out/finding_dossier.md
```

### Structure and Interpretation

1. **Executive Posture Snapshot:** Total findings split by Track A (`cve_threat`) vs Track B (`exposure_weakness`), prioritized count, validly deferred/accepted/mitigated count, invalidated deferrals, CISA KEV count, and unmatched shadow assets.
2. **Why Prioritized:** Lists active prioritized findings (`P1`, `P1B`, `P2`) and any **invalidated deferrals**, showing:
   - Triage tier, SLA (`3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade`), SSVC action (`Act`, `Attend`, `Track*`, `Track`), and `ssvc_path`
   - Track, operational score (`0–10`), raw score (`0–16`), risk band, `detection_mode`, `signal_reliability`, and `(SAST P1-Cap Guardrail Applied)` when triggered
   - Effective CVSS score, version (`2.0`/`3.0`/`3.1`/`4.0`), and provenance (`NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing`)
   - EPSS v5 (`probability / percentile`), CISA KEV metadata (`date_added`, `due_date`, `ransomware`), `verified_exploit`, and `heuristic_exploit_mention`
   - `ACI@2.0` capabilities, chains, confidence, and uplift
   - `score_breakdown` and cross-scanner `finding_evidence` provenance (`source_count`, `is_deduplicated`)
3. **Why Deprioritized / Deferred:**
   - **Invalidated Deferrals & Stale-Assumption Alerts:** Findings whose `decisions.yaml` predicates failed (`expired`, `kev_flipped`, `epss_exceeded`, `epss_percentile_exceeded`, `exposure_flipped`, `cvss_exceeded`).
   - **Validly Deferred / Risk-Accepted / Mitigated Findings:** Documented governance suppressions with owner, expiration, and rationale.
   - **Threat-Evidence & Exposure Deprioritized Findings:** Explains why findings—including `CVSS >= 7.0` or High/Critical scanner severity—were placed in non-urgent tiers (`deprioritization_reasons`).
     - **Active `default`-profile `P3` deprioritization:** Under `--profile default`, active `P3` (`60-day`, `Track*`) and `P4` (`Fix on Upgrade`, `Track`) findings are excluded from the prioritized table (`is_prioritized = False`) and appear in this deprioritized section with their exact rationale (e.g., low EPSS, not in CISA KEV, internal/non-exposed asset, or static SAST reliability weighting). Under `--profile bod-26-04`, `P2` (`60-day`, `Attend`) is prioritized while `P3`/`P4` (`Fix on Upgrade`, `Track`) are deprioritized.
4. **Auditor-Defense Compliance Framing:** Maps prioritization and deferral auditability to **PCI DSS v4.0.1 (Requirements 6.3.1 & 11.3.1)** and **CISA BOD 26-04 / SSVC**.
5. **Shadow / Unmatched Asset Disclosure:** Surfaces `inventory_status = 'unmatched_shadow'` hosts observed in scan or Nmap output that did not match `assets.yaml`.

### Pre-Seal vs Post-Export RunManifest Seal

- **During `vpp scan --output-all`:** `dossier.md` and `dossier.html` are written *before* `build_runmanifest_from_db()` seals the final `manifest_digest` (because `RunManifest` hashes the written dossier files!). Accordingly, dossiers generated inline during `vpp scan` display:
  `Pending post-export RunManifest seal (see runmanifest.json)`.
- **Post-export (`vpp export`):** Once `vpp scan` finishes, `runs.manifest_digest` is persisted in `.vpp.db`. Running `vpp export --db workspace.vpp.db --format dossier-html` (or `dossier-md`) afterwards embeds the sealed `sha256:...` digest directly in the dossier header and footer.

---

## Executive Client Roadmap (`executive_roadmap.html`, `executive_roadmap.md`)

Generate an executive & remediation-owner roadmap from `.vpp.db`:

```bash
vpp export --db workspace.vpp.db --format roadmap-html --output out/executive_roadmap.html
vpp export --db workspace.vpp.db --format roadmap-md --output out/executive_roadmap.md
```

Includes run KPIs, **SLA Bucket Roadmap** (`3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade` excluding validly suppressed findings), **Owner-Grouped Remediation Batches**, **Top Quick-Win Fixes**, **Shadow Assets**, and **Invalidated Deferrals**. All HTML outputs use Jinja2 `autoescape` with zero external CDN dependencies (100% offline self-contained).

---

## PR Diff Comment (`diff_pr_comment.md`)

Compare two runs in `.vpp.db` (or two scan files on the fly) and render a concise CI pull-request Markdown comment:

```bash
vpp diff --db workspace.vpp.db run_base run_head \
  --fail-on stale-assumption \
  --output-pr-comment out/diff_pr_comment.md \
  --output-json out/diff_report.json
```

Surfaces delta counts (`newly_introduced_high_risk`, `threat_intel_escalated`, `verified_remediated` split into `patched` vs `asset_missing`, `invalidated_assumptions`, `shadow_assets_new`/`resolved`) and returns exit code `2` when `--fail-on` triggers.

---

## JSON Interpretation (`--output` / `vpp export --format json`)

DuckDB JSON exports (`schema_version: "2.0.0"`) stream asset-by-asset and finding-by-finding without loading the full run into RAM.

Under the default `namespace` overlay mode:

- **Finding base fields:** `finding_id`, `asset_id`, `scoring_track` (`cve_threat` | `exposure_weakness`), `primary_cve`, `cves`, `cwes`, `ghsa_ids`, `detection_mode`, `signal_reliability`, `ingestion_confidence`, `fidelity_tier`, `source_format`, `is_deduplicated`, `source_count`, `evidence`.
- **`enrichment`:** Effective `cvss_score`, `cvss_vector`, `cvss_version`, `cvss_provenance` (`NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing`), `epss_score`, `epss_percentile`, `epss_model_version`, `epss_date`, `in_kev` (union across primary and secondary CVEs), `kev_date_added`, `kev_due_date`, `kev_ransomware`, `verified_exploit`, `heuristic_exploit_mention`, `exploit_refs`, `sources`.
- **`derived["Scoring@3.0"]`:** `raw_risk_score`, `operational_score`, `risk_band`, and `score_trace` (per-component `breakdown`, `aci_capabilities`, `aci_chains`, and secondary-KEV metadata).
- **`derived["Triage@2.0"]`:** `profile`, `priority_tier`, `oal_compat`, `ssvc_action`, `sla_bucket`, `sla_days`, `decision_status`, `decision_id`, `assumed_state`, `rationale_summary`.
- **`derived["ACI@2.0"]`:** `capabilities`, `chains`, `matched_tokens`, `confidence`, `uplift_score`.

Use `--presentation --overlay-mode flatten` on `vpp scan` (or `--overlay-mode flatten` on `vpp export --format json`) to flatten derived fields directly onto each finding object. See [Presentation Overlays](Presentation%20Overlays.md).

---

## CSV Interpretation

CSV export supports three profiles (`--csv-profile full|analyst|audit`):

1. **`analyst` (40 columns):** Compact triage & SLA queue fields (`run_id`, `asset_*`, `inventory_status`, `owner`, `internet_facing`, `asset_criticality`, `finding_id`, `title`, `severity`, `scoring_track`, `detection_mode`, `signal_reliability`, `ingestion_confidence`, `fidelity_tier`, `source_format`, `primary_cve`, `cvss_score`, `cvss_version`, `cvss_provenance`, `epss_score`, `epss_percentile`, `cisa_kev`, `verified_exploit`, `raw_score`, `operational_score`, `risk_band`, `priority_tier`, `oal_compat`, `ssvc_action`, `sla_bucket`, `sla_days`, `decision_status`, `affected_port`, `protocol`, `is_deduplicated`, `source_count`).
2. **`full` (60 columns, default):** All `analyst` columns plus `canonical_key`, `cves`, `cwes`, `ghsa_ids`, `cvss_vector`, `kev_date_added`, `kev_due_date`, `kev_ransomware`, `heuristic_exploit_mention`, `package_purl`, `location_uri`, `line_number`, `service_name`, `open_ports`, `aci_capabilities`, `aci_chains`, `aci_confidence`, `aci_uplift_score`, `description`, `solution`.
3. **`audit` (68 columns):** All `full` columns plus `matched_rule_id`, `decision_id`, `rationale_summary`, `epss_model_version`, `epss_date`, `enrichment_sources`, `score_trace_json`, `assumed_state_json`.

Example commands:

```bash
# Fast analyst triage sheet from DuckDB workspace
vpp export --db workspace.vpp.db --format csv --csv-profile analyst -o triage.csv

# Full audit traceability sheet during scan
vpp scan scan.nessus --profile bod-26-04 --output-csv audit.csv --csv-profile audit
```

**CSV Formula-Injection Protection:** Enabled by default (prefixes dangerous leading `=`, `+`, `-`, `@`, `\t`, `\r` cells). Disabling sanitization requires **both** `--no-csv-sanitize` and explicit `--confirm-unsafe-csv` (refusal exits with code `2`).

---

## RunManifest & Verification

Verify a generated RunManifest and all listed output artifacts without touching caches or writing files:

```bash
vpp verify out/prod_scan_runmanifest.json
```

See [RunManifest Overview](RunManifest.md) and [RunManifest Technical Deep Dive](RunManifest_Technical.md).

---

## Signed Webhook Output Interpretation

When configured in `config.yaml` (`webhook.enabled: true`) or overridden via `--webhook-endpoint <HTTPS_URL>` and `--webhook-oal-filter <all|P1|P1b|P2>`, VulnParse-Pin emits a signed JSON notification:

- **Headers:** `X-VPP-Signature` (HMAC-SHA256 using `VP_WEBHOOK_HMAC_KEY`), `X-VPP-Timestamp`, `X-VPP-Nonce`, `X-VPP-Key-Id`, `X-VPP-Event`.
- **Ledger reason codes:** `WEBHOOK_EMIT_STARTED`, `WEBHOOK_EMIT_SUCCEEDED`, `WEBHOOK_EMIT_FAILED`, `WEBHOOK_EMIT_SKIPPED_DISABLED`, `WEBHOOK_EMIT_SKIPPED_POLICY`, `WEBHOOK_EMIT_SPOOLED_FOR_RETRY`.
- **Spool fallback:** Failed deliveries (when `webhook.allow_spool: true`) are written to `<output_dir>/webhook_spool/webhook_<timestamp>_<nonce>.json` (default `spool_subdir: webhook_spool`).

---

## Interactive Workbench (`vpp ui`)

For interactive exploration of `.vpp.db` at scale (paged SQL queries in `< 1.0s` even at 500k–700k findings), run:

```bash
vpp ui --db workspace.vpp.db --decisions decisions.yaml --output-dir out/
```

Inside the TUI, press `e` to export a single-finding Decision Defense Dossier or `E` to export a full-run dossier bundle.

## Related Docs

- [Presentation Overlays](Presentation%20Overlays.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [RunManifest Overview](RunManifest.md)
- [RunManifest Technical Deep Dive](RunManifest_Technical.md)
- [ScanResult & DuckDB Schema](ScanResult_Schema.md)
- [Usage](Usage.md)
