# Pass Phases

This document details each stage of the VulnParse-Pin v2.0.0 pipeline from streaming ingestion through DuckDB passes, scan-over-scan diffing, and reporting.

## Phase 0: Streaming Ingestion & Normalization (`iter_batches` -> `ingest_normalized_batches`)

Implemented across `src/vulnparse_pin/parsers/*`, `src/vulnparse_pin/app/normalization.py`, and `src/vulnparse_pin/storage/repositories.py`.

1. **Input validation & detection:** `validate_scanner_input()` runs `FileInputValidator` (size caps, streaming BOM/JSONL/XML prolog checks), and `SchemaDetector.select()` reads at most 64 KiB to select the winning `ParserSpec`.
2. **Batch streaming:** The selected parser yields normalized finding dictionaries via `iter_batches()`.
3. **Ingestion quality gates:** `enforce_batch_ingestion_gates()` enforces `--strict-ingestion`, `--allow-degraded-input` / `--no-allow-degraded-input`, and `--min-ingestion-confidence` on each streamed batch.
4. **Asset resolution & cross-scanner deduplication:** `ingest_normalized_batches()` resolves each target through `AssetContextMatcher` (`assets.yaml`) into `aid_v2_` IDs and deduplicates findings into `fid_v2_` IDs across Track A (`cve_threat`) and Track B (`exposure_weakness`). Raw evidence from every scanner detection is appended to `finding_evidence`, and distinct CVEs are written to `finding_cves`.

## Phase 1: DuckDB Threat Intel Snapshot (`populate_enrichment_snapshots`)

Implemented in `src/vulnparse_pin/app/enrichment.py`.

1. Queries `.vpp.db` for only the distinct CVEs (`finding_cves` / `findings.primary_cve`) and `package_purl` values present in the current `run_id`.
2. Hydrates intelligence from active sources (`NVDFeedCache`, `EPSSFeedCache`, `KEVFeedCache`, `GHSAEnrichmentSource`, `OSVEnrichmentSource`, and Exploit-DB `files_exploit.csv` + negation-aware text heuristics).
3. Computes unified CVSS provenance (`NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing`) via `resolve_cvss_with_provenance()` and source-attributed enrichment confidence.
4. Bulk-inserts run-scoped rows into `enrichment_snapshots` and updates `runs.intel_metadata_json` (EPSS `#model_version` + score date, KEV catalog version + SHA-256, NVD/GHSA/OSV status).

## Phase 2: `run_v2_duckdb_pipeline` Pass DAG

Orchestrated by `run_v2_duckdb_pipeline()` in `src/vulnparse_pin/core/passes/__init__.py`.

### Step 2.1: Nmap Context Adapter (`nmap_adapter@1.0`)

Implemented in `src/vulnparse_pin/core/passes/Nmap/nmap_adapter_pass.py`.

- Opt-in via `--nmap` / `--nmap-ctx <nmap.xml>`.
- Streams Nmap XML using `safe_iterparse()` (`lxml.etree.iterparse` + `_xml_security.py`).
- Performs deterministic DuckDB reconciliation (`_reconcile_duckdb_hosts`) ordered by `asset_id ASC`, reconciling hosts via hostname/IP/alias lookup (`hostname` preferred before IP), merging `open_ports_json`, separating unmatched Nmap hosts into `unmatched_shadow` assets, and inferring exposure for unmatched hosts (`_infer_unmatched_internet_facing`).
- Non-blocking on missing/corrupt input; logs `NMAP_CTX_DISABLED`, `NMAP_CTX_ENABLED`, `NMAP_CTX_INVALID_FORMAT`, or `NMAP_CTX_FAILED` to `LedgerService`.
- See [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md).

### Step 2.2: Attack Capability Inference (`ACI@2.0`)

Implemented in `src/vulnparse_pin/core/passes/ACI/aci_pass.py` (`ACIV2Pass`).

- Evaluates finding titles, descriptions, plugin output, structured tags (e.g., Nuclei tags), CWEs (`CWE-78`, `CWE-89`, `CWE-502`, `CWE-798`, `CWE-918`, etc.), and open ports from `.vpp.db`.
- Enforces remote-service-only guardrails so bare port exposure without exploit/auth/RCE context does not fabricate remote execution capabilities.
- Writes `capabilities_json`, `chains_json`, `matched_tokens_json`, `confidence`, and `uplift_score` into `aci_signals`.

### Step 2.3: Dual-Track Scoring (`Scoring@3.0`)

Implemented in `src/vulnparse_pin/core/passes/Scoring/scoringPass.py` (`ScoringV3Pass`).

- Reads `findings`, `assets`, `enrichment_snapshots`, and `aci_signals` from `.vpp.db`.
- Scores **Track A (`cve_threat`)**: unified CVSS base score + monotonic piecewise EPSS v5 breakpoints + KEV/verified-exploit bonus (without double-counting KEV and Exploit-DB) + bounded-decay multi-CVE stacking (`cve_aggregation_decay=0.35`, `max_contributors=8`) + asset exposure/criticality adjustments + optional Nmap port bonus, weighted by `signal_reliability` (`detection_mode`).
- Scores **Track B (`exposure_weakness`)**: severity baseline + `ACI@2.0` capability/chain/CWE uplifts + exposure bonus, weighted by `signal_reliability`.
- Writes `raw_risk_score`, `operational_score`, `risk_band`, and `score_trace_json` to `scores`, and updates `assets.derived_criticality` (`Extreme` / `High` / `Medium` / `Low`).

### Step 2.4: Triage & SSVC Decisioning (`Triage@2.0`)

Implemented in `src/vulnparse_pin/core/passes/Triage/triage_pass.py` (`TriageDecisionPass`).

- Supports `--profile default` (legacy OAL-compatible `P1`/`P1B`/`P2`/`P3`/`P4` lanes) and `--profile bod-26-04` (CISA BOD 26-04 SSVC tree mapping to `Act` / `Attend` / `Track*` / `Track` and `3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade`).
- Applies `static_sast_p1_cap` guardrail so uncorroborated `static_sast` findings cannot saturate `P1`.
- Evaluates `DecisionsRegistry` (`decisions.yaml` and inline `assets.yaml` decisions) predicates (`expires_at`, `in_kev`, `max_epss`, `max_epss_percentile`, `internet_facing`, `max_cvss`), transitioning violated waivers to `deferred_invalidated` / `accepted_invalidated` / `mitigated_invalidated`.
- Writes decisions, `assumed_state_json`, and `rationale_summary` to `triage_decisions`.

### Step 2.5: Top-N Ranking (`TopN@2.0`)

Implemented in `src/vulnparse_pin/core/passes/TopN/topn_pass.py` (`TopNV2Pass`).

- Uses DuckDB window/ranking SQL over `findings`, `scores`, `triage_decisions`, `aci_signals`, `enrichment_snapshots`, and `assets`.
- Computes decay-weighted asset priority scores and deterministic per-asset and global top-N ranked lists ordered by priority tier (`P1`..`P4`), `operational_score DESC`, `epss_score DESC`, `aci.uplift_score DESC`, and `finding_id ASC`.

### Step 2.6: Executive & Technical Summary (`Summary@2.0`)

Implemented in `src/vulnparse_pin/core/passes/Summary/summary_pass.py` (`SummaryV2Pass`).

- Aggregates DuckDB summary views into `SummaryPassOutput` (`overview`, `asset_summary`, `finding_summary`, `risk_distribution`, `top_risks`, `enrichment_metrics`, `remediation_priorities`, `decision_trace_summary`), tracking shadow assets, CVSS provenance counts, SAST P1 caps, and invalidated decisions.

## Phase 3: DiffEngine & Artifact Rendering

- **Scan-over-Scan Diffing (`vpp diff` / `--baseline-run-id`):** `DiffEngine` (`src/vulnparse_pin/core/diff_engine.py`) compares two runs in `.vpp.db`, categorizing new high-risk findings, threat-intel escalations (KEV additions, EPSS threshold crossings `0.04`/`0.10` or percentile `0.90`/`0.95`, CVSS deltas `>= 1.0`), verified remediations, shadow-asset deltas, and stale-assumption waiver invalidations into `diff_events`.
- **Rendering & Exports (`export_v2_outputs` / `vpp export`):** `src/vulnparse_pin/reporting/renderer.py` renders self-contained Jinja2 HTML and Markdown Decision Defense Dossiers and Executive Roadmaps (`autoescape` + `md_escape`); `csv_exporter.py`, `reportgen.py`, and `runmanifest.py` stream CSV/JSON exports and seal the chunked `RunManifest` + `ledger_events`.

## Legacy v1.x in-memory pass chain

For backward compatibility with `ScanResult` objects outside DuckDB, `ScoringPass` (`Scoring@2.0`), `AttackCapabilityInferencePass` (`ACI@1.0`), `TopNPass` (`TopN@1.0`), and `SummaryPass` (`Summary@1.0`) remain in `src/vulnparse_pin/core/passes/`.

## Deep-dive references

- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Nmap Context Deep Dive](Nmap%20Context%20Deep%20Dive.md)
- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Runtime Policy Deep Dive](Runtime%20Policy%20Deep%20Dive.md)
