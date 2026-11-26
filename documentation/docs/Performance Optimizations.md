# Performance Optimizations

VulnParse-Pin v2.0 (`Apache-2.0`) replaces in-memory full-DOM loading and `ProcessPoolExecutor` pickling with a streaming ingestion, columnar DuckDB (`.vpp.db`) execution, and memoized SQL/vectorized pass architecture built to scale to `500,000–700,000+` multi-scanner findings while keeping interactive UI queries under `1.0s`.

See [Benchmarks](Benchmarks.md) and `benchmarks/bench_scale.py` for the reproducible multi-scanner benchmark harness and empirical measurements.

---

## 1. Streaming Parser & Input Layer

- **SARIF 2.1.0 (`_FastSarifStreamReader` in `src/vulnparse_pin/parsers/sarif_parser.py`):**
  - Streams documents using `4 MiB` (`4 * 1024 * 1024` bytes) incremental UTF-8 reads and C-backed `json.JSONDecoder.raw_decode` instead of full-file `json.load()` or pure-Python token parsing across large `results` arrays.
  - Uses bounded `ijson` sniffing only on the initial head window (`64 KiB` / `HEAD_SNIFF_BYTES`) for schema detection, plus O(1)-memory `_skip_json_value()` skipping for unneeded top-level SARIF properties.
- **Hardened Streaming XML (`src/vulnparse_pin/parsers/_xml_security.py` & `nessusXML_parser.py` / `openvasXML_parser.py` / `qualysXML_parser.py`):**
  - Uses `lxml.etree.iterparse` (`safe_iterparse`) with explicit `tag=(...)` filtering and immediate `prune_element(elem)` after each processed node so memory stays flat across 100 MB+ XML reports (zero `defusedxml` overhead).
  - Builds per-host context once per `<ReportHost>` (`_build_host_ctx` single-pass host context) instead of re-deriving host properties per finding.
- **C Substring Pre-Guards (`src/vulnparse_pin/parsers/base_parser.py`):**
  - `extract_cves_from_text`, `extract_cwes_from_text`, and `extract_ghsas_from_text` perform fast C-level lowercase substring checks (`"cve-" in s.lower()`, `"cwe" in s.lower()`, `"ghsa-" in s.lower()`) before invoking `CVE_RE`, `CWE_RE`, or `GHSA_RE`.

---

## 2. Columnar DuckDB Ingestion (`ingest_normalized_batches`)

Implemented in `src/vulnparse_pin/storage/repositories.py`:

- **Non-Incremental Streaming Fast Path:** When `existing_count == 0` for a `run_id`, `ingest_normalized_batches()` skips upfront `SELECT` hydration of existing `assets`, `asset_aliases`, `finding_evidence`, `finding_cves`, and `findings` tables.
- **Zero-Allocation Hot Loop:** Uses `__slots__`-backed `_PendingFinding` records, tuple-cached asset resolution (`asset_resolve_cache`), finding ID caching (`fid_cache`), and JSON list encoding caches (`json_list_cache`).
- **DuckDB Appender Flush:** Streams `finding_evidence`, `assets`, `asset_aliases`, `findings`, and `finding_cves` in `25,000`-row chunks via `conn.appender(...)` inside an explicit transaction.

---

## 3. Pass DAG Optimizations (`ACI@2.0`, `Scoring@3.0`, `Triage@2.0`)

Executed via `run_v2_duckdb_pipeline()` (`src/vulnparse_pin/core/passes/__init__.py`):

- **`ACI@2.0` (`src/vulnparse_pin/core/passes/ACI/aci_pass.py`):**
  - `_scan_sig` fast-skips pure numeric `nessus:<id>`, `qualys:<id>`, and `openvas:<id>` signatures unless digit/prefix tokens match.
  - Bounded memoization caches (`text_field_memo`, `cwes_memo`, `tags_memo`, `sig_memo`, `refs_memo`, `eval_memo`) deduplicate repeated plugin text and rule evaluations.
  - Appends `aci_signals` via `25,000`-row DuckDB `appender` batches; only materializes per-finding `ACIFindingSemantic` dicts when `row_cnt <= 10_000`.
- **`Scoring@3.0` (`src/vulnparse_pin/core/passes/Scoring/scoringPass.py`):**
  - Probes whether `finding_cves` contains links absent from `findings.cves_json` (`need_fc_join`) and skips the expensive `335k+` `list(cve_id) GROUP BY` join when `findings.cves_json` already holds all CVE links.
  - Memoizes equivalent `(track, cve_tuple, scanner_cvss, detection_mode, signal_reliability, exploit, facing, criticality, aci)` score tuples (`memo`, bounded to `200,000` entries).
  - Writes `scores` in `50,000`-row `appender` batches, bulk-updates `findings.signal_reliability` in SQL, and bulk-updates `assets.derived_criticality` via a temp `_stg_asset_crit` table + `appender`.
- **`Triage@2.0` (`src/vulnparse_pin/core/passes/Triage/triage_pass.py`):**
  - **`DecisionsRegistry` Exact vs Wildcard Indexing:** Checks `exact_finding_ids` and `has_wildcard_finding_ids`; when wildcard-free and no finding CVE/ID/`scanner_sig` hits the index, bypasses `DecisionsRegistry.evaluate()` completely.
  - **SSVC & Triage Memoization (`triage_memo`):** Memoizes identical `(profile, internet_facing, kev, exploit, epss_cutoffs, track, sig_rel, score_cutoffs, cvss_vec, aci, sast_fields)` tuples and flushes `triage_decisions` via `25,000`-row `appender` batches.

---

## 4. Sub-Second UI & Summary Queries (`repositories.py`)

Interactive TUI (`vpp ui`), dossier rendering, and summary banners remain `< 1.0s` even at `500,000–700,000` raw findings via:

- **`_FAST_EFFECTIVE_PRIMARY_CVE_SQL` & `_FAST_SCORE_TRACE_IN_KEV_SQL`:** Pre-filter `score_trace_json` using DuckDB C-level `CONTAINS(...)` string guards so `json_extract` / `json_extract_string` is only parsed on rows where `score_trace_json` actually overrides `f.primary_cve` or indicates `in_kev: true`.
- **`_KEV_CTES_SQL`:** Pre-materializes distinct KEV CVEs (`e_kev`), KEV-linked findings via `finding_cves` (`fc_kev`), and trace-level KEV flags (`s_kev`) as small hash-joinable CTEs instead of per-row correlated subqueries.
- **`GROUPING SETS` Aggregation (`get_run_summary_counts`):** Computes `priority_tier`, `sla_bucket`, and `decision_status` counts in a **single scan** over `triage_decisions` using `GROUP BY GROUPING SETS ((priority_tier), (sla_bucket), (decision_status))`.

---

## 5. Verified Empirical Scale Results (`benchmarks/bench_scale.py`)

Measured with cold caches and isolated subprocess RSS tracking (`--profile bod-26-04`, mixed Nessus + Trivy SARIF + Nuclei JSONL + Semgrep SARIF + Nmap, see [Benchmarks](Benchmarks.md)):

| Raw Findings | Canonical Unique | Parse+Ingest | Enrich | Pipeline DAG | UI+Summary | Total Time | Peak RSS | `.vpp.db` Size |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `500,000` | `335,758` | `39.215s` | `8.572s` | `38.705s` | **`0.8695s`** | `87.362s` (`5,723.3 raw/s`) | `2364.70 MiB` | `278.76 MiB` |
| `700,000` | `420,846` | `162.117s` | `6.631s` | `41.830s` | **`0.9523s`** | `211.531s` (`3,309.2 raw/s`) | `2633.21 MiB` | `351.26 MiB` |

## Related Docs

- [Benchmarks](Benchmarks.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [ACI Technical Deep Dive](ACI%20Technical%20Deep%20Dive.md)
- [ScanResult & DuckDB Schema](ScanResult_Schema.md)
