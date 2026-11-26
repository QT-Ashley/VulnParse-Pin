# Benchmarks

This document tracks both the **v2.0 DuckDB Scale Benchmark Harness** (`benchmarks/bench_scale.py`) and **historical v1.x in-memory pipeline baselines**.

---

## v2.0 DuckDB Scale Benchmarks (Streaming + `.vpp.db`)

VulnParse-Pin v2.0.0 replaces full-DOM XML/JSON loading, in-memory `ScanResult` duplication, and `ProcessPoolExecutor` pickling with:

1. **Streaming ingestion (`iter_batches`)**: Hardened `lxml.etree.iterparse` (XML), C-backed chunked `json.JSONDecoder.raw_decode` streaming (with bounded `ijson` sniffing) for SARIF 2.1.0, and line-streaming JSONL/CSV feeding `VppDatabase.ingest_normalized_batches()` via DuckDB `appender`.
2. **Matched-CVE snapshot hydration (`populate_enrichment_snapshots`)**: Queries distinct matched CVEs/PURLs in `.vpp.db` and hydrates only scan-relevant records from NVD, EPSS v5, CISA KEV, Exploit-DB, GHSA, and OSV.
3. **DuckDB Pass DAG (`run_v2_duckdb_pipeline`)**: `NmapAdapter@1.0` → `ACI@2.0` → `Scoring@3.0` → `Triage@2.0` → `TopN@2.0` → `Summary@2.0`, using memoized scoring/ACI and columnar `appender` writes.
4. **Parameterized UI & Summary Queries**: `query_findings_page(..., priority_tier="P1", limit=100)` + `get_run_summary_counts()` + `get_shadow_assets()`.

### Reproducible Harness (`benchmarks/bench_scale.py`)

`benchmarks/bench_scale.py` generates realistic multi-scanner synthetic datasets (mixed Nessus `.nessus` XML + Trivy `.sarif` + Nuclei `.jsonl` + Semgrep `.sarif` + Nmap `.xml` + pattern `assets.yaml` + `decisions.yaml` + miniature EPSS v5 / KEV / NVD / Exploit-DB snapshots) and executes all four v2.0 pipeline stages end-to-end in isolated per-scale processes so `ru_maxrss` is measured cleanly for each target size.

Run the full 500k–700k scale benchmark:

```bash
python benchmarks/bench_scale.py --findings 500000 --findings 700000 --json-out bench_v2_results.json
```

Quick developer smoke test (`5,000` or `10,000` findings):

```bash
python benchmarks/bench_scale.py --findings 10000
```

### Empirical v2.0 Results

- **Measured on**: `2026-11-24T14:34:55Z` · Python `3.12.3` · `Linux-6.18.58.1-microsoft-standard-WSL2-x86_64-with-glibc2.39` (`32` CPUs) · profile `bod-26-04` · streaming `batch_size=10000` (cold cache, subprocess-isolated per scale).

| Raw Findings | Unique Findings | Assets (Shadow) | Parse+Ingest (s) | Enrich (s) | Pipeline DAG (s) | UI+Summary (s) | Total (s) | Throughput (raw/s) | Peak RSS (MiB) | `.vpp.db` (MiB) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 500,000 | 335,758 | 1,170 (178) | 39.215 | 8.572 | 38.705 | 0.8695 | 87.362 | 5,723.3 | 2364.70 | 278.76 |
| 700,000 | 420,846 | 1,170 (178) | 162.117 | 6.631 | 41.830 | 0.9523 | 211.531 | 3,309.2 | 2633.21 | 351.26 |

- `500,000` breakdown: `56,327` cross-scanner deduplicated findings merged into `335,758` canonical rows; `107,669` P1 (`bod-26-04`) findings; `11,601` KEV-matched findings (`3,843.3 unique/s`, UI+Summary `<0.87s`).
- `700,000` breakdown: `102,225` cross-scanner deduplicated findings merged into `420,846` canonical rows; `139,501` P1 (`bod-26-04`) findings; `14,423` KEV-matched findings (`1,989.5 unique/s`, UI+Summary `<0.96s`) — matching the legacy `v1.0.0rc1` 700k single-scanner wall time (`210.65s`) while executing 4 scanners + Nmap + cold EPSS v5/KEV/Exploit-DB/NVD hydration + 12-table DuckDB + `ACI@2.0` + `Scoring@3.0` + `Triage@2.0` (`bod-26-04`) + paged TUI queries.

---

## Historical v1.x Baselines (In-Memory Pipeline, `v1.0.0rc1–v1.2.2`)

> [!IMPORTANT]
> All measurements below are **legacy `v1.x` in-memory `ScanResult` baselines** captured prior to the v2.0.0 DuckDB, streaming `lxml`/SARIF/Nuclei, EPSS v5, and `Triage@2.0` overhaul. They are preserved for historical comparison only.

### Public benchmark update (April 22, 2026 — `v1.x`)

This section summarizes legacy `v1.x` end-to-end runs with a consistent output set (JSON, CSV, executive Markdown, technical Markdown, and runmanifest).

#### Consolidated v1.x benchmark table

| Scenario | Input | Assets | Findings | Scored findings | Scoring coverage | Enriched findings | Enrichment coverage | Runtime | Throughput |
| ---------- | ------- | -------- | ---------- | ----------------- | ------------------ | ------------------- | --------------------- | --------- | ------------ |
| Baseline lab (101) | Nessus | 2 | 101 | 5 | 4.95% | 4 | 3.96% | 3.333s | 30.30 findings/s |
| Lab scaled 5k | Nessus | 10 | 5,000 | 5,000 | 100.00% | 2,236 | 44.72% | 11.663s | 428.69 findings/s |
| OpenVAS stress 20k | OpenVAS | 20 | 20,000 | 140 | 0.70% | 20,000 | 100.00% | 24.796s | 806.57 findings/s |

Source artifact: `tests_output/public_benchmark_comparison_apr22_2026.csv`

#### What this showed (`v1.x`)

1. Throughput scaled across larger workloads while producing full output artifacts.
1. Coverage behavior is dataset-sensitive, which is expected and useful for explaining risk context quality. The Lab 5k benchmark showed complete scoring coverage by construction, while OpenVAS 20k showed complete enrichment coverage with selective scoring coverage.
1. Exposure-inference signals remained available at scale (rule-hit summaries and confidence buckets), enabling explainable prioritization rather than raw finding count reporting.

#### Feature value versus a regular scanner output

| Feature area | VulnParse-Pin evidence from benchmark runs | Typical regular scanner output | Public-facing implication/value |
| -------------- | --------------------------------------------- | ------------------------------- | --------------------------------- |
| Cross-finding prioritization | Produces scored findings and ranked assets/findings across all runs; 5k run scored 5,000/5,000 findings | Usually reports per-finding severity and plugin output with limited cross-finding ranking logic | Teams can prioritize remediation by risk concentration and asset context, not just severity labels |
| Exposure inference traceability | Decision trace summaries include exposure confidence and rule-hit counts (for example, `private_ip`, `public_service_port_hit`, `critical_asset_hint`) | Often provides host/open-port facts but not a transparent, countable inference trace for prioritization rules | Stakeholders can audit why an asset/finding moved up in priority and defend triage decisions |
| Multi-artifact decision consistency | Same run emits JSON, CSV, executive and technical reports, plus runmanifest with aligned totals validated in this benchmark cycle | Output formats may exist, but consistency validation is commonly left to downstream tooling | Reduces reporting drift between technical and executive views and improves governance confidence |
| Actionable risk shaping | Risk-band distributions and TopN-derived context are surfaced in summary artifacts (critical/high/medium/low/info + top assets) | Regular scanner views frequently center on scanner-native severity bins without policy-aware context | Provides clearer, operations-oriented remediation sequencing and communication to leadership |
| Reproducible benchmark evidence | Public table and raw comparison CSV included from actual e2e runs | Benchmark narratives are often anecdotal or not tied to reusable artifacts | Improves trust in performance/value claims during customer or leadership review |

### Legacy v1.x Test Environment (March 2026)

- Date baseline: March 2026 (`v1.0.0rc1`)
- Platform: Windows Server 2025
- Python: 3.14
- CPU profile: 8-core class system

### Legacy v1.x Nessus Scale Benchmark (NVD Optimization Focus)

- Baseline file: `nessus_expanded_200.xml` (400 findings) → `~20s` (~20 findings/sec)
- Synthetic demo-derived file: `Lab_test_scaled_5k.nessus` (5,000 findings across 10 assets) → `~7.91s` (~632 findings/sec)
- Large-scale file: `nessus_benchmark_50k.xml` (50,000 findings, 338 unique CVEs) → `~194.59s` (~257 findings/sec)

### Legacy v1.x OpenVAS High-Volume Stress Benchmark

Mode used: offline with large-input allowance and low log verbosity (`v1.0.0rc1`).

- `openvas_real_stress_20k.xml` — 20,000 findings (~10.48 MB): `~48.49s` wall clock
- `openvas_real_stress_100k.xml` — 100,000 findings (~52.41 MB): `~42.86s` wall clock
- `openvas_real_stress_700k.xml` — 700,000 findings (~367.10 MB): `~210.65s` wall clock (3m 30.65s)

## Benchmarking Best Practices

- Benchmark with realistic multi-scanner CVE diversity and non-CVE exposure findings
- Isolate cold-cache vs warm-cache runs and per-scale RSS measurements (via subprocess isolation)
- Record per-stage timing (`Parse+Ingest`, `Enrich`, `Pipeline DAG`, `UI+Summary`), not only total time
- Flush DuckDB WAL cleanly (`.close()`) before measuring `.vpp.db` disk footprint
- Keep configuration and feed metadata snapshots for reproducibility
