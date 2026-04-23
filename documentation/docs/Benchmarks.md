# Benchmarks

This document summarizes observed performance behavior for VulnParse-Pin v1.0.0rc.1 under high-volume test scenarios.

## Public benchmark update (April 22, 2026)

This section is intended for external sharing and value communication. It summarizes
the latest end-to-end runs with a consistent output set (JSON, CSV, executive Markdown,
technical Markdown, and runmanifest).

### Consolidated benchmark table

| Scenario | Input | Assets | Findings | Scored findings | Scoring coverage | Enriched findings | Enrichment coverage | Runtime | Throughput |
| ---------- | ------- | -------- | ---------- | ----------------- | ------------------ | ------------------- | --------------------- | --------- | ------------ |
| Baseline lab (101) | Nessus | 2 | 101 | 5 | 4.95% | 4 | 3.96% | 3.333s | 30.30 findings/s |
| Lab scaled 5k | Nessus | 10 | 5,000 | 5,000 | 100.00% | 2,236 | 44.72% | 11.663s | 428.69 findings/s |
| OpenVAS stress 20k | OpenVAS | 20 | 20,000 | 140 | 0.70% | 20,000 | 100.00% | 24.796s | 806.57 findings/s |

Source artifact: `tests_output/public_benchmark_comparison_apr22_2026.csv`

### What this shows (public-facing value)

1. Throughput scales strongly across larger workloads while still producing full output artifacts.
1. Coverage behavior is dataset-sensitive, which is expected and useful for explaining risk context quality. The Lab 5k benchmark shows complete scoring coverage by construction, while OpenVAS 20k shows complete enrichment coverage with selective scoring coverage.
1. Exposure-inference signals remain available at scale (rule-hit summaries and confidence buckets), enabling explainable prioritization rather than raw finding count reporting.

### Feature value versus a regular scanner output

| Feature area | VulnParse-Pin evidence from benchmark runs | Typical regular scanner output | Public-facing implication/value |
| -------------- | --------------------------------------------- | ------------------------------- | --------------------------------- |
| Cross-finding prioritization | Produces scored findings and ranked assets/findings across all runs; 5k run scored 5,000/5,000 findings | Usually reports per-finding severity and plugin output with limited cross-finding ranking logic | Teams can prioritize remediation by risk concentration and asset context, not just severity labels |
| Exposure inference traceability | Decision trace summaries include exposure confidence and rule-hit counts (for example, `private_ip`, `public_service_port_hit`, `critical_asset_hint`) | Often provides host/open-port facts but not a transparent, countable inference trace for prioritization rules | Stakeholders can audit why an asset/finding moved up in priority and defend triage decisions |
| Multi-artifact decision consistency | Same run emits JSON, CSV, executive and technical reports, plus runmanifest with aligned totals validated in this benchmark cycle | Output formats may exist, but consistency validation is commonly left to downstream tooling | Reduces reporting drift between technical and executive views and improves governance confidence |
| Actionable risk shaping | Risk-band distributions and TopN-derived context are surfaced in summary artifacts (critical/high/medium/low/info + top assets) | Regular scanner views frequently center on scanner-native severity bins without policy-aware context | Provides clearer, operations-oriented remediation sequencing and communication to leadership |
| Reproducible benchmark evidence | Public table and raw comparison CSV included from actual e2e runs | Benchmark narratives are often anecdotal or not tied to reusable artifacts | Improves trust in performance/value claims during customer or leadership review |

### Benchmark claims (evidence-bound)

1. VulnParse-Pin processed 20,000 OpenVAS findings in 24.796s while producing JSON, CSV, executive report, technical report, and runmanifest outputs in the same run.
2. On the 5,000-finding Nessus benchmark, VulnParse-Pin achieved 100.00% scoring coverage (5,000 of 5,000 findings).
3. Across benchmark scenarios, VulnParse-Pin maintained cross-artifact numeric consistency between JSON, CSV, markdown summaries, and runmanifest pass summaries.
4. VulnParse-Pin exposes explainable prioritization traces through decision trace summaries (for example, exposure confidence buckets and rule-hit counts).
5. Benchmark claims are backed by reproducible artifacts in `tests_output/public_benchmark_comparison_apr22_2026.csv` and scenario-specific profile/delta files.

Claim boundaries:

- These numbers describe the tested benchmark workloads and environment; they are not universal guarantees for all datasets.
- Coverage percentages vary by input structure, enrichment density, and CVE distribution.

### Important interpretation note

Different datasets have different CVE density and structure. Coverage percentages should be interpreted
as workload characteristics, not universal fixed rates. The value signal is that VulnParse-Pin keeps
decision-support outputs and traceability available across both small and high-volume runs.

## Test environment

- Date baseline: March 2026
- Platform: Windows Server 2025
- Python: 3.14
- CPU profile: 8-core class system

## Nessus scale benchmark (NVD optimization focus)

### Dataset profile

- Baseline file: `nessus_expanded_200.xml`
- Baseline findings: 400
- Synthetic demo-derived file: `Lab_test_scaled_5k.nessus`
- Synthetic demo-derived findings: 5,000 across 10 assets
- Large-scale file: `nessus_benchmark_50k.xml`
- Large-scale findings: 50,000
- Unique CVEs across both: 338

The `Lab_test_scaled_5k.nessus` sample is generated from the bundled `Lab_test.nessus`
template and forces one CVE per finding across years 2019-2025, with populated
titles and plugin outputs for parser and enrichment realism.

### 5k demo-derived benchmark snapshot

- Input file: `Lab_test_scaled_5k.nessus`
- Assets: 10
- Findings: 5,000
- Runtime: ~7.91s wall clock
- Output set: JSON, CSV, executive Markdown, technical Markdown
- Enrichment coverage: 100% scoring coverage, 5,000 CVSS vectors assigned and validated

Observed summary from the benchmark run:

- Known exploits: 47 findings
- KEV hits: 10 findings
- EPSS coverage: 2,225 / 5,000 findings (44.50%)
- Enriched findings: 2,226

### Runtime comparison

- Baseline runtime: ~20s
- 5k runtime: ~7.91s
- 50k runtime: ~194.59s
- Input growth: `125x`
- Runtime growth: `9.73x`

Result: sublinear scaling and significant throughput gains at scale.

### Throughput signal

- Baseline: ~20 findings/sec
- 5k run: ~632 findings/sec
- 50k run: ~257 findings/sec
- Effective throughput improvement: ~12.8x

### NVD optimization impact

Observed NVD phase remained near-flat relative to finding growth due to:

- Streaming/filtered feed handling
- CVE-targeted indexing
- Early termination behavior
- Parallel feed parsing

This decoupled major NVD cost from raw finding count when CVE distribution was stable.

## OpenVAS high-volume stress benchmark

Mode used: offline with large-input allowance and low log verbosity.

### Dataset sizes

- `openvas_real_stress_20k.xml` — 20,000 findings (~10.48 MB)
- `openvas_real_stress_100k.xml` — 100,000 findings (~52.41 MB)
- `openvas_real_stress_700k.xml` — 700,000 findings (~367.10 MB)

### Runtime results

- 20k: ~48.49s wall clock
- 100k: ~42.86s wall clock
- 700k: ~210.65s wall clock (3m 30.65s)

All runs completed with exit code 0.

## Interpretation

- NVD-related work can remain bounded when unique-CVE cardinality is constrained
- At very large scales, bottlenecks shift toward scoring, ranking, and serialization
- Output and I/O overhead become proportionally more significant as payloads grow

## Projection guidance

Based on observed behavior and current architecture:

- 100k findings: practical for single-machine workflows
- 1M findings: feasible but likely dominated by scoring and output costs

Use this as directional guidance, not a guaranteed SLA.

## Benchmarking best practices

- Benchmark with production-like CVE diversity
- Isolate cold-cache vs warm-cache runs
- Record phase timing, not only total time
- Keep configuration snapshots for reproducibility
