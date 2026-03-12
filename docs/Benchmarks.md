# Benchmarks

This document summarizes observed performance behavior for VulnParse-Pin v1.0.0rc.1 under high-volume test scenarios.

## Test environment

- Date baseline: March 2026
- Platform: Windows Server 2025
- Python: 3.14
- CPU profile: 8-core class system

## Nessus scale benchmark (NVD optimization focus)

### Dataset profile

- Baseline file: `nessus_expanded_200.xml`
- Baseline findings: 400
- Large-scale file: `nessus_benchmark_50k.xml`
- Large-scale findings: 50,000
- Unique CVEs across both: 338

### Runtime comparison

- Baseline runtime: ~20s
- 50k runtime: ~194.59s
- Input growth: `125x`
- Runtime growth: `9.73x`

Result: sublinear scaling and significant throughput gains at scale.

### Throughput signal

- Baseline: ~20 findings/sec
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
