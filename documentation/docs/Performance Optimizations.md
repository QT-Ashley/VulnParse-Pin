# Performance Optimizations

VulnParse-Pin is optimized for both small and high-volume workloads by switching execution strategy based on workload size and operation type.

## Performance philosophy

- Minimize overhead on small scans
- Parallelize CPU-heavy paths for large scans
- Keep expensive lookups cache-friendly
- Preserve deterministic results while scaling

## Scoring pass strategy

`ScoringPass` uses three paths:

- **Sequential:** small workloads (low overhead)
- **Thread pool:** medium workloads
- **Process pool:** large workloads (typically 20k+ findings)

Additional optimizations include:

- Plugin attribute pre-caching
- Signature memoization for repeated scoring signatures
- Safe fallback from process pool to thread pool when needed

## TopN pass strategy

`TopNPass` uses process-pool execution for large finding sets and merges partial worker results deterministically.

Important implementation details:

- Chunked worker dispatch for asset/finding partitions
- Stable tie-breakers in heaps (entry counters)
- Controlled global-top merge behavior
- `PostEnrichmentIndex` provides O(1) finding and asset observation lookups, avoiding repeated linear scans for large datasets

## NVD optimization stack

NVD enrichment performance benefits from multiple optimizations:

- Streaming-friendly feed handling
- CVE-target filtering (skip irrelevant records)
- Early termination after required CVEs are found
- Multi-thread feed parsing where useful
- Optional SQLite index for reuse across runs

## Serialization and output efficiency

Large JSON output paths use streaming-friendly behavior to avoid unnecessary memory blowups on oversized payloads.

CSV export is sanitized by default and designed for operational safety, with acceptable tradeoffs for throughput.

## Tuning guidance

For larger datasets:

- Keep process-pool thresholds near proven defaults unless benchmarked
- Avoid adding non-serializable state to worker payloads
- Keep enrichment caches warm in repeated workflows
- Benchmark with realistic CVE cardinality, not only finding count

## Profiling and benchmark helpers

Useful files:

- `profile_runner.py`
- `debug_topn.py`
- `tests/generate_5k_nessus.py`
- `tests/generate_50k_nessus.py`
- `tests/generate_250k_nessus.py`
- `tests/generate_700k_nessus.py`
- `tests/generate_massive_nessus.py`
- `tests/generate_openvas_scaled.py`

## Scaling caveats

- Throughput is affected by CVE uniqueness and enrichment cardinality
- Export and serialization become dominant at very large scales
- At million-finding scale, scoring, summary aggregation, and output phases typically dominate total runtime
- The 700k OpenVAS benchmark has been observed at ~210s wall clock (full pipeline including SummaryPass)
