# Testing Guide

This guide documents test workflows, v2.0.0 test suites, regression guards, and scale benchmarking for contributors and maintainers.

## Prerequisites

1. Python 3.11+ environment
2. Editable install with dev and optional TUI (`[ui]`) dependencies:

```bash
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
# Windows cmd.exe:
# .venv\Scripts\activate.bat

pip install -e ".[dev,ui]"
```

> [!NOTE]
> `test_tui_pilot.py` and interactive `vpp ui` checks require the `[ui]` extra (`textual>=2.1.0`). Headless environments can run core tests without `[ui]` if those UI tests are excluded or skipped, while full CI parity uses `.[dev,ui,sbom]`.

## Test Suite Layout (`v2.0.0`)

### Core v2.0 DuckDB, Pipeline, CLI & TUI Suites

- `tests/test_storage_duckdb.py`: 12-table DuckDB `.vpp.db` schema, `0o600` POSIX permissions, symlink rejection, appender ingestion, deduplication, and parameterized UI/summary queries
- `tests/test_assets_context.py`: `AssetContextMatcher` (5-tier IP/FQDN/URI/CIDR/glob matching & shadow assets) and `DecisionsRegistry` predicates + comment-preserving `upsert_decision`
- `tests/test_bod_26_04.py`: `--profile bod-26-04` vs `default` SSVC actions (`Act`/`Attend`/`Track*`/`Track`), SLA buckets, and `static_sast` P1-cap guardrail
- `tests/test_scoring_v2.py`: `Scoring@3.0` dual-track (`cve_threat` + `exposure_weakness`), EPSS v5 monotonic piecewise breakpoints, Signal Reliability weighting, and `score_trace`
- `tests/test_aci_v2.py`: `ACI@2.0` DuckDB signal enrichment across `finding_cves`, `finding_evidence`, and non-CVE Track B findings
- `tests/test_diff_engine.py`: `DiffEngine` scan-over-scan deltas, stale-assumption deferral invalidations, and `evaluate_fail_gate` exit code `2`
- `tests/test_reporting_v2.py`: Decision Defense Dossiers (HTML/MD), Executive Roadmaps, Diff PR comments, streaming DuckDB CSV/JSON exports, and `RunManifest` digest sealing
- `tests/test_cli_v2.py`: Subcommand CLI (`scan`, `demo`, `diff`, `ui`, `export`, `verify`, `defer`, `intel`), read-only `vpp verify`, exit codes, and legacy compatibility shims
- `tests/test_tui_pilot.py`: Textual `VppApp` pilot tests (tier/track/KEV/shadow filters, search, pagination, diff tab, dossier export, and deferral modal)
- `tests/test_demo_offline.py`: 100% offline `vpp demo` end-to-end execution and bundled multi-scanner fixture validation

### Parser, Security, Intel & Integration Suites

- `tests/test_xxe_hardening.py`: Hardened streaming `lxml.etree.iterparse` XML guards blocking external DTDs, XXE, and Billion Laughs while permitting benign `<!DOCTYPE nmaprun>` / `<!DOCTYPE SCAN>`
- `tests/test_streaming_parsers.py`: Bounded 64 KB sniffing, UTF-8 BOM handling, `iter_batches()`, chunked SARIF 2.1.0, Nuclei JSONL, and `--allow-large` (up to 50 GiB)
- `tests/test_intel_v2.py`: CVSS v4.0/v3.x/v2.0 provenance precedence, EPSS v5 / KEV SQLite caches, GHSA package index, OSV archive hardening, and `vpp intel status`/`sync`
- `tests/test_iter1_intel_sec.py`, `tests/test_iter1_math_diff.py`, `tests/test_iter1_parsers_cli.py`: Iteration 1 security, math/diff, and parser/CLI hardening regression tests
- `tests/test_iter2_cross_component.py`: Iteration 2 cross-component security, CVSS provenance, TUI/Dossier, and `bod-26-04` contract tests

### Legacy & Contract Suites

- `tests/test_parser_*.py`, `tests/test_xml_parsers_realworld.py`: Parser behavior, fallback paths, and real-world XML fixture checks
- `tests/test_pass_contracts.py`: Pass interface, dependency DAG, and backward-compatibility checks
- `tests/test_cvss_utils.py`: Clean-room Apache-2.0 CVSS v2.0 / v3.x / v4.0 calculator and `resolve_effective_cvss_fields`
- `tests/test_runmanifest.py`: `RunManifest` v2 schema, SHA-256 hash-chained decision ledger, and `vpp verify` enforcement
- `tests/test_security_hardening.py`, `tests/test_pfh.py`, `tests/test_csv_sanitization.py`: `PermFileHandler` path policy, CSV formula sanitization, and symlink/root confinement
- `tests/test_aci_phrase_benchmark.py`, `tests/test_topn_inference_reliability_benchmark.py`: Phrase-quality and inference reliability guards

## Recommended Test Commands

### Full suite

```bash
pytest tests/ -v
```

### Targeted v2.0 pipeline & storage verification

```bash
pytest tests/test_storage_duckdb.py tests/test_assets_context.py tests/test_scoring_v2.py tests/test_aci_v2.py tests/test_bod_26_04.py -v
```

### CLI, Diff, Reporting, RunManifest & TUI verification

```bash
pytest tests/test_cli_v2.py tests/test_diff_engine.py tests/test_reporting_v2.py tests/test_runmanifest.py tests/test_tui_pilot.py tests/test_demo_offline.py -v
```

### Security, streaming parsers & threat-intel verification

```bash
pytest tests/test_xxe_hardening.py tests/test_streaming_parsers.py tests/test_intel_v2.py tests/test_cvss_utils.py tests/test_security_hardening.py -v
```

### Iteration 1 & 2 cross-component suites

```bash
pytest tests/test_iter1_intel_sec.py tests/test_iter1_math_diff.py tests/test_iter1_parsers_cli.py tests/test_iter2_cross_component.py -v
```

## Baseline Fixture & Invariant Notes

- **`tests/test_aci_phrase_benchmark.py`**: Exercises legacy in-memory `AttackCapabilityInferencePass` (`ACI@1.0` over `ScoringPass`) against `tests/benchmarks/aci_phrase_benchmark.json`, asserting expected/rejected capability sets and `min_confidence` / `max_confidence` bounds. Keep this green whenever tuning `tn_triage.json` or ACI phrase rules.
- **`TestOpenVASXMLExpanded` (`tests/test_xml_parsers_realworld.py`)**: Parametrized regression tests (`openvas_expanded_3a_150.json` and `openvas_expanded_4a_200.json` under `tests/regression_testing/openvas_json/`) verifying legacy OpenVAS JSON expanded fixtures parse cleanly alongside streaming XML coverage. Ensure regression fixture paths remain intact when running full-suite checks from the repository root.

## Scale & Performance Validation (`benchmarks/bench_scale.py`)

Use `benchmarks/bench_scale.py` to benchmark end-to-end streaming ingestion, matched-CVE snapshot hydration, the DuckDB pass DAG, and paged UI/summary queries in isolated subprocesses:

```bash
# Quick developer smoke benchmark (10,000 findings)
python benchmarks/bench_scale.py --findings 10000

# Full 500k-700k scale benchmark with JSON output
python benchmarks/bench_scale.py --findings 500000 --findings 700000 --json-out bench_v2_results.json
```

See [Benchmarks](Benchmarks.md) and [Performance Optimizations](Performance%20Optimizations.md) for measured `v2.0.0` reference numbers and hardware context.

## Test Expectations for Changes

1. **Parser changes**: Preserve `iter_batches()` streaming, XXE/prolog safety, `--allow-large` (up to 50 GiB), and ingestion confidence/evidence fidelity.
2. **Scoring & triage changes**: Preserve deterministic `Scoring@3.0`, `ACI@2.0`, `Triage@2.0` (`default` and `bod-26-04`), and `DiffEngine` stale-assumption contracts.
3. **Schema or output changes**: Update schemas under `src/vulnparse_pin/core/schemas/`, `storage/schema.sql`, and validation tests together.
4. **RunManifest & CLI changes**: Validate read-only `vpp verify`, exit codes (`0`, `1`, `2`), and `RunManifest` digest/ledger verification.

## PR Verification Checklist

1. Run focused tests for changed modules (and full `pytest tests/ -v` for non-trivial changes).
2. Confirm `test_aci_phrase_benchmark.py` and `test_topn_inference_reliability_benchmark.py` pass when touching scoring/ACI/triage rules.
3. Include exact commands and observed pass/fail counts in your PR description.

## Related Docs

- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
- [Usage](Usage.md)
- [Benchmarks](Benchmarks.md)
- [RunManifest Overview](RunManifest.md)
- [Troubleshooting](Troubleshooting.md)
