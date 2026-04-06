# Testing Guide

This guide documents test workflows for contributors and maintainers.

## Prerequisites

1. Python 3.11+ environment
2. Editable install with dev dependencies

```bash
python -m venv .venv
.venv/Scripts/activate
pip install -e .[dev]
```

## Test Suite Layout

Main test folders and focus areas:

- `tests/test_parser_*.py`: parser behavior and fallback paths
- `tests/test_pass_contracts.py`: pass interface and contract stability
- `tests/test_parallel_scoring.py`: process-pool and scoring behavior
- `tests/test_topn_optimization.py`: TopN optimization and ranking invariants
- `tests/test_scanresult_schema_validation.py`: schema contract checks
- `tests/test_runmanifest.py`: runmanifest integrity and verification
- `tests/regression_testing/`: real/synthetic sample inputs for regression coverage

## Recommended Test Commands

### Full suite

```bash
pytest tests/ -v
```

### Fast contract-focused subset

```bash
pytest tests/test_pass_contracts.py tests/test_parser_smoke.py tests/test_scanresult_schema_validation.py -v
```

### RunManifest and auditability checks

```bash
pytest tests/test_runmanifest.py -v
```

### Parser fallback edge-case checks

```bash
pytest tests/test_openvas_parser_fallbacks.py tests/test_openvas_port_protocol_fallbacks.py tests/test_openvas_title_description_fallbacks.py -v
```

## Large-Input and Performance Validation

For performance-sensitive changes, include at least one scaled or stress validation run using available generators under `tests/`.

Examples:

- `tests/generate_5k_nessus.py`
- `tests/generate_50k_nessus.py`
- `tests/generate_700k_nessus.py`

When executing large workloads, use reduced logging verbosity and document hardware context with results.

## Test Expectations for Changes

### Parser changes

1. Keep detection confidence and parser-selection behavior consistent.
2. Add/update fallback tests for affected fields.
3. Validate no regression on representative real-world samples.

### Pass and scoring changes

1. Preserve deterministic ranking behavior.
2. Keep pass output contracts stable, or version/document changes.
3. Confirm parallel and sequential paths both remain valid.

### Schema or output changes

1. Update schema artifacts where needed.
2. Update schema validation tests.
3. Update usage/output documentation in same PR.

### RunManifest changes

1. Keep integrity verification behavior stable.
2. Validate schema and hash-chain checks.
3. Test compact and expanded mode implications.

## PR Verification Checklist

1. Run focused tests for changed modules.
2. Run full suite before merge for non-trivial changes.
3. Include exact commands run in PR description.
4. Include key pass/fail evidence when fixing regressions.

## Related Docs

<<<<<<< HEAD
- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
=======
- [Contributing](../../CONTRIBUTING.md)
>>>>>>> main
- [Usage](Usage.md)
- [RunManifest Overview](RunManifest.md)
- [Troubleshooting](Troubleshooting.md)