# Contributing to VulnParse-Pin

Thanks for contributing to VulnParse-Pin (`vpp`).

Starting with **v2.0.0**, VulnParse-Pin is licensed under the **Apache License, Version 2.0** (`Apache-2.0`). All new contributions are accepted under `Apache-2.0` (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)). Historical `v1.0.0–v1.2.2` releases remain under `AGPL-3.0-or-later`.

This project prioritizes:

- Secure-by-default behavior (fail-closed path/symlink checks, XXE-hardened streaming XML, HMAC/SHA-256 verified intel caches, CSV formula sanitization)
- Deterministic, explainable outputs (`Scoring@3.0`, `ACI@2.0`, `Triage@2.0`, `TopN@2.0`, `Summary@2.0`, `RunManifest` v2)
- Explicit contracts for parser, pass, storage, and schema behavior
- Zero copyleft runtime dependencies (`Apache-2.0` clean-room runtime stack)

## Development Setup

1. Fork and clone the repository.
2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   # Linux / macOS:
   source .venv/bin/activate
   # Windows PowerShell:
   # .venv\Scripts\Activate.ps1
   # Windows cmd.exe:
   # .venv\Scripts\activate.bat
   ```

3. Install the editable package with dev, TUI, and SBOM extras:

   ```bash
   pip install -e ".[dev,ui,sbom]"
   ```

   For minimal headless CI/core development without Textual UI or SBOM tooling:

   ```bash
   pip install -e ".[dev]"
   ```

## License & SPDX Header Requirements

All new or modified Python source, test, and benchmark files under `src/`, `tests/`, and `benchmarks/` must carry the Apache-2.0 SPDX header at the top of the file:

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley
```

Do **not** introduce copyleft (`GPL`, `AGPL`, `LGPL`) Python dependencies into `pyproject.toml`. CI verifies `Apache-2.0` license and SPDX compliance on every push and pull request.

## Run Core Checks

Run the full test suite:

```bash
pytest tests/ -v
```

Targeted v2.0 suites:

```bash
pytest tests/test_cli_v2.py tests/test_storage_duckdb.py tests/test_scoring_v2.py tests/test_bod_26_04.py -v
pytest tests/test_diff_engine.py tests/test_reporting_v2.py tests/test_runmanifest.py tests/test_tui_pilot.py -v
pytest tests/test_xxe_hardening.py tests/test_streaming_parsers.py tests/test_intel_v2.py tests/test_demo_offline.py -v
pytest tests/test_iter2_cross_component.py -v
```

### Inference & ACI Reliability Regression Guards

When modifying finding-text inference rules, conflict tokens, `ACI@2.0` rules, or source-weight knobs, run both benchmark guard suites before opening a PR:

```bash
pytest tests/test_topn_inference_reliability_benchmark.py tests/test_aci_phrase_benchmark.py -v
```

These suites assert positive/negative phrase separation and capability confidence bounds for `aci_pass.py`, `topn_pass.py`, and packaged `tn_triage.json` defaults.

## Contribution Scope and Quality Bar

### Documentation changes

- Keep command examples aligned with the v2.0 subcommand CLI (`vpp scan`, `vpp demo`, `vpp diff`, `vpp ui`, `vpp export`, `vpp verify`, `vpp defer`, `vpp intel`) and `src/vulnparse_pin/cli/args.py`.
- Link related docs when introducing new concepts.
- If behavior changes, update docs and `CHANGELOG.md` in the same PR.

### Parser and normalization changes

- Implement `iter_batches(batch_size=...)` yielding `NormalizedFindingRecord` batches while maintaining single-pass `parse() -> ScanResult` compatibility.
- Use `lxml` via `src/vulnparse_pin/parsers/_xml_security.py` for XML (never `defusedxml` or `xml.etree` on untrusted XML) and streaming parsers for JSON/SARIF/JSONL.
- Preserve parser detection confidence behavior, `--allow-large` (up to 50 GiB) enforcement, and evidence reporting.
- Add regression tests for any new edge-case input.

### DuckDB storage & pass pipeline changes

- Preserve the 12-table DuckDB schema contract (`src/vulnparse_pin/storage/schema.sql`), canonical v2 identity (`aid_v2_` / `fid_v2_`), and deterministic ordering.
- Keep `Scoring@3.0`, `ACI@2.0`, `Triage@2.0` (`default` and `bod-26-04`), `TopN@2.0`, and `Summary@2.0` pass contracts and `derived` output structure intact.
- Add or update pass and storage contract tests.

### Enrichment and feed handling changes

- Maintain strict `--offline` isolation (never make network calls or allow HTTP/HTTPS URLs when `--offline` is set).
- Preserve `0o600` POSIX permissions, symlink rejection, and HMAC/SHA-256 verification on local SQLite/feed caches.
- Document new config keys or environment variables in `Configs.md`, `Installation.md`, and `CHANGELOG.md`.

## Pull Request Checklist

1. Tests pass locally for changed areas (and full suite for cross-cutting changes).
2. New Python files under `src/`, `tests/`, and `benchmarks/` include `# SPDX-License-Identifier: Apache-2.0`.
3. Any user-visible behavior, CLI flag, or schema changes are documented and reflected in `CHANGELOG.md`.
4. Output schema-impacting changes include JSON Schema (`src/vulnparse_pin/core/schemas/`) and validation test updates.
5. Security-sensitive changes include rationale and threat-model considerations in the PR description.
6. Architecture-impacting changes include an ADR reference and checklist completion.

## Commit and Review Guidance

- Keep PRs focused and reviewable.
- Prefer incremental changes over broad rewrites.
- Include before/after examples and exact verification commands run in the PR description.

## Reporting Bugs and Proposing Features

Please include:

1. VulnParse-Pin version (`vpp --version`).
2. Exact command used (redact sensitive paths/tokens).
3. Input format and approximate finding count.
4. Relevant logs (`--log-level INFO` or `DEBUG`) and error text.
5. Expected vs actual behavior.

## Related Docs

- [Testing Guide](documentation/docs/Testing%20Guide.md)
- [Extension Playbooks](documentation/docs/Extension%20Playbooks.md)
- [ADR Workflow](documentation/docs/ADR%20Workflow.md)
- [Architecture Review Checklist](documentation/docs/Architecture%20Review%20Checklist.md)
- [Deprecation and Versioning Policy](documentation/docs/Deprecation%20and%20Versioning%20Policy.md)
- [Usage](documentation/docs/Usage.md)
- [Upgrade and Migration](documentation/docs/Upgrade%20and%20Migration.md)
- [Troubleshooting](documentation/docs/Troubleshooting.md)
- [Workflow Examples](documentation/docs/Workflow%20Examples.md)
- [Deployment Options](documentation/docs/Deployment%20Options.md)
