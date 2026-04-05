# Contributing to VulnParse-Pin

Thanks for contributing to VulnParse-Pin.

This project prioritizes:

- Secure-by-default behavior
- Deterministic, explainable outputs
- Backward-compatible evolution where practical
- Explicit contracts for parser, pass, and schema behavior

## Development Setup

1. Fork and clone the repository.
2. Create and activate a virtual environment.
3. Install editable package and dev dependencies.

```bash
python -m venv .venv
.venv/Scripts/activate
pip install -e .[dev]
```

## Run Core Checks

```bash
pytest tests/ -v
```

For targeted runs:

```bash
pytest tests/test_pass_contracts.py -v
pytest tests/test_parser_smoke.py -v
pytest tests/test_runmanifest.py -v
```

## Contribution Scope and Quality Bar

### Documentation changes

- Keep command examples aligned with current CLI behavior.
- Link related docs when introducing new concepts.
- If behavior changes, update docs in the same PR.

### Parser and normalization changes

- Preserve parser detection confidence behavior and evidence reporting.
- Keep fallback behavior deterministic.
- Add regression tests for any new edge case input.

### Pass pipeline changes

- Preserve pass contracts and expected `derived` output structure.
- Keep deterministic ordering assumptions intact.
- Add or update pass contract tests.

### Enrichment and feed handling changes

- Maintain clear online/offline behavior.
- Avoid silent fallback changes without docs and changelog updates.
- Preserve existing safety defaults unless explicitly versioned.

## Pull Request Checklist

1. Tests pass locally for changed areas.
2. Any user-visible behavior changes are documented.
3. Changelog entry is added or updated when appropriate.
4. New CLI flags or semantics are reflected in usage/migration docs.
5. Output schema-impacting changes include schema/test updates.
6. Security-sensitive changes include rationale in PR description.
7. Architecture-impacting changes include ADR reference and checklist completion.

## Commit and Review Guidance

- Keep PRs focused and reviewable.
- Prefer incremental changes over broad rewrites.
- Include before/after examples for behavior changes.
- Include sample command and expected output snippets when relevant.

## Reporting Bugs and Proposing Features

Please include:

1. VulnParse-Pin version.
2. Exact command used (redact sensitive info).
3. Input format and approximate size.
4. Relevant logs and error text.
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
