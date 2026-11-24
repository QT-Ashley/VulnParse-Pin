# Architecture Review Checklist

Use this checklist for PRs that change streaming parsers, DuckDB schema/repositories, pass orchestration (`ACI@2.0`, `Scoring@3.0`, `Triage@2.0`, `TopN@2.0`, `Summary@2.0`), `DiffEngine`, enrichment caches, reporting templates, runtime security defaults, or dependencies.

## Trigger Criteria

Run this checklist when any of the following is true:

1. Parser detection, streaming readers, or XML/SARIF/CSV security guards change
2. DuckDB `.vpp.db` schema (`schema.sql`) or repository queries (`repositories.py`) change
3. Pass order, dependency declarations, `Scoring@3.0` / `Triage@2.0` / `DiffEngine` semantics change
4. Enrichment cache signing, HTTPS streaming, or CVSS provenance precedence changes
5. Security-sensitive defaults (PFH, `_UMASK_LOCK`, read-only `vpp verify`/`vpp intel status`, CSV sanitization, Jinja2 escaping) change
6. Runtime or optional dependencies are added or upgraded in `pyproject.toml`

## Checklist

### 1. Clean-Room Licensing & Dependency Gate (`Apache-2.0`)

- [ ] Zero `AGPL`, `GPL`, or `LGPL` runtime dependencies introduced (e.g., no LGPL `cvss` library; keep stdlib clean-room `cvss_utils.py`).
- [ ] New files include `# SPDX-License-Identifier: Apache-2.0` (or `-- SPDX-License-Identifier: Apache-2.0` for SQL).
- [ ] Hardened `lxml` (`_xml_security.py`) is used for XML; `defusedxml` is never reintroduced.

### 2. Streaming, DuckDB & Contract Integrity

- [ ] Parsers stream in bounded memory (`iter_batches`) without whole-file `json.load()` or unpruned DOM trees.
- [ ] All DuckDB SQL queries use `?` parameters and deterministic `ORDER BY` tie-breakers.
- [ ] `.vpp.db`, `.wal`, and `.tmp` paths are validated via `_validate_duckdb_paths()` and created `0o600` under `_UMASK_LOCK`.
- [ ] `Triage@2.0`, `DiffEngine`, and `RunManifest` / `ledger_events` contracts remain deterministic and schema-valid.

### 3. Security & Fail-Closed Defaults

- [ ] `VP_FEED_CACHE_HMAC_KEY` and `VP_SQLITE_HMAC_KEY` reject SHA-256 downgrades and never auto-resign unsigned/tampered caches.
- [ ] Remote HTTPS downloads use `allow_redirects=False` with per-hop HTTPS validation and byte caps.
- [ ] `vpp verify` (`_build_verify_pfh`) and `vpp intel status` remain strictly read-only by default (zero `$HOME`/`XDG_*` writes).
- [ ] HTML/Markdown templates enforce `autoescape` / `md_escape`, and CSV exports sanitize formulas by default unless `--no-csv-sanitize --confirm-unsafe-csv` are both given.

### 4. Test Coverage & Verification

- [ ] Streaming parser, XXE/zip-traversal, DuckDB repository, pass contract, and cross-component CLI tests are added/updated.
- [ ] `RunManifest` digest and `vpp verify` tests pass when pass outputs or reporting bundles change.
- [ ] Documentation (`Usage.md`, `Configs.md`, `Architecture.md`, ADRs, `CHANGELOG.md`) reflects user-visible or architectural changes.

## Completion Record (copy into PR)

```markdown
Architecture Review Checklist
- Trigger: <why checklist applies>
- ADR: <link or N/A>
- Apache-2.0 / Clean-Room Deps Verified: <yes/no>
- Compatibility Impact: <none|additive|breaking>
- Tests Updated: <list>
- Docs Updated: <list>
- Rollback Plan: <summary>
```

## Related Docs

- [ADR Workflow](ADR%20Workflow.md)
- [Deprecation and Versioning Policy](Deprecation%20and%20Versioning%20Policy.md)
- [Security Features](Security%20Features.md)
- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
