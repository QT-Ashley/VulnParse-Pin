# Deprecation and Versioning Policy

This policy defines how VulnParse-Pin (`vpp`) introduces, warns on, deprecates, and removes CLI options, parsers, pass contracts, and output schemas in a predictable, compatibility-safe way.

## Scope

Applies to:

1. CLI subcommands, flags, and exit code semantics
2. Parser selection behavior and parser lifecycle states (`PARSER_SPECS`)
3. Pass output contracts under `derived` (`Scoring@3.0`, `ACI@2.0`, `Triage@2.0`, `TopN@2.0`, `Summary@2.0`)
4. DuckDB workspace schema (`.vpp.db`), JSON/CSV/Dossier/Roadmap artifacts, and `RunManifest` v2 contracts
5. Runtime security and filesystem defaults (`PermFileHandler`, cache integrity, CSV sanitization)

## Versioning & Licensing Model

Project releases follow semantic versioning (`MAJOR.MINOR.PATCH`):

1. **Patch (`x.y.Z`)**: bug fixes, security hardening, and non-breaking improvements
2. **Minor (`x.Y.z`)**: additive features, new parsers/enrichers, and policy-safe behavior additions
3. **Major (`X.y.z`)**: breaking contract shifts, legacy shim removals, or major pipeline/license transitions

License boundary:

- **v2.0.0 and later**: Licensed under **Apache License, Version 2.0** (`Apache-2.0`).
- **v1.0.0 – v1.2.2**: Historical releases remain under `AGPL-3.0-or-later`.

## Deprecation Cadence

Every planned deprecation follows three phases:

1. **Announce**: Document the deprecation in `CHANGELOG.md`, [Upgrade and Migration](Upgrade%20and%20Migration.md), and this policy.
2. **Warn**: Emit clear runtime warnings (visible at standard `stderr`/`INFO` levels) identifying what is deprecated and its replacement.
3. **Remove**: Remove no earlier than the stated version window.

Default minimum deprecation window:

1. At least **one minor release** between first runtime deprecation warning and removal.
2. Breaking removals target a **major release** unless a security vulnerability or safety hazard requires accelerated removal.

## Runtime Warning Requirements

Deprecated compatibility paths must:

1. Identify the deprecated flag, format, or config structure.
2. State the exact replacement command, flag, or schema version.
3. Surface at normal operator log levels (or `stderr` for CLI compatibility shims).

## Current Lifecycle Matrix (`v2.0.0`)

### Parser Lifecycle (`PARSER_SPECS`)

| Parser Name | Formats | Status | Notes |
| --- | --- | --- | --- |
| `nessus-xml` | `.xml`, `.nessus` | `stable` | Streaming `lxml.etree.iterparse` |
| `openvas-xml` | `.xml` | `stable` | Streaming `lxml.etree.iterparse` |
| `qualys-xml` | `.xml` | `stable` | Streaming `lxml.etree.iterparse` |
| `nmap-xml` | `.xml` | `stable` | Streaming `lxml.etree.iterparse` |
| `sarif-2.1.0` | `.sarif`, `.json` | `stable` | Streaming SARIF (`Trivy`, `Grype`, `Semgrep`, `CodeQL`, etc.) |
| `nuclei-jsonl` | `.jsonl`, `.json` | `stable` | Streaming Nuclei JSONL (`active_dast`) |
| `nessus-csv` | `.csv` | `stable` | Single-pass header-indexed CSV |
| `qualys-csv` | `.csv` | `stable` | Single-pass header-indexed CSV |
| `openvas-json` | `.json` | `experimental` / `deprecated` | Retained for compatibility; earliest removal target `v2.1.0+` / `v3.0.0` |
| `nessus-json` | `.json`, `.nessus` | `experimental` / `deprecated` | Retained for compatibility; earliest removal target `v2.1.0+` / `v3.0.0` |

### Legacy CLI Compatibility Shim (`v2.0.x`)

In `v2.0.0`, top-level legacy v1 invocations are transparently rewritten by `_preprocess_legacy_argv()` with a one-line `[DEPRECATED]` notice on `stderr`:

- `vpp -f <file>` / `vpp --file <file>` → `vpp scan ...`
- `vpp --demo` → `vpp demo --no-ui ...` (legacy OpenVAS + Nmap demo compatibility mode)
- `vpp --verify-runmanifest <path>` → `vpp verify <path>`
- `vpp --debug-path-policy` → `vpp scan --debug-path-policy`

**Deprecation window**: These top-level legacy shims remain supported throughout `v2.0.x` and will not be removed earlier than `v2.1.0` (targeted for `v3.0.0` removal unless otherwise announced in `CHANGELOG.md`). Note that `--file` / `-f` and `--nmap-ctx` also remain accepted inside `vpp scan` as compatibility aliases.

### Legacy Configs & Pass Contracts

- **`config.yaml` / `scoring.json` `version: v1`**: Loaded with structured migration warnings during `v2.0.x`; `version: v2` is standard for new deployments.
- **Canonical v1 IDs (`aid_v1_` / `fid_v1_`)**: Preserved for in-memory `ScanResult` compatibility; DuckDB `.vpp.db` and v2 passes emit `aid_v2_` / `fid_v2_`.
- **Pass Identifiers**: v2.0 DuckDB runs emit `Scoring@3.0`, `ACI@2.0`, `Triage@2.0`, `TopN@2.0`, and `Summary@2.0`. Legacy in-memory `ScanResult` pass paths retain `Scoring@2.0`, `ACI@1.0`, `TopN@1.0`, and `Summary@1.0` compatibility.

## Compatibility Contract Rules

1. Stable parser and v2 pass contracts remain backward-compatible within minor `v2.x` releases.
2. New output fields in JSON exports, DuckDB views, and `RunManifest` are additive where possible.
3. Removed or renamed flags, tables, or output fields require explicit migration notes in [Upgrade and Migration](Upgrade%20and%20Migration.md) and `CHANGELOG.md`.
4. CLI removals must include side-by-side before/after migration examples.

## Governance & Documentation Requirements

1. Architecture-impacting deprecations require an ADR ([ADR Workflow](ADR%20Workflow.md)) and review against the [Architecture Review Checklist](Architecture%20Review%20Checklist.md).
2. Emergency security or safety issues (for example XXE, symlink traversal, or cache tampering) may accelerate removal; rationale and immediate mitigations are documented in `CHANGELOG.md` and `SECURITY.md`.

## Related Docs

- [Upgrade and Migration](Upgrade%20and%20Migration.md)
- [Usage](Usage.md)
- [Workflow Examples](Workflow%20Examples.md)
- [Deployment Options](Deployment%20Options.md)
- [ADR Workflow](ADR%20Workflow.md)
- [Architecture Review Checklist](Architecture%20Review%20Checklist.md)
- [Roadmap](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/ROADMAP.md)
