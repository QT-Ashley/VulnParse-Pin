# ADR Workflow

This document defines the Architecture Decision Record (ADR) process used for architecture-impacting changes in VulnParse-Pin (`Apache-2.0`).

## Purpose

Use ADRs to make major architectural and security boundary decisions explicit, reviewable, and historically traceable.

An ADR is required when a change alters one or more core seams:

1. Parser detection, streaming reader, or XML/archive security behavior
2. DuckDB `.vpp.db` schema (`schema.sql`), canonical identity (`aid_v2_`/`fid_v2_`), or cross-scanner deduplication
3. Pass pipeline contracts (`run_v2_duckdb_pipeline`), scoring/triage profiles (`Scoring@3.0`, `Triage@2.0`), or `DiffEngine` gate semantics
4. Enrichment orchestration, HMAC cache integrity, or CVSS provenance precedence
5. Output schemas (`RunManifest`, `assets.schema.json`, `decisions.schema.json`, Dossier/Roadmap contracts)
6. Runtime security defaults (PFH, `_UMASK_LOCK`, read-only `vpp verify`, clean-room `Apache-2.0` dependency boundaries)

## ADR Lifecycle

1. **Draft:** Create a new ADR from [ADR Template](adr/ADR-Template.md) before implementation starts.
2. **Review:** Link the ADR in the PR alongside the [Architecture Review Checklist](Architecture%20Review%20Checklist.md).
3. **Accept or reject:** Maintainers record the final status.
4. **Implement:** Code, schemas, and tests must align with the accepted ADR.
5. **Supersede or annotate:** Never overwrite historical decisions silently; either create a superseding ADR or add a dated `v2.x Status` note referencing subsequent evolution.

## File Location and Naming

Store ADRs in `documentation/docs/adr/` using zero-padded numbering:

- `ADR-0001-config-seam.md`
- `ADR-0002-enrichment-seam.md`

Do not renumber existing ADRs.

## Required ADR Sections

1. Status (`Proposed`, `Accepted`, `Rejected`, `Superseded`)
2. Date
3. Context and problem statement
4. Decision
5. Alternatives considered
6. Consequences (positive and negative)
7. Compatibility & licensing impact (including clean-room `Apache-2.0` dependency compliance)
8. Test and rollout plan
9. Rollback strategy

Use the template at [ADR Template](adr/ADR-Template.md).

## When ADR Is Not Required

- Pure bug fixes that do not alter architecture, schema, or security contracts
- Internal refactors preserving behavior and contract semantics
- Documentation-only updates without behavior changes

When uncertain, default to opening a brief ADR.

## Related Docs

- [Architecture Review Checklist](Architecture%20Review%20Checklist.md)
- [Deprecation and Versioning Policy](Deprecation%20and%20Versioning%20Policy.md)
- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
