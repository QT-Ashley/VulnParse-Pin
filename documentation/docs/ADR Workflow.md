# ADR Workflow

This document defines the lightweight Architecture Decision Record (ADR) process used for architecture-impacting changes.

## Purpose

Use ADRs to make major decisions explicit, reviewable, and historically traceable.

An ADR is required when a change alters one or more core seams:

1. Parser detection/selection behavior
2. Pass pipeline contracts or pass ordering/dependencies
3. Enrichment orchestration and source contract behavior
4. Output schema compatibility or long-term artifact semantics
5. Runtime policy or security default behavior

## ADR Lifecycle

1. Draft: create a new ADR from template before implementation starts.
2. Review: link ADR in PR and request maintainer review.
3. Accept or reject: maintainers set final status.
4. Implement: code and tests must align with accepted ADR.
5. Supersede (if needed): create a new ADR and mark older one superseded.

## File Location and Naming

Store ADRs in `documentation/docs/adr/` using zero-padded numbering:

- `ADR-0001-title.md`
- `ADR-0002-title.md`

Do not renumber existing ADRs.

## Required ADR Sections

1. Status (`Proposed`, `Accepted`, `Rejected`, `Superseded`)
2. Date
3. Context and problem statement
4. Decision
5. Consequences (positive and negative)
6. Compatibility impact
7. Test and rollout plan
8. Rollback strategy

Use the template at [ADR Template](adr/ADR-Template.md).

## PR Requirements for ADR-Scoped Changes

For architecture-impacting PRs:

1. ADR link is present in PR description.
2. ADR status is `Accepted` before merge.
3. Contract tests and docs updates are included.
4. Changelog notes reference the ADR when user-visible behavior changes.

## When ADR Is Not Required

ADR is generally not required for:

1. Pure bug fixes that do not alter architecture or contracts.
2. Internal refactors preserving behavior and contract semantics.
3. Documentation-only updates without behavior changes.

When uncertain, default to opening a brief ADR.

## Related Docs

- [Architecture Review Checklist](Architecture%20Review%20Checklist.md)
- [Deprecation and Versioning Policy](Deprecation%20and%20Versioning%20Policy.md)
<<<<<<< HEAD
- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
=======
- [Contributing](../../CONTRIBUTING.md)
>>>>>>> main
