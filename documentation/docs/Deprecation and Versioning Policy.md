# Deprecation and Versioning Policy

This policy defines how VulnParse-Pin introduces, warns, and removes behavior in a compatibility-safe way.

## Scope

Applies to:

1. CLI flags and option semantics
2. Parser selection behavior and parser lifecycle states
3. Pass output contracts under `derived`
4. Output artifact fields and schema contracts
5. Runtime defaults that change user-visible behavior

## Versioning Model

Project releases use semantic versioning:

1. Patch (`x.y.Z`): bug fixes and low-risk hardening
2. Minor (`x.Y.z`): additive features and policy-safe behavior changes
3. Major (`X.y.z`): compatibility-breaking removals or contract shifts

## Deprecation Cadence

Every deprecation follows three phases:

1. Announce: document deprecation in changelog and policy docs.
2. Warn: emit runtime warnings where practical and provide migration path.
3. Remove: remove no earlier than the stated version window.

Default minimum deprecation window:

1. At least one minor release between first warning and removal.
2. Breaking removals should target a major release unless risk or security requires otherwise.

## Runtime Warning Requirements

For deprecated or experimental compatibility paths:

1. Warning includes what is deprecated.
2. Warning includes recommended replacement path.
3. Warning is visible at normal operator log levels.

Current parser policy:

1. XML parser paths are `stable`.
2. JSON parser paths are `experimental` and `deprecated`.
3. Earliest removal consideration is v1.4.0+, subject to roadmap review.

## Compatibility Contract Rules

1. Stable parser and pass contracts must remain backward-compatible within minor releases.
2. New output fields should be additive where possible.
3. Removed/renamed fields require explicit migration notes and release callouts.
4. CLI removals must include flag migration examples.

## Documentation Requirements

When introducing deprecations:

1. Update `CHANGELOG.md`.
2. Update [Upgrade and Migration](Upgrade%20and%20Migration.md).
3. Update relevant architecture docs (for parser/pass behavior).
4. Update roadmap timeline when removals are planned.

## Governance Requirements

1. Architecture-impacting deprecations require an ADR.
2. PRs with compatibility impact must include the architecture review checklist.

## Exception Handling

Emergency security or safety issues may accelerate removal.

If cadence is shortened:

1. Document rationale in changelog and ADR.
2. Provide immediate mitigation or migration guidance.

## Related Docs

- [ADR Workflow](ADR%20Workflow.md)
- [Architecture Review Checklist](Architecture%20Review%20Checklist.md)
- [Upgrade and Migration](Upgrade%20and%20Migration.md)
<<<<<<< HEAD
- [Roadmap](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/ROADMAP.md)
=======
- [Roadmap](../../ROADMAP.md)
>>>>>>> main
