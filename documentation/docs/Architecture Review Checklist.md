# Architecture Review Checklist

Use this checklist for PRs that change parser, pass, enrichment, schema, or runtime-policy behavior.

## Trigger Criteria

Run this checklist when any of the following is true:

1. Parser detection logic or parser registry metadata changes
2. Pass order, dependency declarations, or pass output shape changes
3. Enrichment source orchestration or fallback behavior changes
4. Schema validation rules or output contracts change
5. Security-sensitive defaults or runtime policy behavior changes

## Checklist

### 1. Decision clarity

- [ ] Problem statement is explicit and bounded.
- [ ] Decision and alternatives are documented.
- [ ] ADR is linked when required.

### 2. Contract integrity

- [ ] Parser/pass/output contracts are preserved or versioned intentionally.
- [ ] Compatibility impact is classified (none/additive/breaking).
- [ ] Migration path exists for any user-visible change.

### 3. Test coverage

- [ ] Contract tests are added or updated.
- [ ] Regression tests cover edge cases and fallback behavior.
- [ ] Relevant runmanifest/assertion checks are updated when pass outputs change.

### 4. Runtime behavior and observability

- [ ] Warning/error behavior is explicit and machine-readable where needed.
- [ ] Decision evidence and logs remain actionable.
- [ ] Large-input and failure-mode behavior is validated.

### 5. Documentation and release hygiene

- [ ] Usage/migration docs reflect behavior changes.
- [ ] Changelog includes user-visible impacts.
- [ ] Roadmap/policy docs updated when deprecation or removal windows change.

### 6. Rollout safety

- [ ] Blast radius and rollback plan are documented.
- [ ] Feature remains deterministic under both normal and degraded dependency modes.

## Completion Record (copy into PR)

```markdown
Architecture Review Checklist
- Trigger: <why checklist applies>
- ADR: <link or N/A>
- Compatibility Impact: <none|additive|breaking>
- Tests Updated: <list>
- Docs Updated: <list>
- Rollback Plan: <summary>
```

## Related Docs

- [ADR Workflow](ADR%20Workflow.md)
- [Deprecation and Versioning Policy](Deprecation%20and%20Versioning%20Policy.md)
<<<<<<< HEAD
- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
=======
- [Contributing](../../CONTRIBUTING.md)
>>>>>>> main
