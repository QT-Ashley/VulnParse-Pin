# ADR-0001: Config Seam Architecture

- Status: Accepted
- Date: 2026-04-05
- Deciders: Architecture Team
- Tags: config|runtime-policy|extensibility

## Context

VulnParse-Pin's configuration loading was tightly coupled within `apppaths.py`, mixing concerns of:
1. File discovery and provisioning
2. Parsing and deserialization
3. Schema validation and version policy
4. Runtime projection into typed bundles

This monolithic approach made it difficult to:
- Test individual concerns
- Reuse components for configuration extensions
- Understand the config loading contract
- Inject custom validators or loaders for derived use cases

## Decision

Implement a staged seam architecture decomposing config loading into explicit boundary-crossing layers:

### Stage 0: Compatibility Wrappers
- Added internal helper functions in `apppaths.py` as adapters (still present for rollback).
- Preserved existing `load_config(ctx)` entrypoint.

### Stage 1: Source Module (`config_source.py`)
- Extracted file provisioning and reading into `ConfigSource` class.
- Owns file discovery, default provisioning, and YAML/JSON parsing.
- Returns `ConfigFileSet` and `RawConfigPayloads` contracts.

### Stage 2: Validator Module (`config_validator.py`)
- Extracted schema validation and version policy into `ConfigValidator` class.
- Owns JSON schema validation and global config version checks.
- Returns `ConfigValidationResult` with warnings and errors.

### Stage 3: Projector Module (`config_projector.py`)
- Extracted runtime projection into `ConfigProjector` class.
- Owns conversion of validated payloads to typed `RuntimeConfigBundle`.
- Enables future policy object construction (scoring, TopN).

## Alternatives Considered

1. **Monolithic refactor in one stage**: Higher risk of regressions; harder to test incrementally.
2. **Dependency injection framework**: Overkill for current scale; adds runtime complexity.
3. **Configuration factory pattern**: Similar outcome but more ceremony for current single config mode.

## Consequences

**Positive:**
1. Clear contract boundaries enable independent testing and extension.
2. Schema validation is now testable in isolation.
3. Future enrichment/pass configuration can reuse same seam pattern.
4. Staged migration reduces rollback risk.
5. Configuration policy decisions are now explicit and documented.

**Negative:**
1. Light increase in module count (3 new focused modules).
2. Import graph now requires coordination across config modules.

## Compatibility Impact

- Classification: additive (no breaking changes)
- Affected contracts: None (all internal refactor)
- Migration guidance: None required; backward-compatible entrypoint preserved

## Test and Validation Plan

1. **Contract tests**: Existing tests remain green (155 passed, 38 xfailed expected).
2. **Regression tests**: Full suite validates no behavior change.
3. **Runtime verification**: 
   - Config schema validation tests pass
   - Pass contract tests pass
   - RunManifest tests pass

## Rollout and Rollback

- Rollout steps:
  1. Deploy new modules to codebase
  2. Verify full test suite passes
  3. Monitor config load paths in first runs
  
- Rollback strategy:
  1. Stage 0 helpers remain in `apppaths.py` but unused (can be removed in cleanup stage)
  2. If drift detected, route back to legacy monolithic path via feature toggle (not implemented; low risk)
  3. All config file formats and version policies remain unchanged

## References

- Related docs:
  - [Config Seam Contract](../Config%20Seam%20Contract.md)
  - [Architecture](../Architecture.md)
- Related PRs/code:
  - `src/vulnparse_pin/core/config_source.py` (ConfigSource class)
  - `src/vulnparse_pin/core/config_validator.py` (ConfigValidator class)
  - `src/vulnparse_pin/core/config_projector.py` (ConfigProjector class)
  - `src/vulnparse_pin/core/apppaths.py` (refactored load_config)
