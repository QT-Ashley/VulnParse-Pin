# Config Seam Contract

This document defines an implementation-ready seam contract for configuration loading and validation, with staged migration and rollback guidance.

## Objective

Create a clear configuration boundary between:

1. File discovery and provisioning
2. Parse and schema validation
3. Version policy and compatibility decisions
4. Runtime projection into typed policy objects

The goal is to reduce coupling inside configuration bootstrap while preserving strict validation, deterministic startup behavior, and backward-compatible migration paths.

## Current State (baseline)

Configuration handling is currently centralized primarily in `src/vulnparse_pin/core/apppaths.py` and consumed in bootstrap.

Current workflow includes:

1. Ensuring user config files exist (`config.yaml`, `scoring.json`, `tn_triage.json`)
2. Reading YAML/JSON with PFH policy enforcement
3. Schema validation against packaged schemas
4. Global config version warning/fail policy
5. Returning raw dict payloads for downstream policy construction

## Seam Contract

### Contract A: Config source boundary

Config source handling should expose one contract for discover/provision/read operations.

```python
class ConfigSource(Protocol):
    def ensure_files(self, ctx: RunContext) -> ConfigFileSet:
        ...

    def read_payloads(self, ctx: RunContext, files: ConfigFileSet) -> RawConfigPayloads:
        ...
```

#### ConfigFileSet

Required fields:

1. `global_yaml`: Path
2. `scoring_json`: Path
3. `topn_json`: Path

#### RawConfigPayloads

Required fields:

1. `global_config`: dict
2. `scoring_config`: dict
3. `topn_config`: dict

### Contract B: Validation boundary

Validation should be isolated and deterministic, producing explicit failure/warning structures.

```python
class ConfigValidator(Protocol):
    def validate(self, payloads: RawConfigPayloads) -> ConfigValidationResult:
        ...
```

#### ConfigValidationResult

Required fields:

1. `ok`: bool
2. `warnings`: list[str]
3. `errors`: list[str]
4. `normalized`: RawConfigPayloads

Validation responsibilities:

1. Schema validation for all runtime configs
2. Global version policy checks (`version: v1` compatibility behavior)
3. Type/top-level object guarantees for all config payloads

### Contract C: Runtime projection boundary

Raw validated config should be projected into typed runtime policy objects in one explicit stage.

```python
@dataclass(frozen=True)
class RuntimeConfigBundle:
    global_config: dict
    scoring_policy: ScoringPolicyV1
    topn_policy: TriageConfigLoadResult
```

This projection boundary preserves strict loading while minimizing config-shape leakage across modules.

## Non-goals

1. No scoring algorithm changes
2. No TopN ranking logic changes
3. No parser detection behavior changes
4. No runtime CLI flag semantics changes

## Migration Sketch

### Stage 0 (compatibility wrappers)

1. Keep existing `load_config(ctx)` entrypoint.
2. Internally split responsibilities into source/validate/project helper modules.
3. Preserve current exception and warning behavior.

### Stage 1 (source split)

1. Move file ensure/read logic into dedicated source module.
2. Keep PFH enforcement and current file naming unchanged.
3. Return `ConfigFileSet` and `RawConfigPayloads`.

### Stage 2 (validation split)

1. Move schema/version validation into validator module.
2. Keep error wording and fail-fast behavior stable where practical.
3. Keep global version compatibility rule unchanged.

### Stage 3 (projection split)

1. Consolidate conversion from raw config dicts to typed policy objects.
2. Keep bootstrap signatures stable via adapter layer.
3. Preserve existing policy defaults and threshold semantics.

### Stage 4 (cleanup)

1. Remove transitional glue once parity is verified.
2. Keep `load_config` compatibility shim until consumers are fully migrated.

## Blast Radius

Potentially affected areas:

1. `src/vulnparse_pin/core/apppaths.py`
2. `src/vulnparse_pin/app/bootstrap.py`
3. `src/vulnparse_pin/core/passes/Scoring/`
4. `src/vulnparse_pin/core/passes/TopN/`
5. config schema resources and related tests

Risk is controlled by preserving current entrypoints and staged migration.

## Rollback Strategy

1. Keep legacy `load_config` path available behind a compatibility branch.
2. If validation/projection drift is detected, route startup back to legacy logic immediately.
3. Preserve current schema files and version policy behavior to avoid startup regressions.

## Verification Plan

Minimum validation for implementation phase:

1. Existing config schema validation tests pass unchanged.
2. Bootstrap and pass-contract tests remain green.
3. Version-policy behavior is verified for:

    - missing `version`
    - supported `version: v1`
    - unsupported versions

4. Runtime startup parity checks validate identical loaded policy outcomes.

## Exit Criteria

1. Config seam contracts are documented and accepted.
2. Migration plan is staged and reversible.
3. Blast radius and rollback plan are explicit.
4. Test matrix for parity and version behavior is defined.

## Related Docs

- [Configs](Configs.md)
- [Architecture](Architecture.md)
- [Pipeline System](Pipeline%20System.md)
- [Enrichment Seam Contract](Enrichment%20Seam%20Contract.md)
- [ADR-0001: Config Seam Architecture](adr/ADR-0001-config-seam.md)
- [Architecture Review Checklist](Architecture%20Review%20Checklist.md)
- [ADR Workflow](ADR%20Workflow.md)
