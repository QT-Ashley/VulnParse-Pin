# Enrichment Seam Contract

This document defines an implementation-ready seam contract for enrichment, with staged migration and rollback guidance.

## Objective

Create a clear orchestration boundary between:

1. Source loading and cache retrieval
2. Finding-level enrichment application
3. Post-enrichment indexing and pass handoff

The goal is to reduce coupling in `run_enrichment_pipeline` while preserving current behavior, performance, and auditability.

## Current State (baseline)

Today, the enrichment stage combines several concerns in one flow:

1. Source selection and fetch/import (`KEV`, `EPSS`, `Exploit-DB`, `NVD`)
2. Finding mutation and enrichment status updates
3. Enrichment telemetry aggregation
4. Post-enrichment index build and service wiring
5. Immediate pass-runner handoff

Primary orchestration lives in `src/vulnparse_pin/app/enrichment.py`.

## Seam Contract

### Contract A: Source adapter boundary

Each enrichment source should expose one source adapter contract.

```python
class SourceAdapter(Protocol):
    key: str  # kev | epss | exploit_db | nvd

    def load(self, ctx: RunContext, plan: SourceLoadPlan) -> SourceLoadResult:
        ...
```

#### SourceLoadPlan

Required fields:

1. `mode`: `online` or `offline`
2. `force_refresh`: bool
3. `allow_regen`: bool
4. `path_or_url`: optional source locator

#### SourceLoadResult

Required fields:

1. `enabled`: bool
2. `available`: bool
3. `payload`: typed source data or `None`
4. `status`: canonical status string for runmanifest/docs
5. `meta`: source metadata (ttl/cache/source-type)

### Contract B: Enrichment application boundary

Enrichment application should consume source results and mutate findings through one orchestrated step.

```python
class EnrichmentApplicator(Protocol):
    def apply(
        self,
        ctx: RunContext,
        scan: ScanResult,
        sources: dict[str, SourceLoadResult],
        *,
        offline_mode: bool,
    ) -> EnrichmentApplyResult:
        ...
```

#### EnrichmentApplyResult

Required fields:

1. `scan_result`: enriched `ScanResult`
2. `source_summary`: stable source availability summary
3. `stats`: normalized enrichment counters
4. `warnings`: machine-readable warning list

### Contract C: Pipeline handoff boundary

Post-enrichment indexing and derived pass handoff should consume `EnrichmentApplyResult` and produce one handoff object.

```python
@dataclass(frozen=True)
class EnrichmentPipelineState:
    scan_result: ScanResult
    sources: dict
    nvd_status: str
```

Current `EnrichmentPipelineState` in `src/vulnparse_pin/app/enrichment.py` remains the compatibility target for this spike.

## Non-goals

1. No scoring/TopN algorithm changes
2. No scanner parser behavior changes
3. No runmanifest schema changes
4. No feed format changes

## Migration Sketch

### Stage 0 (compatibility wrappers)

1. Keep `run_enrichment_pipeline` as entrypoint.
2. Add wrapper adapters around existing loaders (`load_kev`, `load_epss`, `load_exploit_data`, and the NVD cache refresh flow).
3. Preserve all existing source flags and semantics.

### Stage 1 (source loading split)

1. Move source loading decisions into a dedicated source-orchestrator module.
2. Return `SourceLoadResult` per source.
3. Keep current apply logic unchanged.

### Stage 2 (application split)

1. Move finding-level enrichment into an applicator module.
2. Keep exploit batch/parallel behavior unchanged.
3. Keep existing stats fields and status update behavior.

### Stage 3 (index/handoff split)

1. Isolate post-enrichment index build and `RunContext.services` rewire.
2. Keep pass execution order and dependency validation unchanged.

### Stage 4 (cleanup)

1. Remove transitional glue once tests prove parity.
2. Keep backwards-compatible output shape and source summary keys.

## Blast Radius

Potentially affected areas:

1. `src/vulnparse_pin/app/enrichment.py`
2. `src/vulnparse_pin/utils/enricher.py`
3. `src/vulnparse_pin/utils/exploit_enrichment_service.py`
4. `src/vulnparse_pin/utils/nvdcacher.py`
5. runmanifest source summary consumers

Low-risk by design because migration stages preserve existing entrypoints and output contracts.

## Rollback Strategy

1. Retain original `run_enrichment_pipeline` path behind one feature-toggle branch during staged implementation.
2. If drift is detected, route back to legacy orchestration immediately.
3. Keep legacy source-summary map keys stable: `exploitdb`, `kev`, `epss`, `nvd`, `stats`.

## Verification Plan

Minimum validation for implementation phase:

1. Existing enrichment-related tests pass unchanged.
2. Runmanifest tests confirm unchanged summary shape and expected stats.
3. Offline/online matrix validation for KEV, EPSS, Exploit-DB, and NVD status paths.
4. Large-input sanity run to verify no regression in batching/parallel behavior.

## Exit Criteria

1. Seam contracts are documented and accepted.
2. Migration plan is staged and reversible.
3. Blast radius and rollback steps are explicit.
4. Test matrix for parity is defined.

## Related Docs

- [Architecture](Architecture.md)
- [Pipeline System](Pipeline%20System.md)
- [Extension Playbooks](Extension%20Playbooks.md)
- [Architecture Review Checklist](Architecture%20Review%20Checklist.md)
- [ADR Workflow](ADR%20Workflow.md)
- [ADR-0002: Enrichment Seam Architecture](adr/ADR-0002-enrichment-seam.md)
