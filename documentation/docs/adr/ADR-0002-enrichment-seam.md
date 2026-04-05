# ADR-0002: Enrichment Seam Architecture

- Status: Accepted
- Date: 2026-04-05
- Deciders: Architecture Team
- Tags: enrichment|extensibility|orchestration

## Context

VulnParse-Pin's enrichment pipeline was tightly coupled within `app/enrichment.py`, mixing concerns of:
1. Source loading and discovery (KEV, EPSS, Exploit-DB, NVD)
2. Finding-level enrichment application
3. Post-enrichment indexing and pass orchestration

This monolithic approach made it difficult to:
- Test source loading independently
- Extend enrichment behavior via composition
- Understand source contract boundaries
- Compose custom enrichment workflows for derived products

## Decision

Implement a seam architecture decomposing enrichment orchestration into explicit boundary-crossing layers:

### Stage 1: Source Loading Module (`app/enrichment_source_loader.py`)
- Extracted source loading into `EnrichmentSourceLoader` class
- Owns KeySource Loading and NVD cache initialization
- Returns `EnrichmentSourceResult` contract with loaded data and metadata
- Preserves all existing source flags and load-fallback semantics

### Future Stages (design-ready, implementation deferred)
- **Stage 2**: Move enrichment application into dedicated applicator module
- **Stage 3**: Extract post-enrichment indexing and handoff into projector module

## Alternatives Considered

1. **Full 4-stage decomposition in one PR**: Larger refactor; higher regression risk
2. **Standalone enrichment service**: Over-engineered for current scale; adds complexity
3. **Monolithic retention**: Loses extensibility and boundaries

## Consequences

**Positive:**
1. Source loading is now independently testable and reusable
2. Enrichment pipeline logic becomes clearer through separation of concerns
3. Future enrichment extensions (threat feeds, third-party sources) have clear entry point
4. Staged implementation allows incremental de-risking and validation

**Negative:**
1. Light increase in module count (1 new focused module for Stage 1)
2. Requires minimal refactor to `enrichment.py` to call loader

## Compatibility Impact

- Classification: additive (no breaking changes)
- Affected contracts: None (all internal; public pipeline behavior unchanged)
- Migration guidance: None required; enrichment pipeline remain fully backward-compatible

## Test and Validation Plan

1. **Contract tests**: Existing enrichment tests remain green
2. **Regression tests**: Full suite validates no behavior change in source loading or enrichment output
3. **Runtime verification**:
   - Source loader loads all supported feed types
   - Existing feed caching and refresh logic preserved
   - Offline and online modes work as before

## Rollout and Rollback

- Rollout steps:
  1. Deploy enrichment_source_loader module
  2. Verify full enrichment test suite passes (no regressions)
  3. Monitor enrichment phase in first production runs
  
- Rollback strategy:
  1. If `EnrichmentSourceLoader` fails, route back to monolithic `enrichment.py` logic
  2. Source module can be safely disabled without affecting pipeline (low risk)
  3. All feed loading contracts and caching remain unchanged

## References

- Related docs:
  - [Enrichment Seam Contract](../Enrichment%20Seam%20Contract.md)
  - [Architecture](../Architecture.md)
  - [Architecture Review Checklist](../Architecture%20Review%20Checklist.md)
- Related code:
  - `src/vulnparse_pin/app/enrichment_source_loader.py` (EnrichmentSourceLoader module)
  - `src/vulnparse_pin/app/enrichment.py` (existing orchestrator, unchanged in Stage 1)
