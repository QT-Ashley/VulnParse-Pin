# Architecture

VulnParse-Pin is organized as a staged pipeline with strong separation of concerns:

`Input -> Validation -> Detection -> Parsing -> Enrichment -> PassRunner -> Output`

## High-level module map

- `src/vulnparse_pin/main.py` — CLI orchestration and end-to-end workflow
- `src/vulnparse_pin/parsers/` — scanner format adapters
- `src/vulnparse_pin/core/` — identity, schema detection, pass system, dataclasses
- `src/vulnparse_pin/utils/` — enrichment, caching, exporting, logging, validation
- `src/vulnparse_pin/io/pfhandler.py` — constrained and policy-aware file I/O

## Core data structures

Primary models are in `src/vulnparse_pin/core/classes/dataclass.py`:

- `Finding` — normalized vulnerability observation
- `Asset` — host identity and attached findings
- `ScanResult` — top-level parsed/enriched object for one run
- `RunContext` — immutable runtime services and path/config state

Pass contracts are in `src/vulnparse_pin/core/classes/pass_classes.py`:

- `Pass` protocol (`run(ctx, scan) -> DerivedPassResult`)
- `PassRunner` sequential orchestrator
- `DerivedContext` append-only pass output registry

## Control-plane flow (`main.py`)

At runtime, the orchestrator does the following:

1. Parse CLI args and establish app paths
2. Initialize PFH path policy and logger
3. Validate input and detect schema/parser
4. Parse input into normalized `ScanResult`
5. Enrich findings using configured feed/cache strategy
6. Execute derived passes (`ScoringPass`, `TopNPass`, `SummaryPass`)
7. Emit output artifacts (JSON and optional CSV)

## Architectural invariants

- **Deterministic identity:** IDs are stable for equivalent canonical inputs
- **Immutable derived context:** pass outputs are versioned and append-only
- **Policy-driven scoring:** risk behavior comes from config, not hidden constants
- **Secure defaults:** path handling and CSV export are hardened
- **Scale thresholds:** computational strategy switches based on workload size

## Why this architecture works

- Keeps parser complexity isolated from risk logic
- Keeps enrichment logic independent of scoring logic
- Enables focused testability per stage
- Enables targeted optimization without changing external UX

## Recommended reading order

1. [Detection and Parsing](Detection%20and%20Parsing.md)
2. [Pipeline System](Pipeline%20System.md)
3. [Pass Phases](Pass%20Phases.md)
4. [Performance Optimizations](Performance%20Optimizations.md)
