# Pass Phases

This document breaks down the major post-parse phases and what each contributes to final triage output.

## Phase 0: Normalized input baseline

Before pass execution, all scanner-native records are mapped into `ScanResult` with:

- Stable asset identity
- Stable finding identity
- Scanner provenance fields
- Core severity/CVSS metadata

This baseline is the shared contract for all downstream phases.

## Phase 1: Enrichment

Enrichment augments findings with external intelligence and supporting metadata.

Typical enrichment sources:

- CISA KEV indicators
- EPSS probability
- NVD CVE details
- Exploit-DB hits

Outputs of enrichment feed later scoring and operational decisioning.

## Phase 2: Scoring pass (`Scoring@1.0`)

Implemented in `src/vulnparse_pin/core/passes/Scoring/scoringPass.py`.

Purpose:

- Compute raw and operational risk values
- Apply configurable weighting policy
- Generate coverage metrics and asset-level summaries

Core policy inputs come from `src/vulnparse_pin/resources/scoring.json`:

- EPSS scaling
- KEV/exploit evidence weights
- Risk band thresholds

Typical scoring output includes:

- Per-finding scored records
- Asset max risk map
- Coverage ratio (scored vs total)
- High-level scoring aggregates

## Phase 3: TopN pass (`TopN@1.0`)

Implemented in `src/vulnparse_pin/core/passes/TopN/topn_pass.py`.

Purpose:

- Rank assets for remediation focus
- Select top findings per asset
- Generate global top findings across all assets
- Infer exposure signal from host/service attributes

Configuration source: `src/vulnparse_pin/resources/tn_triage.json`.

Key mechanics:

- Decay-weighted top-k finding contribution per asset
- Configurable ranking basis (`raw` / policy-defined basis)
- Predicate-driven exposure inference confidence levels

## Phase 4: Summary pass (`Summary@1.0`)

Implemented in `src/vulnparse_pin/core/passes/Summary/summary_pass.py`.

Purpose:

- Build operator-ready aggregates from normalized + derived data
- Generate executive and technical report metrics
- Produce ranked top-risk finding summaries
- Compute remediation-priority buckets

Configuration source: `src/vulnparse_pin/resources/config.yaml`.

Key config currently exposed:

- `summary.top_n_findings` (how many top findings to include in report sections)

Typical summary output includes:

- Overview totals and average risk metrics
- Asset-level summary table (risk-ordered)
- Risk-band distribution
- Top-N high-risk finding list
- Remediation-priority breakdown

## Phase 5: Output shaping

After pass execution, output layers serialize:

- Core normalized scan data
- Derived pass outputs
- Optional CSV projections
- Optional presentation overlays

Output shaping should not alter core identity or pass invariants.

## Phase interaction rules

- Enrichment should be additive, not destructive
- Scoring consumes enrichment and base finding signals
- TopN consumes scoring output and asset observations
- Summary consumes normalized scan metadata plus scoring outputs
- Downstream exporters consume both base and derived contexts

## Validation and confidence

Phase-level confidence comes from dedicated tests:

- Pass contract tests (`tests/test_pass_contracts.py`)
- Parallel scoring tests (`tests/test_parallel_scoring.py`)
- TopN optimization tests (`tests/test_topn_optimization.py`)
