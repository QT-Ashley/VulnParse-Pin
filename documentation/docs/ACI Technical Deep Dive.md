# ACI Technical Deep Dive

This deep dive documents ACI internals end to end: data flow, rule semantics, confidence computation, ranking integration, reporting integration, and validation boundaries.

## Scope and implementation map

Primary implementation files:

- `src/vulnparse_pin/core/passes/ACI/aci_pass.py`
- `src/vulnparse_pin/core/passes/TopN/TN_triage_semantics.py`
- `src/vulnparse_pin/core/passes/TopN/TN_triage_config.py`
- `src/vulnparse_pin/core/schemas/topN.schema.json`
- `src/vulnparse_pin/core/passes/TopN/topn_pass.py`
- `src/vulnparse_pin/utils/markdown_report.py`

## Pass dependency and lifecycle

Default derived pass order includes:

1. `Scoring@2.0`
2. `ACI@1.0`
3. `TopN@1.0`
4. `Summary@1.0`

`AttackCapabilityInferencePass` declares:

- `name = "ACI"`
- `version = "1.0"`
- `requires_passes = ("Scoring@2.0",)`

`TopNPass` depends on `ACI@1.0` output for ranking behavior.

## Signal extraction pipeline

Signal extraction is centralized in `_extract_signals(...)` and pulls from:

- finding-level flags: exploit and KEV
- finding affected port (remote service signal list)
- CVE analysis entries
- title/description/plugin output
- reference URLs/text

Normalization behavior:

- lowercase matching
- substring match against effective token vocabulary

Effective token vocabulary is built by `_effective_text_tokens(cfg)` using:

- core tokens (maintainer baseline)
- alias overlays (`signal_aliases`)
- optional core token suppression (`disabled_core_tokens`)
- replacement mode (`token_mode = replace`)

## Rule evaluation model

### Capability rules

For each finding:

1. collect normalized signals
2. iterate enabled capability rules
3. match if any rule signal is present in finding signals
4. append capability and add rule weight to confidence base

Confidence base is capped at `1.0`.

### Exploit bonus

If exploit boost is enabled and exploit evidence exists:

- exploit bonus is computed from base confidence and capped by `max_bonus`
- confidence factors include `exploit_boost` when bonus applies

### Final confidence

Final confidence:

`confidence = min(1.0, confidence_base + exploit_bonus)`

Bucket mapping:

- `high` if `>= 0.8`
- `medium` if `>= 0.5`
- `low` otherwise

## Chain inference model

ACI evaluates enabled chain rules after capabilities are resolved.

Chain match condition:

- `set(rule.requires_all)` is a subset of matched capabilities

Matched chain labels are emitted in finding semantics, and rule hit counts are aggregated in metrics.

## Rank uplift model

Finding-level uplift uses thresholded linear interpolation:

If `confidence >= min_confidence`:

`uplift = max_uplift * ((confidence - min_confidence) / (1.0 - min_confidence))`

Else:

`uplift = 0`

Then clamp:

`uplift = clamp(uplift, 0, max_uplift)`

Asset-level uplift aggregates finding uplifts and scales by `asset_uplift_weight`, then clamps by `max_uplift`.

## Output contracts

### Finding semantic contract

Each finding semantic record includes:

- `finding_id`
- `asset_id`
- `confidence`
- `confidence_factors`
- `capabilities`
- `chain_candidates`
- `cwe_ids`
- `evidence`
- `exploit_boost_applied`
- `rank_uplift`

### Asset semantic contract

Each asset semantic record includes:

- `asset_id`
- `weighted_confidence`
- `max_confidence`
- `capability_count`
- `chain_candidate_count`
- `ranked_finding_count`
- `rank_uplift`

### Metrics contract

Metrics include:

- `total_findings`
- `inferred_findings`
- `coverage_ratio`
- `capabilities_detected`
- `chain_candidates_detected`
- `confidence_buckets`
- `uplifted_findings`

## Decision ledger integration

ACI writes structured ledger events when ledger service is present:

1. pass-level summary event
2. preview of inferred finding events (bounded sample)

Evidence fields include capabilities, chain candidates, confidence, and uplift, enabling review and runmanifest traceability.

## Configuration and validation boundaries

### Schema layer

`topN.schema.json` validates structure and ranges for:

- `aci.enabled`
- confidence and uplift parameters
- token mode and alias arrays
- capability rule shapes
- chain rule shapes

### Semantic layer

`TN_triage_semantics._parse_aci` validates semantics such as:

- unique rule IDs
- non-empty normalized signal arrays
- token and signal length constraints
- supported token mode values
- range checks for all numeric fields

These checks prevent malformed policy from reaching runtime pass logic.

## Fallback behavior

If config validation fails in non-strict mode:

- loader returns safe fallback config
- fallback ACI defaults are loaded from packaged `tn_triage.json` when possible
- otherwise last-resort ACI fallback disables inference and emits empty rules

This prevents hard failures in tolerant runtime modes while preserving safe behavior.

## Integration with markdown reporting

`markdown_report.py` consumes ACI output to render:

- ACI metrics snapshot
- top capability signals
- top assets mapped to top findings and inferred capabilities
- chain candidates and confidence per finding
- explicit inference disclaimer for decision hygiene

This appears in both executive and technical markdown report modes.

## Performance characteristics

ACI runs in-memory over findings and assets and uses:

- linear scans over findings
- set-based signal matching
- dictionary aggregation for metrics and rollups

Expected complexity is approximately linear in finding count multiplied by configured rule counts. Typical cost is low relative to enrichment and large-volume scoring paths.

## Testing coverage and invariants

Relevant tests include:

- `tests/test_aci_pass.py`
- `tests/test_config_schema_validation.py`
- `tests/test_topn_summary_aggregation_alignment.py`
- `tests/test_runmanifest.py`
- `tests/test_markdown_report.py`

Notable validated invariants:

- replace mode honors alias-only vocabulary
- merge mode supports selective core token disablement
- TopN parity is preserved across sequential and parallel paths
- ACI uplift behavior is deterministic for tie-break intent

## Extension guidance

When extending ACI policy:

1. add capability rules first
2. add chain rules only after capability quality is stable
3. add aliases for environment-specific phrases
4. tune weights conservatively and compare output deltas
5. preserve deterministic IDs and labels for audit continuity

## Residual risks

1. Substring matching can over-trigger on ambiguous language.
2. Over-broad aliases can increase false-positive capability inference.
3. Excessive uplift settings can distort practical triage order.

Mitigations:

- maintain conservative defaults
- disable proven noisy tokens
- validate via representative datasets and runmanifest review

## Related docs

- [ACI Feature Explanation](ACI%20Feature%20Explanation.md)
- [ACI Rule Authoring Tutorial](ACI%20Rule%20Authoring%20Tutorial.md)
- [Configs](Configs.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Output Interpretation](Output%20Interpretation.md)
