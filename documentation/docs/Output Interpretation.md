# Output Interpretation

This guide explains how to read VulnParse-Pin output artifacts and use them for triage decisions.

## Output Artifact Types

VulnParse-Pin can emit:

1. JSON (`--output`): canonical machine-readable output.
2. CSV (`--output-csv` + optional `--csv-profile`): flat row output for analyst workflows and spreadsheet tooling.
3. Executive markdown (`--output-md`): high-level, action-oriented summary.
4. Technical markdown (`--output-md-technical`): detailed tables for practitioners.
5. RunManifest (`--output-runmanifest`): verifiable audit artifact for provenance and integrity.

## Webhook Output Interpretation

Webhook delivery is an output-side integration that emits a compact signed event when configured.

Primary operator checks:

1. Confirm headers expected by your receiver: `X-VPP-Signature`, `X-VPP-Timestamp`, `X-VPP-Nonce`, `X-VPP-Key-Id`, `X-VPP-Event`.
2. Validate `oal_filter_applied` and `top_findings` shape in the posted body.
3. Confirm delivery status in RunManifest decision ledger reason codes.

Reason-code outcomes in RunManifest:

1. `WEBHOOK_EMIT_STARTED`
2. `WEBHOOK_EMIT_SUCCEEDED`
3. `WEBHOOK_EMIT_FAILED`
4. `WEBHOOK_EMIT_SKIPPED_DISABLED`
5. `WEBHOOK_EMIT_SKIPPED_POLICY`
6. `WEBHOOK_EMIT_SPOOLED_FOR_RETRY`

Spool fallback behavior:

- If delivery fails and spooling is enabled, payloads are written under `<output_dir>/<spool_subdir>/`.
- Default subdirectory is `webhook_spool`.
- Files follow `webhook_<timestamp>_<nonce>.json` naming for replay-friendly handling.

## JSON Structure: What to Read First

High-value sections for triage:

1. `assets`: normalized asset entities.
2. `assets[].findings`: vulnerability findings attached to assets.
3. `derived["Scoring@2.0"]`: scoring coverage, score traces, and score distribution details.
4. `derived["TopN@1.0"]`: ranked assets and high-priority findings.
5. `derived["Summary@1.0"]`: aggregate operator summary and risk-band distribution with whole-of-CVEs-aware remediation buckets.

Suggested review order:

1. Confirm parse/enrichment completion.
2. Check top ranked assets/findings from TopN.
3. Validate summary totals against expected workload size.

## Finding-Level Signals

Common signals used in prioritization include:

- CVE identifiers and references
- KEV presence
- EPSS score context
- Exploit availability indicators
- CVSS vector/base score context
- Derived risk score and risk band
- `score_trace` when you need per-CVE contribution detail for audit or analyst review

Use these in combination, not isolation.

## CSV Interpretation

CSV is flattened for operational handling and exports. Useful for sorting/filtering at scale.

Profiles:

1. `full` (default): complete schema with legacy-compatible column order.
2. `analyst`: focused on triage/ranking (`risk_band`, `topn_*`, union exploit/KEV context, remediation bucket).
3. `audit`: analyst fields plus scoring traceability (`aggregation_mode`, contributor counts, top contributor CVEs).

Recommended profile by workflow:

1. SOC triage queues: use `analyst` for compact, high-signal sorting and ticket creation.
2. IR or vulnerability engineering deep dives: use `audit` when you need contributor-level traceability.
3. Existing integrations expecting legacy headers: keep `full` to avoid breaking downstream parsers.

Example commands:

```bash
# Fast analyst triage sheet
vpp -f <input_file> --output-csv triage.csv --csv-profile analyst

# Traceability/evidence sheet for audits and post-incident review
vpp -f <input_file> --output-csv evidence.csv --csv-profile audit
```

Tips:

1. Sort by derived risk-related columns first, not scanner severity alone.
2. Use asset context columns to separate internet-facing and internal workflows.
3. Treat sentinel values (for unavailable numeric score fields) as missing data, not low risk.
4. For whole-of-CVEs scoring visibility, use `audit` profile and inspect `aggregated_*` and `top_contributor_*` fields.

## Markdown Reports

### Executive Markdown

Designed for leadership-level triage posture:

- Risk-band overview
- Top target assets
- High-priority vulnerability highlights
- Decision Context section that explains ranking basis and tie interpretation
- Data Quality Scorecard section for scored/enriched coverage framing
- Remediation Plan by Time Horizon (24-48h, 7d, 30d)
- Risk Concentration snapshot to show where critical/high exposure is clustered

Use it for meeting preparation and remediation prioritization checkpoints.

### Technical Markdown

Designed for engineering and operations:

- Detailed vulnerability and asset breakdowns
- Operational context for investigation
- Data aligned with downstream remediation workflows
- Tie-Break Explainability section for ranking interpretation
- Analyst Caveats section to prevent finding-level versus asset-level misreads
- Trust and Provenance section that points operators to runmanifest verification

Interpretation note:

- `Finding Agg CVEs` is finding-level contributor breadth for the representative row and should not be interpreted as an asset-level aggregate count.

## RunManifest Interpretation

RunManifest is the provenance and integrity artifact.

Primary sections to inspect:

1. Runtime metadata and input/config hashes
2. Pass summaries and metrics
3. Enrichment phase summary
4. Decision ledger entries (compact or expanded mode)
5. Verification block

Best practice:

1. Verify after generation.
2. Verify again before trust actions (sharing, compliance evidence, or archival).

```bash
vpp --verify-runmanifest out.runmanifest.json
```

## Practical Triage Pattern

1. Start with `derived["TopN@1.0"]` to focus operator effort.
2. Cross-check high-priority items against KEV/EPSS/exploit signals.
3. Inspect `assets[].findings[].score_trace` or `derived["Scoring@2.0"].scored_findings[*].score_trace` for whole-of-CVEs contribution details.
4. When TopN scores are tied, expect findings/assets with broader exploit/KEV contributor signals in `score_trace` to rank first.
5. Use technical markdown for analyst handoff.
6. Use RunManifest to preserve auditability of decisions.

## Tabletop Prioritization Policy (Exploitability vs ACI Chains)

Use this policy when deciding whether a chain-candidate finding should be treated above a currently exploitable public-facing finding.

Methodology principle:

- VulnParse-Pin triage is impact-probability first in real-world terms: prioritize findings with the highest near-term likelihood of meaningful operational impact.
- This is a default operating model, not a one-size-fits-all mandate. Teams should adjust configs and triage policy to fit their environment, risk appetite, regulatory duties, and business goals.

Operational Action Lanes (`OAL`):

1. `OAL-1 Immediate Exploitable`
   - KEV-listed or public exploit available
   - internet/public-facing exposure
   - high derived risk (typically Critical/High band)

2. `OAL-2 High-Confidence Chain Path`
   - ACI indicates chain candidates with strong confidence
   - chain implies meaningful blast radius (credential theft, privilege expansion, lateral movement)
   - corroborating operational evidence exists (asset criticality, exposure path, adjacent controls posture)

3. `OAL-3 Remaining High Risk`
   - high-risk findings without immediate exploitability evidence
   - lower-confidence or uncorroborated chain candidates

Default precedence rule:

- A lower-ranked chain-candidate finding does not automatically outrank a currently exploitable, public-facing finding in `OAL-1`.

Escalation exception:

- Elevate a chain-candidate finding into `OAL-2` above some `OAL-1` backlog items only when chain confidence and expected impact indicate materially higher near-term compromise potential for the environment.

Evidence fields to review before exception handling:

1. `derived["ACI@1.0"].data.finding_semantics[*].chain_candidates`
2. `derived["ACI@1.0"].data.finding_semantics[*].confidence`
3. `derived["ACI@1.0"].data.metrics.chain_candidates_detected`
4. `derived["TopN@1.0"]` ranking and reason context
5. `derived["Summary@1.0"]` concentration and remediation pressure

Analyst note:

- Treat ACI chain outputs as decision-support signals. They improve triage order but are not proof of exploit success or compromise on their own.

### OAL Policy Knobs and Practical Implications

TopN `triage_policy` exposes OAL behavior as explicit knobs. The defaults are tuned for conservative real-world actionability.

Primary knobs:

- `oal1_risk_bands`
- `oal1_require_public_exposure`
- `oal1_require_exploit_or_kev`
- `oal2_risk_bands`
- `oal2_min_aci_confidence`
- `oal2_require_chain_candidate`
- `oal2_require_public_exposure`
- `preserve_oal1_precedence`

Current default posture highlights:

- `oal2_min_aci_confidence: 0.8`
- `oal2_require_public_exposure: true`

Implication profile of this default:

1. `OAL-2` precision increases by requiring stronger semantic confidence.
2. Internal-only chain candidates are less likely to surface as `OAL-2` unless public exposure evidence exists.
3. `OAL-2` queue volume decreases versus looser settings; analyst trust typically increases.
4. `OAL-3` may contain meaningful internal chain risk that some environments may choose to elevate by policy.

If your environment is east-west dominant and intentionally prioritizes internal blast radius, consider policy tuning (for example setting `oal2_require_public_exposure: false`) with explicit governance and periodic review.

### Context Tag Taxonomy (v1)

Context tags in markdown are lightweight analyst cues derived from canonical TopN/ACI outputs and summary context. They are not independent scoring logic.

v1 tag families:

1. Exposure posture
   - `Externally-Facing Inferred`
   - `Public-Service Ports Inferred`
   - `Exposure Confidence: Low|Medium|High`

2. Asset pressure
   - `Criticality: Low|Medium|High|Extreme`
   - `Critical Findings Present`
   - `High Findings Present`
   - `Top Risk Concentration`

3. Lane presence
   - `Contains OAL-1 Findings`
   - `Contains OAL-2 Findings`

4. OAL-2 lightweight prioritization
   - `OAL-2 Priority: Immediate Analyst Validation`
   - `OAL-2 Priority: Validate Next`
   - `OAL-2 Priority: Monitor`
   - `OAL-2 Chain-Corroborated`
   - `OAL-2 Coexists With OAL-1`

OAL-2 lightweight tag behavior:

- Priority tags are based on the highest OAL-2 finding confidence on the asset:
  - `>= 0.90` -> `Immediate Analyst Validation`
  - `>= 0.80 and < 0.90` -> `Validate Next`
  - otherwise -> `Monitor`
- `OAL-2 Chain-Corroborated` appears when at least one OAL-2 finding has non-empty chain candidates.
- `OAL-2 Coexists With OAL-1` appears when OAL-2 findings exist on an asset that also has OAL-1 findings.

Rendered example (as it appears in markdown reports):

```markdown
Context Tags: Externally-Facing Inferred | Public-Service Ports Inferred | Exposure Confidence: High | Criticality: High | Contains OAL-1 Findings | Contains OAL-2 Findings | OAL-2 Priority: Immediate Analyst Validation | OAL-2 Chain-Corroborated | OAL-2 Coexists With OAL-1

OAL-2 tag legend: `Immediate Analyst Validation` = confidence >= 0.90, `Validate Next` = confidence >= 0.80 and < 0.90, `Monitor` = lower-confidence OAL-2.
```

### Finding-Text Inference Hardening (v1)

`finding_text_contains_any` is now tuned for conservative behavior and reproducible analyst traceability.

Hardening principles:

1. Bounded monotonicity with diminishing returns
   - Additional text matches can increase evidence, but each incremental hit contributes less than earlier hits.
   - Weighted evidence is capped by `finding_text_max_weighted_hits`.

2. Source-quality weighting
   - Matches in finding title are weighted highest, description next, plugin output lowest.
   - Controlled with:
     - `finding_text_title_weight`
     - `finding_text_description_weight`
     - `finding_text_plugin_output_weight`

3. Negative constraints and conflict handling
   - Contradictory lexical cues (for example internal-only language) reduce inferred finding-text weight.
   - Controlled with:
     - `finding_text_conflict_tokens`
     - `finding_text_conflict_penalty`

4. Explainability and reproducibility
   - TopN evidence includes deterministic trace fragments for finding-text rules:
     - total token hits
     - source-specific hit counts
     - weighted and bounded evidence values
     - conflict-token hits
     - final applied rule weight

Default conservative starter profile:

- `finding_text_min_token_matches: 2`
- `finding_text_title_weight: 3`
- `finding_text_description_weight: 2`
- `finding_text_plugin_output_weight: 1`
- `finding_text_max_weighted_hits: 4`
- `finding_text_conflict_penalty: 2`
- `finding_text_diminishing_factors: [1.0, 0.6, 0.4]`

## Related Docs

- [Usage](Usage.md)
- [RunManifest Overview](RunManifest.md)
- [RunManifest Technical Deep Dive](RunManifest_Technical.md)
- [Upgrade and Migration](Upgrade%20and%20Migration.md)
- [Troubleshooting](Troubleshooting.md)
