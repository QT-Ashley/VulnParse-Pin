# Output Interpretation

This guide explains how to read VulnParse-Pin output artifacts and use them for triage decisions.

## Output Artifact Types

VulnParse-Pin can emit:

1. JSON (`--output`): canonical machine-readable output.
2. CSV (`--output-csv`): flat row output for analyst workflows and spreadsheet tooling.
3. Executive markdown (`--output-md`): high-level, action-oriented summary.
4. Technical markdown (`--output-md-technical`): detailed tables for practitioners.
5. RunManifest (`--output-runmanifest`): verifiable audit artifact for provenance and integrity.

## JSON Structure: What to Read First

High-value sections for triage:

1. `assets`: normalized asset entities.
2. `assets[].findings`: vulnerability findings attached to assets.
3. `derived["Scoring@1.0"]`: scoring coverage and score distribution details.
4. `derived["TopN@1.0"]`: ranked assets and high-priority findings.
5. `derived["Summary@1.0"]`: aggregate operator summary and risk-band distribution.

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

Use these in combination, not isolation.

## CSV Interpretation

CSV is flattened for operational handling and exports. Useful for sorting/filtering at scale.

Tips:

1. Sort by derived risk-related columns first, not scanner severity alone.
2. Use asset context columns to separate internet-facing and internal workflows.
3. Treat sentinel values (for unavailable numeric score fields) as missing data, not low risk.

## Markdown Reports

### Executive Markdown

Designed for leadership-level triage posture:

- Risk-band overview
- Top target assets
- High-priority vulnerability highlights

Use it for meeting preparation and remediation prioritization checkpoints.

### Technical Markdown

Designed for engineering and operations:

- Detailed vulnerability and asset breakdowns
- Operational context for investigation
- Data aligned with downstream remediation workflows

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
3. Use technical markdown for analyst handoff.
4. Use RunManifest to preserve auditability of decisions.

## Related Docs

- [Usage](Usage.md)
- [RunManifest Overview](RunManifest.md)
- [RunManifest Technical Deep Dive](RunManifest_Technical.md)
- [Upgrade and Migration](Upgrade%20and%20Migration.md)
- [Troubleshooting](Troubleshooting.md)