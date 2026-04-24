# RunManifest Overview

RunManifest is VulnParse-Pin's execution artifact for traceability, reproducibility, and explainable prioritization.

When enabled, VulnParse-Pin emits a JSON artifact that captures:

- Run metadata and runtime details.
- Input and config fingerprints.
- Pass phase summaries with metrics.
- A tamper-evident decision ledger.
- Verification metadata for integrity checks.

The artifact is designed to be useful in day-to-day triage workflows and in governance or audit reviews where teams need to answer, "What was decided, and why?"

## Why RunManifest Exists

Raw scanner output tells you what was found. RunManifest tells you how VulnParse-Pin decided what mattered most.

It closes a common gap in vulnerability operations:

- Security engineering needs reproducible runs.
- Analysts need explainability for prioritization.
- Program owners need an evidence trail for decisions.
- Auditors need integrity checks, not only logs.

## Practical Uses

### 1. Triage evidence pack

Attach the RunManifest to remediation tickets or change approvals. It gives reviewers an auditable explanation of scoring and ranking outcomes.

### 2. Repeatability checks

Compare manifests across runs to confirm behavior remains stable after config changes, feed updates, or code updates.

### 3. Governance and controls

Use verification output in control procedures to prove artifacts were not tampered with after generation.

### 4. Pipeline interoperability

Store the manifest in artifact repositories with JSON, CSV, and Markdown outputs so downstream systems can consume one canonical execution record.

## What Is Captured

Top-level sections include:

- `manifest_version`
- `runmanifest_mode`
- `run_id`
- `generated_at_utc`
- `runtime`
- `inputs`
- `config_hashes`
- `outputs`
- `enrichment_summary`
- `pass_summaries`
- `decision_ledger`
- `verification`

## Decision Ledger at a Glance

The embedded `decision_ledger` stores append-only entries with a hash chain:

- Sequential `seq` values.
- `prev_hash` links to the previous entry.
- `entry_hash` protects each entry body.
- `chain_root` anchors the full sequence.

This provides tamper evidence at the event level rather than only at the file level.

In current ingestion-hardening workflows, the ledger also records parser and normalization quality gates, including:

- CSV row drops for minimum-signal contract failures.
- CSV malformed-row skips for schema-shape violations.
- Strict-ingestion rejections.
- Minimum ingestion-confidence threshold rejections.

This makes degraded-input handling auditable in the same artifact as scoring and TopN decisions.

## Output Modes

RunManifest supports two detail levels:

- `compact` (default): high-impact decision events, lower storage overhead.
- `expanded`: richer decision detail for forensic or deep-analysis scenarios.

## Core Commands

Generate a runmanifest:

```bash
vpp -f scan.nessus -o result.json --output-runmanifest runmanifest.json
```

Generate with expanded decision detail:

```bash
vpp -f scan.nessus -o result.json --output-runmanifest runmanifest.json --runmanifest-mode expanded
```

Verify an existing manifest later (no scan re-run):

```bash
vpp --verify-runmanifest runmanifest.json
```

## What Verification Confirms

Verification validates:

- JSON schema conformance.
- Per-entry hash-chain continuity.
- Entry hash recomputation.
- Manifest digest recomputation.

A successful verification means the artifact structure and integrity checks both pass.

Best-practice for auditability:

- Treat an unverified RunManifest as untrusted data.
- Verify immediately after pipeline generation.
- Verify again before any downstream trust action (ticket evidence, stakeholder sharing, governance review, or archival as final evidence).

## Recommended Operational Pattern

- Always emit RunManifest for production runs.
- Immediately run `vpp --verify-runmanifest <path>` after pipeline completion.
- Use `compact` by default for continuous workflows.
- Use `expanded` for incident response and deep investigations.
- Verify manifests before sharing them externally or using them as audit evidence.
- Archive manifests with the corresponding output bundle.
