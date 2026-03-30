# RunManifest Technical Deep Dive

This document explains the internal mechanics of RunManifest, including schema contract, integrity validation, and audit implications.

## Architecture

RunManifest is generated from runtime context and derived pass outputs.

Primary components:

- `LedgerService` appends decision events during execution.
- Pass orchestration emits lifecycle events.
- Scoring and TopN emit high-impact decision events.
- Output phase builds and writes `runmanifest.json`.
- Validation enforces schema and integrity before write.

## Data Flow

1. Runtime initializes `services.ledger`.
2. Enrichment and pass phases append ledger events.
3. Derived pass outputs are collected from `scan_result.derived`.
4. RunManifest builder composes artifact sections.
5. Verification digest is computed over canonicalized, non-volatile content.
6. Schema validation and integrity verification execute before write.

## Pass Metrics Population

`pass_summaries[*].metrics` are derived from pass output payloads:

- Scoring metrics include coverage, scored findings, asset scoring counts, and scoring averages.
- TopN metrics include ranked assets, ranked findings, decay settings, and global top findings counts.
- Summary metrics include aggregate totals and top-risk list count.

This keeps metrics connected to real pass output rather than static placeholders.

## Decision Ledger Entry Model

Each entry stores:

- `seq`
- `ts`
- `component`
- `event_type`
- `subject_ref`
- `why`
- `evidence_digest`
- `prev_hash`
- `entry_hash`

The `why` block standardizes explainability fields:

- `reason_code`
- `reason_text`
- `factor_refs`
- Optional `confidence`
- Optional `weight_context`

## Hash Chain Mechanics

For each entry, hash input includes all immutable decision fields and `prev_hash`.

Chain properties:

- `seq` must be contiguous starting at 1.
- `prev_hash` must match the prior `entry_hash`.
- `entry_hash` must match canonical recomputation.
- `chain_root` must equal the final `entry_hash`.

The empty-ledger case uses a fixed sentinel root.

## Manifest Digest Mechanics

RunManifest computes `verification.manifest_digest` from canonical JSON with volatile fields removed.

Volatile exclusions include:

- Top-level generation timestamp.
- Pass start/end timestamps.
- Per-entry event timestamps.

This supports stable digest behavior across equivalent runs where only timestamps differ.

## Schema Contract

RunManifest validation uses JSON Schema Draft 2020-12.

Validation guarantees:

- Required top-level blocks exist.
- Typed structures are present for ledger and verification blocks.
- `runmanifest_mode` is constrained to supported enum values.

## CLI and Operational Controls

- `--output-runmanifest PATH`: emits runmanifest artifact.
- `--runmanifest-mode compact|expanded`: controls decision detail volume.
- `--verify-runmanifest PATH`: validates an existing artifact and exits.

Recommended control profile:

- Continuous operation: `compact` + emit + archive.
- Investigations: `expanded` + emit + verify + retain evidence.

## Auditable Implications

RunManifest improves audit posture by providing:

- A deterministic, schema-bound execution artifact.
- Event-level tamper evidence via hash chaining.
- Structured, machine-readable decision rationale.
- Verifiable linkage from inputs and configs to outputs.

It supports several assurance use cases:

- Internal control evidence for vulnerability prioritization workflows.
- Change review evidence for policy tuning in scoring and TopN.
- Forensic reconstruction of decision path after remediation disputes.

## Practical Limits and Tradeoffs

- `expanded` mode increases artifact size due to richer event capture.
- Hash chain integrity indicates tamper evidence, not cryptographic signing or non-repudiation.
- If source feeds change between runs, digest equality is not expected even with the same scan input.

## Suggested Release/Operations Checklist

- Generate runmanifest for all scheduled runs.
- Verify each generated runmanifest immediately after pipeline completion.
- Verify manifests again in CI before publish/share.
- Treat unverified manifests as non-authoritative for audit decisions.
- Store runmanifest with JSON/CSV/Markdown artifacts.
- Track retained manifests by run date and scanner input hash.
- Periodically test verification against known tamper samples.
