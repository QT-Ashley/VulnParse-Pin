# RunManifest Overview

RunManifest v2 is VulnParse-Pin's provenance, integrity, and audit-defense artifact (`manifest_version: "2.0"`). Built directly from `.vpp.db` via `build_runmanifest_from_db()` (`src/vulnparse_pin/utils/runmanifest.py`), it captures:

- Run metadata (`run_id`, `profile`, `assets_sha256`, `decisions_sha256`, runtime version).
- SHA-256 input & configuration fingerprints (`inputs.input_files_sha256`, `config_hashes`).
- Output file paths and SHA-256 digests (`outputs`, `output_hashes`) across the exported artifact bundle.
- Threat-intelligence metadata & snapshot statistics (`enrichment_summary`).
- Per-pass summaries (`NmapAdapter`, `ACI@2.0`, `Scoring@3.0`, `Triage@2.0`, `Summary@2.0`) including multi-CVE KEV parity.
- An append-only, SHA-256 hash-chained `decision_ledger` backed by DuckDB `ledger_events`.
- Deterministic `verification.manifest_digest` for offline tamper detection.

## Why RunManifest Exists

Raw scanner output tells you what was found. Decision Defense Dossiers tell stakeholders *why* a finding was prioritized or deferred. **RunManifest v2** cryptographically ties the inputs, policies, threat-intel snapshots, decision ledger, and exported artifacts together so teams can verify nothing was altered after the run.

## Practical Uses

1. **Triage & Audit Evidence Pack:** Attach `runmanifest.json` alongside Decision Defense Dossiers (`dossier.html`, `dossier.md`) and CSV/JSON exports to prove scoring, SSVC decisions, and deferral evaluations match the recorded policy and threat feeds.
2. **Repeatability & Drift Audits:** Compare `config_hashes`, `assets_sha256`, `decisions_sha256`, and `enrichment_summary.intel_metadata` across runs (complemented by `vpp diff`).
3. **Tamper-Evident CI Gates:** Run `vpp verify <runmanifest.json>` in CI/CD or before archival to validate both the manifest digest/ledger chain and the SHA-256 digests of every listed output artifact on disk.

## What Is Captured

Top-level sections (`runManifest.schema.json`, Draft 2020-12):

- `manifest_version` (`"2.0"`)
- `runmanifest_mode` (`"compact"` or `"expanded"`)
- `run_id`, `profile`, `assets_sha256`, `decisions_sha256`
- `generated_at_utc`
- `runtime` (`vulnparse_version`, `python_version`, `platform`)
- `inputs` (`target_path`, `target_sha256`, `input_files`, `input_files_sha256`, `baseline_run_id`)
- `config_hashes` (`config_yaml_sha256`, `scoring_json_sha256`, `tn_triage_json_sha256`, `assets_sha256`, `decisions_sha256`)
- `outputs` & `output_hashes` (in `--output-all`, hashes all 6 written output keys: `json`, `csv`, `executive_markdown`, `technical_markdown`, `dossier_markdown`, `dossier_html`)
- `enrichment_summary` (`kev_enabled`, `epss_enabled`, `nvd_enabled`, `exploit_enabled`, `ghsa_enabled`, `osv_enabled`, `intel_metadata`, `stats`)
- `pass_summaries`
- `decision_ledger`
- `verification` (`canonicalization: "json-c14n-v1"`, `volatile_fields_excluded`, `manifest_digest`)

## Decision Ledger at a Glance

The embedded `decision_ledger` mirrors the DuckDB `ledger_events` table with an append-only SHA-256 hash chain:

- Sequential `seq` values starting at `1`.
- `prev_hash` links to the previous entry (`EMPTY_LEDGER_ROOT` for entry `1` / empty ledger).
- `entry_hash` protects every entry body and `evidence_digest`.
- `chain_root` anchors the final entry hash.

The ledger records ingestion quality gates (CSV drops, malformed skips, strict-ingestion / confidence rejections), ACI summaries, Scoring summaries, Triage outcomes, and webhook emission statuses.

## Output Modes

- `compact` (default): high-impact decision events with minimal overhead.
- `expanded`: richer per-finding/per-asset decision detail and SLA bucket breakdowns.

## Core Commands

Generate a RunManifest during `vpp scan`:

```bash
vpp scan scan.nessus --profile bod-26-04 --db workspace.vpp.db \
  -o out/result.json --output-runmanifest out/runmanifest.json
```

Generate the full 6-artifact `--output-all` bundle with `expanded` RunManifest mode:

```bash
vpp scan scan.nessus --profile bod-26-04 --db workspace.vpp.db \
  --output-all out/prod --runmanifest-mode expanded
```

Verify an existing RunManifest and its listed outputs (strictly read-only by default):

```bash
vpp verify out/prod_runmanifest.json
```

Enforce root confinement or inspect symlink-read overrides during verification:

```bash
vpp verify out/prod_runmanifest.json --enforce-root-read
vpp verify out/prod_runmanifest.json --allow-symlinks-read
```

## What `vpp verify` Confirms

`vpp verify` performs strictly read-only verification (no directories or log files are created unless you pass a custom `--log-file <name>`):

1. Symlink rejection on the manifest path and all listed output artifacts (unless `--allow-symlinks-read` is explicitly passed), plus optional root confinement (`--enforce-root-read`).
2. JSON Schema Draft 2020-12 conformance (`runManifest.schema.json`).
3. Per-entry hash-chain continuity (`seq`, `prev_hash`, `entry_hash`, `chain_root`).
4. Canonical `verification.manifest_digest` recomputation (`json-c14n-v1`).
5. Existence and SHA-256 digest verification (`hmac.compare_digest`) for every non-null output listed in `outputs` / `output_hashes`.

## Related Docs

- [RunManifest Technical Deep Dive](RunManifest_Technical.md)
- [Output Interpretation](Output%20Interpretation.md)
- [ScanResult & DuckDB Schema](ScanResult_Schema.md)
- [Security Features](Security%20Features.md)
