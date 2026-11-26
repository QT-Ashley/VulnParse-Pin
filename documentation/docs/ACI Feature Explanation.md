# Attack Capability Inference (ACI) Feature Explanation

This page explains what `ACI@2.0` is, what problem it solves across CVE and non-CVE scanner findings, what DuckDB inputs it consumes, and how its outputs appear in scoring, triage, the Textual TUI, and Decision Defense Dossiers.

## Why ACI Exists

Vulnerability scanners emit thousands of findings across Nessus, OpenVAS, Qualys, Trivy/Grype/Semgrep/CodeQL SARIF, and Nuclei JSONL. Analysts still need a deterministic way to answer:

- Which findings imply high-impact attacker capability (e.g., `remote_execution`, `command_execution`, `auth_bypass`, `sql_injection`, `deserialization`, `ssrf`), especially when **no CVE exists** (Track B `exposure_weakness`)?
- Which findings combine into multi-step attack pathway candidates (`chain_candidates`)?
- Which findings should break ties inside `TopN@2.0` and qualify for SSVC `automatable` / `technical_impact=total` escalation in `Triage@2.0`?

ACI adds a deterministic, explainable inference pass that preserves raw scanner truth while feeding structured capability signals into `Scoring@3.0`, `Triage@2.0`, and `TopN@2.0`.

## What ACI@2.0 Is

`ACIV2Pass` (`ACI@2.0` in `src/vulnparse_pin/core/passes/ACI/aci_pass.py`) is the default-enabled DuckDB-first pass that:

1. Streams findings from `.vpp.db` joined with `finding_cves`, `enrichment_snapshots`, and `finding_evidence`.
2. Extracts normalized signals from text, structured Nuclei/SARIF tags, CWE IDs, normalized `scanner_sig` rule IDs (`_scan_sig`), affected remote ports, and KEV/exploit flags.
3. Evaluates capability rules (with guardrails against generic remote-port or protocol-only false positives) and multi-capability chain rules.
4. Computes bounded `confidence` (`0.0–1.0`) and `uplift_score` (`0.0–max_uplift`).
5. Persists per-finding results into the DuckDB `aci_signals` table and emits `ACI@2.0` metrics/semantics.

## What ACI Is Not

ACI is decision support—not:

- proof of exploit success or network reachability
- proof of compromise
- a replacement for analyst validation or compensating-control review

## Inputs ACI@2.0 Uses

In the v2.0 DuckDB pipeline, `ACIV2Pass` joins:

- **`findings`**: `title`, `description`, `plugin_output`, `references_json`, `tags_json`, `cwes_json`, `affected_port`, `exploit_evidence`
- **`finding_cves` + `enrichment_snapshots`**: `BOOL_OR` union of `in_kev` and `verified_exploit` across **all** linked CVEs (both `primary_cve` and secondary CVEs)
- **`finding_evidence`**: distinct `scanner_sig` values aggregated across deduplicated cross-scanner evidence rows, parsed via `_scan_sig`

## Outputs ACI@2.0 Produces

### DuckDB `aci_signals` Table

For every finding in a run, `ACIV2Pass` writes one row to `aci_signals`:

- `capabilities_json`: sorted list of inferred capabilities (e.g., `["auth_bypass", "remote_execution"]`)
- `chains_json`: matched attack pathway labels (e.g., `["Initial access and credential theft pathway"]`)
- `matched_tokens_json`: normalized tokens/signals that triggered inference
- `confidence`: bounded float in `[0.0, 1.0]`
- `uplift_score`: bounded float in `[0.0, max_uplift]`

### Metrics & Derived Output

For runs up to `10,000` findings, `DerivedPassResult` also populates `finding_semantics` in memory (`asset_semantics` up to `50,000` assets) alongside aggregate `metrics` (`total_findings`, `inferred_findings`, `coverage_ratio`, `capabilities_detected`, `chain_candidates_detected`, `confidence_buckets`, `uplifted_findings`). Larger runs stream directly through DuckDB without holding per-finding semantic objects in RAM.

## How ACI Integrates with Scoring@3.0, Triage@2.0, and TopN@2.0

Unlike v1.x (where `ACI@1.0` ran after `Scoring@2.0`), in v2.0 **`ACI@2.0` runs before `Scoring@3.0`**:

1. **Track B (`exposure_weakness`) in `Scoring@3.0`:** Non-CVE findings (Nuclei, Semgrep, misconfigurations) receive `+3.5` for high-impact ACI capabilities (or `+2.0` for general ACI capabilities) and `+1.0` for `aci_chains`, before applying `signal_reliability`.
2. **SSVC & Guardrails in `Triage@2.0`:**
   - High-impact capabilities/tokens (`remote_execution`, `command_execution`, `auth_bypass`, `default-login`, `rce`) feed SSVC `exploitation=active` (when `scoring_track == "exposure_weakness"` and `signal_reliability >= 0.90`), `automatable=true`, and `technical_impact=total`.
   - `aci_chains` elevate findings to `P2` (`Attend`, `60-day` in `bod-26-04`; `14-day` in `default`).
   - High-impact ACI capabilities/chains can corroborate internet-facing `High`/`Critical` `static_sast` findings under the SAST P1-cap guardrail.
3. **Tie-Breaking in `TopN@2.0`:** `TopNV2Pass` orders ties after `(priority_tier, operational_score, epss_score)` by `aci.uplift_score DESC`.

## Display in `vpp ui` and Decision Defense Dossiers

- **`vpp ui`:** The finding detail inspector renders `ACI Caps` and `ACI Chains` directly from `aci_signals` (with `score_trace` fallback).
- **Decision Defense Dossiers (`dossier.html`, `dossier.md`):** Prioritized finding blocks display **ACI Signals** (`capabilities`, `chains`, `confidence`, `uplift`).
- **JSON & CSV Exports:** `namespace` JSON includes `derived["ACI@2.0"]` (`capabilities`, `chains`, `matched_tokens`, `confidence`, `uplift_score`); `full` and `audit` CSV profiles include `aci_capabilities`, `aci_chains`, `aci_confidence`, and `aci_uplift_score`.

## Guardrails and Token Vocabulary Governance

- **Hybrid token model (`tn_triage.json`):** Maintainer-owned core tokens + word-boundary short-token matching (`rce`, `sqli`, `lfi`, `smb`, `ssh`, `rdp`, `rpc`, `xss`) + structured tag/CWE maps + user `signal_aliases`, `disabled_core_tokens`, or `token_mode: "replace"`.
- **Precision guardrails:** `remote_service` port matches alone never trigger `remote_execution` or `initial_access`, and bare protocol tokens (`smb`, `ssh`, `rdp`, `rpc`) require lateral/exploit/credential context before inferring `lateral_movement`.

## Related Docs

- [ACI Rule Authoring Tutorial](ACI%20Rule%20Authoring%20Tutorial.md)
- [ACI Technical Deep Dive](ACI%20Technical%20Deep%20Dive.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Output Interpretation](Output%20Interpretation.md)
- [RunManifest Overview](RunManifest.md)
