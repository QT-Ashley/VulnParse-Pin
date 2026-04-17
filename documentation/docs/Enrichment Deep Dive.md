# Enrichment Deep Dive

This document explains VulnParse-Pin enrichment sources, runtime flow, policy controls, and how to interpret enrichment-derived output fields.

## Purpose

Enrichment adds threat and context signals to scanner findings so downstream prioritization can distinguish:

- baseline scanner context,
- known exploitation and prevalence signals,
- exploitability indicators,
- confidence provenance.

Enrichment does not replace scanner truth. It augments findings with external intelligence and records source evidence.

## Enrichment Sources

VulnParse-Pin enrichment currently integrates the following source families:

- CISA KEV
- EPSS
- Exploit-DB
- NVD
- GHSA

### CISA KEV

What it provides:

- Presence/absence of CVE in Known Exploited Vulnerabilities catalog.

How it is represented:

- `finding.cisa_kev` boolean.
- Confidence/source contribution includes `kev` when matched.

Implementation details:

- Loaded through feed-cache workflow with TTL and checksum sidecars.
- Supports online and offline file import modes.

Implications:

- KEV hit is a strong prioritization signal and can influence exploitability interpretation.

### EPSS

What it provides:

- Probabilistic exploitation likelihood score per CVE.

How it is represented:

- `finding.epss_score` float.
- Confidence/source contribution includes `epss` when populated.

Implementation details:

- Supports streamed online `.csv.gz` and offline `.csv`/`.csv.gz` import.
- Normalized via scoring policy in pass phases.

Implications:

- EPSS helps rank findings with similar base severity.
- Absence of EPSS score is explicitly tracked as a miss during enrichment telemetry.

### Exploit-DB

What it provides:

- Known exploit references and exploit availability evidence.

How it is represented:

- `finding.exploit_references` list.
- `finding.exploit_available` boolean.
- Confidence/source contribution includes `exploitdb` when exploit signal is present.

Implementation details:

- Can run from online import or offline local dataset.
- Feed cache and integrity controls apply to source ingestion.

Implications:

- Presence of exploit references is a high-value operational signal.

### NVD

What it provides:

- CVSS vectors/scores and fallback metadata for CVE-driven normalization.

How it is represented:

- `finding.cvss_vector`
- `finding.cvss_score`
- Confidence/source contribution includes `nvd` when lookup produces usable data.

Implementation details:

- Uses NVD cache policy with yearly/modified feed control.
- Supports targeted CVE loading and SQLite-backed optimization.

Implications:

- NVD helps normalize inconsistent scanner-provided vector data.
- Sentinel vector markers are used when no authoritative vector is available.

### GHSA

What it provides:

- GitHub advisory matches by CVE and package token.
- Advisory severity and references.
- Optional exploit-signal inference from high/critical advisories.

How it is represented:

- `finding.enrichment_sources` includes `ghsa` when matched.
- `finding.references` may be augmented with GHSA advisory links.
- `finding.confidence_evidence` can include:
  - `ghsa`
  - `ghsa_bonus`
  - `ghsa_exploit_signal`
- `finding.exploit_available` may be promoted when configured high-severity signal mode is enabled.

Implementation details:

- CLI activation is required (`--ghsa`); config does not auto-enable.
- Online mode supports CVE prefetch budget (`--ghsa-budget` or config fallback).
- Token auth uses configured env var (`enrichment.ghsa_token_env`), defaulting to `VP_GHSA_TK`, with `GITHUB_TOKEN` fallback.
- Offline mode supports advisory database file or repo-directory ingest.
- SQLite warm-cache accelerates repeated offline loads for target CVEs.

GHSA auth hardening:

- `ghsa_token_env` is validated as an env-var name (`^[A-Za-z_][A-Za-z0-9_]{0,127}$`).
- Token values are rejected if they contain header-unsafe control characters (`\r` or `\n`).
- Token values must match known GitHub token prefixes:
  - `ghp_`
  - `gho_`
  - `ghu_`
  - `ghs_`
  - `ghr_`
  - `github_pat_`
- Invalid custom env names or rejected token values fall back to the next candidate (`GITHUB_TOKEN`), and secrets are never logged.

Implications:

- GHSA expands context where CVE metadata alone is sparse.
- Signal bonus and exploit promotion behavior are policy-controlled and auditable.

## Runtime Flow

At a high level, enrichment runs before pass phases and updates each finding in-place:

1. Normalize confidence policy.
2. Build source lookups (KEV/EPSS/NVD/GHSA indexes).
3. For each finding, evaluate CVEs and enrichment matches.
4. Merge source-derived fields (scores, KEV flags, references, vectors).
5. Compute source-attributed confidence and evidence map.
6. Emit summary telemetry and miss logs.

## Confidence and Source Evidence

Confidence is derived from:

- baseline scanner signal,
- per-source weights,
- GHSA advisory count bonus (bounded),
- optional GHSA exploit-signal bonus.

Output fields:

- `finding.confidence` integer score.
- `finding.confidence_evidence` map containing component contributions and final cap.

Interpretation guidance:

- Treat confidence as provenance strength, not direct risk severity.
- Compare confidence with risk score and triage priority for final decisions.

## Offline vs Online Modes

General behavior:

- Online mode favors freshness with network dependency.
- Offline mode favors deterministic reproducibility.

Operational guidance:

- Use offline mode for controlled, repeatable CI/CD and regulated workflows.
- Use online mode for near-real-time feed freshness.

## Caching and Integrity

Enrichment source ingestion uses cache and integrity controls across loaders.

Common controls include:

- TTL-based freshness,
- content checksum sidecars,
- optional HMAC-integrity modes via environment variables,
- bounded response-size protections for remote fetches.

For deep implementation details, see:

- `Caching Deep Dive`
- `Runtime Policy Deep Dive`

## Field Interpretation Reference

Common output fields affected by enrichment:

- `cisa_kev`: KEV membership signal.
- `epss_score`: exploitation probability signal.
- `cvss_vector` and `cvss_score`: normalized vector/score path.
- `exploit_available`: exploitability indicator from exploit refs, KEV implication, or configured GHSA signal path.
- `enrichment_sources`: ordered source provenance list.
- `confidence` and `confidence_evidence`: source-attributed confidence model outputs.

## Technical Caveats

- Source availability varies by network mode, cache freshness, and dataset completeness.
- Missing source data is expected in some environments and is logged as miss telemetry.
- Confidence contribution from sources is configurable; changing policy can alter downstream ranking behavior.
- GHSA high-severity exploit-signal promotion is opt-in by policy.

## Implementation Pointers

Core implementation locations:

- `src/vulnparse_pin/app/enrichment.py`
- `src/vulnparse_pin/app/enrichment_source_loader.py`
- `src/vulnparse_pin/utils/enricher.py`
- `src/vulnparse_pin/utils/ghsa_enrichment.py`
- `src/vulnparse_pin/resources/config.yaml`
- `src/vulnparse_pin/core/schemas/config.schema.json`

Key test coverage locations:

- `tests/test_ghsa_enrichment.py`
- `tests/test_enrichment_confidence_policy.py`
- `tests/test_config_schema_validation.py`
- `tests/test_cli_flags_matrix.py`

## Recommended Validation Checklist

1. Validate config schema and policy bounds.
2. Run focused source tests after enrichment changes.
3. Run full regression suite before release.
4. Inspect output artifact samples for source attribution and confidence evidence.
5. Confirm run manifests reflect selected mode and source behavior.
