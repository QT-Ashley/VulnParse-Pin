# VulnParse-Pin Value Proposition: One-Pager

## The Problem

**Static CVSS-only vulnerability management creates noise without defensible context:**

- Scanners flood teams with uncontextualized Critical/High CVSS counts while missing low-CVSS vulnerabilities that are actively exploited in CISA KEV.
- Multi-scanner pipelines (Nessus/OpenVAS + Trivy SARIF + Nuclei + Semgrep SAST) emit overlapping and non-CVE findings with no unified reliability weighting.
- Risk acceptances and `60-day` deferrals go stale silently when a CVE enters KEV, EPSS spikes, or an asset becomes internet-facing.
- Auditors and leadership demand evidence of *why* findings were prioritized or deprioritized—not raw spreadsheets.

## The Solution: VulnParse-Pin v2.0 (`Apache-2.0`)

**Offline-first vulnerability triage, diffing, and audit defense backed by a local DuckDB workspace (`.vpp.db`):**

- **Dual-Track Risk & Reliability (`Scoring@3.0` + `ACI@2.0`):**
  - **Track A (`cve_threat`):** Authoritative CVSS v2/v3/v4 (`NVD > CNA > GHSA > OSV > Scanner-Supplied`), EPSS v5 piecewise probability + FIRST percentile, non-double-counted CISA KEV + verified exploits, and `assets.yaml` exposure.
  - **Track B (`exposure_weakness`):** Non-CVE Nuclei/SAST/misconfiguration scoring with `ACI@2.0` capability & chain inference, weighted by `detection_mode` `signal_reliability` (`1.0` active DAST/credentialed, `0.90` SCA, `0.85` banner, `0.55` SAST + P1-cap guardrail).
- **SSVC & BOD 26-04 Decision Profiles (`Triage@2.0`):** Built-in `default` and `--profile bod-26-04` SSVC trees (`Act`, `Attend`, `Track*`, `Track`) mapping directly to `3-day + Forensic Triage`, `14-day`, `60-day`, and `Fix on Upgrade` SLAs.
- **Scan-over-Scan Drift & Stale-Assumption CI Gates (`vpp diff`):** Detects new high-risk issues, threat-intel escalations, verified remediations, shadow assets, and invalidated deferrals (`--fail-on stale-assumption`, exit `2`).
- **Audit-Ready Outputs & Tamper-Evident Verification:** Self-contained HTML/Markdown **Decision Defense Dossiers**, **Executive Client Roadmaps**, **PR Diff Comments**, interactive **`vpp ui`** TUI, and strictly read-only **`vpp verify`** over hash-chained **RunManifest v2** bundles.

## Verified Evidence (Multi-Scanner Scale + Historical Baseline)

- **Verified v2.0 Scale (`benchmarks/bench_scale.py`, `bod-26-04`, cold cache):**
  - **`500,000` raw findings** across Nessus + Trivy + Nuclei + Semgrep + Nmap deduplicated (`56,327` merged) into `335,758` canonical rows, isolating `107,669` `P1` and `11,601` KEV-matched findings in `87.362s` (`5,723.3 raw/s`) with **`0.8695s`** UI + summary query time.
  - **`700,000` raw findings** deduplicated (`102,225` merged) into `420,846` canonical rows (`139,501` `P1`, `14,423` KEV) in `211.531s` with **`0.9523s`** UI + summary query time.
- **Historical v1.x Alert-Fatigue Baseline (`Lab_test_scaled_5k.nessus`, `v1.0.1`, March 26, 2026):** On a 5,000-finding Nessus dataset, legacy v1 scoring reduced Critical/High alert volume by **`94.2%`** (`1,250` CVSS Critical/High → `72` prioritized findings) while surfacing 100% of the `47` public-exploit and `10` CISA KEV findings (including `CVE-2020-10148` at CVSS `3.7`).

*(See [Benchmarks](Benchmarks.md) and [Value Proof Analysis](Value_Proof_Analysis.md) for full methodology and stage timings.)*

## Honest Boundary: Network & Operational Reachability

VulnParse-Pin evaluates **asset-context exposure** (`assets.yaml` `internet_facing` + Nmap open-port verification) and **`detection_mode` reliability**—not live L3–L7 firewall/WAF packet reachability or runtime eBPF call paths. Compensating controls are explicitly documented and continuously re-evaluated in `decisions.yaml`.

## Quick Start (`vpp` Subcommand CLI)

```bash
# 1. Run the 100% offline multi-scanner demo + dossier + diff walkthrough
vpp demo --profile bod-26-04

# 2. Scan multi-scanner inputs into DuckDB and export the full artifact bundle
vpp scan scan.nessus trivy.sarif nuclei.jsonl --assets assets.yaml --decisions decisions.yaml \
  --profile bod-26-04 --db workspace.vpp.db --output-all out/release

# 3. Gate CI on stale assumptions or new P1s
vpp diff --db workspace.vpp.db run_prev run_curr --fail-on stale-assumption --output-pr-comment pr.md

# 4. Inspect interactively or verify RunManifest strictly read-only
vpp ui --db workspace.vpp.db
vpp verify out/release_runmanifest.json
```

## Related Docs

- [Value Proof Analysis](Value_Proof_Analysis.md)
- [CVSS vs VulnParse Scoring Comparison](CVSS_vs_VulnParse_Scoring_Comparison.md)
- [Benchmarks](Benchmarks.md)
- [Getting Started In 5 Minutes](Getting%20Started%20In%205%20Minutes.md)
