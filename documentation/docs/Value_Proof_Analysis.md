# VulnParse-Pin Value Proof & Methodology Analysis

**Objective:** Document how VulnParse-Pin v2.0 (`Apache-2.0`) converts noisy, multi-scanner output into auditable, evidence-backed remediation queues—and clearly separate **historical v1.x dataset measurements** from **verified v2.0 scale benchmarks**.

---

## Executive Summary

Static CVSS-only triage treats every `9.8` finding as an emergency while burying `3.7–5.5` CVEs that are actively exploited in the wild—and ignores non-CVE exposures (Nuclei default logins, exposed admin panels, SAST findings) altogether.

VulnParse-Pin v2.0 addresses this with a deterministic, offline-capable DuckDB pipeline:

1. **Dual-Track Scoring (`Scoring@3.0`):** Track A (`cve_threat`) blends authoritative CVSS (`NVD > CNA > GHSA > OSV > Scanner-Supplied`), EPSS v5 piecewise probabilities + FIRST percentiles, non-double-counted CISA KEV + verified exploit signals, and `assets.yaml` exposure; Track B (`exposure_weakness`) scores non-CVE Nuclei/SAST/exposure findings weighted by `detection_mode` `signal_reliability`.
2. **Decision-Ready SSVC & SLAs (`Triage@2.0`):** Maps every finding to `default` or `--profile bod-26-04` SSVC actions (`Act`, `Attend`, `Track*`, `Track`) and concrete SLAs (`3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade`), with static SAST P1-cap guardrails.
3. **Continuous Assumption Governance (`vpp diff`):** Detects newly introduced high-risk findings, threat-intel escalations, verified remediations, shadow-asset deltas, and **stale-assumption deferral invalidations** (including `60-day -> 14-day/3-day` baseline drift under `--fail-on stale-assumption`).
4. **Audit-Defensible Artifacts:** Emits self-contained **Decision Defense Dossiers** (`dossier.html`, `dossier.md`), **Executive Client Roadmaps**, and strictly read-only verifiable **RunManifest v2** chains (`vpp verify`).

---

## Methodology & Boundary Transparency

### Network & Operational Reachability Boundary

VulnParse-Pin models **asset-context exposure** (`assets.yaml` `internet_facing` rules + Nmap open-port verification) and **detection-mode reliability** (`credentialed_host` / `active_dast` `1.0`, `sca_container` `0.90`, `uncredentialed_banner` `0.85`, `static_sast` `0.55`). It does **not** perform live L3–L7 firewall/WAF/network-segmentation reachability probing or runtime eBPF call-graph analysis. Teams should treat `Scoring@3.0` and `Triage@2.0` as deterministic prioritization evidence paired with compensating-control validation recorded in `decisions.yaml`.

### Benchmark & Dataset Integrity Policy

To prevent mixing v1.x and v2.0 metrics or presenting synthetic projections as empirical measurements:

- **v2.0 Empirical Scale & Deduplication Numbers** below come exclusively from executed `benchmarks/bench_scale.py` runs recorded in [Benchmarks](Benchmarks.md).
- **Historical v1.x 5,000-Finding Dataset Numbers** below are explicitly preserved as `v1.0.1` (`March 26, 2026`) empirical measurements on `Lab_test_scaled_5k.nessus` under the legacy `Scoring@1.0`/`v1` ceiling (`25.0`) prior to v2.0's `16.0` ceiling, EPSS v5, and `Triage@2.0` overhaul.

---

## Verified v2.0 Multi-Scanner Scale & Prioritization Evidence

From `benchmarks/bench_scale.py` (`--profile bod-26-04`, cold cache, mixed Nessus `.nessus` + Trivy `.sarif` + Nuclei `.jsonl` + Semgrep `.sarif` + Nmap `.xml`, `assets.yaml` + `decisions.yaml`, see [Benchmarks](Benchmarks.md)):

| Scale Run | Raw Findings | Cross-Scanner Deduplicated | Canonical Unique Findings | `P1` (`bod-26-04`) | KEV-Matched Findings | Total Runtime | UI + Summary Query |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **500k Multi-Scanner** | `500,000` | `56,327` merged | `335,758` | `107,669` (`32.1%`) | `11,601` | `87.362s` (`5,723.3 raw/s`) | `0.8695s` |
| **700k Multi-Scanner** | `700,000` | `102,225` merged | `420,846` | `139,501` (`33.1%`) | `14,423` | `211.531s` (`3,309.2 raw/s`) | `0.9523s` |

What this demonstrates operationally in v2.0:

1. **Cross-Scanner Deduplication:** `56,327` (at 500k) and `102,225` (at 700k) overlapping detections across Nessus, Trivy, Nuclei, and Semgrep were collapsed into canonical `(asset_id, primary_cve)` / `(asset_id, nocve_key)` findings while preserving all raw detections in `finding_evidence`.
2. **Sub-Second Analyst Queryability:** Even with `420,846` canonical rows in `.vpp.db`, paged priority queries and summary aggregations execute in `< 1.0s` (`0.8695s` / `0.9523s`), backing `vpp ui` and on-demand `vpp export`.
3. **High-Signal Triage Isolation:** KEV-matched findings (`11,601` / `14,423`) and exposed high-impact Track B findings are isolated cleanly into `3-day + Forensic Triage` / `14-day` SLAs while uncorroborated `static_sast` findings are capped out of `P1` by the SAST P1-cap guardrail.

---

## Historical v1.x Noise-Reduction Baseline (`Lab_test_scaled_5k.nessus`, March 26, 2026)

> [!NOTE]
> The metrics in this section were measured on **VulnParse-Pin `v1.0.1` (`2026-03-26`)** using the legacy `v1` scoring model (`max_raw_risk = 25.0`, `kev = 2.5`, `exploit = 5.0`, `epss * 10 * 0.6/0.4`) on the 5,000-finding `Lab_test_scaled_5k.nessus` dataset (10 assets). They are retained for historical reference; v2.0 uses `Scoring@3.0` (`max_raw_risk = 16.0`, EPSS v5 piecewise cutoffs, and `Triage@2.0`).

In that historical 5,000-finding v1.0.1 run:

- **CVSS-only Critical/High:** `1,250` findings (`25.0%` of scan: ~`625` Critical, ~`625` High).
- **VulnParse-Pin v1.0.1 Critical/High:** `72` findings (`1.4%` of scan: `35` Critical, `37` High) — a **`94.2%` reduction** in urgent queue volume.
- **Exploitation coverage:** All `47` findings with public exploits (`0.9%`), all `10` CISA KEV findings (`0.2%`), and all `8` dual-signal (`KEV + Exploit`) findings were surfaced inside the top prioritized tiers (`26` immediate 24–48h findings), including low-CVSS actively exploited CVEs such as `CVE-2020-10148` (CVSS `3.7`, KEV + Exploit) and `CVE-2019-12989` (CVSS `5.5`, KEV + Exploit).

---

## Qualitative Value Drivers Introduced in v2.0

| Operational Challenge | v2.0 Capability | Auditable Output |
| --- | --- | --- |
| **Non-CVE exposure & SAST noise** | Track B `exposure_weakness` + `ACI@2.0` + `signal_reliability` (`0.55` SAST + P1-cap) | `scores.score_trace_json`, `triage_decisions`, `dossier.html` |
| **Federal / BOD 26-04 compliance** | `--profile bod-26-04` SSVC decision tree (`Act`/`Attend`/`Track*`/`Track`) | `3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade` buckets |
| **Stale risk acceptances & silent drift** | `decisions.yaml` assumption predicates + `vpp diff --fail-on stale-assumption` | Exit code `2` in CI + `diff_pr_comment.md` + Dossier invalidation alerts |
| **Unowned / shadow infrastructure** | 5-tier `assets.yaml` matching + `unmatched_shadow` disclosure | Shadow Asset table in CLI summary, TUI, Roadmap, and Dossier |
| **Auditor & tamper-resistance demands** | `RunManifest` v2 + `ledger_events` SHA-256 chain + read-only `vpp verify` | `runmanifest.json` verified without write permissions |

---

## Reproduce Locally in 30 Seconds (100% Offline)

```bash
# Run the bundled multi-scanner v2.0 demo (Nessus + Trivy + Nuclei + Semgrep + Nmap + diff)
vpp demo --no-ui --profile bod-26-04 --output-dir out/demo

# Verify the generated RunManifest strictly read-only
vpp verify out/demo/runmanifest.json

# Or run your own scan and diff against a baseline run
vpp scan current.nessus --assets assets.yaml --decisions decisions.yaml \
  --profile bod-26-04 --baseline-run-id run_base --db workspace.vpp.db \
  --output-all out/current
```

## Related Docs

- [Benchmarks](Benchmarks.md)
- [CVSS vs VulnParse-Pin: Technical Scoring Comparison](CVSS_vs_VulnParse_Scoring_Comparison.md)
- [Value Proposition One-Pager](Value_Proposition_One_Pager.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Output Interpretation](Output%20Interpretation.md)
