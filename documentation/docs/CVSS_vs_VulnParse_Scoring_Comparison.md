# CVSS vs VulnParse-Pin: Technical Scoring Comparison

**Objective:** Compare static CVSS-only vulnerability triage against VulnParse-Pin v2.0 (`Apache-2.0`) dual-track scoring (`Scoring@3.0`), Attack Capability Inference (`ACI@2.0`), CISA BOD 26-04 SSVC triage (`Triage@2.0`), and cross-run drift detection (`DiffEngine`).

---

## Why CVSS Alone Fails Operations Teams

CVSS base scores measure **technical severity at disclosure** assuming theoretical worst-case impact. They do not tell you:

1. **Whether exploitation is occurring in the wild** (CISA KEV, verified exploit code, or empirical EPSS v5 exploit probability/percentile).
2. **Whether the vulnerable service is exposed or internal** (`assets.yaml` `internet_facing` + Nmap open-port verification).
3. **Whether a finding is CVE-backed or an exposure/SAST weakness** (Nuclei default-logins/misconfigs, Semgrep/CodeQL SAST rules, uncredentialed banners).
4. **Whether a 60-day deferral or baseline assumption became stale** between scans (KEV addition, EPSS spike, or exposure flip).

VulnParse-Pin v2.0 computes exact **CVSS v2.0, v3.0, v3.1, and v4.0** base scores using a clean-room stdlib-only Apache-2.0 engine (`src/vulnparse_pin/utils/cvss_utils.py`, zero LGPL `cvss` dependency), resolves authoritative provenance (`NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing`), and feeds CVSS into a multi-signal decision pipeline rather than treating CVSS as the final priority.

---

## Concrete Comparison Case Studies (v2.0 `Scoring@3.0` + `Triage@2.0`)

### Case Study 1: Low/Medium CVSS, Active Exploitation

**Scenario:** An internet-facing edge service carries **CVE-2020-10148** (CVSS `3.7` Low / or similar Low-CVSS auth bypass) that is listed in **CISA KEV**, has a **verified public exploit**, and has **EPSS v5 = 0.89 (`99th` percentile)**.

| Dimension | CVSS-Only Scanner | VulnParse-Pin v2.0 (`Scoring@3.0` + `Triage@2.0`) |
| --- | --- | --- |
| Base CVSS Signal | `3.7` (**Low**) | `3.7` (NVD provenance retained as base input) |
| EPSS v5 Piecewise | Ignored | `+4.82` pts (interpolated on `[0.50→4.2, 1.0→5.0]`) |
| CISA KEV + Verified Exploit | Ignored | `+4.5` (KEV) `+ 0.5` (verified exploit with KEV, non-double-counted) |
| Asset Exposure Bonus | Ignored | `+1.25` (`internet_facing=true`) |
| `raw_risk_score` / `operational_score` | `3.7` static | `14.77 / 16.0` (`Critical` band), **`9.23 / 10.0`** operational |
| SSVC / Remediation SLA | Deferred / ignored (`Low`) | **`P1` (`OAL-1`, `Act`) — `3-day + Forensic Triage`** |

**Outcome:** A CVSS-only workflow ignores a `3.7` finding; VulnParse-Pin surfaces it at the top of the `3-day + Forensic Triage` queue under both `default` and `bod-26-04` profiles.

### Case Study 2: High CVSS (9.8), No Active Exploitation on Internal Asset

**Scenario:** An internal, non-internet-facing host (`internet_facing=false`, `declared_criticality=medium`) has a CVE with **CVSS `9.8`**, **CISA KEV = `false`**, **verified exploit = `false`**, and **EPSS v5 = `0.008` (`< 4%`, `~60th` percentile)**.

| Dimension | CVSS-Only Scanner | VulnParse-Pin v2.0 (`Scoring@3.0` + `Triage@2.0`) |
| --- | --- | --- |
| Base CVSS Signal | `9.8` (**Critical**) | `9.8` (authoritative provenance preserved) |
| EPSS v5 Piecewise | Ignored | `+0.36` pts (`0.008 / 0.04 * 1.8`) |
| KEV / Verified Exploit | Ignored | `+0.0` (neither signal present) |
| Asset Exposure Bonus | Ignored | `+0.0` (`internet_facing=false`) |
| `raw_risk_score` / `operational_score` | `9.8` static | `10.16 / 16.0` (`High` band), **`6.35 / 10.0`** operational |
| SSVC / Remediation SLA (`bod-26-04`) | Treated as emergency (`Critical`) | **`P3` (`OAL-3`, `Track`) — `Fix on Upgrade`** *(not `Act` or `60-day`)* |
| SSVC / Remediation SLA (`default`) | Treated as emergency (`Critical`) | **`P3` (`OAL-3`, `Track*`) — `60-day`** |

**Outcome:** Instead of triggering an emergency fire drill for every unexploited CVSS 9.8 internal finding, VulnParse-Pin places it in a scheduled `60-day` / `Fix on Upgrade` queue—and documents the exact rationale in the **Decision Defense Dossier**.

### Case Study 3: Non-CVE Exposure & Static SAST Guardrail (Track B `exposure_weakness`)

CVSS-only tools struggle when findings have **no CVE** (e.g., Nuclei `default-login` templates, exposed `.env` files) or noisy **SAST** findings (e.g., Semgrep rule hits):

- **Nuclei `default-login` on internet-facing asset (`active_dast`, `signal_reliability = 1.0`):** `ACI@2.0` infers `auth_bypass`; Track B scores it into `P1` (`Act`, `3-day + Forensic Triage` under `bod-26-04`) even with zero CVEs.
- **Uncorroborated Static SAST (`static_sast`, `signal_reliability = 0.55`):** `Scoring@3.0` scales raw risk by `0.55`, and `Triage@2.0` enforces the **SAST P1-cap guardrail** (`static_sast_p1_cap: true`), preventing uncorroborated SAST hits from flooding `P1` while permitting corroborated high-confidence internet-facing RCE/SQLi/Auth-Bypass findings (`CWE-78`/`89`/`94`/`287`/`306`/`434`/`502`/`798`/`918`) to escalate.

---

## Side-by-Side Model Comparison

| Capability | Static CVSS Only | VulnParse-Pin v2.0 (`Scoring@3.0` + `Triage@2.0`) |
| --- | --- | --- |
| **CVSS Versions & Engine** | Depends on scanner output; often mixed v2/v3 without provenance | Clean-room Apache-2.0 CVSS **v2.0 / v3.0 / v3.1 / v4.0** calculator; `NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing` |
| **Exploitation Likelihood** | Static base severity | **EPSS v5** monotonic piecewise breakpoints + **FIRST percentile** (`>= 90th`, `>= 95th`) |
| **Active Exploitation** | Ignored | **CISA KEV** (`+4.5`) + **Verified Exploit** (`+2.0`, or `+0.5` with KEV; zero heuristic double-count) |
| **Non-CVE Weaknesses** | Scanner severity label only | **Track B (`exposure_weakness`)** with `ACI@2.0` capabilities/chains & CWE weighting |
| **Detection Confidence** | All scanners treated equally | `signal_reliability` by `detection_mode` (`1.0` DAST/cred, `0.90` SCA, `0.85` banner, `0.55` SAST + P1-cap) |
| **Decision Framework** | Arbitrary severity cutoffs | **`default`** and **`bod-26-04` SSVC** (`Act`, `Attend`, `Track*`, `Track`; `3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade`) |
| **Multi-CVE Findings** | Single highest or arbitrary CVE | Stacked decay aggregation (`decay=0.35`, `max_contributors=8`) + secondary-KEV union tracking |
| **Cross-Run Drift & Deferrals** | Manual spreadsheet tracking | **`vpp diff`** + `decisions.yaml` predicates + fail-closed `--fail-on stale-assumption` CI gate (exit `2`) |
| **Audit Evidence** | Raw export | **Decision Defense Dossier** (HTML/MD), **Executive Roadmap**, & hash-chained **RunManifest v2** |

---

## v2.0 `Scoring@3.0` Formula Reference

```text
Track A (cve_threat):
  cve_raw = cvss_score
          + epss_v5_piecewise(epss_score)          # 0.0..5.0 via (0.04->1.8, 0.10->3.0, 0.50->4.2, 1.0->5.0)
          + (4.5 if in_kev else 0.0)
          + (0.5 if verified_exploit and in_kev else 2.0 if verified_exploit else 0.0)

  stacked_cve_raw = sum(sorted_cve_raw[i] * (0.35 ** i) for i in range(min(n, 8)))
  raw_score = clamp(stacked_cve_raw + (1.25 if internet_facing else 0.0) + criticality_bonus, 0.0, 16.0)
  operational_score = (raw_score / 16.0) * 10.0

Track B (exposure_weakness):
  base_score = scanner_cvss_score (or vector) else severity_base[scanner_severity]
  unweighted_raw = base_score + aci_cap_bonus + aci_chain_bonus + cwe_bonus + (1.5 if internet_facing else 0.0)
  raw_score = clamp(unweighted_raw * signal_reliability, 0.0, 16.0)
  operational_score = (raw_score / 16.0) * 10.0

Risk Bands (raw_score):
  Critical >= 12.8 | High >= 9.6 | Medium >= 6.4 | Low >= 3.2 | Informational < 3.2
```

### Verified v2.0 Empirical Scale Context

In `benchmarks/bench_scale.py` (see [Benchmarks](Benchmarks.md) for full environment details and stage timings):

- **500,000 raw findings** (`335,758` canonical after cross-scanner deduplication across Nessus, Trivy, Nuclei, Semgrep, and Nmap) processed in `87.362s` (`5,723.3 raw/s`), isolating **`107,669` `P1`** findings under `--profile bod-26-04` and **`11,601` KEV-matched** findings, with `< 0.87s` UI/Summary query time.
- **700,000 raw findings** (`420,846` canonical) processed in `211.531s` (`3,309.2 raw/s`), isolating **`139,501` `P1`** findings and **`14,423` KEV-matched** findings with `< 0.96s` UI/Summary query time.

---

## Boundary: What VulnParse-Pin Does Not Replace

VulnParse-Pin models **asset-context exposure** (`assets.yaml` `internet_facing` + Nmap open ports) and **detection-mode reliability**, not live L3–L7 firewall/WAF/segmentation packet reachability or runtime eBPF call-graph reachability. Treat `Scoring@3.0`, `ACI@2.0`, and `Triage@2.0` as deterministic, audit-defensible prioritization inputs paired with compensating-control validation in `decisions.yaml`.

---

## Appendix: Default v2 `scoring.json` Policy

```json
{
  "version": "v2",
  "epss": {
    "scale": 5.0,
    "min": 0.0,
    "max": 1.0,
    "use_percentile": true,
    "high_cutoff": 0.10,
    "medium_cutoff": 0.04,
    "percentile_high_cutoff": 0.95,
    "percentile_medium_cutoff": 0.90,
    "breakpoints": [
      [0.0, 0.0],
      [0.04, 1.8],
      [0.10, 3.0],
      [0.50, 4.2],
      [1.0, 5.0]
    ]
  },
  "evidence_points": {
    "kev": 4.5,
    "exploit": 2.0,
    "verified_exploit": 2.0,
    "verified_exploit_with_kev": 0.5,
    "heuristic_exploit": 0.0
  },
  "bands": {
    "critical": 12.8,
    "high": 9.6,
    "medium": 6.4,
    "low": 3.2
  },
  "aggregation": {
    "asset_score": "max",
    "finding_cve_score": "stacked_decay",
    "finding_cve_decay": 0.35,
    "finding_cve_max_contributors": 8
  },
  "risk_ceiling": {
    "max_raw_risk": 16.0,
    "max_operational_risk": 10.0
  },
  "signal_reliability": {
    "enabled": true,
    "weights": {
      "active_dast": 1.0,
      "credentialed_host": 1.0,
      "sca_container": 0.9,
      "uncredentialed_banner": 0.85,
      "static_sast": 0.55,
      "network_probe": 0.8
    }
  }
}
```
