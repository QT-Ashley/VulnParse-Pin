<!-- markdownlint-disable MD009 MD026 MD032 MD033 MD041 MD045 -->

<p align="center">
  <img src="/assets/logos/vpp_logo_pack_transparent/logo.svg" width="420">
</p>

<h1 align="center">VulnParse‑Pin v1.2.0</h1>

<p align="center">
Vulnerability Intelligence & Decision Support Engine
</p>

<p align="center">
Normalize • Enrich • Prioritize • Decide
</p>

<p align="center">
<a href="https://docs.vulnparse-pin.com">Documentation</a> •
<a href="https://docs.vulnparse-pin.com/Overview">Overview</a> •
<a href="https://docs.vulnparse-pin.com/Features">Features</a> •
<a href="https://docs.vulnparse-pin.com/Architecture">Architecture</a> •
<a href="https://docs.vulnparse-pin.com/Getting%20Started%20In%205%20Minutes">Getting Started</a> •
<a href="/CHANGELOG.md">Changelog</a> •
<a href="https://docs.vulnparse-pin.com/Licensing">Licensing</a>
</p>

![Static Badge](https://img.shields.io/badge/VulnParsePin-pin?style=plastic&color=%230096FF&logo=github)
![License](https://img.shields.io/badge/license-AGPLv3%2B-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Security](https://img.shields.io/badge/security-audited-green.svg)
![SBOM](https://img.shields.io/badge/SBOM-included-green.svg)
![Release Version](https://img.shields.io/github/v/tag/QT-Ashley/VulnParse-Pin)
![Last Commit](https://img.shields.io/github/last-commit/QT-Ashley/VulnParse-Pin)
![Stars](https://img.shields.io/github/stars/QT-Ashley/VulnParse-Pin)
![Issues](https://img.shields.io/github/issues/QT-Ashley/VulnParse-Pin)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/vulnparse-pin?period=total&units=INTERNATIONAL_SYSTEM&left_color=BRIGHTGREEN&right_color=BRIGHTGREEN&left_text=PyPi+downloads)](https://pepy.tech/projects/vulnparse-pin)

⭐ ***If you find VulnParse-Pin useful, please consider starring the repository to show your support!*** ⭐

⚙️ ***If you want to contribute, check out the [CONTRIBUTING.md](CONTRIBUTING.md) guide for details on how to get involved.*** ⚙️

🎗️ ***Feedback is very much desired. Please leave a discussion or issue!*** 🎗️

---

<h2 align="center">Table of Contents</h2>

<p align="center">
  <a href="#whats-new-in-v120">What's New in v1.2.0</a> <br>
  <a href="#try-it-in-60-seconds">Try It In 60 Seconds</a> <br>
  <a href="#why-vulnparse-pin-exists">Why VulnParse-Pin Exists</a> <br>
  <a href="#what-makes-vulnparse-pin-different">What Makes VulnParse-Pin Different?</a> <br>
  <a href="#where-it-fits">Where It Fits</a> <br>
  <a href="#who-is-vulnparse-pin-for">Who Is VulnParse-Pin For?</a> <br>
  <a href="#key-features">Key Features</a> <br>
  <a href="#installation">Installation</a> <br>
  <a href="#feedback-and-contributions">Feedback and Contributions</a> <br>
  <a href="#roadmap-and-future-enhancements">Roadmap and Future Enhancements</a> <br>
  <a href="#documentation">Documentation</a>
</p>

## 12,000 vulnerabilities. Which ones would an attacker exploit first?

VulnParse-Pin reduces vulnerability noise by up to **94%** and produces a **ranked, explainable remediation plan based on real-world exploitability.**

Stop sorting by severity. Start prioritizing what actually matters.

VulnParse-Pin is a **post-scan intelligence and decision support engine** that turns thousands of scanner findings into a **ranked, explainable remediation plan based on real-world exploitability**.

Most vulnerability programs prioritize by **CVSS severity alone**, which leads to **inflated backlogs** and **triage fatigue**. 

VulnParse-Pin prioritizes by:

- **Known-Exploited Risk (CISA KEV)**: KEV status and public exploit signals take precedence to focus on what matters most.
- **Real-World probability (EPSS)**: Exploitation probability is factored into scoring to surface high-risk vulnerabilities that may have lower CVSS but are more likely to be exploited.
- **Exploit Availability (ExploitDB, GHSA)**: Presence of known exploits in public databases is a critical signal for prioritization.
- **Attack Capability Context (ACI, NMAP)**: Asset context and inferred attacker capability help break ties and focus on what is most actionable.
- **Whole-of-CVEs Context**: When multiple CVEs contribute to a finding, VulnParse-Pin aggregates their signals for a more accurate risk assessment.

👉 **Find what actually matters. Defend why it matters. Act on it.**

## What's New in v1.2.0

VulnParse-Pin now goes beyond prioritization — it delivers **context-aware, explainable decision intelligence** to help you **defend your remediation decisions** and **communicate risk effectively**.

This release transforms VulnParse-Pin into a **fully auditable vulnerability intelligence decision support engine (VIDE).**

### Attack Capability Inference (ACI)

- Infers real-world attack capability from evidence signals in findings (RCE, lateral movement, privilege escalation, etc.).
- Detects potential exploit chains, not just individual vulnerabilities.

### Whole-of-CVEs Scoring

- Scores findings across **all associated CVEs** with bounded decay, not just the highest CVSS contributor. This enables a more realistic risk assessment.
- Includes full **score trace** for auditability and explainability.

### Ingestion Trust Layer

- Detect degraded or low-quality scanner input.
- Confidence scoring and strict ingestion gates.
- Decision ledger events for ingestion outcomes.

### GHSA Enrichment

- Signed + quarantined SQLite cache governance for reliable online/offline GHSA enrichment with source confidence normalization.
- Online + offline modes with error handling and fallback.
- Package-level fallback when CVE-level GHSA data is unavailable.

### NMAP Attack Surface Mapping

- Uses real open-port data to refine prioritization.
- Influences ranking **without mutating source findings**.

### Webhook Delivery

- HMAC-SHA256 signed scan-complete events with replay protection and OAL filtering for secure integration with external systems.
- Replay protection with timestamp and nonce validation.

### Why You Can Trust the Output

Most VM tools tell you *what* to fix.

VulnParse-Pin shows you:

- **Why a vulnerability is ranked where it is**
- **Which signals contributed to that decision**
- **How multiple CVEs influenced the final risk score**
- **What data quality issues may affect confidence**

Every decision includes:
- `score_trace` → how risk was calculated
- Decision ledger → how prioritization decisions were made
- Ingestion confidence → how trustworthy the input data is

👉 You’re not just prioritizing risk — you’re **proving it.**

![Infograph](documentation/img/infograph.jpg)

**In a sample dataset of 1,250 findings, VulnParse-Pin reduced triage scope to 72 high-priority items while surfacing all KEV-listed vulnerabilities at the top.**
**This resulted in a <mark>~94% reduction</mark> in triage volume without losing known-exploited risk signals.**

## Try It In 60 Seconds

No configuration required — just install and run the demo profile to see VulnParse-Pin in action with a sample OpenVAS report and Nmap context. 

### What you'll see in under a minute:

- Your **top exploitable** vulnerabilities
- Prioritization back by **real-world risk signals** (KEV, EPSS, ExploitDB, NVD, and more)
- **Explainable scoring artifacts to support your decisions**
- **Executive and technical reports for communicating risk and remediation plans**
- Automatic NMAP Attack Surface Mapping for refined prioritization based on **real open ports**

```bash
pip install vulnparse-pin
vpp --demo
```

Demo profile defaults:

- Input: packaged OpenVAS sample (`openvas_updated_test.xml`, 15 assets / 2,000 findings)
- Nmap context: packaged Nmap sample (`base_test_nmap.xml`)
- GHSA: forced `online` with `--ghsa-budget 25`
- Outputs: JSON, CSV, executive markdown, technical markdown, runmanifest

> Results are saved automatically to user's local app data and path shown in the terminal.

### What Happens?

VulnParse-Pin analyzed your report and prioritized vulnerabilities based on:
- **KEV** known-exploited status
- **EPSS** exploitation probability
- **ExploitDB** presence and recency
- **CVSS** metrics 
- Most recent **NVD** context
- **Asset context** (internal vs. external, public_ip vs private_ip, etc.)

### What This Means For You:

#### Instead of **12,000** findings with:

- CVSS-only scoring
- No exploit context
- No clear prioritization
- No asset context
- Black-box scoring with no explainability

#### You Now Have:

- **Ranked** enriched findings with exploit context and scoring metadata
- **Auditable**, prioritized outputs for technical and executive review
- **JSON, CSV, and Markdown reporting options** for downstream workflows and presentations

This is your vulnerability data, but now it's actionable and focused on what matters most. You can review the top-ranked vulnerabilities with confidence, knowing that the prioritization is based on real-world risk signals and enriched context.

***You now have a clear starting point for remediation.***

![Report Snippet](documentation/img/top20.jpg)

![Asset Prioritization Example](documentation/img/techreportsnip.jpg)

See the [Getting Started In 5 Minutes](documentation/docs/Getting%20Started%20In%205%20Minutes.md) or [Installation](documentation/docs/Installation.md) guide for more details and options.

## Why VulnParse-Pin Exists

Vulnerability scanners answer:

> "What vulnerabilities exist in my environment?"

What they don't answer is:

> "What should I fix first, and why?"

The gap is where vulnerability management fails.

---

### VulnParse-Pin closes that gap.

Instead of:

- CVSS-only prioritization
- Overload of "critical" findings
- No explainability

You get:

- [Exploit-driven prioritization](https://www.cisa.gov/known-exploited-vulnerabilities)
- [Context-aware risk modeling]
- Full explainability with auditable scoring artifacts
- Flexible reporting for technical and executive audiences
- Consistent outputs across formats for governance confidence

## What Makes VulnParse-Pin Different?

### Before vs. After Prioritization

| Traditional Tools | VulnParse-Pin |
|------------------|--------------|
| CVSS-based prioritization | Exploit + probability + context-driven prioritization |
| Black-box scoring | Fully explainable `score_trace` and decision ledger |
| Single-CVE scoring | Whole-of-CVEs aggregation |
| No input validation | Ingestion confidence + degraded input detection |
| Static vulnerability view | Attack capability inference (ACI) |
| Limited pipeline integration | Signed webhook delivery + run manifests |
| Narrow configurability | Flexible, policy-driven scoring and prioritization |

## Where It Fits

1. Run vulnerability scans as usual with your existing tools (Nessus/OpenVAS XML supported, plus Nessus/Qualys CSV constrained-export ingestion).
2. **Export** results in supported formats.
3. Use VulnParse-Pin to ***ingest, enrich, and prioritize*** findings based on real-world risk signals and configurable policies.
4. **Review** the prioritized outputs for triage and remediation planning.
5. ***Patch, mitigate, or accept*** risk based on the enriched context and explainable scoring artifacts provided by VulnParse-Pin.

`You decide what to prioritize, but VulnParse-Pin helps you make informed decisions and defend them with data.`

## Who Is VulnParse-Pin For?

VulnParse-Pin is for teams that need to triage high volumes of vulnerability findings without losing focus on what is most actionable.

- **CI/CD Workflows**: DevSecOps teams integrating vulnerability management into CI/CD pipelines for faster feedback and remediation.
- **Practitioners**: Security analysts, security engineers, SOC teams, red teams, and penetration testers.
- **Program and risk owners**: Vulnerability program managers, risk assessors, and security leadership.
- **Service providers and builders**: Consultants, MSSPs, researchers, and developers integrating or extending workflows.

See the [Overview](documentation/docs/Overview.md) documentation for more details on use cases and target audiences.

## Key Features

- ✅ **Scanner-Agnostic Normalization**: Ingests and standardizes output from any vulnerability scanner or feed (Currently Nessus/OpenVAS).

- ✅ **Powerful Attack Capability Inference (ACI)**: Infers real-world attack capabilities from finding evidence to enhance prioritization beyond CVSS.

- ✅ **Powerful Optimizations**: Designed for both small and high-volume workloads with dynamic execution strategies, caching, and parallel processing:
  - Sublinear scaling with finding count
  - Parallelized scoring and prioritization paths
  - Optimized NVD enrichment with streaming and filtering
  - Tested on datasets up to 700k findings with real-world CVE distributions (~1800 findings/sec in under 5 minutes).

- ✅ **Exploit Intelligence Enrichment**: Integrates with CISA KEV, ExploitDB, NVD, and more for comprehensive context.

- ✅ **Configurable Scoring and Prioritization Engine**: Flexible, policy-driven scoring that can be tuned to organizational risk tolerance and priorities. This includes the ability to prioritize known-exploited vulnerabilities and adjust scoring based on asset context.

- ✅ **Deterministic Pass Pipelines**: Modular processing stages for enrichment, scoring, and prioritization that can be customized or extended.

- ✅ **Executive and Technical Reporting**: Provides both high-level summaries for executives and detailed insights for technical teams, with explainable scoring and prioritization artifacts.

- ✅ **Offline Mode and Local Feeds**: Supports offline operation and local feed management for environments with limited connectivity or strict data handling requirements.

- ✅ **Decision Ledger & RunManifest**: Full traceability of how every priority decision was made, with a structured ledger of decision events and a run manifest for auditability and governance.

See the [Features](documentation/docs/Features.md) documentation for a comprehensive list of features and capabilities.

## Installation

VulnParse-Pin can be installed using pip:

```bash
pip install vulnparse-pin
```

or

install from source:

```bash
git clone https://github.com/QT-Ashley/VulnParse-Pin.git
cd VulnParse-Pin
pip install -e .
```

Standalone executables with release artifacts are also available on PyPI and GitHub Releases, which include pre-built wheels for easy installation:

```bash
pip install vulnparse_pin-*py3-none-any.whl
```

### Run Your Own Scan

After installation, you can run VulnParse-Pin with your own scanner exports:

```bash
vpp -f path/to/your_scan.[nessus|xml] -o <output_file>.json -pp -oC <output_file>.csv -oM <output_file>.md -oMT <output_file>_technical.md --output-runmanifest <output_file>_runmanifest.json
```

CSV profile examples for reporting workflows:

```bash
# Analyst-facing triage CSV
vpp -f path/to/your_scan.[nessus|xml] --output-csv <output_file>_analyst.csv --csv-profile analyst

# Audit-facing traceability CSV
vpp -f path/to/your_scan.[nessus|xml] --output-csv <output_file>_audit.csv --csv-profile audit
```

Verify a previously generated runmanifest artifact without rerunning the pipeline:

```bash
vpp --verify-runmanifest <output_file>_runmanifest.json
```

Check out [Releases](https://github.com/QT-Ashley/VulnParse-Pin/releases) for the latest release artifacts.

A list of all available command-line options can be found in the [Getting Started In 5 Minutes](documentation/docs/Getting%20Started%20In%205%20Minutes.md) guide.

## Feedback and Contributions

### Tried it out? Found a bug? Have a feature request or want to contribute?

If you tried VulnParse-Pin, even briefly, please consider leaving feedback or contributing to the project:

- Did it fit your workflow?
- What was confusing or difficult to use?
- What features would you like to see next?
- What other use cases do you have in mind?

Anything you can share is helpful, whether it's a quick comment, a detailed issue, or a pull request with improvements.

Contributor workflow and expectations are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap and Future Enhancements

- **Additional Scanner Support**: Expanding normalization capabilities to support more vulnerability scanners and feeds.
- **Advanced Enrichment Sources**: Integrating additional threat intelligence sources for richer context.
- **Machine Learning Integration**: Exploring the use of machine learning models for enhanced scoring, prioritization, and AI-augmented reporting at the derived context layer (truth layer remains immutable).
- **Historical Trend Analysis**: Adding features to analyze historical vulnerability data and trends over time.
- **Community Contributions**: Encouraging and incorporating contributions from the open source community to enhance features and expand use cases.

For the latest updates on the roadmap and future enhancements, please refer to the [Roadmap](ROADMAP.md) documentation.

## Documentation

For more detailed information on how to use, configure, and extend VulnParse-Pin, please refer to the documentation:

- [Docs Index](documentation/docs/index.md)
- [Overview](documentation/docs/Overview.md)
- [Getting Started In 5 Minutes](documentation/docs/Getting%20Started%20In%205%20Minutes.md)
- [Upgrade and Migration](documentation/docs/Upgrade%20and%20Migration.md)
- [Troubleshooting](documentation/docs/Troubleshooting.md)
- [Output Interpretation](documentation/docs/Output%20Interpretation.md)
- [Testing Guide](documentation/docs/Testing%20Guide.md)
- [Architecture](documentation/docs/Architecture.md)
- [Extension Playbooks](documentation/docs/Extension%20Playbooks.md)
- [ADR Workflow](documentation/docs/ADR%20Workflow.md)
- [Architecture Review Checklist](documentation/docs/Architecture%20Review%20Checklist.md)
- [Deprecation and Versioning Policy](documentation/docs/Deprecation%20and%20Versioning%20Policy.md)
- [Pipeline System](documentation/docs/Pipeline%20System.md)
- [RunManifest Overview](documentation/docs/RunManifest.md)
- [RunManifest Technical Deep Dive](documentation/docs/RunManifest_Technical.md)
- [Security Features](documentation/docs/Security%20Features.md)
- [Current Scoring Profile (March 2026)](documentation/docs/Configs.md)
- [Configs](documentation/docs/Configs.md)
- [Benchmarks](documentation/docs/Benchmarks.md)
- [Performance Optimizations](documentation/docs/Performance%20Optimizations.md)
- [Licensing](documentation/docs/Licensing.md)
- [Value Proposition One Pager](documentation/docs/Value_Proposition_One_Pager.md)
- [VulnParse-Pin Wiki Docs](https://qt-ashley.github.io/VulnParse-Pin/)

Check out the [CHANGELOG](CHANGELOG.md) for a detailed history of changes and updates.

## License

VulnParse-Pin is licensed under the **GNU Affero General Public License v3.0 or later (AGPLv3+)**.

This ensures that improvements to VulnParse-Pin — including those used in hosted or network-accessible services — remain open and benefit the community.

### What this means in practice

- ✅ Free to use, modify, and run internally
- ✅ Free for research, education, SOC pipelines, and consulting
- ✅ Free to sell services **using** VulnParse-Pin
- ⚠️ If you run a modified version as a hosted service, you must make the source available

Unmodified use does **not** require source disclosure.

Modified use **does** require source disclosure if the modified version is used in a hosted or network-accessible service.

## Disclaimers

VulnParse-Pin is provided "as is" without any warranties or guarantees. The developers and contributors are ***not*** liable for any damages or losses resulting from the use of VulnParse-Pin. Users are responsible for ensuring that their use of VulnParse-Pin complies with all applicable laws and regulations.

VulnParse-Pin is a tool designed to assist in vulnerability management and prioritization. It should be used as part of a comprehensive security program and not as a standalone solution. Always validate and verify findings through additional analysis and testing before taking remediation actions.

VulnParse-Pin does ***not*** guarantee the accuracy or completeness of the vulnerability data it processes. Users should exercise caution and use their judgment when interpreting results and making decisions based on VulnParse-Pin's outputs.

VulnParse-Pin is ***not*** responsible for any misuse or abuse of the tool. It is intended for ethical use by security professionals and organizations to improve their security posture.

For a full list of disclaimers and legal information, please refer to the [Licensing](documentation/docs/Licensing.md) documentation.
