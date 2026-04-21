# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

"""
Markdown report generator for executive and technical audiences.

"""

from datetime import datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.io.pfhandler import PathLike


def _ghsa_reference_metrics(scan: Any) -> tuple[int, int]:
    """Return (findings_with_ghsa_reference, total_ghsa_references)."""
    if scan is None:
        return 0, 0

    findings_with_ghsa = 0
    total_ghsa_refs = 0
    assets = getattr(scan, "assets", []) or []
    for asset in assets:
        findings = getattr(asset, "findings", []) or []
        for finding in findings:
            refs = getattr(finding, "references", []) or []
            ghsa_refs = [r for r in refs if "GHSA-" in str(r)]
            if ghsa_refs:
                findings_with_ghsa += 1
                total_ghsa_refs += len(ghsa_refs)
    return findings_with_ghsa, total_ghsa_refs


def generate_markdown_report(
    ctx: "RunContext",
    scan: "ScanResult",
    output_path: "PathLike",
    report_type: str = "executive"
) -> None:
    """
    Generate a Markdown report from scan results.
    
    Args:
        ctx: Runtime context with logger and PFH
        scan: Processed scan results
        output_path: Destination file path
        report_type: "executive" or "technical"
    
    Raises:
        ValueError: If Summary@1.0 pass has not run or invalid report_type
    """
    summary_data = scan.derived.get("Summary@1.0")
    if not summary_data:
        raise ValueError("Summary@1.0 pass must run before generating Markdown report")
    
    summary = summary_data.data
    
    if report_type == "executive":
        content = _generate_executive_report(scan, summary)
    elif report_type == "technical":
        content = _generate_technical_report(scan, summary)
    else:
        raise ValueError(f"Unknown report type: {report_type}. Expected 'executive' or 'technical'.")

    # Caller provides the target path (io_resolution sets distinct exec/technical names).
    target = ctx.pfh.ensure_writable_file(
        output_path,
        label=f"{report_type.capitalize()} Markdown Report",
        create_parents=True,
        overwrite=True
    )
    
    with ctx.pfh.open_for_write(target, mode="w", encoding="utf-8", label="Markdown Report") as f:
        f.write(content)
    
    ctx.logger.print_success(
        f"{report_type.capitalize()} report generated: {ctx.pfh.format_for_log(target)}",
        label="Markdown Report"
    )


def _generate_executive_report(_scan: "ScanResult", summary: Any) -> str:
    """
    Generate executive-level summary report.

    Focused on:
    - High-level metrics
    - Risk distribution
    - Immediate action items
    - Remediation priorities
    """
    overview = summary.overview
    risk_dist = summary.risk_distribution
    top_risks = summary.top_risks
    remediation = summary.remediation_priorities
    asset_summary = summary.asset_summary
    enrichment = summary.enrichment_metrics
    ghsa_findings, ghsa_refs = _ghsa_reference_metrics(_scan)

    assets = asset_summary.get('assets', []) if isinstance(asset_summary, dict) else []
    total_critical_findings = sum(int(a.get('critical_findings', 0) or 0) for a in assets)
    total_high_findings = sum(int(a.get('high_findings', 0) or 0) for a in assets)
    top_assets = assets[:3]
    top3_critical = sum(int(a.get('critical_findings', 0) or 0) for a in top_assets)
    top3_high = sum(int(a.get('high_findings', 0) or 0) for a in top_assets)
    top3_critical_pct = (top3_critical / total_critical_findings * 100.0) if total_critical_findings else 0.0
    top3_high_pct = (top3_high / total_high_findings * 100.0) if total_high_findings else 0.0

    def _risk_drivers(risk: Any) -> str:
        drivers: list[str] = []
        if risk.get('kev_listed'):
            drivers.append('KEV')
        if risk.get('exploit_available'):
            drivers.append('Public Exploit')
        epss_val = risk.get('epss_score')
        if isinstance(epss_val, (int, float)) and epss_val >= 0.50:
            drivers.append('EPSS>=0.50')
        return ", ".join(drivers) if drivers else "Risk Score Driven"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = f"""# Vulnerability Scan Executive Summary

**Generated:** {timestamp}  
**Scan Period:** {overview.get('scan_timestamp', 'N/A')}

---

## 🎯 Key Findings

| Metric | Value |
|--------|-------|
| **Total Assets Scanned** | {overview['total_assets']:,} |
| **Total Vulnerabilities** | {overview['total_findings']:,} |
| **Average Asset Risk Score** | {overview['average_asset_risk']:.2f} |
| **Exploitable Vulnerabilities** | {overview['exploitable_findings']:,} |
| **CISA KEV Listed** | {overview['kev_listed_findings']:,} |
| **GHSA Advisory Matches** | {ghsa_findings:,} findings ({ghsa_refs:,} references) |

---

## 🧠 Decision Context

- CVE rows are ranked by **Finding Risk (Raw)** from derived scoring outputs.
- For near-tied rows, contributor-breadth signals are applied to keep ordering deterministic.
- **Finding Agg CVEs** is a finding-level contributor-breadth signal, not an asset-level aggregate.

---

## ✅ Data Quality Scorecard

| Signal | Value |
|--------|-------|
| Scored Findings Coverage | {risk_dist['total_scored']:,}/{overview['total_findings']:,} |
| Enriched Findings Coverage | {enrichment['enriched_findings']:,}/{enrichment['total_findings']:,} ({enrichment['enrichment_coverage']:.1%}) |
| KEV-listed Findings | {overview['kev_listed_findings']:,} |
| Public Exploit Findings | {overview['exploitable_findings']:,} |
| GHSA Advisory Matches | {ghsa_findings:,} findings ({ghsa_refs:,} references) |

---

## 📊 Risk Distribution

Derived risk bands below are calculated by VulnParse-Pin scoring and should be used for remediation prioritization.

| Risk Band | Count |
|-----------|-------|
| 🔴 **Critical** | {risk_dist['by_risk_band']['Critical']:,} |
| 🟠 **High** | {risk_dist['by_risk_band']['High']:,} |
| 🟡 **Medium** | {risk_dist['by_risk_band']['Medium']:,} |
| 🟢 **Low** | {risk_dist['by_risk_band']['Low']:,} |
| ⚪ **Informational** | {risk_dist['by_risk_band']['Informational']:,} |

---

## ⚠️ Immediate Action Required

**{remediation['immediate_action']} vulnerabilities** require immediate remediation due to:
- Critical risk rating
- Known exploitation in the wild (KEV) or public exploits available

### Top Priority CVEs:

"""

    for i, cve in enumerate(remediation['immediate_cves'][:5], 1):
        md += f"{i}. `{cve}`\n"

    if not remediation['immediate_cves']:
        md += "- No immediate-action CVEs detected in this scan window.\n"

    md += f"""

---

## 📈 Top {len(top_risks)} Highest Risk CVEs (De-duplicated, Derived Risk)

| CVE | Finding Risk (Raw) | Band | Exploit? | KEV? | Finding Agg CVEs | Agg Exploitable | Agg KEV | CVSS | Occurrences | Primary Drivers |
|-----|---------------------|------|----------|------|----------|-----------------|---------|------|-------------|-----------------|
"""

    for risk in top_risks:
        exploit_icon = "✅" if risk['exploit_available'] else "❌"
        kev_icon = "✅" if risk['kev_listed'] else "❌"
        cvss = risk.get('cvss_base_score', 'N/A')
        occurrences = risk.get('occurrence_count', 1)
        agg_count = int(risk.get('aggregated_cve_count', 1) or 1)
        agg_exploit = int(risk.get('aggregated_exploitable_cve_count', 0) or 0)
        agg_kev = int(risk.get('aggregated_kev_cve_count', 0) or 0)

        md += (
            f"| {risk['cve']} | {risk['finding_risk_score']:.2f} | {risk['risk_band']} | "
            f"{exploit_icon} | {kev_icon} | {agg_count:,} | {agg_exploit:,} | {agg_kev:,} | "
            f"{cvss} | {occurrences:,} | {_risk_drivers(risk)} |\n"
        )

    md += """

---

## 🧭 Recommended Asset Target List (Patching Priority)

These are the recommended most vulnerable assets to target first for patching based on derived scoring and asset criticality.

| Asset ID | Hostname | Criticality | Critical (Derived) | High (Derived) | #1 CVE |
|----------|----------|-------------|--------------------|----------------|--------|
"""

    for asset in asset_summary['assets'][:10]:
        md += (
            f"| {asset.get('asset_id', 'N/A')} | {asset.get('hostname') or 'N/A'} | "
            f"{asset.get('criticality') or 'N/A'} | {asset.get('critical_findings', 0):,} | "
            f"{asset.get('high_findings', 0):,} | {asset.get('top_cve', 'N/A')} |\n"
        )

    md += f"""

### Executive SLA Recommendation

- **Extreme criticality assets:** Patch critical findings within **24-48 hours**
- **High criticality assets:** Patch critical/high findings within **7 days**
- **Medium/Low criticality assets:** Patch according to standard change windows (up to **30 days**)

---

## ⏱️ Remediation Plan by Time Horizon

| Horizon | Focus | Count |
|---------|-------|-------|
| 24-48 hours | Immediate-action vulnerabilities | {remediation['immediate_action']:,} |
| 7 days | High-priority vulnerabilities | {remediation['high_priority']:,} |
| 30 days | Medium-priority vulnerabilities | {remediation['medium_priority']:,} |

Immediate-action CVE shortlist:

"""

    if remediation['immediate_cves']:
        for i, cve in enumerate(remediation['immediate_cves'][:5], 1):
            md += f"{i}. `{cve}`\n"
    else:
        md += "- No immediate-action CVEs detected in this scan window.\n"

    md += f"""

---

## 🎯 Risk Concentration

| Concentration Signal | Value |
|----------------------|-------|
| Top 3 assets critical-share | {top3_critical:,}/{total_critical_findings:,} ({top3_critical_pct:.1f}%) |
| Top 3 assets high-share | {top3_high:,}/{total_high_findings:,} ({top3_high_pct:.1f}%) |
| Assets considered in concentration view | {len(top_assets):,} of {len(assets):,} |

Interpretation: higher concentration usually means faster risk reduction when remediation starts with the top exposed assets.

---

## 🛡️ Remediation Priority Breakdown

| Priority | Count | Recommended Timeframe |
|----------|-------|----------------------|
| **Immediate** | {remediation['immediate_action']:,} | Within 24-48 hours |
| **High** | {remediation['high_priority']:,} | Within 1 week |
| **Medium** | {remediation['medium_priority']:,} | Within 30 days |

---

## 📝 Recommendations

1. **Immediate Focus:** Address the {remediation['immediate_action']} critical vulnerabilities with known exploits
2. **Asset Prioritization:** Focus on the highest risk assets identified in the technical report
3. **Patch Management:** Implement a regular patching cycle for the {remediation['high_priority']} high-priority findings
4. **Monitoring:** Deploy detection rules for CVEs listed in CISA KEV catalog
5. **Interpretation Note:** Treat scanner severity as input signal; use derived risk band and raw score to break ties within large critical buckets
6. **Aggregation Context:** Where Finding Agg CVEs > 1, prioritize remediation by addressing primary shared root-cause components first

---

*Report generated by VulnParse-Pin - Automated Vulnerability Intelligence*
"""

    return md


def _generate_technical_report(_scan: "ScanResult", summary: Any) -> str:
    """
    Generate detailed technical report for vulnerability engineers.

    Includes:
    - Detailed asset breakdown
    - Finding-level analysis
    - Enrichment statistics
    - Top risk CVEs with full context
    """
    overview = summary.overview
    asset_summary = summary.asset_summary
    finding_summary = summary.finding_summary
    risk_dist = summary.risk_distribution
    top_risks = summary.top_risks
    enrichment = summary.enrichment_metrics
    ghsa_findings, ghsa_refs = _ghsa_reference_metrics(_scan)

    def _risk_drivers(risk: Any) -> str:
        drivers: list[str] = []
        if risk.get('kev_listed'):
            drivers.append('KEV')
        if risk.get('exploit_available'):
            drivers.append('Public Exploit')
        epss_val = risk.get('epss_score')
        if isinstance(epss_val, (int, float)) and epss_val >= 0.50:
            drivers.append('EPSS>=0.50')
        return ", ".join(drivers) if drivers else "Risk Score Driven"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = f"""# Vulnerability Scan Technical Report

**Generated:** {timestamp}  
**Assets Analyzed:** {overview['total_assets']:,}  
**Total Findings:** {overview['total_findings']:,}

---

## 📋 Table of Contents

1. [Scan Overview](#scan-overview)
2. [Asset Analysis](#asset-analysis)
3. [Scanner Severity Breakdown](#scanner-severity-breakdown)
4. [Derived Risk Breakdown](#derived-risk-breakdown)
5. [Top Risk Findings](#top-risk-findings)
6. [Tie-Break Explainability](#tie-break-explainability)
7. [Enrichment Coverage](#enrichment-coverage)
8. [Analyst Caveats](#analyst-caveats)
9. [Trust and Provenance](#trust-and-provenance)

---

## 🔍 Scan Overview

| Metric | Value |
|--------|-------|
| Total Assets | {overview['total_assets']:,} |
| Total Findings | {overview['total_findings']:,} |
| Average Risk Score | {overview['average_asset_risk']:.2f} |
| Exploitable (Public PoC) | {overview['exploitable_findings']:,} |
| CISA KEV Listed | {overview['kev_listed_findings']:,} |
| GHSA Advisory Matches | {ghsa_findings:,} findings ({ghsa_refs:,} references) |
| Scan Timestamp | {overview.get('scan_timestamp', 'N/A')} |

---

## 💻 Asset Analysis

### Top {len(asset_summary['assets'])} Highest Risk Assets

| Asset ID | IP Address | Hostname | Criticality | Findings | Risk Score | Critical | High |
|----------|------------|----------|-------------|----------|------------|----------|------|
"""

    for asset in asset_summary['assets'][:20]:  # Limit for readability
        md += (
            f"| {asset['asset_id']} | {asset['ip'] or 'N/A'} | {asset['hostname'] or 'N/A'} | "
            f"{asset.get('criticality') or 'N/A'} | {asset['total_findings']:,} | {asset['risk_score']:.2f} | "
            f"{asset['critical_findings']:,} | {asset['high_findings']:,} |\n"
        )

    md += f"""

**Total Assets Evaluated:** {asset_summary['total_assets']:,}

---

## 🐛 Scanner Severity Breakdown

### By Severity (Scanner Classification, Unadjusted)

Scanner severity is the source tool's native rating and can overstate operational priority at scale.

| Severity | Count |
|----------|-------|
| Critical | {finding_summary['by_severity']['Critical']:,} |
| High | {finding_summary['by_severity']['High']:,} |
| Medium | {finding_summary['by_severity']['Medium']:,} |
| Low | {finding_summary['by_severity']['Low']:,} |
| Informational | {finding_summary['by_severity']['Informational']:,} |

**Total:** {finding_summary['total']:,} findings

---

## 🎯 Derived Risk Breakdown

### By Risk Band (Scoring Output)

Use this distribution for remediation prioritization and queue ordering.

| Risk Band | Count |
|-----------|-------|
| Critical | {risk_dist['by_risk_band']['Critical']:,} |
| High | {risk_dist['by_risk_band']['High']:,} |
| Medium | {risk_dist['by_risk_band']['Medium']:,} |
| Low | {risk_dist['by_risk_band']['Low']:,} |
| Informational | {risk_dist['by_risk_band']['Informational']:,} |

**Total Scored:** {risk_dist['total_scored']:,} findings

---

## ⚠️ Top Risk Findings (Detailed)

### Top {len(top_risks)} CVEs by Finding Risk Score (Raw, Derived)

| # | CVE | Finding Risk (Raw) | Band | CVSS | EPSS | Exploit | KEV | Finding Agg CVEs | Agg Exploitable | Agg KEV | Occurrences | Primary Drivers |
|---|-----|---------------------|------|------|------|---------|-----|----------|-----------------|---------|-------------|-----------------|
"""

    for i, risk in enumerate(top_risks, 1):
        exploit = "✅ Yes" if risk['exploit_available'] else "❌ No"
        kev = "✅ Yes" if risk['kev_listed'] else "❌ No"
        epss = f"{risk.get('epss_score', 0.0):.4f}" if risk.get('epss_score') else "N/A"
        cvss = risk.get('cvss_base_score', 'N/A')
        occurrences = risk.get('occurrence_count', 1)
        agg_count = int(risk.get('aggregated_cve_count', 1) or 1)
        agg_exploit = int(risk.get('aggregated_exploitable_cve_count', 0) or 0)
        agg_kev = int(risk.get('aggregated_kev_cve_count', 0) or 0)

        md += (
            f"| {i} | `{risk['cve']}` | {risk['finding_risk_score']:.2f} | {risk['risk_band']} | "
            f"{cvss} | {epss} | {exploit} | {kev} | {agg_count:,} | {agg_exploit:,} | {agg_kev:,} | "
            f"{occurrences:,} | {_risk_drivers(risk)} |\n"
        )

    md += f"""

---

## 🧷 Tie-Break Explainability

- Rankings are ordered by **Finding Risk (Raw)** first.
- For near-equal scores, contributor-breadth signals are used to keep ordering deterministic.
- **Finding Agg CVEs**, **Agg Exploitable**, and **Agg KEV** provide contributor-breadth context for each representative finding row.

---

## 📊 Enrichment Coverage

| Metric | Value |
|--------|-------|
| Total Findings | {enrichment['total_findings']:,} |
| Total CVEs | {enrichment['total_cves']:,} |
| Enriched Findings | {enrichment['enriched_findings']:,} |
| **Enrichment Coverage** | **{enrichment['enrichment_coverage']:.1%}** |

### Data Sources

- ✅ CISA Known Exploited Vulnerabilities (KEV)
- ✅ FIRST Exploit Prediction Scoring System (EPSS)
- ✅ Exploit-DB Public Exploits
- ✅ GitHub Security Advisories (GHSA)
- ✅ National Vulnerability Database (NVD)

---

## ⚖️ Analyst Caveats

- "Finding Risk (Raw)" is finding-level and should not be treated as an asset aggregate.
- "Finding Agg CVEs" describes score-trace contributor breadth for the representative finding row.
- "Occurrences" captures recurrence of the displayed CVE in the de-duplicated top-risk set.
- Scanner severity is intentionally separated from derived risk to avoid queue-ordering bias.

---

## 🔐 Trust and Provenance

| Signal | Value |
|--------|-------|
| Report Generated At | {timestamp} |
| Scan Timestamp | {overview.get('scan_timestamp', 'N/A')} |
| Integrity Reference | Use runmanifest verification for artifact-level trust validation |

Provenance note: this markdown report summarizes derived outputs; verifiable integrity and decision-chain validation are provided by the runmanifest artifact when generated.

---

## 🔧 Technical Notes

- "Finding Risk (Raw)" is the highest per-finding score observed for that CVE (not an asset aggregate score)
- Risk scores are calculated using CVSS base scores, EPSS probability, and evidence-based factors (KEV listing, exploit availability)
- Asset risk is aggregated from individual finding scores using configured policy
- Scanner severity and derived risk band are intentionally shown separately to reduce prioritization ambiguity
- Findings with CVSS v3.1 scores are prioritized; v2.0 used as fallback
- Exploit availability indicates public proof-of-concept code exists
- "Finding Agg CVEs" indicates whole-of-CVEs aggregation breadth from score_trace contributors for the representative finding shown on that row

---

*For detailed finding-level data, refer to the JSON/CSV output files.*
"""

    return md
