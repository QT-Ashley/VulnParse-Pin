# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
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
    
    # Write using PFH
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

---

## 📊 Risk Distribution

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
    
    md += f"""

---

## 📈 Top {len(top_risks)} Highest Risk CVEs (De-duplicated)

| CVE | Finding Risk (Raw) | Band | Exploit? | KEV? | CVSS | Occurrences |
|-----|---------------------|------|----------|------|------|-------------|
"""
    
    for risk in top_risks:
        exploit_icon = "✅" if risk['exploit_available'] else "❌"
        kev_icon = "✅" if risk['kev_listed'] else "❌"
        cvss = risk.get('cvss_base_score', 'N/A')
        occurrences = risk.get('occurrence_count', 1)
        
        md += f"| {risk['cve']} | {risk['finding_risk_score']:.2f} | {risk['risk_band']} | {exploit_icon} | {kev_icon} | {cvss} | {occurrences:,} |\n"
    
    md += f"""

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
    top_risks = summary.top_risks
    enrichment = summary.enrichment_metrics
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    md = f"""# Vulnerability Scan Technical Report

**Generated:** {timestamp}  
**Assets Analyzed:** {overview['total_assets']:,}  
**Total Findings:** {overview['total_findings']:,}

---

## 📋 Table of Contents

1. [Scan Overview](#scan-overview)
2. [Asset Analysis](#asset-analysis)
3. [Vulnerability Breakdown](#vulnerability-breakdown)
4. [Top Risk Findings](#top-risk-findings)
5. [Enrichment Coverage](#enrichment-coverage)

---

## 🔍 Scan Overview

| Metric | Value |
|--------|-------|
| Total Assets | {overview['total_assets']:,} |
| Total Findings | {overview['total_findings']:,} |
| Average Risk Score | {overview['average_asset_risk']:.2f} |
| Exploitable (Public PoC) | {overview['exploitable_findings']:,} |
| CISA KEV Listed | {overview['kev_listed_findings']:,} |
| Scan Timestamp | {overview.get('scan_timestamp', 'N/A')} |

---

## 💻 Asset Analysis

### Top {len(asset_summary['assets'])} Highest Risk Assets

| Asset ID | IP Address | Hostname | Findings | Risk Score | Critical | High |
|----------|------------|----------|----------|------------|----------|------|
"""
    
    for asset in asset_summary['assets'][:20]:  # Limit for readability
        md += f"| {asset['asset_id']} | {asset['ip'] or 'N/A'} | {asset['hostname'] or 'N/A'} | {asset['total_findings']:,} | {asset['risk_score']:.2f} | {asset['critical_findings']:,} | {asset['high_findings']:,} |\n"
    
    md += f"""

**Total Assets Evaluated:** {asset_summary['total_assets']:,}

---

## 🐛 Vulnerability Breakdown

### By Severity (Scanner Classification)

| Severity | Count |
|----------|-------|
| Critical | {finding_summary['by_severity']['Critical']:,} |
| High | {finding_summary['by_severity']['High']:,} |
| Medium | {finding_summary['by_severity']['Medium']:,} |
| Low | {finding_summary['by_severity']['Low']:,} |
| Informational | {finding_summary['by_severity']['Informational']:,} |

**Total:** {finding_summary['total']:,} findings

---

## ⚠️ Top Risk Findings (Detailed)

### Top {len(top_risks)} CVEs by Finding Risk Score (Raw)

| # | CVE | Finding Risk (Raw) | Band | CVSS | EPSS | Exploit | KEV | Occurrences |
|---|-----|---------------------|------|------|------|---------|-----|-------------|
"""
    
    for i, risk in enumerate(top_risks, 1):
        exploit = "✅ Yes" if risk['exploit_available'] else "❌ No"
        kev = "✅ Yes" if risk['kev_listed'] else "❌ No"
        epss = f"{risk.get('epss_score', 0.0):.4f}" if risk.get('epss_score') else "N/A"
        cvss = risk.get('cvss_base_score', 'N/A')
        occurrences = risk.get('occurrence_count', 1)
        
        md += f"| {i} | `{risk['cve']}` | {risk['finding_risk_score']:.2f} | {risk['risk_band']} | {cvss} | {epss} | {exploit} | {kev} | {occurrences:,} |\n"
    
    md += f"""

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
- ✅ National Vulnerability Database (NVD)

---

## 🔧 Technical Notes

- "Finding Risk (Raw)" is the highest per-finding score observed for that CVE (not an asset aggregate score)
- Risk scores are calculated using CVSS base scores, EPSS probability, and evidence-based factors (KEV listing, exploit availability)
- Asset risk is aggregated from individual finding scores using configured policy
- Findings with CVSS v3.1 scores are prioritized; v2.0 used as fallback
- Exploit availability indicates public proof-of-concept code exists

---

*For detailed finding-level data, refer to the JSON/CSV output files.*
"""
    
    return md
