#!/usr/bin/env python3
"""
VulnParse-Pin Value Proof Analysis
===================================

This script demonstrates VulnParse-Pin's value proposition:
1. Noise Reduction: Shows how VulnParse-Pin's scoring filters out high-CVSS findings that lack real-world exploit risk
2. Signal Enhancement: Demonstrates how real-world exploitation signals (KEV, public exploits, EPSS) are surfaced
3. Risk Stratification: Proves that derived risk bands provide better triage than raw scanner severity

Run with: python tests/value_proof_analysis.py
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Any
from dataclasses import dataclass


@dataclass
class VulnAnalysis:
    """Analysis of a single vulnerability."""
    cve_id: str
    scanner_severity: str  # Nessus severity rating
    cvss_score: float
    epss_score: float
    kev_listed: bool
    exploit_available: bool
    vpp_raw_score: float
    vpp_band: str
    parity: str  # "aligned", "downgraded", "upgraded", "noise_reduced"


def load_demo_output(output_path: str) -> dict:
    """Load the demo output JSON."""
    with open(output_path, 'r') as f:
        return json.load(f)


def categorize_finding(finding: dict) -> VulnAnalysis:
    """Categorize a single finding's alignment."""
    cve = finding.get("cve_id", "N/A")
    scanner_sev = finding.get("severity", "Unknown")
    cvss = finding.get("cvss_score", 0.0)
    epss = finding.get("epss_score", 0.0)
    kev = finding.get("kev_listed", False)
    exploit = finding.get("exploit_available", False)
    
    # Get VulnParse-Pin score from the Summary@1.0 pass
    vpp_score = 0.0
    vpp_band = "Unknown"
    
    for pass_result in finding.get("passes", []):
        if pass_result.get("pass_name") == "Summary@1.0":
            vpp_score = pass_result.get("risk_score", 0.0)
            vpp_band = pass_result.get("risk_band", "Unknown")
            break
    
    # Determine alignment category
    # CVSS critical/high that VulnParse-Pin downgraded = noise reduction
    # Lower CVSS with KEV/exploits that VulnParse-Pin upgraded = signal enhancement
    
    cvss_is_high = cvss >= 9.0
    vpp_is_high = vpp_band in ("Critical", "High")
    
    if cvss_is_high and not vpp_is_high:
        # High CVSS but no real-world risk signals
        parity = "noise_reduced"
    elif not cvss_is_high and vpp_is_high and (kev or exploit):
        # Lower CVSS but real-world risk signals present
        parity = "upgraded"
    elif cvss_is_high and vpp_is_high:
        parity = "aligned"
    else:
        parity = "downgraded"
    
    return VulnAnalysis(
        cve_id=cve,
        scanner_severity=scanner_sev,
        cvss_score=cvss,
        epss_score=epss,
        kev_listed=kev,
        exploit_available=exploit,
        vpp_raw_score=vpp_score,
        vpp_band=vpp_band,
        parity=parity
    )


def analyze_dataset(output_path: str):
    """Analyze the full dataset and generate insights."""
    data = load_demo_output(output_path)
    
    findings = data.get("findings", [])
    print(f"\n{'='*80}")
    print(f"VulnParse-Pin Value Proof Analysis")
    print(f"{'='*80}\n")
    print(f"Total Findings Analyzed: {len(findings)}\n")
    
    # Analyze all findings
    analyses = [categorize_finding(f) for f in findings]
    
    # Statistics by category
    stats = defaultdict(int)
    for analysis in analyses:
        stats[analysis.parity] += 1
    
    print("NOISE REDUCTION & SIGNAL ENHANCEMENT")
    print("-" * 80)
    
    # Noise reduction: High CVSS without real-world signals
    noise_reduced = [a for a in analyses if a.parity == "noise_reduced"]
    print(f"\n✅ NOISE REDUCED (High CVSS, no real-world risk signals): {len(noise_reduced)}")
    if noise_reduced:
        print("   These findings have high CVSS scores but lack KEV listing or public exploits.")
        print("   VulnParse-Pin downgrades them, reducing alert fatigue.\n")
        
        # Sample 5 examples
        for analysis in noise_reduced[:5]:
            print(f"   • {analysis.cve_id:15} | CVSS: {analysis.cvss_score:4.1f} | EPSS: {analysis.epss_score:6.4f} | "
                  f"VPP Band: {analysis.vpp_band:12} (score: {analysis.vpp_raw_score:5.2f})")
    
    # Signal enhancement: Real-world risk signals surfaced
    upgraded = [a for a in analyses if a.parity == "upgraded"]
    print(f"\n🎯 SIGNAL ENHANCED (Lower CVSS + Real-World Signals): {len(upgraded)}")
    if upgraded:
        print("   These findings have real evidence of exploitation but lower CVSS ratings.")
        print("   VulnParse-Pin upgrades them based on KEV listing and public exploits.\n")
        
        # Sample 5 examples
        for analysis in upgraded[:5]:
            signals = []
            if analysis.kev_listed:
                signals.append("KEV")
            if analysis.exploit_available:
                signals.append("PublicExploit")
            print(f"   • {analysis.cve_id:15} | CVSS: {analysis.cvss_score:4.1f} | Signals: {','.join(signals):20} | "
                  f"VPP Band: {analysis.vpp_band:12} (score: {analysis.vpp_raw_score:5.2f})")
    
    # Risk band distribution
    band_dist = defaultdict(int)
    cvss_band_dist = defaultdict(int)
    
    for analysis in analyses:
        band_dist[analysis.vpp_band] += 1
        
        # Estimate CVSS band
        if analysis.cvss_score >= 9.0:
            cvss_band = "Critical"
        elif analysis.cvss_score >= 7.0:
            cvss_band = "High"
        elif analysis.cvss_score >= 4.0:
            cvss_band = "Medium"
        else:
            cvss_band = "Low"
        cvss_band_dist[cvss_band] += 1
    
    print(f"\n\nRISK BAND DISTRIBUTION COMPARISON")
    print("-" * 80)
    print("\nScanner CVSS Distribution:")
    for band in ["Critical", "High", "Medium", "Low"]:
        count = cvss_band_dist.get(band, 0)
        pct = (count / len(findings) * 100) if findings else 0
        print(f"  {band:12}: {count:5} findings ({pct:5.1f}%)")
    
    print("\nVulnParse-Pin Derived Risk Band Distribution:")
    for band in ["Critical", "High", "Medium", "Low", "Informational"]:
        count = band_dist.get(band, 0)
        pct = (count / len(findings) * 100) if findings else 0
        print(f"  {band:12}: {count:5} findings ({pct:5.1f}%)")
    
    # Calculate noise reduction metric
    total_critical_cvss = cvss_band_dist.get("Critical", 0)
    total_critical_vpp = band_dist.get("Critical", 0)
    noise_pct = 0
    if total_critical_cvss > 0:
        noise_reduction = total_critical_cvss - total_critical_vpp
        noise_pct = (noise_reduction / total_critical_cvss * 100)
    
    print(f"\n🔊 NOISE REDUCTION METRIC")
    print("-" * 80)
    print(f"CVSS-Critical findings: {total_critical_cvss}")
    print(f"VulnParse-Pin Critical: {total_critical_vpp}")
    print(f"Findings Rebalanced:    {total_critical_cvss - total_critical_vpp}")
    if total_critical_cvss > 0:
        print(f"Alert Fatigue Reduction: {noise_pct:.1f}%")
    
    # Real-world exploitation signals
    print(f"\n\nREAL-WORLD EXPLOITATION SIGNALS")
    print("-" * 80)
    
    kev_count = sum(1 for a in analyses if a.kev_listed)
    exploit_count = sum(1 for a in analyses if a.exploit_available)
    both_count = sum(1 for a in analyses if a.kev_listed and a.exploit_available)
    
    print(f"KEV Listed (CISA):                {kev_count:5} findings ({kev_count/len(findings)*100:5.1f}%)")
    print(f"Public Exploits Available:        {exploit_count:5} findings ({exploit_count/len(findings)*100:5.1f}%)")
    print(f"Both KEV + Public Exploit:        {both_count:5} findings ({both_count/len(findings)*100:5.1f}%)")
    print(f"Either Signal Present:            {len([a for a in analyses if a.kev_listed or a.exploit_available]):5} findings")
    
    # High-risk findings with both signals (true exploit risk)
    high_signal_findings = [a for a in analyses if (a.kev_listed or a.exploit_available) and a.vpp_band in ("Critical", "High")]
    print(f"\nCritical/High VulnParse-Pin + Real-World Signal: {len(high_signal_findings)} findings")
    print("These are the TRUE HIGH-RISK vulnerabilities requiring immediate attention.\n")
    
    # CVSS vs VulnParse-Pin correlation (examples)
    print(f"\nEXAMPLE: HOW VulnParse-Pin REORDERS PRIORITIES")
    print("-" * 80)
    
    # Find examples of high CVSS + no signals vs low CVSS + signals
    high_cvss_no_signal = [a for a in analyses if a.cvss_score >= 9.0 and not a.kev_listed and not a.exploit_available]
    low_cvss_with_signal = [a for a in analyses if a.cvss_score < 7.0 and (a.kev_listed or a.exploit_available)]
    
    if high_cvss_no_signal and low_cvss_with_signal:
        print("\nHigh CVSS, No Real-World Risk Signal (Not Priority):")
        for analysis in high_cvss_no_signal[:3]:
            print(f"  {analysis.cve_id}: CVSS {analysis.cvss_score:.1f} → VPP {analysis.vpp_band} (score: {analysis.vpp_raw_score:.2f})")
        
        print("\nLow CVSS, But Real-World Exploitation Data (SHOULD BE PRIORITY):")
        for analysis in low_cvss_with_signal[:3]:
            signals = "KEV" if analysis.kev_listed else ""
            if analysis.exploit_available:
                signals += ", Exploit" if signals else "Exploit"
            print(f"  {analysis.cve_id}: CVSS {analysis.cvss_score:.1f} [{signals}] → VPP {analysis.vpp_band} (score: {analysis.vpp_raw_score:.2f})")
    
    print(f"\n{'='*80}\n")


if __name__ == "__main__":
    # Find demo output
    demo_path = Path("C:/Users/ashle/AppData/Local/VulnParse-Pin/versions/1.0.1/outputs/demo_output.json")
    
    if not demo_path.exists():
        print(f"Error: Could not find demo output at {demo_path}")
        print("Please run: vpp --demo")
        sys.exit(1)
    
    try:
        analyze_dataset(str(demo_path))
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
