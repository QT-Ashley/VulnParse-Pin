# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

"""
Post-enrichment index builder.

Builds the PostEnrichmentIndex immediately after enrichment completes,
before pass phase execution. Provides O(1) lookups for pass phases to avoid
repeated ScanResult traversals.
"""

from typing import Dict, List, Any
from vulnparse_pin.core.classes.dataclass import (
    ScanResult,
    PostEnrichmentIndex,
    AssetObservation,
    Finding,
)


def build_post_enrichment_index(scan: ScanResult) -> PostEnrichmentIndex:
    """
    Build immutable post-enrichment index from ScanResult.
    
    Traverses ScanResult once to precompute:
    - O(1) finding lookups by finding_id
    - findings grouped by asset_id
    - precomputed asset observations
    - frequently-accessed finding attributes
    
    Args:
        scan: ScanResult to index
        
    Returns:
        PostEnrichmentIndex with all precomputed views
    """
    finding_by_id: Dict[str, Finding] = {}
    findings_by_asset_id: Dict[str, List[Finding]] = {}
    asset_observations: Dict[str, AssetObservation] = {}
    finding_attributes: Dict[str, Dict[str, Any]] = {}
    findings_by_severity: Dict[str, List[Finding]] = {}
    findings_by_cve: Dict[str, List[Finding]] = {}
    
    # Single traversal through all assets and findings
    for asset in scan.assets:
        asset_id = asset.asset_id or f"{asset.hostname}:{asset.ip_address}"
        findings_for_asset: List[Finding] = []
        open_ports: set[int] = set()
        
        for finding in asset.findings:
            # Core index: finding by ID
            finding_by_id[finding.finding_id] = finding
            
            # Group findings by asset
            findings_for_asset.append(finding)
            
            # Collect finding attributes for quick access
            finding_attributes[finding.finding_id] = {
                "asset_id": asset_id,
                "affected_port": finding.affected_port,
                "severity": finding.severity,
                "cvss_score": finding.cvss_score,
                "epss_score": finding.epss_score,
                "cisa_kev": finding.cisa_kev,
                "exploit_available": finding.exploit_available,
                "risk_score": finding.risk_score,
                "raw_risk_score": finding.raw_risk_score,
                "risk_band": finding.risk_band,
            }
            
            # Secondary index: findings by severity
            if finding.severity not in findings_by_severity:
                findings_by_severity[finding.severity] = []
            findings_by_severity[finding.severity].append(finding)
            
            # Secondary index: findings by CVE
            for cve in finding.cves:
                if cve not in findings_by_cve:
                    findings_by_cve[cve] = []
                findings_by_cve[cve].append(finding)
            
            # Collect open ports for asset observation
            if isinstance(finding.affected_port, int):
                open_ports.add(finding.affected_port)
        
        # Store grouped findings
        findings_by_asset_id[asset_id] = findings_for_asset
        
        # Precompute asset observations
        asset_observations[asset_id] = AssetObservation(
            asset_id=asset_id,
            ip=asset.ip_address,
            hostname=asset.hostname,
            criticality=asset.criticality,
            open_ports=tuple(sorted(open_ports)),
        )
    
    return PostEnrichmentIndex(
        finding_by_id=finding_by_id,
        findings_by_asset_id=findings_by_asset_id,
        asset_observations=asset_observations,
        finding_attributes=finding_attributes,
        findings_by_severity=findings_by_severity,
        findings_by_cve=findings_by_cve,
    )
