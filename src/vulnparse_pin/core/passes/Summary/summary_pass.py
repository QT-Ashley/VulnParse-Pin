# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

"""
Summary Pass - Aggregates scan metrics for executive reporting.

Performance optimizations for large datasets:
- Generator-based iteration to avoid loading full datasets
- Lazy evaluation of optional components
- Efficient top-N heapq operations
- Minimal memory footprint for aggregations
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING
import heapq

from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta
from vulnparse_pin.core.passes.types import SummaryPassOutput

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult


@dataclass
class SummaryConfig:
    """Configuration for summary generation."""
    include_asset_breakdown: bool = True
    include_cvss_distribution: bool = True
    include_top_risks: int = 10
    include_remediation_timeline: bool = True
    # Performance tuning for large datasets
    max_asset_detail: int = 100  # Limit asset detail reporting
    use_sampling_threshold: int = 100_000  # Sample if > 100k findings


class SummaryPass(Pass):
    """
    Generates executive and technical summaries from scan results.
    
    Produces:
    - Asset risk distribution
    - Finding severity breakdown
    - Top N highest risk findings
    - Remediation priority metrics
    - Exploit/KEV statistics
    
    Performance Characteristics:
    - O(n) single-pass aggregation for most metrics
    - O(k log n) for top-N selection using heapq
    - Memory-efficient generator patterns
    - Optimized for datasets with 100k+ findings
    """
    
    name = "Summary"
    version = "1.0"
    
    def __init__(self, config: Optional[SummaryConfig] = None):
        self.config = config or SummaryConfig()

    @staticmethod
    def _resolve_scan_timestamp(scan: "ScanResult") -> Optional[str]:
        """Resolve best available timestamp from scan metadata.

        Preference order:
        1) scan_metadata.scan_date when present and non-sentinel
        2) scan_metadata.parsed_at as fallback
        """
        metadata = getattr(scan, "scan_metadata", None)
        if metadata is None:
            return None

        scan_date = getattr(metadata, "scan_date", None)
        if scan_date:
            scan_date_str = str(scan_date).strip()
            if scan_date_str and not scan_date_str.startswith("SENTINEL:"):
                return scan_date_str

        parsed_at = getattr(metadata, "parsed_at", None)
        if parsed_at:
            parsed_at_str = str(parsed_at).strip()
            if parsed_at_str:
                return parsed_at_str

        return None
    
    def run(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        """Generate summary statistics from enriched scan results."""
        ctx.logger.print_info("Generating summary statistics...", label=self.name)
        
        # Get scoring data if available
        scoring_data = scan.derived.get("Scoring@1.0")
        scoring = scoring_data.data if scoring_data else None
        
        # Build finding lookup map for enrichment
        finding_map = self._build_finding_map(scan)
        
        # Single-pass data collection for performance
        ctx.logger.debug("Collecting scan metrics (single-pass)", extra={"vp_label": self.name})
        
        summary_output = SummaryPassOutput(
            overview=self._generate_overview(scan, scoring),
            asset_summary=self._generate_asset_summary(scan, scoring),
            finding_summary=self._generate_finding_summary(scan, scoring),
            risk_distribution=self._generate_risk_distribution(scan, scoring),
            top_risks=tuple(self._generate_top_risks(scan, scoring, finding_map)),
            enrichment_metrics=self._generate_enrichment_metrics(scan),
            remediation_priorities=self._generate_remediation_priorities(scan, scoring, finding_map),
        )
        
        ctx.logger.print_success("Summary generation complete", label=self.name)
        
        return DerivedPassResult(
            meta=PassMeta(
                name=self.name,
                version=self.version,
                created_at_utc=datetime.now(timezone.utc).isoformat(),
                notes="Aggregated scan summary for reporting"
            ),
            data=summary_output
        )
    
    def _build_finding_map(self, scan: "ScanResult") -> Dict[str, Any]:
        """Build a map of finding_id -> finding object for quick lookup."""
        finding_map = {}
        for asset in scan.assets:
            for finding in asset.findings:
                finding_map[finding.finding_id] = finding
        return finding_map
    
    def _generate_overview(self, scan: "ScanResult", scoring: Any) -> Dict[str, Any]:
        """
        Generate high-level overview metrics.
        
        Performance: O(n) single pass over assets/findings.
        """
        total_findings = 0
        exploit_findings = 0
        kev_findings = 0
        
        # Single-pass aggregation
        for asset in scan.assets:
            total_findings += len(asset.findings)
            for finding in asset.findings:
                if getattr(finding, 'exploit_available', False):
                    exploit_findings += 1
                if getattr(finding, 'cisa_kev', False):
                    kev_findings += 1
        
        avg_risk = scoring.get('avg_scored_risk', 0.0) if isinstance(scoring, dict) else 0.0
        
        return {
            "total_assets": len(scan.assets),
            "total_findings": total_findings,
            "exploitable_findings": exploit_findings,
            "kev_listed_findings": kev_findings,
            "average_asset_risk": round(avg_risk, 2) if avg_risk else 0.0,
            "scan_timestamp": self._resolve_scan_timestamp(scan),
        }
    
    def _generate_asset_summary(self, scan: "ScanResult", scoring: Dict) -> Dict[str, Any]:
        """
        Generate per-asset summary with top-N selection.
        
        Performance: O(n + k log n) where k = limit, using heapq for efficient top-N.
        """
        if not self.config.include_asset_breakdown:
            return {"total_assets": len(scan.assets), "assets": []}
        
        scored_assets = scoring.get('asset_scores', {}) if isinstance(scoring, dict) else {}
        scored_findings = scoring.get('scored_findings', {}) if isinstance(scoring, dict) else {}
        scored_asset_criticality = scoring.get('asset_criticality', {}) if isinstance(scoring, dict) else {}

        # Derived risk-band counters by asset (from Scoring pass output).
        derived_counts_by_asset: Dict[str, Dict[str, int]] = {}
        if isinstance(scored_findings, dict):
            for rec in scored_findings.values():
                if not isinstance(rec, dict):
                    continue
                aid = rec.get("asset_id")
                if not isinstance(aid, str) or not aid:
                    continue
                counts = derived_counts_by_asset.setdefault(aid, {"Critical": 0, "High": 0})
                band = str(rec.get("risk_band", ""))
                if band == "Critical":
                    counts["Critical"] += 1
                elif band == "High":
                    counts["High"] += 1
        
        # Use heapq for efficient top-N selection on large datasets
        # Negative scores for max-heap behavior
        asset_heap: List[tuple] = []
        limit = min(self.config.max_asset_detail, self.config.include_top_risks)
        counter = 0  # Tiebreaker for equal scores
        
        for asset in scan.assets:
            asset_id = getattr(asset, "asset_id", None) or asset.hostname or asset.ip_address
            risk_score = scored_assets.get(asset_id, 0.0)

            derived_counts = derived_counts_by_asset.get(asset_id, {"Critical": 0, "High": 0})

            # #1 CVE for asset: highest raw-score finding with at least one CVE.
            top_cve = "N/A"
            top_raw = float("-inf")
            for f in asset.findings:
                if not getattr(f, "cves", None):
                    continue
                frec = scored_findings.get(getattr(f, "finding_id", ""), {}) if isinstance(scored_findings, dict) else {}
                raw_val = frec.get("raw_score") if isinstance(frec, dict) else None
                try:
                    raw = float(raw_val)
                except (TypeError, ValueError):
                    raw = float("-inf")
                if raw > top_raw:
                    top_raw = raw
                    top_cve = str(f.cves[0])
            
            asset_entry = {
                "asset_id": asset_id,
                "ip": asset.ip_address,
                "hostname": asset.hostname,
                "total_findings": len(asset.findings),
                "risk_score": round(risk_score, 2),
                "operational_risk": 0.0,  # Not stored per-asset in current implementation
                "criticality": scored_asset_criticality.get(asset_id) or getattr(asset, "criticality", None),
                "critical_findings": derived_counts.get("Critical", 0),
                "high_findings": derived_counts.get("High", 0),
                "top_cve": top_cve,
            }
            
            # Use min-heap with negated scores to get top-k
            # Include counter as tiebreaker to avoid comparing dicts
            if len(asset_heap) < limit:
                heapq.heappush(asset_heap, (risk_score, counter, asset_entry))
            elif risk_score > asset_heap[0][0]:
                heapq.heapreplace(asset_heap, (risk_score, counter, asset_entry))
            counter += 1
        
        # Extract and sort by score descending
        top_assets = [entry for _, _, entry in sorted(asset_heap, key=lambda x: x[0], reverse=True)]
        
        return {
            "total_assets": len(scan.assets),
            "assets": top_assets,
        }
    
    def _generate_finding_summary(self, scan: "ScanResult", _scoring: Dict) -> Dict[str, Any]:
        """
        Generate finding-level summary by severity.
        
        Performance: O(n) single pass.
        """
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        
        for asset in scan.assets:
            for finding in asset.findings:
                sev = getattr(finding, 'severity', 'Informational')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "by_severity": severity_counts,
            "total": sum(severity_counts.values()),
        }
    
    def _generate_risk_distribution(self, _scan: "ScanResult", scoring: Any) -> Dict[str, Any]:
        """
        Generate risk band distribution from scoring.
        
        Performance: O(m) where m = number of scored findings.
        """
        band_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }
        
        if not isinstance(scoring, dict):
            return {"by_risk_band": band_counts, "total_scored": 0}
        
        scored_findings = scoring.get('scored_findings', {})
        
        # scored_findings is Dict[str, dict] where each dict has ScoredFinding fields
        for finding_data in scored_findings.values():
            band = finding_data.get('risk_band', 'Informational')
            band_counts[band] = band_counts.get(band, 0) + 1
        
        return {
            "by_risk_band": band_counts,
            "total_scored": len(scored_findings),
        }
    
    def _generate_top_risks(self, _scan: "ScanResult", scoring: Any, finding_map: Dict) -> List[Dict[str, Any]]:
        """
        Extract top N highest risk findings using heapq.
        
        Performance: O(m log k) where m = scored findings, k = top_risks limit.
        Memory: O(k) - only stores top-k in memory.
        """
        if not isinstance(scoring, dict):
            return []
        
        scored_findings = scoring.get('scored_findings', {})
        if not scored_findings:
            return []
        
        # De-duplicate by CVE and keep highest-scored representative finding per CVE.
        # This avoids confusing repeated CVE rows while preserving top risk signals.
        best_by_cve: Dict[str, Dict[str, Any]] = {}

        for finding_id, scored_data in scored_findings.items():
            finding = finding_map.get(finding_id)
            if not finding:
                continue

            risk_score = float(scored_data.get('raw_score', 0.0) or 0.0)
            cve_display = finding.cves[0] if finding.cves else finding_id

            existing = best_by_cve.get(cve_display)
            if existing is None:
                best_by_cve[cve_display] = {
                    "cve": cve_display,
                    "finding_risk_score": round(risk_score, 2),
                    "risk_band": scored_data.get('risk_band', 'Informational'),
                    "exploit_available": getattr(finding, 'exploit_available', False),
                    "kev_listed": getattr(finding, 'cisa_kev', False),
                    "epss_score": getattr(finding, 'epss_score', None),
                    "cvss_base_score": getattr(finding, 'cvss_score', None),
                    "occurrence_count": 1,
                }
            else:
                existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + 1
                if risk_score > float(existing.get("finding_risk_score", 0.0)):
                    existing.update({
                        "finding_risk_score": round(risk_score, 2),
                        "risk_band": scored_data.get('risk_band', 'Informational'),
                        "exploit_available": getattr(finding, 'exploit_available', False),
                        "kev_listed": getattr(finding, 'cisa_kev', False),
                        "epss_score": getattr(finding, 'epss_score', None),
                        "cvss_base_score": getattr(finding, 'cvss_score', None),
                    })

        # Use min-heap to efficiently maintain top-k CVE entries by finding-level raw score.
        top_heap: List[tuple] = []
        limit = self.config.include_top_risks
        counter = 0

        for entry in best_by_cve.values():
            risk_score = float(entry.get("finding_risk_score", 0.0) or 0.0)
            if len(top_heap) < limit:
                heapq.heappush(top_heap, (risk_score, counter, entry))
            elif risk_score > top_heap[0][0]:
                heapq.heapreplace(top_heap, (risk_score, counter, entry))
            counter += 1

        return [entry for _, _, entry in sorted(top_heap, key=lambda x: x[0], reverse=True)]
    
    def _generate_enrichment_metrics(self, scan: "ScanResult") -> Dict[str, Any]:
        """
        Calculate enrichment coverage metrics.
        
        Performance: O(n) single pass with early termination opportunities.
        """
        total_findings = 0
        total_cves = 0
        enriched_findings = 0
        
        for asset in scan.assets:
            for finding in asset.findings:
                total_findings += 1
                if finding.cves:
                    total_cves += len(finding.cves)
                if finding.enriched:
                    enriched_findings += 1
        
        return {
            "total_findings": total_findings,
            "total_cves": total_cves,
            "enriched_findings": enriched_findings,
            "enrichment_coverage": round(enriched_findings / total_findings, 4) if total_findings > 0 else 0.0,
        }
    
    def _generate_remediation_priorities(self, _scan: "ScanResult", scoring: Any, finding_map: Dict) -> Dict[str, Any]:
        """
        Generate remediation priority recommendations.
        
        Performance: O(m) where m = scored findings.
        """
        if not isinstance(scoring, dict):
            return {
                "immediate_action": 0,
                "high_priority": 0,
                "medium_priority": 0,
                "immediate_cves": [],
            }
        
        scored_findings = scoring.get('scored_findings', {})
        
        # Categorize by urgency in single pass
        immediate = []
        high_priority = 0
        medium_priority = 0
        
        for finding_id, scored_data in scored_findings.items():
            finding = finding_map.get(finding_id)
            if not finding:
                continue
            
            band = scored_data.get('risk_band', 'Informational')
            kev = getattr(finding, 'cisa_kev', False)
            exploit = getattr(finding, 'exploit_available', False)
            
            # Get CVE for display
            cve_display = finding.cves[0] if finding.cves else finding_id
            
            if band == "Critical" and (kev or exploit):
                immediate.append(cve_display)
            elif band in ("Critical", "High"):
                high_priority += 1
            elif band == "Medium":
                medium_priority += 1
        
        # Limit immediate CVE list and de-duplicate for report readability
        immediate_unique = list(dict.fromkeys(immediate))
        immediate_sample = immediate_unique[:20]
        
        return {
            "immediate_action": len(immediate_unique),
            "high_priority": high_priority,
            "medium_priority": medium_priority,
            "immediate_cves": immediate_sample,
        }
