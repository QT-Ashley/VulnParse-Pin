# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
Summary Pass - Aggregates scan metrics for executive reporting.

Performance optimizations for large datasets:
- Generator-based iteration to avoid loading full datasets
- Lazy evaluation of optional components
- Efficient top-N heapq operations
- Minimal memory footprint for aggregations
"""

from dataclasses import asdict, dataclass
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
        scoring_data = scan.derived.get("Scoring@2.0")
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
            decision_trace_summary=self._generate_decision_trace_summary(scan),
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

    @staticmethod
    def _coerce_score_trace(scored_data: Dict[str, Any]) -> Dict[str, Any]:
        trace = scored_data.get("score_trace", {}) if isinstance(scored_data, dict) else {}
        return trace if isinstance(trace, dict) else {}

    @staticmethod
    def _score_trace_union_flags(scored_data: Dict[str, Any]) -> Dict[str, bool]:
        trace = SummaryPass._coerce_score_trace(scored_data)
        union = trace.get("union_flags", {})
        if not isinstance(union, dict):
            union = {}
        return {
            "kev": bool(union.get("kev", False)),
            "exploit": bool(union.get("exploit", False)),
        }

    @staticmethod
    def _score_trace_contributor_stats(scored_data: Dict[str, Any]) -> Dict[str, int]:
        trace = SummaryPass._coerce_score_trace(scored_data)
        contributors = trace.get("contributors", [])
        if not isinstance(contributors, list):
            contributors = []

        cve_count = trace.get("cve_count")
        try:
            cve_count_int = int(cve_count)
        except (TypeError, ValueError):
            cve_count_int = len(contributors)
        cve_count_int = max(0, cve_count_int)

        exploitable_cve_count = 0
        kev_cve_count = 0
        for contributor in contributors:
            if not isinstance(contributor, dict):
                continue
            if bool(contributor.get("exploit_available", False)):
                exploitable_cve_count += 1
            if bool(contributor.get("cisa_kev", False)):
                kev_cve_count += 1

        return {
            "cve_count": cve_count_int,
            "exploitable_cve_count": exploitable_cve_count,
            "kev_cve_count": kev_cve_count,
        }

    @staticmethod
    def _score_trace_display_cve(scored_data: Dict[str, Any]) -> Optional[str]:
        trace = SummaryPass._coerce_score_trace(scored_data)
        display_cve = trace.get("display_cve")
        if display_cve:
            return str(display_cve)
        primary_cve = trace.get("primary_cve")
        if primary_cve:
            return str(primary_cve)
        return None
    
    def _generate_overview(self, scan: "ScanResult", scoring: Any) -> Dict[str, Any]:
        """
        Generate high-level overview metrics.
        
        Performance: O(n) single pass over assets/findings.
        """
        total_findings = 0
        exploit_findings = 0
        kev_findings = 0
        
        scored_findings = scoring.get("scored_findings", {}) if isinstance(scoring, dict) else {}

        # Single-pass aggregation
        for asset in scan.assets:
            total_findings += len(asset.findings)
            for finding in asset.findings:
                scored_data = scored_findings.get(getattr(finding, "finding_id", ""), {}) if isinstance(scored_findings, dict) else {}
                union_flags = self._score_trace_union_flags(scored_data)
                if getattr(finding, 'exploit_available', False) or union_flags["exploit"]:
                    exploit_findings += 1
                if getattr(finding, 'cisa_kev', False) or union_flags["kev"]:
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
                frec = scored_findings.get(getattr(f, "finding_id", ""), {}) if isinstance(scored_findings, dict) else {}
                raw_val = frec.get("raw_score") if isinstance(frec, dict) else None
                try:
                    raw = float(raw_val)
                except (TypeError, ValueError):
                    raw = float("-inf")
                if raw > top_raw:
                    top_raw = raw
                    top_cve = str(
                        self._score_trace_display_cve(frec)
                        or getattr(f, "enrichment_source_cve", None)
                        or (f.cves[0] if getattr(f, "cves", None) else "N/A")
                    )
            
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
            cve_display = (
                self._score_trace_display_cve(scored_data)
                or getattr(finding, "enrichment_source_cve", None)
                or (finding.cves[0] if finding.cves else finding_id)
            )
            contributor_stats = self._score_trace_contributor_stats(scored_data)
            union_flags = self._score_trace_union_flags(scored_data)

            existing = best_by_cve.get(cve_display)
            if existing is None:
                best_by_cve[cve_display] = {
                    "cve": cve_display,
                    "finding_risk_score": round(risk_score, 2),
                    "risk_band": scored_data.get('risk_band', 'Informational'),
                    "exploit_available": getattr(finding, 'exploit_available', False) or union_flags["exploit"],
                    "kev_listed": getattr(finding, 'cisa_kev', False) or union_flags["kev"],
                    "epss_score": getattr(finding, 'epss_score', None),
                    "cvss_base_score": getattr(finding, 'cvss_score', None),
                    "aggregated_cve_count": contributor_stats["cve_count"],
                    "aggregated_exploitable_cve_count": max(
                        contributor_stats["exploitable_cve_count"],
                        1 if union_flags["exploit"] else 0,
                    ),
                    "aggregated_kev_cve_count": max(
                        contributor_stats["kev_cve_count"],
                        1 if union_flags["kev"] else 0,
                    ),
                    "occurrence_count": 1,
                }
            else:
                existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + 1
                if risk_score > float(existing.get("finding_risk_score", 0.0)):
                    existing.update({
                        "finding_risk_score": round(risk_score, 2),
                        "risk_band": scored_data.get('risk_band', 'Informational'),
                        "exploit_available": getattr(finding, 'exploit_available', False) or union_flags["exploit"],
                        "kev_listed": getattr(finding, 'cisa_kev', False) or union_flags["kev"],
                        "epss_score": getattr(finding, 'epss_score', None),
                        "cvss_base_score": getattr(finding, 'cvss_score', None),
                        "aggregated_cve_count": contributor_stats["cve_count"],
                        "aggregated_exploitable_cve_count": max(
                            contributor_stats["exploitable_cve_count"],
                            1 if union_flags["exploit"] else 0,
                        ),
                        "aggregated_kev_cve_count": max(
                            contributor_stats["kev_cve_count"],
                            1 if union_flags["kev"] else 0,
                        ),
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
            union_flags = self._score_trace_union_flags(scored_data)
            kev = getattr(finding, 'cisa_kev', False) or union_flags["kev"]
            exploit = getattr(finding, 'exploit_available', False) or union_flags["exploit"]
            
            # Get CVE for display
            cve_display = (
                self._score_trace_display_cve(scored_data)
                or getattr(finding, "enrichment_source_cve", None)
                or (finding.cves[0] if finding.cves else finding_id)
            )
            
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

    def _generate_decision_trace_summary(self, scan: "ScanResult") -> Dict[str, Any]:
        """Aggregate compact TopN/ACI trace signals for downstream reporting."""
        topn_result = scan.derived.get("TopN@1.0")
        aci_result = scan.derived.get("ACI@1.0")

        topn_data = getattr(topn_result, "data", None)
        if not isinstance(topn_data, dict):
            topn_data = {}

        aci_data = getattr(aci_result, "data", None)
        if not isinstance(aci_data, dict):
            aci_data = {}

        exposure_confidence_counts = {"high": 0, "medium": 0, "low": 0}
        exposure_rule_hit_counts: Dict[str, int] = {}

        for asset_row in topn_data.get("assets", []) or []:
            if not isinstance(asset_row, dict):
                continue
            inference = asset_row.get("inference", {})
            if not isinstance(inference, dict):
                inference = {}
            confidence = str(inference.get("confidence", "")).strip().lower()
            if confidence in exposure_confidence_counts:
                exposure_confidence_counts[confidence] += 1
            for rid in inference.get("evidence_rule_ids", []) or []:
                key = str(rid).strip()
                if not key:
                    continue
                exposure_rule_hit_counts[key] = exposure_rule_hit_counts.get(key, 0) + 1

        findings_by_risk_band: Dict[str, int] = {}
        for flist in (topn_data.get("findings_by_asset", {}) or {}).values():
            if not isinstance(flist, (list, tuple)):
                continue
            for frec in flist:
                if not isinstance(frec, dict):
                    continue
                band = str(frec.get("risk_band", "") or "").strip().lower()
                if not band:
                    continue
                findings_by_risk_band[band] = findings_by_risk_band.get(band, 0) + 1

        aci_metrics = aci_data.get("metrics", {})
        if not isinstance(aci_metrics, dict):
            aci_metrics = {}
        chain_candidates = aci_metrics.get("chain_candidates_detected", {})
        if not isinstance(chain_candidates, dict):
            chain_candidates = {}

        _band_order = ("critical", "high", "medium", "low", "info")
        findings_by_risk_band_sorted = {
            b: findings_by_risk_band[b]
            for b in _band_order
            if b in findings_by_risk_band
        }
        # Append any unrecognised bands in sorted order
        for b in sorted(findings_by_risk_band):
            if b not in findings_by_risk_band_sorted:
                findings_by_risk_band_sorted[b] = findings_by_risk_band[b]

        return {
            "assets_with_exposure_inference": int(sum(exposure_confidence_counts.values())),
            "exposure_confidence_counts": exposure_confidence_counts,
            "exposure_rule_hit_counts": dict(sorted(exposure_rule_hit_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "findings_by_risk_band": findings_by_risk_band_sorted,
            "aci_inferred_findings": int(aci_metrics.get("inferred_findings", 0) or 0),
            "aci_chain_candidates_detected": dict(chain_candidates),
        }


def _resolve_summary_duckdb_conn(db_obj: Any) -> Any:
    if db_obj is None:
        return None
    inner = getattr(db_obj, "conn", None)
    if inner is not None and hasattr(inner, "execute"):
        return inner
    if hasattr(db_obj, "execute"):
        return db_obj
    return None


class SummaryV2Pass(Pass):
    """Unified DuckDB-first Summary@2.0 aggregation pass requiring Triage@2.0."""

    name: str = "Summary"
    version: str = "2.0"
    requires_passes: tuple[str, ...] = ("Triage@2.0",)

    def __init__(self, config: Optional[Any] = None) -> None:
        if isinstance(config, SummaryConfig):
            self.config = config
        elif config is not None and hasattr(config, "v2"):
            self.config = SummaryConfig(include_top_risks=int(config.v2.summary_top_n))
        elif config is not None and hasattr(config, "summary_top_n"):
            self.config = SummaryConfig(include_top_risks=int(config.summary_top_n))
        else:
            self.config = SummaryConfig()

    def run(self, ctx: "RunContext", scan: Optional["ScanResult"] = None) -> DerivedPassResult:
        services = getattr(ctx, "services", None)
        db = getattr(ctx, "db", None) or getattr(services, "db", None)
        run_id = getattr(ctx, "run_id", None) or getattr(services, "run_id", None)
        conn = _resolve_summary_duckdb_conn(db) if (db is not None and run_id is not None) else None

        if conn is not None and run_id is not None:
            return self._run_duckdb(ctx, conn, str(run_id))

        if scan is None:
            raise ValueError("SummaryV2Pass requires either DuckDB (ctx.db + ctx.run_id) or ScanResult.")
        return self._run_scan_result(ctx, scan)

    def _run_duckdb(self, ctx: "RunContext", conn: Any, run_id: str) -> DerivedPassResult:
        import json

        def _group_counts(sql: str, *args: Any) -> Dict[str, int]:
            out: Dict[str, int] = {}
            for k, cnt in conn.execute(sql, list(args)).fetchall():
                if k is not None:
                    out[str(k)] = int(cnt)
            return out

        run_row = conn.execute("SELECT profile, vpp_version FROM runs WHERE run_id = ?", [run_id]).fetchone()
        run_profile = run_row[0] if run_row and run_row[0] else "default"

        asset_row = conn.execute(
            """
            SELECT
                COUNT(*),
                SUM(CASE WHEN inventory_status = 'matched' THEN 1 ELSE 0 END),
                SUM(CASE WHEN inventory_status = 'unmatched_shadow' THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(internet_facing, FALSE) THEN 1 ELSE 0 END)
            FROM assets WHERE run_id = ?
            """,
            [run_id],
        ).fetchone()

        finding_row = conn.execute(
            """
            SELECT
                COUNT(*),
                SUM(CASE WHEN f.scoring_track = 'cve_threat' THEN 1 ELSE 0 END),
                SUM(CASE WHEN f.scoring_track = 'exposure_weakness' THEN 1 ELSE 0 END),
                SUM(CASE WHEN s.finding_id IS NOT NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN td.finding_id IS NOT NULL THEN 1 ELSE 0 END),
                MAX(s.operational_score),
                AVG(s.operational_score),
                AVG(s.raw_risk_score)
            FROM findings f
            LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
            LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
            WHERE f.run_id = ?
            """,
            [run_id],
        ).fetchone()

        intel_row = conn.execute(
            """
            SELECT
                SUM(
                    CASE
                        WHEN (
                            COALESCE(e.in_kev, FALSE)
                            OR COALESCE(fc_agg.fc_in_kev, FALSE)
                            OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                        ) THEN 1
                        ELSE 0
                    END
                ),
                SUM(
                    CASE
                        WHEN (
                            COALESCE(e.verified_exploit, FALSE)
                            OR COALESCE(fc_agg.fc_verified_exploit, FALSE)
                            OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.verified_exploit') AS BOOLEAN), FALSE)
                        ) THEN 1
                        ELSE 0
                    END
                ),
                SUM(
                    CASE
                        WHEN (
                            COALESCE(e.heuristic_exploit_mention, FALSE)
                            OR COALESCE(fc_agg.fc_heuristic_exploit, FALSE)
                            OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.heuristic_exploit_mention') AS BOOLEAN), FALSE)
                        )
                        AND NOT (
                            COALESCE(e.verified_exploit, FALSE)
                            OR COALESCE(fc_agg.fc_verified_exploit, FALSE)
                            OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.verified_exploit') AS BOOLEAN), FALSE)
                        ) THEN 1
                        ELSE 0
                    END
                ),
                SUM(CASE WHEN e.epss_score IS NOT NULL THEN 1 ELSE 0 END)
            FROM findings f
            LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
            LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id
                AND UPPER(e.cve_id) = COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), UPPER(f.primary_cve))
            LEFT JOIN (
                SELECT
                    fc.finding_id,
                    BOOL_OR(COALESCE(es.in_kev, FALSE)) AS fc_in_kev,
                    BOOL_OR(COALESCE(es.verified_exploit, FALSE)) AS fc_verified_exploit,
                    BOOL_OR(COALESCE(es.heuristic_exploit_mention, FALSE)) AS fc_heuristic_exploit
                FROM finding_cves fc
                JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id)
                WHERE fc.run_id = ?
                GROUP BY fc.finding_id
            ) fc_agg ON fc_agg.finding_id = f.finding_id
            WHERE f.run_id = ?
            """,
            [run_id, run_id],
        ).fetchone()

        by_priority = _group_counts(
            "SELECT priority_tier, COUNT(*) FROM triage_decisions WHERE run_id = ? GROUP BY priority_tier",
            run_id,
        )
        by_sla = _group_counts(
            "SELECT sla_bucket, COUNT(*) FROM triage_decisions WHERE run_id = ? GROUP BY sla_bucket",
            run_id,
        )
        by_status = _group_counts(
            "SELECT decision_status, COUNT(*) FROM triage_decisions WHERE run_id = ? GROUP BY decision_status",
            run_id,
        )
        by_band = _group_counts(
            "SELECT risk_band, COUNT(*) FROM scores WHERE run_id = ? GROUP BY risk_band",
            run_id,
        )
        by_track = _group_counts(
            "SELECT scoring_track, COUNT(*) FROM findings WHERE run_id = ? GROUP BY scoring_track",
            run_id,
        )
        by_sev = _group_counts(
            "SELECT scanner_severity, COUNT(*) FROM findings WHERE run_id = ? GROUP BY scanner_severity",
            run_id,
        )
        by_mode = _group_counts(
            "SELECT detection_mode, COUNT(*) FROM findings WHERE run_id = ? GROUP BY detection_mode",
            run_id,
        )
        by_crit = _group_counts(
            "SELECT derived_criticality, COUNT(*) FROM assets WHERE run_id = ? GROUP BY derived_criticality",
            run_id,
        )
        by_prov = _group_counts(
            "SELECT json_extract_string(score_trace_json, '$.cvss_provenance'), COUNT(*) "
            "FROM scores WHERE run_id = ? GROUP BY 1",
            run_id,
        )
        by_ssvc_action = _group_counts(
            "SELECT ssvc_action, COUNT(*) FROM triage_decisions WHERE run_id = ? GROUP BY ssvc_action",
            run_id,
        )

        hist_row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN operational_score >= 9.0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN operational_score >= 7.0 AND operational_score < 9.0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN operational_score >= 4.0 AND operational_score < 7.0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN operational_score < 4.0 THEN 1 ELSE 0 END)
            FROM scores WHERE run_id = ?
            """,
            [run_id],
        ).fetchone()

        top_n = max(1, int(self.config.include_top_risks))
        top_risks_rows = conn.execute(
            """
            SELECT
                f.finding_id,
                f.asset_id,
                f.title,
                COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) AS primary_cve,
                s.scoring_track,
                s.raw_risk_score,
                s.operational_score,
                s.risk_band,
                td.priority_tier,
                td.oal_compat,
                td.ssvc_action,
                td.sla_bucket,
                td.decision_status,
                COALESCE(a.internet_facing, FALSE)
            FROM findings f
            JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
            JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
            LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id
            LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id
                AND UPPER(e.cve_id) = COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), UPPER(f.primary_cve))
            WHERE f.run_id = ?
            ORDER BY
                CASE UPPER(COALESCE(td.priority_tier, 'P4'))
                    WHEN 'P1' THEN 1
                    WHEN 'P1B' THEN 2
                    WHEN 'P2' THEN 3
                    WHEN 'P3' THEN 4
                    WHEN 'P4' THEN 5
                    ELSE 99
                END ASC,
                s.operational_score DESC NULLS LAST,
                e.epss_score DESC NULLS LAST,
                f.finding_id ASC
            LIMIT ?
            """,
            [run_id, top_n],
        ).fetchall()

        top_risks = tuple(
            {
                "finding_id": r[0],
                "asset_id": r[1],
                "title": r[2],
                "primary_cve": r[3],
                "scoring_track": r[4],
                "raw_risk_score": round(float(r[5] or 0.0), 4),
                "operational_score": round(float(r[6] or 0.0), 4),
                "risk_band": r[7],
                "priority_tier": r[8],
                "oal_compat": r[9],
                "ssvc_action": r[10],
                "sla_bucket": r[11],
                "decision_status": r[12],
                "internet_facing": bool(r[13]),
            }
            for r in top_risks_rows
        )

        top_asset_rows = conn.execute(
            """
            SELECT
                a.asset_id,
                a.canonical_key,
                a.inventory_status,
                a.derived_criticality,
                MAX(s.operational_score) AS max_op,
                COUNT(f.finding_id) AS finding_cnt
            FROM assets a
            LEFT JOIN findings f ON f.run_id = a.run_id AND f.asset_id = a.asset_id
            LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
            WHERE a.run_id = ?
            GROUP BY a.asset_id, a.canonical_key, a.inventory_status, a.derived_criticality
            ORDER BY max_op DESC NULLS LAST, finding_cnt DESC, a.asset_id ASC
            LIMIT 10
            """,
            [run_id],
        ).fetchall()

        imm_cves = [
            r[0]
            for r in conn.execute(
                """
                SELECT DISTINCT
                    COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) AS eff_cve
                FROM findings f
                LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
                JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
                WHERE f.run_id = ?
                  AND COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) IS NOT NULL
                  AND UPPER(COALESCE(td.priority_tier, '')) IN ('P1', 'P1B', 'P2')
                ORDER BY eff_cve ASC
                LIMIT 20
                """,
                [run_id],
            ).fetchall()
            if r[0]
        ]

        aci_cnt_row = conn.execute(
            "SELECT COUNT(*), SUM(CASE WHEN uplift_score > 0 THEN 1 ELSE 0 END) "
            "FROM aci_signals WHERE run_id = ? AND capabilities_json != '[]'",
            [run_id],
        ).fetchone()

        sast_cap_row = conn.execute(
            "SELECT COUNT(*) FROM triage_decisions "
            "WHERE run_id = ? AND json_extract_string(assumed_state_json, '$.sast_p1_capped') = 'true'",
            [run_id],
        ).fetchone()

        overview = {
            "run_id": run_id,
            "profile": run_profile,
            "total_assets": int(asset_row[0] or 0),
            "matched_assets": int(asset_row[1] or 0),
            "shadow_assets": int(asset_row[2] or 0),
            "total_findings": int(finding_row[0] or 0),
            "cve_findings": int(finding_row[1] or 0),
            "exposure_findings": int(finding_row[2] or 0),
            "scored_findings": int(finding_row[3] or 0),
            "triaged_findings": int(finding_row[4] or 0),
            "highest_operational_score": round(float(finding_row[5]), 4) if finding_row[5] is not None else 0.0,
            "avg_operational_score": round(float(finding_row[6]), 4) if finding_row[6] is not None else 0.0,
            "avg_raw_score": round(float(finding_row[7]), 4) if finding_row[7] is not None else 0.0,
        }
        asset_summary = {
            "total_assets": int(asset_row[0] or 0),
            "matched_assets": int(asset_row[1] or 0),
            "shadow_assets": int(asset_row[2] or 0),
            "internet_facing_assets": int(asset_row[3] or 0),
            "criticality_distribution": by_crit,
            "top_assets": [
                {
                    "asset_id": r[0],
                    "canonical_key": r[1],
                    "inventory_status": r[2],
                    "derived_criticality": r[3],
                    "max_operational_score": round(float(r[4] or 0.0), 4),
                    "finding_count": int(r[5] or 0),
                }
                for r in top_asset_rows
            ],
        }
        finding_summary = {
            "total_findings": int(finding_row[0] or 0),
            "by_priority_tier": by_priority,
            "by_sla_bucket": by_sla,
            "by_decision_status": by_status,
            "by_scoring_track": by_track,
            "by_severity": by_sev,
            "by_detection_mode": by_mode,
        }
        risk_distribution = {
            "by_risk_band": by_band,
            "operational_score_histogram": {
                "critical_ge_9": int(hist_row[0] or 0),
                "high_7_to_9": int(hist_row[1] or 0),
                "medium_4_to_7": int(hist_row[2] or 0),
                "low_lt_4": int(hist_row[3] or 0),
            },
        }
        enrichment_metrics = {
            "kev_findings": int(intel_row[0] or 0),
            "verified_exploit_findings": int(intel_row[1] or 0),
            "heuristic_only_findings": int(intel_row[2] or 0),
            "epss_covered_findings": int(intel_row[3] or 0),
            "by_cvss_provenance": by_prov,
        }
        remediation_priorities = {
            "by_priority_tier": by_priority,
            "by_sla_bucket": by_sla,
            "immediate_action": int(by_priority.get("P1", 0)) + int(by_priority.get("P1B", 0)),
            "high_priority": int(by_priority.get("P2", 0)),
            "medium_priority": int(by_priority.get("P3", 0)),
            "invalidated_decisions": int(
                by_status.get("deferred_invalidated", 0)
                + by_status.get("accepted_invalidated", 0)
                + by_status.get("mitigated_invalidated", 0)
            ),
            "immediate_cves": imm_cves,
        }
        decision_trace_summary = {
            "aci_inferred_findings": int(aci_cnt_row[0] or 0),
            "aci_uplifted_findings": int(aci_cnt_row[1] or 0),
            "ssvc_action_counts": by_ssvc_action,
            "sast_p1_capped_findings": int(sast_cap_row[0] or 0),
        }

        output = SummaryPassOutput(
            overview=overview,
            asset_summary=asset_summary,
            finding_summary=finding_summary,
            risk_distribution=risk_distribution,
            top_risks=top_risks,
            enrichment_metrics=enrichment_metrics,
            remediation_priorities=remediation_priorities,
            decision_trace_summary=decision_trace_summary,
        )
        ctx.logger.info(
            "[pass:summary@2.0] duckdb | assets=%d | findings=%d | p1=%d",
            overview["total_assets"],
            overview["total_findings"],
            remediation_priorities["immediate_action"],
            extra={"vp_label": "SummaryV2Pass"},
        )
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Unified DuckDB Summary@2.0 report aggregation.",
        )
        return DerivedPassResult(meta=meta, data=asdict(output))

    def _run_scan_result(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        triage_res = scan.derived.get("Triage@2.0")
        scoring_res = scan.derived.get("Scoring@3.0") or scan.derived.get("Scoring@2.0")
        triage_map = (triage_res.data or {}).get("decisions", {}) if triage_res else {}
        scored_map = (scoring_res.data or {}).get("scored_findings", {}) if scoring_res else {}

        by_priority = dict((triage_res.data or {}).get("by_priority_tier", {}) if triage_res else {})
        by_sla = dict((triage_res.data or {}).get("by_sla_bucket", {}) if triage_res else {})
        by_status = dict((triage_res.data or {}).get("by_decision_status", {}) if triage_res else {})

        by_band: Dict[str, int] = {}
        op_scores: List[float] = []
        top_items: List[Dict[str, Any]] = []
        for fid, sf in scored_map.items():
            band = str(sf.get("risk_band") or "Informational")
            by_band[band] = by_band.get(band, 0) + 1
            op = float(sf.get("operational_score", 0.0) or 0.0)
            op_scores.append(op)
            td = triage_map.get(fid) or {}
            top_items.append(
                {
                    "finding_id": fid,
                    "asset_id": sf.get("asset_id"),
                    "operational_score": round(op, 4),
                    "raw_risk_score": round(float(sf.get("raw_score", 0.0) or 0.0), 4),
                    "risk_band": band,
                    "priority_tier": td.get("priority_tier"),
                    "sla_bucket": td.get("sla_bucket"),
                    "decision_status": td.get("decision_status", "active"),
                }
            )
        top_items.sort(key=lambda r: (-float(r["operational_score"]), str(r["finding_id"])))
        top_risks = tuple(top_items[: max(1, int(self.config.include_top_risks))])

        total_findings = sum(len(a.findings) for a in scan.assets)
        output = SummaryPassOutput(
            overview={
                "total_assets": len(scan.assets),
                "total_findings": total_findings,
                "scored_findings": len(scored_map),
                "triaged_findings": len(triage_map),
                "avg_operational_score": round(sum(op_scores) / len(op_scores), 4) if op_scores else 0.0,
            },
            asset_summary={"total_assets": len(scan.assets)},
            finding_summary={
                "total_findings": total_findings,
                "by_priority_tier": by_priority,
                "by_sla_bucket": by_sla,
                "by_decision_status": by_status,
            },
            risk_distribution={"by_risk_band": by_band},
            top_risks=top_risks,
            enrichment_metrics={},
            remediation_priorities={
                "by_priority_tier": by_priority,
                "by_sla_bucket": by_sla,
                "immediate_action": int(by_priority.get("P1", 0)) + int(by_priority.get("P1B", 0)),
                "high_priority": int(by_priority.get("P2", 0)),
                "invalidated_decisions": int(
                    by_status.get("deferred_invalidated", 0)
                    + by_status.get("accepted_invalidated", 0)
                    + by_status.get("mitigated_invalidated", 0)
                ),
            },
            decision_trace_summary={
                "sast_p1_capped_findings": int((triage_res.data or {}).get("sast_p1_capped", 0) if triage_res else 0),
            },
        )
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Summary@2.0 report aggregation (ScanResult fallback).",
        )
        return DerivedPassResult(meta=meta, data=asdict(output))
