# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Set, TYPE_CHECKING, List, Sequence, Tuple, Any, Union
import concurrent.futures as cf
import json
import math
import re
import threading
import os

from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass
from vulnparse_pin.core.passes.types import ScoreCoverage, ScoredFinding, ScoringPassOutput
from vulnparse_pin.core.classes.pass_classes import PassMeta

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.classes.dataclass import Finding


def _finalize_score_trace(
    attrs: Dict[str, Any],
    *,
    raw: float,
    score: float,
    band: str,
    reasons: List[str],
    nmap_component: float,
) -> Dict[str, Any]:
    base_trace = attrs.get("score_trace_base")
    if not isinstance(base_trace, dict):
        base_trace = {}

    trace = dict(base_trace)
    union_flags = trace.get("union_flags")
    if not isinstance(union_flags, dict):
        union_flags = {}
    union_flags["nmap_open_port"] = bool(attrs.get("nmap_open_port", False))
    trace["union_flags"] = union_flags
    trace["nmap_component"] = round(nmap_component, 4)
    trace["final_raw_score"] = round(raw, 4)
    trace["final_operational_score"] = round(score, 4)
    trace["final_risk_band"] = band
    trace["final_reasons"] = list(reasons)
    return trace


def _score_signal_components_from_policy_values(
    *,
    kev: bool,
    exploit: bool,
    cvss: Any,
    epss: Any,
    policy_values: Dict[str, float],
) -> Tuple[float, List[str]]:
    raw = 0.0
    reasons: List[str] = []

    if cvss is not None:
        try:
            c = float(cvss)
            raw += c
            reasons.append(f"cvss={c:.2f}")
        except (TypeError, ValueError):
            pass

    if epss is not None:
        try:
            e = float(epss)
            e = min(max(e, float(policy_values["epss_min"])), float(policy_values["epss_max"]))
            e_scaled = e * float(policy_values["epss_scale"])

            mult = 1.0
            if e >= 0.70:
                mult = float(policy_values["w_epss_high"])
                reasons.append(f"epss_high*{policy_values['w_epss_high']:g}")
            elif e >= 0.40:
                mult = float(policy_values["w_epss_medium"])
                reasons.append(f"epss_medium*{policy_values['w_epss_medium']:g}")

            raw += e_scaled * mult
            reasons.append(f"epss={e:.5f}({e_scaled:.2f})")
        except (TypeError, ValueError):
            pass

    if kev:
        raw += float(policy_values["kev_evd"]) * float(policy_values["w_kev"])
        reasons.append("KEV Present")

    if exploit:
        raw += float(policy_values["exploit_evd"]) * float(policy_values["w_exploit"])
        reasons.append("Exploit Available")

    return raw, reasons


def _score_components_from_policy(
    attrs: Dict[str, Any],
    policy_values: Dict[str, float],
) -> Optional[Tuple[float, float, str, str, Dict[str, Any]]]:
    """Process-safe scoring helper for process pool workers."""
    kev = bool(attrs.get("kev", False))
    exploit = bool(attrs.get("exploit", False))
    cvss = attrs.get("cvss", None)
    epss = attrs.get("epss", None)
    nmap_open_port = bool(attrs.get("nmap_open_port", False))
    whole_cve_raw = attrs.get("whole_cve_raw", None)

    if whole_cve_raw is None and not kev and not exploit and cvss is None and epss is None:
        return None

    if whole_cve_raw is not None:
        try:
            raw = float(whole_cve_raw)
        except (TypeError, ValueError):
            return None
        reasons = list(attrs.get("whole_cve_reason_parts") or ["Whole-of-CVEs Aggregated"])
    else:
        raw, reasons = _score_signal_components_from_policy_values(
            kev=kev,
            exploit=exploit,
            cvss=cvss,
            epss=epss,
            policy_values=policy_values,
        )

    if nmap_open_port:
        nmap_bonus = float(policy_values.get("nmap_port_bonus", 0.0))
        if nmap_bonus > 0:
            raw += nmap_bonus
        reasons.append("Nmap Port Observed")
    else:
        nmap_bonus = 0.0

    max_raw_risk = float(policy_values["max_raw_risk"])
    max_op_risk = float(policy_values["max_op_risk"])
    score = (raw / max_raw_risk) * max_op_risk
    score = max(0.0, min(score, max_op_risk))

    if raw >= float(policy_values["band_critical"]):
        band = "Critical"
    elif raw >= float(policy_values["band_high"]):
        band = "High"
    elif raw >= float(policy_values["band_medium"]):
        band = "Medium"
    elif raw >= float(policy_values["band_low"]):
        band = "Low"
    else:
        band = "Informational"

    score_trace = _finalize_score_trace(
        attrs,
        raw=raw,
        score=score,
        band=band,
        reasons=reasons,
        nmap_component=nmap_bonus if nmap_open_port else 0.0,
    )
    return raw, score, band, ";".join(reasons), score_trace


def _score_chunk_process(
    chunk: List[Tuple[str, str, Dict[str, Any]]],
    policy_values: Dict[str, float],
) -> Tuple[Dict[str, Tuple[str, float, float, str, str, Dict[str, Any]]], Dict[str, float]]:
    """Process worker: returns finding tuples and per-asset max score."""
    chunk_results: Dict[str, Tuple[str, float, float, str, str, Dict[str, Any]]] = {}
    chunk_assets: Dict[str, float] = {}

    for finding_id, asset_id, attrs in chunk:
        score_parts = _score_components_from_policy(attrs, policy_values)
        if score_parts is None:
            continue
        raw, score, band, reason, score_trace = score_parts
        chunk_results[finding_id] = (asset_id, raw, score, band, reason, score_trace)
        if asset_id not in chunk_assets or raw > chunk_assets[asset_id]:
            chunk_assets[asset_id] = raw

    return chunk_results, chunk_assets

@dataclass
class ScoringPass(Pass):
    name: str = "Scoring"
    version: str = "2.0"
    requires_passes: tuple[str, ...] = ()

    def __init__(
        self,
        policy: ScoringPolicyV1,
        parallel_threshold: int = 100,
        min_findings_per_worker: int = 50,
        process_pool_threshold: int = 20_000,
        process_workers: Optional[int] = None,
        critical_extreme_min_critical: int = 3,
        critical_high_min_critical: int = 1,
        critical_high_min_high: int = 2,
        critical_medium_min_high: int = 1,
        critical_medium_min_medium: int = 5,
    ):
        self.policy = policy
        self.parallel_threshold = max(1, int(parallel_threshold))
        self.min_findings_per_worker = max(1, int(min_findings_per_worker))
        self.process_pool_threshold = max(1, int(process_pool_threshold))
        self.process_workers = process_workers
        self.critical_extreme_min_critical = max(1, int(critical_extreme_min_critical))
        self.critical_high_min_critical = max(1, int(critical_high_min_critical))
        self.critical_high_min_high = max(1, int(critical_high_min_high))
        self.critical_medium_min_high = max(1, int(critical_medium_min_high))
        self.critical_medium_min_medium = max(1, int(critical_medium_min_medium))
        self._result_lock = threading.Lock()
        self._memo_lock = threading.Lock()

    def _policy_values(self) -> Dict[str, float]:
        return {
            "epss_scale": self.policy.epss_scale,
            "epss_min": self.policy.epss_min,
            "epss_max": self.policy.epss_max,
            "w_epss_high": self.policy.w_epss_high,
            "w_epss_medium": self.policy.w_epss_medium,
            "kev_evd": self.policy.kev_evd,
            "w_kev": self.policy.w_kev,
            "exploit_evd": self.policy.exploit_evd,
            "w_exploit": self.policy.w_exploit,
            "max_raw_risk": self.policy.max_raw_risk,
            "max_op_risk": self.policy.max_op_risk,
            "band_critical": self.policy.band_critical,
            "band_high": self.policy.band_high,
            "band_medium": self.policy.band_medium,
            "band_low": self.policy.band_low,
            "nmap_port_bonus": self.policy.nmap_port_bonus,
        }

    def run(self, ctx: "RunContext", scan: "ScanResult") -> "DerivedPassResult":
        """
        Run scoring pass with parallel execution on finding batches.
        Smart caches plugin attributes to avoid repeated getattr() calls.
        """
        # Flatten findings with asset context (asset_id, ip_address)
        findings_with_context: List[Tuple[Any, str, Optional[str]]] = []
        assets_by_id: Dict[str, Any] = {}
        findings_by_id: Dict[str, Any] = {}
        total = 0
        
        for asset in scan.assets:
            for f in asset.findings:
                total += 1
                asset_id = getattr(asset, "asset_id", None) or f.asset_id or asset.ip_address
                findings_with_context.append((f, asset_id, asset.ip_address))
                findings_by_id[f.finding_id] = f
                if asset_id not in assets_by_id:
                    assets_by_id[asset_id] = asset

        # Pre-compute plugin attributes once (smart caching)
        nmap_open_ports = self._get_nmap_open_ports_by_asset(scan)
        plugin_cache = self._build_plugin_cache(findings_with_context, nmap_open_ports)

        # Parallel execution for medium+ workloads
        use_parallel = len(findings_with_context) > self.parallel_threshold

        # Shared memo for repeated score signatures (thread-safe in parallel mode)
        score_memo: Dict[Tuple[bool, bool, Any, Any, bool], Optional[Tuple[float, float, str, str, Dict[str, Any]]]] = {}
        
        if use_parallel and (os.cpu_count() or 1) > 1:
            if len(findings_with_context) >= self.process_pool_threshold:
                scored_findings, asset_scores = self._score_process_pool(
                    ctx, findings_with_context, plugin_cache
                )
            else:
                scored_findings, asset_scores = self._score_parallel(
                    ctx, findings_with_context, plugin_cache, score_memo
                )
        else:
            scored_findings, asset_scores = self._score_sequential(
                findings_with_context, plugin_cache, score_memo
            )

        self._write_finding_scores(findings_by_id, scored_findings)

        scored = len(scored_findings)
        coverage_ratio = (scored / total * 1.0) if total else 0.0
        avg_scored = (sum(sf.raw_score for sf in scored_findings.values()) / scored) if scored else None
        avg_op = (sum(sf.operational_score for sf in scored_findings.values()) / scored) if scored else None

        highest_asset: str = None
        highest_score: float = None
        if asset_scores:
            highest_asset = max(asset_scores, key=asset_scores.get)
            highest_score = asset_scores[highest_asset]

        asset_criticality, asset_band_counts = self._derive_asset_criticality(scored_findings)
        self._write_asset_criticality(assets_by_id, asset_criticality)

        criticality_thresholds = {
            "extreme_min_critical": self.critical_extreme_min_critical,
            "high_min_critical": self.critical_high_min_critical,
            "high_min_high": self.critical_high_min_high,
            "medium_min_high": self.critical_medium_min_high,
            "medium_min_medium": self.critical_medium_min_medium,
        }

        output = ScoringPassOutput(
            scored_findings=scored_findings,
            asset_scores=asset_scores,
            asset_criticality=asset_criticality,
            asset_band_counts=asset_band_counts,
            asset_criticality_thresholds=criticality_thresholds,
            coverage=ScoreCoverage(total_findings=total, scored_findings=scored, coverage_ratio=coverage_ratio),
            highest_risk_asset=highest_asset,
            highest_risk_asset_score=highest_score,
            avg_scored_risk=avg_scored,
            avg_operational_risk=avg_op
        )

        services = getattr(ctx, "services", None)
        ledger = getattr(services, "ledger", None)
        runmanifest_mode = str(getattr(services, "runmanifest_mode", "compact") or "compact").lower()
        if ledger is not None:
            ledger.append_event(
                component="Scoring",
                event_type="decision",
                subject_ref="scoring:summary",
                reason_code=DecisionReasonCodes.SCORING_SUMMARY_COMPUTED,
                reason_text="Scoring summary metrics computed for this run.",
                factor_refs=["coverage", "avg_scored_risk", "avg_operational_risk"],
                weight_context=(
                    f"kev={self.policy.kev_evd}*{self.policy.w_kev}, "
                    f"exploit={self.policy.exploit_evd}*{self.policy.w_exploit}, "
                    f"epss_scale={self.policy.epss_scale}, "
                    f"decay={self.policy.cve_aggregation_decay}"
                ),
                evidence={
                    "total_findings": total,
                    "scored_findings": scored,
                    "coverage_ratio": coverage_ratio,
                },
            )

            if highest_asset is not None:
                ledger.append_event(
                    component="Scoring",
                    event_type="decision",
                    subject_ref=f"asset:{highest_asset}",
                    reason_code=DecisionReasonCodes.HIGHEST_RISK_ASSET_SELECTED,
                    reason_text="Asset selected as highest risk based on max raw score.",
                    factor_refs=["asset_scores", "highest_risk_asset_score"],
                    confidence="high",
                    evidence={
                        "asset_id": highest_asset,
                        "raw_score": highest_score,
                    },
                )

            if runmanifest_mode == "expanded":
                top_assets = sorted(asset_scores.items(), key=lambda kv: kv[1], reverse=True)[:10]
                for rank, (asset_id, score) in enumerate(top_assets, start=1):
                    ledger.append_event(
                        component="Scoring",
                        event_type="decision",
                        subject_ref=f"asset:{asset_id}",
                        reason_code=DecisionReasonCodes.HIGHEST_RISK_ASSET_SELECTED,
                        reason_text="Asset included in expanded scoring leaderboard by raw score.",
                        factor_refs=["asset_scores", "highest_risk_asset_score"],
                        confidence="medium" if rank > 3 else "high",
                        evidence={
                            "rank": rank,
                            "asset_id": asset_id,
                            "raw_score": score,
                        },
                    )

            ledger.append_event(
                component="Scoring",
                event_type="decision",
                subject_ref="assets:criticality_distribution",
                reason_code=DecisionReasonCodes.ASSET_CRITICALITY_DERIVED,
                reason_text="Asset criticality distribution derived from risk-band thresholds.",
                factor_refs=[
                    "asset_criticality_thresholds",
                    "asset_band_counts",
                ],
                evidence={
                    "assets_with_criticality": len(asset_criticality),
                    "thresholds": criticality_thresholds,
                },
            )

        mode_label = "sequential"
        if use_parallel:
            mode_label = "process" if len(findings_with_context) >= self.process_pool_threshold else "parallel"
        ctx.logger.info(
            "[pass:scoring] %s | scored=%d/%d (%.2f%%)",
            mode_label, scored, total, coverage_ratio,
            extra = {"vp_label": "ScoringPass"}
        )
        
        # Detailed logging to file only
        ctx.logger.debug(
            "[pass:scoring] execution_mode=%s | threads_available=%d | workload=%d findings | cache_size=%d",
            mode_label, os.cpu_count() or 1, len(findings_with_context), len(plugin_cache),
            extra = {"vp_label": "ScoringPass"}
        )

        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived risk scoring (truth-preserving)."
        )
        return DerivedPassResult(meta=meta, data=asdict(output))

    def _derive_asset_criticality(
        self,
        scored_findings: Dict[str, ScoredFinding],
    ) -> Tuple[Dict[str, str], Dict[str, Dict[str, int]]]:
        """Derive per-asset criticality from scored finding risk-band counts."""
        band_counts: Dict[str, Dict[str, int]] = {}

        for sf in scored_findings.values():
            aid = sf.asset_id
            if aid not in band_counts:
                band_counts[aid] = {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Informational": 0,
                }
            band = sf.risk_band if sf.risk_band in band_counts[aid] else "Informational"
            band_counts[aid][band] += 1

        asset_criticality: Dict[str, str] = {}
        for aid, counts in band_counts.items():
            critical_count = counts.get("Critical", 0)
            high_count = counts.get("High", 0)
            medium_count = counts.get("Medium", 0)

            if critical_count >= self.critical_extreme_min_critical:
                asset_criticality[aid] = "Extreme"
            elif (
                critical_count >= self.critical_high_min_critical
                or high_count >= self.critical_high_min_high
            ):
                asset_criticality[aid] = "High"
            elif (
                high_count >= self.critical_medium_min_high
                or medium_count >= self.critical_medium_min_medium
            ):
                asset_criticality[aid] = "Medium"
            else:
                asset_criticality[aid] = "Low"

        return asset_criticality, band_counts

    def _write_asset_criticality(
        self,
        assets_by_id: Dict[str, Any],
        asset_criticality: Dict[str, str],
    ) -> None:
        """Persist derived asset criticality back to the mutable ScanResult asset objects."""
        for asset_id, criticality in asset_criticality.items():
            asset = assets_by_id.get(asset_id)
            if asset is not None:
                asset.criticality = criticality

    def _get_nmap_open_ports_by_asset(self, scan: "ScanResult") -> Dict[str, set[int]]:
        """Load Nmap adapter open-port index from derived context, if available."""
        try:
            derived = scan.derived.get("nmap_adapter@1.0")
        except (AttributeError, TypeError):
            return {}

        if derived is None or not isinstance(getattr(derived, "data", None), dict):
            return {}

        data = derived.data
        if str(data.get("status", "")).lower() != "enabled":
            return {}

        raw_ports = data.get("asset_open_ports", {})
        if not isinstance(raw_ports, dict):
            return {}

        out: Dict[str, set[int]] = {}
        for asset_id, ports in raw_ports.items():
            if not isinstance(asset_id, str):
                continue
            if not isinstance(ports, (list, tuple)):
                continue
            normalized: set[int] = set()
            for port in ports:
                try:
                    normalized.add(int(port))
                except (TypeError, ValueError):
                    continue
            if normalized:
                out[asset_id] = normalized
        return out

    def _preview_cve_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cve_id = str(record.get("cve_id", "") or "").strip().upper()
        if not cve_id:
            return None

        cvss = record.get("resolved_cvss_score")
        if cvss is None:
            cvss = record.get("scanner_cvss_score")
        epss = record.get("epss_score")
        kev = bool(record.get("cisa_kev", False))
        exploit = bool(record.get("exploit_available", False))

        raw, reasons = _score_signal_components_from_policy_values(
            kev=kev,
            exploit=exploit,
            cvss=cvss,
            epss=epss,
            policy_values=self._policy_values(),
        )
        if raw <= 0.0:
            return None

        score = (raw / self.policy.max_raw_risk) * self.policy.max_op_risk
        score = max(0.0, min(score, self.policy.max_op_risk))
        band = self._band(raw)
        return {
            "cve_id": cve_id,
            "raw_score": round(raw, 4),
            "operational_score": round(score, 4),
            "risk_band": band,
            "reasons": list(reasons),
            "cvss_score": cvss,
            "cvss_vector": record.get("resolved_cvss_vector") or record.get("scanner_cvss_vector"),
            "summary": record.get("summary"),
            "published": record.get("published"),
            "last_modified": record.get("last_modified"),
            "epss_score": epss,
            "cisa_kev": kev,
            "exploit_available": exploit,
            "exploit_reference_count": int(record.get("exploit_reference_count", 0) or 0),
            "ghsa_advisory_count": int(record.get("ghsa_advisory_count", 0) or 0),
            "ghsa_max_severity": record.get("ghsa_max_severity"),
            "ghsa_match_type": record.get("ghsa_match_type"),
            "selected_for_display": bool(record.get("selected_for_display", False)),
        }

    def _build_whole_cve_score_base(self, finding: "Finding") -> Optional[Dict[str, Any]]:
        raw_analysis = getattr(finding, "cve_analysis", []) or []
        if not isinstance(raw_analysis, list):
            return None

        contributors: List[Dict[str, Any]] = []
        union_kev = False
        union_exploit = False

        for record in raw_analysis:
            if not isinstance(record, dict):
                continue
            preview = self._preview_cve_record(record)
            if preview is None:
                continue
            contributors.append(preview)
            union_kev = union_kev or bool(preview.get("cisa_kev", False))
            union_exploit = union_exploit or bool(preview.get("exploit_available", False))

        if not contributors:
            return None

        contributors.sort(
            key=lambda item: (
                -float(item.get("raw_score", 0.0) or 0.0),
                str(item.get("cve_id", "")),
            )
        )

        max_contributors = max(1, int(self.policy.cve_aggregation_max_contributors))
        decay = min(max(float(self.policy.cve_aggregation_decay), 0.0), 1.0)

        aggregated_raw = 0.0
        included_count = 0
        display_cve = getattr(finding, "enrichment_source_cve", None)
        if not display_cve:
            display_cve = next(
                (
                    contributor.get("cve_id")
                    for contributor in contributors
                    if contributor.get("selected_for_display")
                ),
                contributors[0].get("cve_id"),
            )

        for index, contributor in enumerate(contributors):
            within_cap = index < max_contributors
            weight = pow(decay, index) if within_cap else 0.0
            contribution = float(contributor.get("raw_score", 0.0) or 0.0) * weight
            contributor["aggregation_rank"] = index + 1
            contributor["aggregation_weight"] = round(weight, 4)
            contributor["raw_contribution"] = round(contribution, 4)
            contributor["selected_for_score"] = within_cap and weight > 0.0
            contributor["primary_contributor"] = index == 0
            if within_cap:
                aggregated_raw += contribution
                included_count += 1

        primary = contributors[0]
        aggregate_reason_parts = [
            "Whole-of-CVEs Aggregated",
            f"cve_count={len(contributors)}",
            f"cve_primary={primary.get('cve_id')}",
            f"cve_mode={self.policy.cve_aggregation_mode}",
        ]

        return {
            "whole_cve_raw": round(aggregated_raw, 4),
            "whole_cve_reason_parts": aggregate_reason_parts,
            "score_trace_base": {
                "aggregation_mode": self.policy.cve_aggregation_mode,
                "decay_factor": round(decay, 4),
                "max_contributors": max_contributors,
                "included_contributors": included_count,
                "primary_cve": primary.get("cve_id"),
                "display_cve": display_cve,
                "cve_count": len(contributors),
                "contributors": contributors,
                "aggregate_cve_raw_score": round(aggregated_raw, 4),
                "union_flags": {
                    "kev": union_kev,
                    "exploit": union_exploit,
                },
                "primary_components": {
                    "raw_score": primary.get("raw_score"),
                    "operational_score": primary.get("operational_score"),
                    "risk_band": primary.get("risk_band"),
                },
            },
        }

    def _write_finding_scores(
        self,
        findings_by_id: Dict[str, Any],
        scored_findings: Dict[str, ScoredFinding],
    ) -> None:
        for finding_id, finding in findings_by_id.items():
            scored = scored_findings.get(finding_id)
            if scored is None:
                finding.raw_risk_score = None
                finding.risk_score = None
                finding.risk_band = None
                finding.score_trace = {}
                continue
            finding.raw_risk_score = scored.raw_score
            finding.risk_score = scored.operational_score
            finding.risk_band = scored.risk_band
            finding.score_trace = dict(scored.score_trace)

    def _build_plugin_cache(
        self,
        findings_with_context: List[Tuple[Any, str, str]],
        nmap_open_ports: Dict[str, set[int]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Pre-compute plugin attributes once to avoid repeated getattr() calls.
        Secure design: read-only access to findings, no modifications.
        Returns: {finding_id -> {kev, exploit, cvss, epss}}
        """
        cache = {}
        for finding, asset_id, _ in findings_with_context:
            finding_port = getattr(finding, "affected_port", None)
            has_nmap_open_port = False
            if isinstance(finding_port, int):
                has_nmap_open_port = finding_port in nmap_open_ports.get(asset_id, set())

            attrs = {
                "kev": bool(getattr(finding, "cisa_kev", False)),
                "exploit": bool(getattr(finding, "exploit_available", False)),
                "cvss": getattr(finding, "cvss_score", None),
                "epss": getattr(finding, "epss_score", None),
                "nmap_open_port": has_nmap_open_port,
            }
            whole_cve_attrs = self._build_whole_cve_score_base(finding)
            if whole_cve_attrs is not None:
                attrs.update(whole_cve_attrs)

            cache[finding.finding_id] = attrs
        return cache

    def _score_sequential(
        self, 
        findings_with_context: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]],
        score_memo: Dict[Tuple[bool, bool, Any, Any, bool], Optional[Tuple[float, float, str, str, Dict[str, Any]]]]
    ) -> Tuple[Dict[str, ScoredFinding], Dict[str, float]]:
        """Score findings sequentially (fallback or small workloads)."""
        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}

        for finding, asset_id, _ in findings_with_context:
            attrs = plugin_cache[finding.finding_id]
            sf = self._score_one_with_memo(finding, asset_id, attrs, score_memo)
            
            if sf is None:
                continue
            
            scored_findings[sf.finding_id] = sf
            
            if asset_id not in asset_scores or sf.raw_score > asset_scores[asset_id]:
                asset_scores[asset_id] = sf.raw_score

        return scored_findings, asset_scores

    def _score_process_pool(
        self,
        ctx: "RunContext",
        findings_with_context: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]],
    ) -> Tuple[Dict[str, ScoredFinding], Dict[str, float]]:
        """Score very large workloads via process pool (GIL-safe speedup)."""
        cpu_total = os.cpu_count() or 1
        worker_cap = self.process_workers if self.process_workers is not None else cpu_total
        num_workers = max(1, min(worker_cap, cpu_total))

        policy_values = self._policy_values()

        work_items: List[Tuple[str, str, Dict[str, Any]]] = []
        for finding, asset_id, _ in findings_with_context:
            work_items.append((finding.finding_id, asset_id, plugin_cache[finding.finding_id]))

        chunk_size = max(1, len(work_items) // num_workers)
        chunks = [
            work_items[i:i + chunk_size]
            for i in range(0, len(work_items), chunk_size)
        ]

        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}

        try:
            with cf.ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = {
                    executor.submit(_score_chunk_process, chunk, policy_values): index
                    for index, chunk in enumerate(chunks)
                }

                for future in cf.as_completed(futures):
                    chunk_results, chunk_assets = future.result()

                    for finding_id, payload in chunk_results.items():
                        asset_id, raw, score, band, reason, score_trace = payload
                        scored_findings[finding_id] = ScoredFinding(
                            finding_id=finding_id,
                            asset_id=asset_id,
                            raw_score=round(raw, 4),
                            operational_score=round(score, 4),
                            risk_band=band,
                            reason=reason,
                            score_trace=score_trace,
                        )

                    for asset_id, score in chunk_assets.items():
                        if asset_id not in asset_scores or score > asset_scores[asset_id]:
                            asset_scores[asset_id] = score

            return scored_findings, asset_scores
        except Exception as exc:  # pylint: disable=broad-exception-caught
            ctx.logger.warning(
                "[pass:scoring] process pool unavailable, falling back to thread pool | reason=%s",
                exc,
                extra={"vp_label": "ScoringPass"},
            )
            score_memo: Dict[Tuple[bool, bool, Any, Any, bool], Optional[Tuple[float, float, str, str, Dict[str, Any]]]] = {}
            return self._score_parallel(ctx, findings_with_context, plugin_cache, score_memo)

    def _score_parallel(
        self,
        _ctx: "RunContext",
        findings_with_context: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]],
        score_memo: Dict[Tuple[bool, bool, Any, Any, bool], Optional[Tuple[float, float, str, str, Dict[str, Any]]]]
    ) -> Tuple[Dict[str, ScoredFinding], Dict[str, float]]:
        """
        Score findings in parallel using ThreadPoolExecutor.
        Thread-safe result aggregation with minimal lock contention.
        """
        # Determine optimal chunk size and worker count
        num_workers = min(len(findings_with_context) // self.min_findings_per_worker + 1, os.cpu_count() or 1)
        chunk_size = max(1, len(findings_with_context) // num_workers)

        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}

        # Submit all chunks to executor
        with cf.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {
                executor.submit(
                    self._score_chunk_range,
                    findings_with_context,
                    i,
                    min(i + chunk_size, len(findings_with_context)),
                    plugin_cache,
                    score_memo,
                ): i
                for i in range(0, len(findings_with_context), chunk_size)
            }

            # Collect results as they complete (not necessarily in order)
            for future in cf.as_completed(futures):
                chunk_results, chunk_assets = future.result()
                
                # Thread-safe merge: acquisition is minimal (insert-only)
                with self._result_lock:
                    scored_findings.update(chunk_results)
                    for asset_id, score in chunk_assets.items():
                        if asset_id not in asset_scores or score > asset_scores[asset_id]:
                            asset_scores[asset_id] = score

        return scored_findings, asset_scores

    def _score_chunk_range(
        self,
        findings_with_context: List[Tuple[Any, str, str]],
        start_idx: int,
        end_idx: int,
        plugin_cache: Dict[str, Dict[str, Any]],
        score_memo: Dict[Tuple[bool, bool, Any, Any, bool], Optional[Tuple[float, float, str, str, Dict[str, Any]]]]
    ) -> Tuple[Dict[str, ScoredFinding], Dict[str, float]]:
        """
        Score a batch of findings (thread worker function).
        No shared state modification here; returns local results.
        """
        chunk_findings: Dict[str, ScoredFinding] = {}
        chunk_assets: Dict[str, float] = {}

        for finding, asset_id, _ in findings_with_context[start_idx:end_idx]:
            attrs = plugin_cache[finding.finding_id]
            sf = self._score_one_with_memo(finding, asset_id, attrs, score_memo)
            
            if sf is None:
                continue
            
            chunk_findings[sf.finding_id] = sf
            
            # Prefer higher score per asset within this chunk
            if asset_id not in chunk_assets or sf.raw_score > chunk_assets[asset_id]:
                chunk_assets[asset_id] = sf.raw_score

        return chunk_findings, chunk_assets

    def _score_one_cached(
        self,
        f: "Finding",
        asset_id: str,
        attrs: Dict[str, Any]
    ) -> Optional[ScoredFinding]:
        """Score a single finding using pre-cached attributes."""
        score_parts = self._calculate_score_components(attrs)
        if score_parts is None:
            return None

        raw, score, band, reason, score_trace = score_parts

        return ScoredFinding(
            finding_id=f.finding_id,
            asset_id=asset_id,
            raw_score=round(raw, 4),
            operational_score=round(score, 4),
            risk_band=band,
            reason=reason,
            score_trace=score_trace,
        )

    def _score_one_with_memo(
        self,
        f: "Finding",
        asset_id: str,
        attrs: Dict[str, Any],
        score_memo: Dict[Tuple[bool, bool, Any, Any, bool], Optional[Tuple[float, float, str, str, Dict[str, Any]]]]
    ) -> Optional[ScoredFinding]:
        """Score a finding using signature memoization for repeated attribute sets."""
        if isinstance(attrs.get("score_trace_base"), dict):
            return self._score_one_cached(f, asset_id, attrs)

        signature = self._score_signature(attrs)
        cached = score_memo.get(signature)

        if cached is None and signature not in score_memo:
            computed = self._calculate_score_components(attrs)
            with self._memo_lock:
                score_memo[signature] = computed
            cached = computed

        if cached is None:
            return None

        raw, score, band, reason, score_trace = cached

        return ScoredFinding(
            finding_id=f.finding_id,
            asset_id=asset_id,
            raw_score=round(raw, 4),
            operational_score=round(score, 4),
            risk_band=band,
            reason=reason,
            score_trace=score_trace,
        )

    def _score_signature(self, attrs: Dict[str, Any]) -> Tuple[bool, bool, Any, Any, bool]:
        """Build deterministic memoization key from cached scoring inputs."""
        return (
            bool(attrs.get("kev", False)),
            bool(attrs.get("exploit", False)),
            attrs.get("cvss", None),
            attrs.get("epss", None),
            bool(attrs.get("nmap_open_port", False)),
        )

    def _calculate_score_components(
        self,
        attrs: Dict[str, Any]
    ) -> Optional[Tuple[float, float, str, str, Dict[str, Any]]]:
        """Calculate raw/op score components from cached attrs. Returns None if gated."""
        pol = self.policy

        kev = attrs["kev"]
        exploit = attrs["exploit"]
        cvss = attrs["cvss"]
        epss = attrs["epss"]
        nmap_open_port = bool(attrs.get("nmap_open_port", False))
        whole_cve_raw = attrs.get("whole_cve_raw", None)

        # Gate: if no enrichment data, no score
        if whole_cve_raw is None and not kev and not exploit and cvss is None and epss is None:
            return None

        if whole_cve_raw is not None:
            try:
                raw = float(whole_cve_raw)
            except (TypeError, ValueError):
                return None
            reasons = list(attrs.get("whole_cve_reason_parts") or ["Whole-of-CVEs Aggregated"])
        else:
            raw, reasons = _score_signal_components_from_policy_values(
                kev=kev,
                exploit=exploit,
                cvss=cvss,
                epss=epss,
                policy_values=self._policy_values(),
            )

        # NMAP Component
        if nmap_open_port:
            if pol.nmap_port_bonus > 0:
                raw += pol.nmap_port_bonus
            reasons.append("Nmap Port Observed")
            nmap_component = pol.nmap_port_bonus if pol.nmap_port_bonus > 0 else 0.0
        else:
            nmap_component = 0.0

        score = (raw / pol.max_raw_risk) * pol.max_op_risk
        score = max(0.0, min(score, pol.max_op_risk))
        band = self._band(raw)
        score_trace = _finalize_score_trace(
            attrs,
            raw=raw,
            score=score,
            band=band,
            reasons=reasons,
            nmap_component=nmap_component,
        )
        return raw, score, band, ";".join(reasons), score_trace

    def _score_one(self, f: "Finding") -> Optional[ScoredFinding]:
        """
        Legacy method for backward compatibility.
        Kept for tests and external callers; uses cached scoring internally.
        """
        attrs = {
            "kev": bool(getattr(f, "cisa_kev", False)),
            "exploit": bool(getattr(f, "exploit_available", False)),
            "cvss": getattr(f, "cvss_score", None),
            "epss": getattr(f, "epss_score", None),
        }
        asset_id = f.asset_id or "SENTINEL:AssetID_Missing"
        return self._score_one_cached(f, asset_id, attrs)

    def _band(self, score: float) -> str:
        pol = self.policy
        if score >= pol.band_critical:
            return "Critical"
        if score >= pol.band_high:
            return "High"
        if score >= pol.band_medium:
            return "Medium"
        if score >= pol.band_low:
            return "Low"
        return "Informational"


_CVSS_PROVENANCE_RANK: Dict[str, int] = {
    "NVD": 5,
    "CNA": 4,
    "GHSA": 3,
    "OSV": 2,
    "Scanner-Supplied": 1,
    "Missing": 0,
}

_PROVENANCE_NORM: Dict[str, str] = {
    "nvd": "NVD",
    "cna": "CNA",
    "ghsa": "GHSA",
    "osv": "OSV",
    "scanner": "Scanner-Supplied",
    "scanner-supplied": "Scanner-Supplied",
    "scanner_supplied": "Scanner-Supplied",
    "missing": "Missing",
}

_HIGH_IMPACT_CWES = frozenset({
    "CWE-22",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-250",
    "CWE-269",
    "CWE-287",
    "CWE-306",
    "CWE-434",
    "CWE-502",
    "CWE-798",
    "CWE-918",
})

_CWE_NUM_RE = re.compile(r"CWE[-_:\s]*0*([0-9]+)", re.IGNORECASE)
_DEFAULT_EPSS_V5_BREAKPOINTS: Tuple[Tuple[float, float], ...] = (
    (0.0, 0.0),
    (0.04, 1.8),
    (0.10, 3.0),
    (0.50, 4.2),
    (1.0, 5.0),
)


def _norm_cwe(val: Any) -> Optional[str]:
    if not val:
        return None
    m = _CWE_NUM_RE.search(str(val))
    if not m:
        return None
    return f"CWE-{int(m.group(1))}"


def _safe_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _ordinal(n: int) -> str:
    val = int(n)
    if 10 <= (val % 100) <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(val % 10, "th")
    return f"{val}{suffix}"


def _epss_v5_points(
    epss_score: Optional[float],
    epss_percentile: Optional[float] = None,
    breakpoints: Sequence[Tuple[float, float]] = _DEFAULT_EPSS_V5_BREAKPOINTS,
) -> float:
    """Strictly monotonic piecewise-linear EPSS v5 scoring function."""
    _ = epss_percentile  # Kept in signature for trace/caller symmetry; monotonicity is over epss_score.
    if epss_score is None:
        return 0.0
    try:
        raw = float(epss_score)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(raw):
        return 0.0
    p = 1.0 if (math.isinf(raw) and raw > 0) else (0.0 if math.isinf(raw) else raw)
    p = max(0.0, min(1.0, p))

    pts = sorted(((float(x), float(y)) for x, y in breakpoints), key=lambda kv: kv[0])
    if not pts:
        pts = list(_DEFAULT_EPSS_V5_BREAKPOINTS)

    if p <= pts[0][0]:
        return float(pts[0][1])
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if p <= x1:
            if x1 <= x0:
                return float(max(y0, y1))
            ratio = (p - x0) / (x1 - x0)
            y_hi = max(y0, y1)
            return float(y0 + ratio * (y_hi - y0))
    return float(pts[-1][1])


def _format_epss_display(
    epss_score: Optional[float],
    epss_percentile: Optional[float],
) -> Optional[str]:
    score = _safe_float(epss_score)
    pct = _safe_float(epss_percentile)
    if score is None and pct is None:
        return None
    pct_str: Optional[str] = None
    if pct is not None:
        pct_num = int(round(pct * 100.0 if pct <= 1.0 else pct))
        pct_num = max(0, min(100, pct_num))
        pct_str = _ordinal(pct_num)
    if score is not None:
        p = max(0.0, min(1.0, score))
        base = f"{p * 100.0:.1f}%"
        return f"{base} / {pct_str}" if pct_str is not None else base
    return f"N/A / {pct_str}"


def _norm_provenance(prov: Optional[str]) -> str:
    if not prov:
        return "Missing"
    return _PROVENANCE_NORM.get(str(prov).strip().lower(), "Missing")


def _resolve_best_cvss(
    snap_score: Optional[float],
    snap_version: Optional[str],
    snap_provenance: Optional[str],
    scanner_score: Optional[float],
    scanner_vector: Optional[str] = None,
) -> Tuple[float, Optional[str], str]:
    best_rank = 0
    best_score = 0.0
    best_ver: Optional[str] = None
    best_prov = "Missing"

    sc_snap = _safe_float(snap_score)
    if sc_snap is not None and 0.0 <= sc_snap <= 10.0:
        prov_n = _norm_provenance(snap_provenance)
        rank = _CVSS_PROVENANCE_RANK.get(prov_n, 0)
        if rank >= _CVSS_PROVENANCE_RANK["OSV"]:
            best_rank = rank
            best_score = sc_snap
            best_ver = snap_version
            best_prov = prov_n

    sc_scan = _safe_float(scanner_score)
    if (sc_scan is None or not (0.0 <= sc_scan <= 10.0)) and scanner_vector:
        try:
            from vulnparse_pin.utils.cvss_utils import compute_cvss_base_score
            vec_score = _safe_float(compute_cvss_base_score(str(scanner_vector)))
            if vec_score is not None and 0.0 <= vec_score <= 10.0:
                sc_scan = vec_score
        except Exception:
            pass
    if sc_scan is not None and 0.0 <= sc_scan <= 10.0:
        scan_rank = _CVSS_PROVENANCE_RANK["Scanner-Supplied"]
        if scan_rank > best_rank:
            best_score = sc_scan
            best_prov = "Scanner-Supplied"
            if scanner_vector:
                try:
                    from vulnparse_pin.utils.cvss_utils import detect_cvss_exact_version
                    best_ver = detect_cvss_exact_version(str(scanner_vector))
                except Exception:
                    best_ver = None

    return best_score, best_ver, best_prov


def _coerce_v2_scoring_policy(policy: Any) -> Any:
    from vulnparse_pin.core.config_projector import (
        ConfigProjector,
        RuntimeConfigBundle,
        ScoringPolicyV2,
        build_scoring_policy_v2,
    )

    if policy is None:
        return ConfigProjector.load_packaged_default_bundle().scoring_policy
    if isinstance(policy, RuntimeConfigBundle):
        return policy.scoring_policy
    if isinstance(policy, ScoringPolicyV2):
        return policy
    if isinstance(policy, dict):
        return build_scoring_policy_v2(policy)
    if isinstance(policy, ScoringPolicyV1):
        return ScoringPolicyV2(
            kev_points=float(policy.kev_evd),
            verified_exploit_points=float(policy.exploit_evd),
            max_raw_risk=float(policy.max_raw_risk),
            max_operational_risk=float(policy.max_op_risk),
            bands={
                "critical": float(policy.band_critical),
                "high": float(policy.band_high),
                "medium": float(policy.band_medium),
                "low": float(policy.band_low),
            },
            asset_aggregation=str(policy.asset_aggregation),
            cve_aggregation_mode=str(policy.cve_aggregation_mode),
            cve_aggregation_decay=float(policy.cve_aggregation_decay),
            cve_aggregation_max_contributors=int(policy.cve_aggregation_max_contributors),
            nmap_port_bonus=float(policy.nmap_port_bonus),
        )
    raise TypeError(f"Unsupported scoring v2 policy type: {type(policy).__name__}")


def _resolve_duckdb_conn(db_obj: Any) -> Any:
    if db_obj is None:
        return None
    inner = getattr(db_obj, "conn", None)
    if inner is not None and hasattr(inner, "execute"):
        return inner
    if hasattr(db_obj, "execute"):
        return db_obj
    return None


class ScoringV3Pass(Pass):
    """Dual-track, vectorized DuckDB Scoring@3.0 pass (Track A cve_threat + Track B exposure_weakness)."""

    name: str = "Scoring"
    version: str = "3.0"
    requires_passes: tuple[str, ...] = ()

    def __init__(
        self,
        policy: Optional[Any] = None,
        *,
        critical_extreme_min_critical: int = 3,
        critical_high_min_critical: int = 1,
        critical_high_min_high: int = 2,
        critical_medium_min_high: int = 1,
        critical_medium_min_medium: int = 5,
    ) -> None:
        self.policy = _coerce_v2_scoring_policy(policy)
        self.critical_extreme_min_critical = max(1, int(critical_extreme_min_critical))
        self.critical_high_min_critical = max(1, int(critical_high_min_critical))
        self.critical_high_min_high = max(1, int(critical_high_min_high))
        self.critical_medium_min_high = max(1, int(critical_medium_min_high))
        self.critical_medium_min_medium = max(1, int(critical_medium_min_medium))

    def _band(self, raw_score: float) -> str:
        bands = self.policy.bands
        if raw_score >= float(bands.get("critical", 12.8)):
            return "Critical"
        if raw_score >= float(bands.get("high", 9.6)):
            return "High"
        if raw_score >= float(bands.get("medium", 6.4)):
            return "Medium"
        if raw_score >= float(bands.get("low", 3.2)):
            return "Low"
        return "Informational"

    def _derive_asset_criticality_level(self, crit_c: int, high_c: int, med_c: int) -> str:
        if crit_c >= self.critical_extreme_min_critical:
            return "Extreme"
        if crit_c >= self.critical_high_min_critical or high_c >= self.critical_high_min_high:
            return "High"
        if high_c >= self.critical_medium_min_high or med_c >= self.critical_medium_min_medium:
            return "Medium"
        return "Low"

    def _score_track_a(
        self,
        *,
        cve_ids: Sequence[str],
        enrich_map: Dict[str, Tuple[Any, ...]],
        scanner_cvss_score: Optional[float],
        scanner_cvss_vector: Optional[str],
        finding_exploit_evidence: bool,
        aci_capabilities: Tuple[str, ...],
        aci_chains: Tuple[str, ...],
        detection_mode: Optional[str],
        signal_reliability: float,
        asset_inventory_status: Optional[str],
        internet_facing: bool,
        declared_criticality: Optional[str],
    ) -> Tuple[float, float, str, Dict[str, Any]]:
        pol = self.policy
        contributors: List[Dict[str, Any]] = []

        union_kev = False
        union_verified_exp = False
        union_heur_exp = bool(finding_exploit_evidence)
        kev_meta: Optional[Tuple[Optional[str], Optional[str], Optional[str]]] = None

        for raw_cve in cve_ids:
            cve = str(raw_cve).strip().upper()
            if not cve:
                continue
            snap = enrich_map.get(cve)
            if snap is not None:
                (
                    snap_cvss,
                    snap_ver,
                    snap_prov,
                    epss_score,
                    epss_pct,
                    epss_ver,
                    epss_date,
                    epss_pts,
                    epss_disp,
                    in_kev,
                    kev_added,
                    kev_due,
                    kev_ransom,
                    ver_exp,
                    heur_exp,
                ) = snap
            else:
                snap_cvss = None
                snap_ver = None
                snap_prov = "Missing"
                epss_score = None
                epss_pct = None
                epss_ver = None
                epss_date = None
                epss_pts = 0.0
                epss_disp = None
                in_kev = False
                kev_added = None
                kev_due = None
                kev_ransom = None
                ver_exp = False
                heur_exp = False

            cvss_val, cvss_ver, cvss_prov = _resolve_best_cvss(
                snap_cvss, snap_ver, snap_prov, scanner_cvss_score, scanner_cvss_vector
            )
            kev_pts = float(pol.kev_points) if in_kev else 0.0
            if ver_exp:
                exp_pts = float(pol.verified_exploit_with_kev_points if in_kev else pol.verified_exploit_points)
            else:
                exp_pts = 0.0

            cve_raw = cvss_val + epss_pts + kev_pts + exp_pts
            union_kev = union_kev or in_kev
            union_verified_exp = union_verified_exp or ver_exp
            union_heur_exp = union_heur_exp or heur_exp
            if in_kev and kev_meta is None:
                kev_meta = (kev_added, kev_due, kev_ransom)

            contributors.append(
                {
                    "cve_id": cve,
                    "cve_raw": cve_raw,
                    "cvss_score": cvss_val,
                    "cvss_version": cvss_ver,
                    "cvss_provenance": cvss_prov,
                    "epss_score": epss_score,
                    "epss_percentile": epss_pct,
                    "epss_display": epss_disp,
                    "epss_model_version": epss_ver,
                    "epss_date": epss_date,
                    "epss_points": epss_pts,
                    "in_kev": in_kev,
                    "kev_date_added": kev_added,
                    "kev_due_date": kev_due,
                    "kev_ransomware": kev_ransom,
                    "kev_points": kev_pts,
                    "verified_exploit": ver_exp,
                    "verified_exploit_points": exp_pts,
                }
            )

        contributors.sort(key=lambda item: (-float(item["cve_raw"]), str(item["cve_id"])))
        decay = min(max(float(pol.cve_aggregation_decay), 0.0), 1.0)
        max_k = max(1, int(pol.cve_aggregation_max_contributors))

        stacked_cve_raw = 0.0
        for idx, item in enumerate(contributors[:max_k]):
            stacked_cve_raw += float(item["cve_raw"]) * (decay ** idx)

        primary = contributors[0] if contributors else {
            "cve_id": None,
            "cve_raw": 0.0,
            "cvss_score": 0.0,
            "cvss_version": None,
            "cvss_provenance": "Missing",
            "epss_score": None,
            "epss_percentile": None,
            "epss_display": None,
            "epss_model_version": None,
            "epss_date": None,
            "epss_points": 0.0,
            "in_kev": False,
            "kev_date_added": None,
            "kev_due_date": None,
            "kev_ransomware": None,
            "kev_points": 0.0,
            "verified_exploit": False,
            "verified_exploit_points": 0.0,
        }

        exposure_pts = float(pol.exposure_bonus) if internet_facing else 0.0
        crit_key = str(declared_criticality or "").strip().lower()
        crit_pts = float(pol.criticality_bonuses.get(crit_key, 0.0))

        pre_clamp_raw = stacked_cve_raw + exposure_pts + crit_pts
        max_raw = float(pol.max_raw_risk)
        max_op = float(pol.max_operational_risk)
        raw_score = round(max(0.0, min(max_raw, pre_clamp_raw)), 4)
        operational_score = round(max(0.0, min(max_op, (raw_score / max_raw) * max_op)), 4) if max_raw > 0 else 0.0
        risk_band = self._band(raw_score)

        if primary.get("in_kev"):
            resolved_kev_meta = (
                primary.get("kev_date_added"),
                primary.get("kev_due_date"),
                primary.get("kev_ransomware"),
            )
        else:
            kev_contributor = next((c for c in contributors if c.get("in_kev")), None)
            if kev_contributor is not None:
                resolved_kev_meta = (
                    kev_contributor.get("kev_date_added"),
                    kev_contributor.get("kev_due_date"),
                    kev_contributor.get("kev_ransomware"),
                )
            else:
                resolved_kev_meta = kev_meta or (None, None, None)
        multi_cve_extra = stacked_cve_raw - float(primary.get("cve_raw", 0.0))

        trace = {
            "scoring_track": "cve_threat",
            "primary_cve": primary.get("cve_id"),
            "cvss_score": round(float(primary["cvss_score"]), 4) if primary.get("cvss_provenance") != "Missing" else 0.0,
            "cvss_version": primary.get("cvss_version"),
            "cvss_provenance": primary.get("cvss_provenance", "Missing"),
            "epss_score": primary.get("epss_score"),
            "epss_percentile": primary.get("epss_percentile"),
            "epss_display": primary.get("epss_display"),
            "epss_model_version": primary.get("epss_model_version"),
            "epss_date": primary.get("epss_date"),
            "in_kev": bool(union_kev),
            "kev_date_added": resolved_kev_meta[0] if union_kev else None,
            "kev_due_date": resolved_kev_meta[1] if union_kev else None,
            "kev_ransomware": resolved_kev_meta[2] if union_kev else None,
            "verified_exploit": bool(union_verified_exp),
            "heuristic_exploit_mention": bool(union_heur_exp),
            "aci_capabilities": list(aci_capabilities),
            "aci_chains": list(aci_chains),
            "detection_mode": detection_mode,
            "signal_reliability": round(signal_reliability, 4),
            "asset_inventory_status": asset_inventory_status,
            "internet_facing": bool(internet_facing),
            "declared_criticality": declared_criticality,
            "breakdown": {
                "cvss_points": round(float(primary["cvss_score"]), 4),
                "epss_points": round(float(primary["epss_points"]), 4),
                "kev_points": round(float(primary["kev_points"]), 4),
                "verified_exploit_points": round(float(primary["verified_exploit_points"]), 4),
                "heuristic_exploit_points": 0.0,
                "multi_cve_additional_points": round(multi_cve_extra, 4),
                "exposure_bonus": round(exposure_pts, 4),
                "criticality_bonus": round(crit_pts, 4),
                "pre_clamp_raw_score": round(pre_clamp_raw, 4),
                "raw_risk_score": raw_score,
                "operational_score": operational_score,
                "cve_count": len(contributors),
            },
        }
        return raw_score, operational_score, risk_band, trace

    def _score_track_b(
        self,
        *,
        scanner_cvss_score: Optional[float],
        scanner_cvss_vector: Optional[str],
        scanner_severity: Optional[str],
        finding_exploit_evidence: bool,
        cwes: Tuple[str, ...],
        aci_capabilities: Tuple[str, ...],
        aci_chains: Tuple[str, ...],
        detection_mode: Optional[str],
        signal_reliability: float,
        asset_inventory_status: Optional[str],
        internet_facing: bool,
        declared_criticality: Optional[str],
    ) -> Tuple[float, float, str, Dict[str, Any]]:
        pol = self.policy
        exp_cfg = pol.exposure_track or {}
        sev_map = exp_cfg.get("severity_base") or {
            "critical": 8.5,
            "high": 7.0,
            "medium": 4.5,
            "low": 2.0,
            "informational": 0.5,
            "info": 0.5,
        }

        sc_scan = _safe_float(scanner_cvss_score)
        if (sc_scan is None or not (0.0 <= sc_scan <= 10.0)) and scanner_cvss_vector:
            try:
                from vulnparse_pin.utils.cvss_utils import compute_cvss_base_score
                vec_score = _safe_float(compute_cvss_base_score(str(scanner_cvss_vector)))
                if vec_score is not None and 0.0 <= vec_score <= 10.0:
                    sc_scan = vec_score
            except Exception:
                pass
        if sc_scan is not None and 0.0 <= sc_scan <= 10.0:
            base_score = sc_scan
            cvss_prov = "Scanner-Supplied"
            cvss_ver: Optional[str] = None
            if scanner_cvss_vector:
                try:
                    from vulnparse_pin.utils.cvss_utils import detect_cvss_exact_version
                    cvss_ver = detect_cvss_exact_version(str(scanner_cvss_vector))
                except Exception:
                    cvss_ver = None
        else:
            sev_key = str(scanner_severity or "informational").strip().lower()
            base_score = float(sev_map.get(sev_key, sev_map.get("informational", 0.5)))
            cvss_prov = "Missing"
            cvss_ver = None

        high_impact_caps = set(exp_cfg.get("aci_high_impact_caps") or ())
        if any(c in high_impact_caps for c in aci_capabilities):
            aci_cap_bonus = float(exp_cfg.get("aci_high_impact_bonus", 3.5))
        elif aci_capabilities:
            aci_cap_bonus = float(exp_cfg.get("aci_exposure_bonus", 2.0))
        else:
            aci_cap_bonus = 0.0

        aci_chain_bonus = float(exp_cfg.get("aci_chain_bonus", 1.0)) if aci_chains else 0.0
        cwe_bonus = float(exp_cfg.get("cwe_high_impact_bonus", 1.5)) if any(c in _HIGH_IMPACT_CWES for c in cwes) else 0.0
        exposure_pts = float(exp_cfg.get("exposure_bonus", 1.5)) if internet_facing else 0.0

        unweighted_raw = base_score + aci_cap_bonus + aci_chain_bonus + cwe_bonus + exposure_pts
        weighted_raw = unweighted_raw * float(signal_reliability)

        max_raw = float(pol.max_raw_risk)
        max_op = float(pol.max_operational_risk)
        raw_score = round(max(0.0, min(max_raw, weighted_raw)), 4)
        operational_score = round(max(0.0, min(max_op, (raw_score / max_raw) * max_op)), 4) if max_raw > 0 else 0.0
        risk_band = self._band(raw_score)

        trace = {
            "scoring_track": "exposure_weakness",
            "primary_cve": None,
            "cvss_score": round(sc_scan, 4) if cvss_prov != "Missing" and sc_scan is not None else None,
            "cvss_version": cvss_ver,
            "cvss_provenance": cvss_prov,
            "epss_score": None,
            "epss_percentile": None,
            "epss_display": None,
            "epss_model_version": None,
            "epss_date": None,
            "in_kev": False,
            "kev_date_added": None,
            "kev_due_date": None,
            "kev_ransomware": None,
            "verified_exploit": False,
            "heuristic_exploit_mention": bool(finding_exploit_evidence),
            "aci_capabilities": list(aci_capabilities),
            "aci_chains": list(aci_chains),
            "cwes": list(cwes),
            "detection_mode": detection_mode,
            "signal_reliability": round(signal_reliability, 4),
            "asset_inventory_status": asset_inventory_status,
            "internet_facing": bool(internet_facing),
            "declared_criticality": declared_criticality,
            "breakdown": {
                "base_score": round(base_score, 4),
                "aci_capability_bonus": round(aci_cap_bonus, 4),
                "aci_chain_bonus": round(aci_chain_bonus, 4),
                "cwe_high_impact_bonus": round(cwe_bonus, 4),
                "exposure_bonus": round(exposure_pts, 4),
                "unweighted_raw_score": round(unweighted_raw, 4),
                "signal_reliability": round(signal_reliability, 4),
                "raw_risk_score": raw_score,
                "operational_score": operational_score,
            },
        }
        return raw_score, operational_score, risk_band, trace

    def run(self, ctx: "RunContext", scan: Optional["ScanResult"] = None) -> "DerivedPassResult":
        services = getattr(ctx, "services", None)
        db = getattr(ctx, "db", None) or getattr(services, "db", None)
        run_id = getattr(ctx, "run_id", None) or getattr(services, "run_id", None)
        conn = _resolve_duckdb_conn(db) if (db is not None and run_id is not None) else None

        if conn is not None and run_id is not None:
            return self._run_duckdb(ctx, conn, str(run_id))

        if scan is None:
            raise ValueError("ScoringV3Pass requires either DuckDB (ctx.db + ctx.run_id) or ScanResult.")
        return self._run_scan_result(ctx, scan)

    def _build_duckdb_enrich_map(self, conn: Any, run_id: str) -> Dict[str, Tuple[Any, ...]]:
        enrich_map: Dict[str, Tuple[Any, ...]] = {}
        bps = self.policy.epss_breakpoints
        rows = conn.execute(
            """
            SELECT cve_id, cvss_score, cvss_version, cvss_provenance,
                   epss_score, epss_percentile, epss_model_version, epss_date,
                   in_kev, kev_date_added, kev_due_date, kev_ransomware,
                   verified_exploit, heuristic_exploit_mention
            FROM enrichment_snapshots
            WHERE run_id = ?
            """,
            [run_id],
        ).fetchall()
        for (
            cve_id,
            cvss_score,
            cvss_version,
            cvss_provenance,
            epss_score,
            epss_percentile,
            epss_model_version,
            epss_date,
            in_kev,
            kev_added,
            kev_due,
            kev_ransom,
            ver_exp,
            heur_exp,
        ) in rows:
            cve_u = str(cve_id).strip().upper()
            epss_s = _safe_float(epss_score)
            epss_p = _safe_float(epss_percentile)
            epss_pts = _epss_v5_points(epss_s, epss_p, bps)
            epss_disp = _format_epss_display(epss_s, epss_p)
            enrich_map[cve_u] = (
                _safe_float(cvss_score),
                cvss_version,
                cvss_provenance,
                epss_s,
                epss_p,
                epss_model_version,
                epss_date,
                epss_pts,
                epss_disp,
                bool(in_kev),
                kev_added,
                kev_due,
                kev_ransom,
                bool(ver_exp),
                bool(heur_exp),
            )
        return enrich_map

    def _bulk_update_finding_reliability(self, conn: Any, run_id: str) -> None:
        rel_pol = self.policy.signal_reliability
        if not rel_pol.enabled:
            conn.execute(
                "UPDATE findings SET signal_reliability = 1.0 WHERE run_id = ?",
                [run_id],
            )
            return

        weights = dict(rel_pol.weights)
        if weights:
            when_clauses = []
            params: List[Any] = []
            for mode_key, weight_val in sorted(weights.items()):
                when_clauses.append("WHEN ? THEN ?")
                params.extend([str(mode_key).strip().lower(), float(weight_val)])
            case_sql = f"CASE lower(trim(detection_mode)) {' '.join(when_clauses)} ELSE NULL END"
        else:
            case_sql = "NULL"

        sql = f"""
            UPDATE findings
            SET signal_reliability = COALESCE(
                {case_sql},
                CASE WHEN signal_reliability IS NOT NULL THEN LEAST(2.0, GREATEST(0.0, signal_reliability)) ELSE NULL END,
                CASE WHEN ingestion_confidence IS NOT NULL THEN LEAST(1.0, GREATEST(0.0, ingestion_confidence)) ELSE NULL END,
                0.70
            )
            WHERE run_id = ?
        """
        params.append(run_id)
        conn.execute(sql, params)

    def _run_duckdb(self, ctx: "RunContext", conn: Any, run_id: str) -> "DerivedPassResult":
        enrich_map = self._build_duckdb_enrich_map(conn, run_id)
        cve_has_auth_cvss: Set[str] = {
            cve_u
            for cve_u, snap in enrich_map.items()
            if snap[0] is not None
            and 0.0 <= snap[0] <= 10.0
            and _CVSS_PROVENANCE_RANK.get(_norm_provenance(snap[2]), 0) >= _CVSS_PROVENANCE_RANK["OSV"]
        }
        rel_pol = self.policy.signal_reliability
        row_cnt = int((conn.execute("SELECT COUNT(*) FROM findings WHERE run_id = ?", [run_id]).fetchone() or (0,))[0] or 0)
        populate_derived = row_cnt <= 10_000

        # Skip expensive 335k+ list(cve_id) GROUP BY when findings.cves_json already carries every link
        need_fc_join = (
            conn.execute(
                """
                SELECT 1
                FROM (
                    SELECT finding_id, COUNT(*) AS cnt
                    FROM finding_cves
                    WHERE run_id = ?
                    GROUP BY finding_id
                ) fc
                JOIN findings f
                  ON f.run_id = ? AND f.finding_id = fc.finding_id
                WHERE (f.cves_json IS NULL OR f.cves_json = '[]')
                   OR (fc.cnt > 1 AND f.cves_json NOT LIKE '%,%')
                LIMIT 1
                """,
                [run_id, run_id],
            ).fetchone()
            is not None
        )

        # Streaming read cursor (separate cursor avoids disturbing write transaction/appender)
        cursor = conn.cursor()
        if need_fc_join:
            cursor.execute(
                """
                SELECT
                    f.finding_id,
                    f.asset_id,
                    f.scoring_track,
                    f.primary_cve,
                    f.cves_json,
                    f.cwes_json,
                    f.scanner_severity,
                    f.scanner_cvss_score,
                    f.scanner_cvss_vector,
                    f.detection_mode,
                    f.signal_reliability,
                    f.ingestion_confidence,
                    f.exploit_evidence,
                    a.internet_facing,
                    a.declared_criticality,
                    a.inventory_status,
                    aci.capabilities_json,
                    aci.chains_json,
                    fc.cve_list
                FROM findings f
                LEFT JOIN assets a
                  ON a.run_id = f.run_id AND a.asset_id = f.asset_id
                LEFT JOIN aci_signals aci
                  ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id
                LEFT JOIN (
                    SELECT finding_id, list(cve_id) AS cve_list
                    FROM finding_cves
                    WHERE run_id = ?
                    GROUP BY finding_id
                ) fc
                  ON fc.finding_id = f.finding_id
                WHERE f.run_id = ?
                """,
                [run_id, run_id],
            )
        else:
            cursor.execute(
                """
                SELECT
                    f.finding_id,
                    f.asset_id,
                    f.scoring_track,
                    f.primary_cve,
                    f.cves_json,
                    f.cwes_json,
                    f.scanner_severity,
                    f.scanner_cvss_score,
                    f.scanner_cvss_vector,
                    f.detection_mode,
                    f.signal_reliability,
                    f.ingestion_confidence,
                    f.exploit_evidence,
                    a.internet_facing,
                    a.declared_criticality,
                    a.inventory_status,
                    aci.capabilities_json,
                    aci.chains_json,
                    NULL AS cve_list
                FROM findings f
                LEFT JOIN assets a
                  ON a.run_id = f.run_id AND a.asset_id = f.asset_id
                LEFT JOIN aci_signals aci
                  ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id
                WHERE f.run_id = ?
                """,
                [run_id],
            )

        total_findings = 0
        raw_sum = 0.0
        op_sum = 0.0
        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}
        asset_band_counts: Dict[str, Dict[str, int]] = {}
        band_idx_map = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        asset_counts_fast: Dict[str, List[int]] = {}
        memo: Dict[Tuple[Any, ...], Tuple[str, float, float, str, int, str, Dict[str, Any]]] = {}
        sig_rel_memo: Dict[Tuple[Any, Any, Any], float] = {}
        primary_cve_tuple_cache: Dict[str, Tuple[str, ...]] = {}
        json_list_cache: Dict[str, Tuple[str, ...]] = {}
        cwe_list_cache: Dict[str, Tuple[str, ...]] = {}

        def _parse_json_tuple(raw_s: Optional[str]) -> Tuple[str, ...]:
            if not raw_s or raw_s == "[]":
                return ()
            cached = json_list_cache.get(raw_s)
            if cached is not None:
                return cached
            try:
                parsed = json.loads(raw_s)
                tup = tuple(str(x) for x in parsed if x) if isinstance(parsed, list) else ()
            except Exception:
                tup = ()
            if len(json_list_cache) < 50_000:
                json_list_cache[raw_s] = tup
            return tup

        def _parse_cwes(raw_s: Optional[str]) -> Tuple[str, ...]:
            if not raw_s or raw_s == "[]":
                return ()
            cached = cwe_list_cache.get(raw_s)
            if cached is not None:
                return cached
            try:
                parsed = json.loads(raw_s)
                vals = [c for c in (_norm_cwe(x) for x in parsed) if c] if isinstance(parsed, list) else []
                tup = tuple(dict.fromkeys(vals))
            except Exception:
                tup = ()
            if len(cwe_list_cache) < 50_000:
                cwe_list_cache[raw_s] = tup
            return tup

        conn.execute("BEGIN TRANSACTION")
        try:
            conn.execute("DELETE FROM scores WHERE run_id = ?", [run_id])
            with conn.appender("scores") as appender:
                batch_rows: List[Tuple[Any, ...]] = []
                while True:
                    chunk = cursor.fetchmany(50_000)
                    if not chunk:
                        break
                    for (
                        finding_id,
                        asset_id,
                        track_hint,
                        primary_cve,
                        cves_json,
                        cwes_json,
                        scanner_sev,
                        scanner_cvss,
                        scanner_cvss_vec,
                        detection_mode,
                        explicit_rel,
                        ing_conf,
                        exploit_ev,
                        internet_facing,
                        declared_crit,
                        inv_status,
                        caps_json,
                        chains_json,
                        cve_list,
                    ) in chunk:
                        total_findings += 1
                        if cve_list:
                            cve_tuple = tuple(dict.fromkeys(str(c).strip().upper() for c in cve_list if c))
                        elif primary_cve and cves_json and "," not in cves_json and cves_json == f'["{primary_cve}"]':
                            cve_tuple = primary_cve_tuple_cache.get(primary_cve)
                            if cve_tuple is None:
                                cve_tuple = (str(primary_cve).strip().upper(),)
                                if len(primary_cve_tuple_cache) < 100_000:
                                    primary_cve_tuple_cache[primary_cve] = cve_tuple
                        elif cves_json and cves_json != "[]":
                            parsed_cves = _parse_json_tuple(cves_json)
                            cve_tuple = tuple(dict.fromkeys(str(c).strip().upper() for c in parsed_cves if c))
                            if primary_cve:
                                p_u = str(primary_cve).strip().upper()
                                if p_u and p_u not in cve_tuple:
                                    cve_tuple = (p_u,) + cve_tuple
                        elif primary_cve:
                            cve_tuple = primary_cve_tuple_cache.get(primary_cve)
                            if cve_tuple is None:
                                cve_tuple = (str(primary_cve).strip().upper(),)
                                if len(primary_cve_tuple_cache) < 100_000:
                                    primary_cve_tuple_cache[primary_cve] = cve_tuple
                        else:
                            cve_tuple = ()

                        facing_bool = bool(internet_facing)
                        exploit_bool = bool(exploit_ev)
                        sr_key = (detection_mode, explicit_rel, ing_conf)
                        sig_rel = sig_rel_memo.get(sr_key)
                        if sig_rel is None:
                            sig_rel = rel_pol.weight_for(
                                detection_mode,
                                ingestion_confidence=_safe_float(ing_conf),
                                explicit_reliability=_safe_float(explicit_rel),
                            )
                            if len(sig_rel_memo) < 10_000:
                                sig_rel_memo[sr_key] = sig_rel

                        use_track_a = bool(cve_tuple) and (
                            not track_hint or str(track_hint).strip().lower() != "exposure_weakness"
                        )
                        if use_track_a:
                            all_auth = all(c in cve_has_auth_cvss for c in cve_tuple)
                            eff_scan_cvss = None if all_auth else scanner_cvss
                            eff_scan_vec = None if all_auth else scanner_cvss_vec
                            memo_key = (
                                1,
                                cve_tuple,
                                eff_scan_cvss,
                                eff_scan_vec,
                                detection_mode,
                                sig_rel,
                                exploit_bool,
                                facing_bool,
                                declared_crit,
                                inv_status,
                                caps_json,
                                chains_json,
                            )
                        else:
                            memo_key = (
                                0,
                                scanner_cvss,
                                scanner_cvss_vec,
                                scanner_sev,
                                detection_mode,
                                sig_rel,
                                exploit_bool,
                                cwes_json,
                                facing_bool,
                                declared_crit,
                                inv_status,
                                caps_json,
                                chains_json,
                            )

                        cached_score = memo.get(memo_key)
                        if cached_score is None:
                            caps = _parse_json_tuple(caps_json)
                            chains = _parse_json_tuple(chains_json)

                            if use_track_a:
                                raw_s, op_s, band, trace = self._score_track_a(
                                    cve_ids=cve_tuple,
                                    enrich_map=enrich_map,
                                    scanner_cvss_score=_safe_float(scanner_cvss),
                                    scanner_cvss_vector=scanner_cvss_vec,
                                    finding_exploit_evidence=exploit_bool,
                                    aci_capabilities=caps,
                                    aci_chains=chains,
                                    detection_mode=detection_mode,
                                    signal_reliability=sig_rel,
                                    asset_inventory_status=inv_status,
                                    internet_facing=facing_bool,
                                    declared_criticality=declared_crit,
                                )
                                track = "cve_threat"
                            else:
                                cwes = _parse_cwes(cwes_json)
                                raw_s, op_s, band, trace = self._score_track_b(
                                    scanner_cvss_score=_safe_float(scanner_cvss),
                                    scanner_cvss_vector=scanner_cvss_vec,
                                    scanner_severity=scanner_sev,
                                    finding_exploit_evidence=exploit_bool,
                                    cwes=cwes,
                                    aci_capabilities=caps,
                                    aci_chains=chains,
                                    detection_mode=detection_mode,
                                    signal_reliability=sig_rel,
                                    asset_inventory_status=inv_status,
                                    internet_facing=facing_bool,
                                    declared_criticality=declared_crit,
                                )
                                track = "exposure_weakness"

                            trace_json_str = json.dumps(trace, ensure_ascii=True, separators=(",", ":"))
                            bidx = band_idx_map.get(band, 4)
                            cached_score = (track, raw_s, op_s, band, bidx, trace_json_str, trace)
                            if len(memo) < 200_000:
                                memo[memo_key] = cached_score

                        track, raw_s, op_s, band, bidx, trace_json_str, trace_dict = cached_score
                        batch_rows.append(
                            (
                                run_id,
                                finding_id,
                                asset_id,
                                track,
                                raw_s,
                                op_s,
                                band,
                                trace_json_str,
                            )
                        )
                        if len(batch_rows) >= 50_000:
                            appender.append_rows(batch_rows)
                            batch_rows.clear()

                        raw_sum += raw_s
                        op_sum += op_s
                        prev_max = asset_scores.get(asset_id)
                        if prev_max is None or raw_s > prev_max:
                            asset_scores[asset_id] = raw_s

                        counts = asset_counts_fast.get(asset_id)
                        if counts is None:
                            counts = [0, 0, 0, 0, 0]
                            asset_counts_fast[asset_id] = counts
                        counts[bidx] += 1

                        if populate_derived:
                            scored_findings[finding_id] = ScoredFinding(
                                finding_id=finding_id,
                                asset_id=asset_id,
                                raw_score=raw_s,
                                operational_score=op_s,
                                risk_band=band,
                                reason=track,
                                score_trace=trace_dict,
                            )

                if batch_rows:
                    appender.append_rows(batch_rows)
                    batch_rows.clear()

            # Bulk-update findings.signal_reliability inside DuckDB
            self._bulk_update_finding_reliability(conn, run_id)

            # Bulk-update assets.derived_criticality via temp staging table + appender
            asset_criticality: Dict[str, str] = {}
            crit_rows: List[Tuple[str, str]] = []
            for aid, counts in asset_counts_fast.items():
                lvl = self._derive_asset_criticality_level(counts[0], counts[1], counts[2])
                asset_criticality[aid] = lvl
                crit_rows.append((aid, lvl))
                if len(asset_counts_fast) <= 50_000:
                    asset_band_counts[aid] = {
                        "Critical": counts[0],
                        "High": counts[1],
                        "Medium": counts[2],
                        "Low": counts[3],
                        "Informational": counts[4],
                    }

            if crit_rows:
                conn.execute("CREATE TEMP TABLE IF NOT EXISTS _stg_asset_crit (asset_id VARCHAR, derived_criticality VARCHAR)")
                conn.execute("DELETE FROM _stg_asset_crit")
                with conn.appender("_stg_asset_crit") as crit_app:
                    for off in range(0, len(crit_rows), 25_000):
                        crit_app.append_rows(crit_rows[off : off + 25_000])
                conn.execute(
                    """
                    UPDATE assets
                    SET derived_criticality = s.derived_criticality
                    FROM _stg_asset_crit s
                    WHERE assets.run_id = ? AND assets.asset_id = s.asset_id
                    """,
                    [run_id],
                )
                conn.execute("DROP TABLE IF EXISTS _stg_asset_crit")

            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            try:
                cursor.close()
            except Exception:
                pass

        highest_asset: Optional[str] = None
        highest_score: Optional[float] = None
        if asset_scores:
            highest_asset = max(asset_scores, key=asset_scores.get)
            highest_score = asset_scores[highest_asset]

        avg_raw = round(raw_sum / total_findings, 4) if total_findings else None
        avg_op = round(op_sum / total_findings, 4) if total_findings else None
        output_data = {
            "scored_findings": {
                fid: {
                    "finding_id": sf.finding_id,
                    "asset_id": sf.asset_id,
                    "raw_score": sf.raw_score,
                    "operational_score": sf.operational_score,
                    "risk_band": sf.risk_band,
                    "reason": sf.reason,
                    "score_trace": sf.score_trace,
                }
                for fid, sf in scored_findings.items()
            },
            "asset_scores": asset_scores if len(asset_scores) <= 50_000 else {},
            "asset_criticality": asset_criticality if len(asset_criticality) <= 50_000 else {},
            "asset_band_counts": asset_band_counts,
            "asset_criticality_thresholds": {
                "extreme_min_critical": self.critical_extreme_min_critical,
                "high_min_critical": self.critical_high_min_critical,
                "high_min_high": self.critical_high_min_high,
                "medium_min_high": self.critical_medium_min_high,
                "medium_min_medium": self.critical_medium_min_medium,
            },
            "coverage": {
                "total_findings": total_findings,
                "scored_findings": total_findings,
                "coverage_ratio": 1.0 if total_findings else 0.0,
            },
            "highest_risk_asset": highest_asset,
            "highest_risk_asset_score": highest_score,
            "avg_scored_risk": avg_raw,
            "avg_operational_risk": avg_op,
        }

        ledger = getattr(getattr(ctx, "services", None), "ledger", None)
        if ledger is not None:
            ledger.append_event(
                component="Scoring",
                event_type="decision",
                subject_ref="scoring:summary",
                reason_code=DecisionReasonCodes.SCORING_SUMMARY_COMPUTED,
                reason_text="Scoring@3.0 vectorized dual-track summary computed.",
                factor_refs=["scoring.epss_v5", "scoring.kev_exploit_split", "scoring.exposure_track"],
                evidence={
                    "total_findings": total_findings,
                    "scored_findings": total_findings,
                    "coverage_ratio": 1.0 if total_findings else 0.0,
                    "avg_scored_risk": avg_raw,
                    "avg_operational_risk": avg_op,
                },
            )

        ctx.logger.info(
            "[pass:scoring@3.0] duckdb | scored=%d | avg_raw=%s | avg_op=%s",
            total_findings,
            avg_raw,
            avg_op,
            extra={"vp_label": "ScoringV3Pass"},
        )
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Vectorized dual-track v2 risk scoring (EPSS v5, non-double-count KEV/exploit, Track B reliability).",
        )
        return DerivedPassResult(meta=meta, data=output_data)

    def _run_scan_result(self, ctx: "RunContext", scan: "ScanResult") -> "DerivedPassResult":
        """In-memory ScanResult compatibility mode for Scoring@3.0."""
        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}
        asset_counts: Dict[str, Dict[str, int]] = {}
        assets_by_id: Dict[str, Any] = {}
        total = 0
        raw_sum = 0.0
        op_sum = 0.0

        for asset in scan.assets:
            aid = str(getattr(asset, "asset_id", None) or getattr(asset, "ip_address", None) or "SENTINEL:AssetID_Missing")
            assets_by_id[aid] = asset
            internet_facing = bool(getattr(asset, "internet_facing", False))
            declared_crit = getattr(asset, "declared_criticality", None) or getattr(asset, "criticality", None)
            inv_status = getattr(asset, "inventory_status", None)

            for f in asset.findings:
                total += 1
                fid = str(getattr(f, "finding_id", ""))
                raw_cves = list(getattr(f, "cves", None) or ())
                if not raw_cves and getattr(f, "primary_cve", None):
                    raw_cves = [getattr(f, "primary_cve")]
                cve_tuple = tuple(dict.fromkeys(str(c).strip().upper() for c in raw_cves if c))

                det_mode = getattr(f, "detection_mode", None)
                ing_conf = _safe_float(getattr(f, "ingestion_confidence", None))
                exp_rel = _safe_float(getattr(f, "signal_reliability", None))
                sig_rel = self.policy.signal_reliability.weight_for(
                    det_mode, ingestion_confidence=ing_conf, explicit_reliability=exp_rel
                )
                caps = tuple(str(c) for c in (getattr(f, "aci_capabilities", None) or ()))
                chains = tuple(str(c) for c in (getattr(f, "aci_chains", None) or ()))
                heur_exp = bool(getattr(f, "heuristic_exploit_mention", False) or getattr(f, "exploit_available", False))
                ver_exp = bool(getattr(f, "verified_exploit", False))
                in_kev = bool(getattr(f, "cisa_kev", False) or getattr(f, "in_kev", False))
                scanner_cvss = _safe_float(getattr(f, "cvss_score", None))
                scanner_vec = getattr(f, "cvss_vector", None)

                if cve_tuple:
                    enrich_local: Dict[str, Tuple[Any, ...]] = {}
                    for cve in cve_tuple:
                        epss_s = _safe_float(getattr(f, "epss_score", None))
                        epss_p = _safe_float(getattr(f, "epss_percentile", None))
                        prov = _norm_provenance(getattr(f, "cvss_provenance", None))
                        if prov == "Missing" and scanner_cvss is not None:
                            prov = "Scanner-Supplied"
                        enrich_local[cve] = (
                            scanner_cvss if prov != "Scanner-Supplied" else None,
                            getattr(f, "cvss_version", None),
                            prov if prov != "Scanner-Supplied" else "Missing",
                            epss_s,
                            epss_p,
                            getattr(f, "epss_model_version", None),
                            getattr(f, "epss_date", None),
                            _epss_v5_points(epss_s, epss_p, self.policy.epss_breakpoints),
                            _format_epss_display(epss_s, epss_p),
                            in_kev,
                            getattr(f, "kev_date_added", None),
                            getattr(f, "kev_due_date", None),
                            getattr(f, "kev_ransomware", None),
                            ver_exp,
                            heur_exp,
                        )
                    raw_s, op_s, band, trace = self._score_track_a(
                        cve_ids=cve_tuple,
                        enrich_map=enrich_local,
                        scanner_cvss_score=scanner_cvss,
                        scanner_cvss_vector=scanner_vec,
                        finding_exploit_evidence=heur_exp,
                        aci_capabilities=caps,
                        aci_chains=chains,
                        detection_mode=det_mode,
                        signal_reliability=sig_rel,
                        asset_inventory_status=inv_status,
                        internet_facing=internet_facing,
                        declared_criticality=declared_crit,
                    )
                else:
                    cwes = tuple(c for c in (_norm_cwe(x) for x in (getattr(f, "cwes", None) or ())) if c)
                    raw_s, op_s, band, trace = self._score_track_b(
                        scanner_cvss_score=scanner_cvss,
                        scanner_cvss_vector=scanner_vec,
                        scanner_severity=getattr(f, "severity", None),
                        finding_exploit_evidence=heur_exp,
                        cwes=cwes,
                        aci_capabilities=caps,
                        aci_chains=chains,
                        detection_mode=det_mode,
                        signal_reliability=sig_rel,
                        asset_inventory_status=inv_status,
                        internet_facing=internet_facing,
                        declared_criticality=declared_crit,
                    )

                sf = ScoredFinding(
                    finding_id=fid,
                    asset_id=aid,
                    raw_score=raw_s,
                    operational_score=op_s,
                    risk_band=band,
                    reason=str(trace["scoring_track"]),
                    score_trace=trace,
                )
                scored_findings[fid] = sf
                f.raw_risk_score = raw_s
                f.operational_score = op_s
                f.risk_band = band
                f.score_trace = trace
                raw_sum += raw_s
                op_sum += op_s
                if aid not in asset_scores or raw_s > asset_scores[aid]:
                    asset_scores[aid] = raw_s
                cnts = asset_counts.setdefault(aid, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0})
                cnts[band if band in cnts else "Informational"] += 1

        asset_criticality: Dict[str, str] = {}
        for aid, cnts in asset_counts.items():
            lvl = self._derive_asset_criticality_level(cnts["Critical"], cnts["High"], cnts["Medium"])
            asset_criticality[aid] = lvl
            if aid in assets_by_id:
                assets_by_id[aid].criticality = lvl

        highest_asset = max(asset_scores, key=asset_scores.get) if asset_scores else None
        highest_score = asset_scores[highest_asset] if highest_asset else None
        avg_raw = round(raw_sum / total, 4) if total else None
        avg_op = round(op_sum / total, 4) if total else None

        output = ScoringPassOutput(
            scored_findings=scored_findings,
            asset_scores=asset_scores,
            asset_criticality=asset_criticality,
            asset_band_counts=asset_counts,
            asset_criticality_thresholds={
                "extreme_min_critical": self.critical_extreme_min_critical,
                "high_min_critical": self.critical_high_min_critical,
                "high_min_high": self.critical_high_min_high,
                "medium_min_high": self.critical_medium_min_high,
                "medium_min_medium": self.critical_medium_min_medium,
            },
            coverage=ScoreCoverage(
                total_findings=total,
                scored_findings=len(scored_findings),
                coverage_ratio=(len(scored_findings) / total) if total else 0.0,
            ),
            highest_risk_asset=highest_asset,
            highest_risk_asset_score=highest_score,
            avg_scored_risk=avg_raw,
            avg_operational_risk=avg_op,
        )
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Dual-track v2 risk scoring (ScanResult compatibility mode).",
        )
        return DerivedPassResult(meta=meta, data=asdict(output))
