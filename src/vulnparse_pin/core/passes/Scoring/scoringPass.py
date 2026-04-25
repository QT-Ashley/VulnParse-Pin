# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, TYPE_CHECKING, List, Tuple, Any
import concurrent.futures as cf
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
