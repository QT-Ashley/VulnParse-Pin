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
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import threading
import os

from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass
from vulnparse_pin.core.passes.types import ScoreCoverage, ScoredFinding, ScoringPassOutput
from vulnparse_pin.core.classes.pass_classes import PassMeta

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.classes.dataclass import Finding


def _score_components_from_policy(
    attrs: Dict[str, Any],
    policy_values: Dict[str, float],
) -> Optional[Tuple[float, float, str, str]]:
    """Process-safe scoring helper for process pool workers."""
    kev = bool(attrs.get("kev", False))
    exploit = bool(attrs.get("exploit", False))
    cvss = attrs.get("cvss", None)
    epss = attrs.get("epss", None)

    if not kev and not exploit and cvss is None and epss is None:
        return None

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

    return raw, score, band, ";".join(reasons)


def _score_chunk_process(
    chunk: List[Tuple[str, str, Dict[str, Any]]],
    policy_values: Dict[str, float],
) -> Tuple[Dict[str, Tuple[str, float, float, str, str]], Dict[str, float]]:
    """Process worker: returns finding tuples and per-asset max score."""
    chunk_results: Dict[str, Tuple[str, float, float, str, str]] = {}
    chunk_assets: Dict[str, float] = {}

    for finding_id, asset_id, attrs in chunk:
        score_parts = _score_components_from_policy(attrs, policy_values)
        if score_parts is None:
            continue
        raw, score, band, reason = score_parts
        chunk_results[finding_id] = (asset_id, raw, score, band, reason)
        if asset_id not in chunk_assets or raw > chunk_assets[asset_id]:
            chunk_assets[asset_id] = raw

    return chunk_results, chunk_assets

@dataclass
class ScoringPass(Pass):
    name: str = "Scoring"
    version: str = "1.0"

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

    def run(self, ctx: "RunContext", scan: "ScanResult") -> "DerivedPassResult":
        """
        Run scoring pass with parallel execution on finding batches.
        Smart caches plugin attributes to avoid repeated getattr() calls.
        """
        # Flatten findings with asset context (asset_id, ip_address)
        findings_with_context: List[Tuple[Any, str, Optional[str]]] = []
        assets_by_id: Dict[str, Any] = {}
        total = 0
        
        for asset in scan.assets:
            for f in asset.findings:
                total += 1
                asset_id = getattr(asset, "asset_id", None) or f.asset_id or asset.ip_address
                findings_with_context.append((f, asset_id, asset.ip_address))
                if asset_id not in assets_by_id:
                    assets_by_id[asset_id] = asset

        # Pre-compute plugin attributes once (smart caching)
        plugin_cache = self._build_plugin_cache(findings_with_context)

        # Parallel execution for medium+ workloads
        use_parallel = len(findings_with_context) > self.parallel_threshold

        # Shared memo for repeated score signatures (thread-safe in parallel mode)
        score_memo: Dict[Tuple[bool, bool, Any, Any], Optional[Tuple[float, float, str, str]]] = {}
        
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
        self._write_asset_criticality(scan, assets_by_id, asset_criticality)

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
        scan: "ScanResult",
        assets_by_id: Dict[str, Any],
        asset_criticality: Dict[str, str],
    ) -> None:
        """Persist derived asset criticality back to the mutable ScanResult asset objects."""
        for asset_id, criticality in asset_criticality.items():
            asset = assets_by_id.get(asset_id)
            if asset is not None:
                asset.criticality = criticality

    def _build_plugin_cache(self, findings_with_context: List[Tuple[Any, str, str]]) -> Dict[str, Dict[str, Any]]:
        """
        Pre-compute plugin attributes once to avoid repeated getattr() calls.
        Secure design: read-only access to findings, no modifications.
        Returns: {finding_id -> {kev, exploit, cvss, epss}}
        """
        cache = {}
        for finding, _, _ in findings_with_context:
            cache[finding.finding_id] = {
                "kev": bool(getattr(finding, "cisa_kev", False)),
                "exploit": bool(getattr(finding, "exploit_available", False)),
                "cvss": getattr(finding, "cvss_score", None),
                "epss": getattr(finding, "epss_score", None),
            }
        return cache

    def _score_sequential(
        self, 
        findings_with_context: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]],
        score_memo: Dict[Tuple[bool, bool, Any, Any], Optional[Tuple[float, float, str, str]]]
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

        policy_values = {
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
        }

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
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = {
                    executor.submit(_score_chunk_process, chunk, policy_values): index
                    for index, chunk in enumerate(chunks)
                }

                for future in as_completed(futures):
                    chunk_results, chunk_assets = future.result()

                    for finding_id, payload in chunk_results.items():
                        asset_id, raw, score, band, reason = payload
                        scored_findings[finding_id] = ScoredFinding(
                            finding_id=finding_id,
                            asset_id=asset_id,
                            raw_score=round(raw, 4),
                            operational_score=round(score, 4),
                            risk_band=band,
                            reason=reason,
                        )

                    for asset_id, score in chunk_assets.items():
                        if asset_id not in asset_scores or score > asset_scores[asset_id]:
                            asset_scores[asset_id] = score

            return scored_findings, asset_scores
        except Exception as exc:
            ctx.logger.warning(
                "[pass:scoring] process pool unavailable, falling back to thread pool | reason=%s",
                exc,
                extra={"vp_label": "ScoringPass"},
            )
            score_memo: Dict[Tuple[bool, bool, Any, Any], Optional[Tuple[float, float, str, str]]] = {}
            return self._score_parallel(ctx, findings_with_context, plugin_cache, score_memo)

    def _score_parallel(
        self,
        ctx: "RunContext",
        findings_with_context: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]],
        score_memo: Dict[Tuple[bool, bool, Any, Any], Optional[Tuple[float, float, str, str]]]
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
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
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
            for future in as_completed(futures):
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
        score_memo: Dict[Tuple[bool, bool, Any, Any], Optional[Tuple[float, float, str, str]]]
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

        raw, score, band, reason = score_parts

        return ScoredFinding(
            finding_id=f.finding_id,
            asset_id=asset_id,
            raw_score=round(raw, 4),
            operational_score=round(score, 4),
            risk_band=band,
            reason=reason
        )

    def _score_one_with_memo(
        self,
        f: "Finding",
        asset_id: str,
        attrs: Dict[str, Any],
        score_memo: Dict[Tuple[bool, bool, Any, Any], Optional[Tuple[float, float, str, str]]]
    ) -> Optional[ScoredFinding]:
        """Score a finding using signature memoization for repeated attribute sets."""
        signature = self._score_signature(attrs)
        cached = score_memo.get(signature)

        if cached is None and signature not in score_memo:
            computed = self._calculate_score_components(attrs)
            with self._memo_lock:
                score_memo[signature] = computed
            cached = computed

        if cached is None:
            return None

        raw, score, band, reason = cached

        return ScoredFinding(
            finding_id=f.finding_id,
            asset_id=asset_id,
            raw_score=round(raw, 4),
            operational_score=round(score, 4),
            risk_band=band,
            reason=reason,
        )

    def _score_signature(self, attrs: Dict[str, Any]) -> Tuple[bool, bool, Any, Any]:
        """Build deterministic memoization key from cached scoring inputs."""
        return (
            bool(attrs.get("kev", False)),
            bool(attrs.get("exploit", False)),
            attrs.get("cvss", None),
            attrs.get("epss", None),
        )

    def _calculate_score_components(
        self,
        attrs: Dict[str, Any]
    ) -> Optional[Tuple[float, float, str, str]]:
        """Calculate raw/op score components from cached attrs. Returns None if gated."""
        pol = self.policy

        kev = attrs["kev"]
        exploit = attrs["exploit"]
        cvss = attrs["cvss"]
        epss = attrs["epss"]

        # Gate: if no enrichment data, no score
        if not kev and not exploit and cvss is None and epss is None:
            return None

        raw = 0.0
        reasons = []

        # CVSS Component (0..10)
        if cvss is not None:
            try:
                c = float(cvss)
                raw += c
                reasons.append(f"cvss={c:.2f}")
            except (TypeError, ValueError):
                pass

        # EPSS Component (0..1.0 | 0..scale), with weights
        if epss is not None:
            try:
                e = float(epss)
                e = min(max(e, pol.epss_min), pol.epss_max)
                e_scaled = e * pol.epss_scale
                
                # Bucket thresholds
                mult = 1.0
                if e >= 0.70:
                    mult = pol.w_epss_high
                    reasons.append(f"epss_high*{pol.w_epss_high:g}")
                elif e >= 0.40:
                    mult = pol.w_epss_medium
                    reasons.append(f"epss_medium*{pol.w_epss_medium:g}")

                raw += e_scaled * mult
                reasons.append(f"epss={e:.5f}({e_scaled:.2f})")
            except (TypeError, ValueError):
                pass

        # KEV Component
        if kev:
            raw += pol.kev_evd * pol.w_kev
            reasons.append("KEV Present")

        # Exploit Component
        if exploit:
            raw += pol.exploit_evd * pol.w_exploit
            reasons.append("Exploit Available")

        score = (raw / pol.max_raw_risk) * pol.max_op_risk
        score = max(0.0, min(score, pol.max_op_risk))
        band = self._band(raw)
        return raw, score, band, ";".join(reasons)

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
