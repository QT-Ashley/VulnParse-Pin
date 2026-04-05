# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
import concurrent.futures as cf
import os

from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta
from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.dataclass import AssetObservation
from vulnparse_pin.core.passes.types import (
    ExposureInference,
    RankedAssetRef,
    RankedFindingRef,
    TopNPassOutput
)
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import TNTriageConfig, ParsedPredicate
from vulnparse_pin.core.passes.TopN.workers import _rank_findings_chunk_worker, _topn_asset_chunk_worker
from vulnparse_pin.core.passes.TopN.workers import _is_private_ip, _is_public_ip

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.passes.types import ScoredFinding
    from vulnparse_pin.core.passes.TopN.TN_triage_semantics import ConfidenceThreshold


# -------------------------------------------
# TopN Pass
# -------------------------------------------

class TopNPass(Pass):
    name = "TopN"
    version: str = "1.0"
    requires_passes: tuple[str, ...] = ("Scoring@1.0",)

    def __init__(
        self, 
        triage_cfg: TNTriageConfig,
        process_pool_threshold: int = 20_000,
        process_workers: Optional[int] = None,
    ) -> None:
        self.cfg = triage_cfg
        self.process_pool_threshold = max(1, int(process_pool_threshold))
        self.process_workers = process_workers

    def run(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        """
        Consumes scan result to include previous derived passes data.
        Produces:
         - topn derived key = TopNPassOutput
        """
        # 0 retrieve Scoring pass output for scoring results
        scoring = self._get_scoring_output(scan)                    # Returns Scoring Pass DerivedPassResult
        if scoring is None:
            ctx.logger.error("Missing scoring output; cannot rank.", extra={"vp_label": "TopNPass"})
            services = getattr(ctx, "services", None)
            ledger = getattr(services, "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="TopN",
                    event_type="decision",
                    subject_ref="topn:summary",
                    reason_code=DecisionReasonCodes.TOPN_SKIPPED_MISSING_SCORING,
                    reason_text="TopN skipped because Scoring@1.0 output was missing.",
                    factor_refs=["dependency:Scoring@1.0"],
                    evidence={"status": "skipped", "missing_dependency": "Scoring@1.0"},
                )

            output = TopNPassOutput(
                rank_basis=self.cfg.topn.rank_basis,
                k=self.cfg.topn.k,
                decay=self.cfg.topn.decay,
                assets=(),
                findings_by_asset={},
                global_top_findings=(),
            )
            data = asdict(output)
            data["status"] = "skipped"
            data["error"] = {
                "code": "missing_dependency",
                "message": "Scoring@1.0 output not found; TopN ranking not executed.",
                "missing": ["Scoring@1.0"],
            }

            meta = PassMeta(
                name=self.name,
                version=self.version,
                created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                notes="TopN soft no-op due to missing Scoring pass output.",
            )
            return DerivedPassResult(meta=meta, data=data)

        # 1 Build lookup index
        asset_to_findings = self._index_findings_by_asset(scan)     # { asset_id: [fid, fid, fid] }
        # Count total findings
        total_findings = sum(len(fids) for fids in asset_to_findings.values())
        use_process_pool = total_findings > self.process_pool_threshold

        rank_basis = self.cfg.topn.rank_basis

        if use_process_pool:
            ctx.logger.info(
                f"Using process-pool parallelism for {total_findings:,} findings across {len(asset_to_findings):,} assets",
                extra={"vp_label": "TopNPass"}
            )
            inference_by_asset, findings_by_asset_ranked, ranked_assets, global_top = self._run_parallel_pipeline(
                ctx=ctx,
                scan=scan,
                scoring=scoring,
                asset_to_findings=asset_to_findings,
                rank_basis=rank_basis,
            )
        else:
            # 2 Compute inference per asset
            inference_by_asset: Dict[str, ExposureInference] = {}
            for asset_id, _ in asset_to_findings.items():
                obs = self._collect_asset_observation(scan, asset_id, finding_ids=asset_to_findings[asset_id], ctx=ctx)
                if obs is None:
                    continue
                inference_by_asset[asset_id] = self._infer_exposure(obs)

            # 3 Rank findings per asset
            findings_by_asset_ranked: Dict[str, Tuple[RankedFindingRef, ...]] = {}
            for asset_id, fids, in asset_to_findings.items():
                ranked = self._rank_findings_for_asset(
                    scan=scan,
                    scoring=scoring,
                    asset_id=asset_id,
                    finding_ids=fids,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.max_findings_per_asset,
                )
                findings_by_asset_ranked[asset_id] = ranked

            # 4 Rank assets via Top-K (K=len(decay))
            ranked_assets = self._rank_assets(
                scan=scan,
                scoring=scoring,
                asset_to_findings=asset_to_findings,
                inference_by_asset=inference_by_asset,
                rank_basis=rank_basis,
                ctx=ctx,
            )

            # trim to max_assets
            ranked_assets = ranked_assets[: self.cfg.topn.max_assets]

            # 5 Optional global top findings
            global_top: Tuple[RankedFindingRef, ...] = ()
            if self.cfg.topn.include_global_top_findings:
                global_top = self._rank_global_findings(
                    scan=scan,
                    scoring=scoring,
                    asset_to_findings=asset_to_findings,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.global_top_findings
                )

        output = TopNPassOutput(
            rank_basis=rank_basis,
            k=self.cfg.topn.k,
            decay=self.cfg.topn.decay,
            assets=tuple(ranked_assets),
            findings_by_asset=findings_by_asset_ranked,
            global_top_findings=global_top,
        )

        services = getattr(ctx, "services", None)
        ledger = getattr(services, "ledger", None)
        runmanifest_mode = str(getattr(services, "runmanifest_mode", "compact") or "compact").lower()
        if ledger is not None:
            ledger.append_event(
                component="TopN",
                event_type="decision",
                subject_ref="topn:summary",
                reason_code=DecisionReasonCodes.TOPN_RANKING_COMPLETED,
                reason_text="TopN ranking completed for assets and findings.",
                factor_refs=["rank_basis", "topn.max_assets", "topn.global_top_findings"],
                evidence={
                    "ranked_assets": len(output.assets),
                    "global_top_findings": len(output.global_top_findings),
                },
            )

            asset_event_limit = 5 if runmanifest_mode == "compact" else min(len(output.assets), 20)
            for asset_ref in output.assets[:asset_event_limit]:
                ledger.append_event(
                    component="TopN",
                    event_type="decision",
                    subject_ref=f"asset:{asset_ref.asset_id}",
                    reason_code=DecisionReasonCodes.TOP_ASSET_SELECTED,
                    reason_text="Asset selected in TopN ranked asset set.",
                    factor_refs=["rank_basis", "top_scores", "inference"],
                    confidence="high" if asset_ref.rank <= 3 else "medium",
                    evidence={
                        "rank": asset_ref.rank,
                        "score": asset_ref.score,
                        "scored_findings": asset_ref.scored_findings,
                    },
                )

            inference_conf = {"high": 0, "medium": 0, "low": 0}
            for inf in inference_by_asset.values():
                c = (inf.confidence or "low").lower()
                if c in inference_conf:
                    inference_conf[c] += 1
            ledger.append_event(
                component="TopN",
                event_type="decision",
                subject_ref="topn:exposure_inference",
                reason_code=DecisionReasonCodes.EXPOSURE_INFERENCE_SUMMARY,
                reason_text="Exposure inference confidence distribution computed.",
                factor_refs=["inference.rules", "inference.confidence_thresholds"],
                evidence={
                    "assets_with_inference": len(inference_by_asset),
                    "confidence_counts": inference_conf,
                },
            )

        # 6 Write out
        ctx.logger.info("Produced %d ranked assets", len(output.assets), extra={"vp_label": "TopNPass"})

        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived TopN Asset and Findings rankings."
        )
        return DerivedPassResult(meta=meta, data=asdict(output))

    def _run_parallel_pipeline(
        self,
        *,
        ctx: "RunContext",
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        rank_basis: str,
    ) -> Tuple[
        Dict[str, ExposureInference],
        Dict[str, Tuple[RankedFindingRef, ...]],
        List[RankedAssetRef],
        Tuple[RankedFindingRef, ...],
    ]:
        cpu_total = os.cpu_count() or 1
        worker_cap = self.process_workers if self.process_workers is not None else cpu_total
        num_workers = max(1, min(worker_cap, cpu_total))

        scoring_data: Dict[str, Dict[str, Any]] = {}
        data = getattr(scoring, "data", None)
        if isinstance(data, dict):
            scored = data.get("scored_findings", {})
        else:
            scored = getattr(data, "scored_findings", {})

        if isinstance(scored, dict):
            for fid, rec in scored.items():
                scoring_data[fid] = {
                    "raw_score": rec.get("raw_score", 0.0),
                    "operational_score": rec.get("operational_score", 0.0),
                    "risk_band": rec.get("risk_band", "unknown"),
                    "reason": rec.get("reason", ""),
                }

        finding_attrs: Dict[str, Dict[str, Any]] = {}
        asset_obs_by_id: Dict[str, Dict[str, Any]] = {}
        asset_criticality_by_id: Dict[str, Optional[str]] = {}

        for asset in scan.assets:
            aid = getattr(asset, "asset_id", None)
            if aid is not None:
                asset_criticality_by_id[aid] = getattr(asset, "criticality", None)
            for finding in asset.findings:
                if aid is None:
                    aid = getattr(finding, "asset_id", None)
                fid = finding.finding_id
                port = getattr(finding, "affected_port", None)
                finding_attrs[fid] = {
                    "port": port,
                    "proto": getattr(finding, "protocol", None),
                    "plugin_id": getattr(finding, "vuln_id", None),
                }

        idx = getattr(getattr(ctx, "services", None), "post_enrichment_index", None)
        if idx is not None:
            for aid, obs in idx.asset_observations.items():
                criticality = asset_criticality_by_id.get(aid, obs.criticality)
                asset_obs_by_id[aid] = {
                    "asset_id": aid,
                    "ip": obs.ip,
                    "hostname": obs.hostname,
                    "criticality": criticality,
                    "open_ports": tuple(obs.open_ports),
                }
        else:
            for asset in scan.assets:
                aid = getattr(asset, "asset_id", None)
                ip_addr = getattr(asset, "ip_address", None)
                hostname = getattr(asset, "hostname", None)
                crit = getattr(asset, "criticality", None)
                open_ports: set[int] = set()
                for finding in asset.findings:
                    if aid is None:
                        aid = getattr(finding, "asset_id", None)
                    port = getattr(finding, "affected_port", None)
                    if isinstance(port, int):
                        open_ports.add(port)
                if aid is not None:
                    asset_obs_by_id[aid] = {
                        "asset_id": aid,
                        "ip": ip_addr,
                        "hostname": hostname,
                        "criticality": crit,
                        "open_ports": tuple(sorted(open_ports)),
                    }

        inference_cfg = {
            "thresholds": {
                "medium": int(self.cfg.inference.confidence_thresholds.medium),
                "high": int(self.cfg.inference.confidence_thresholds.high),
            },
            "public_service_ports": tuple(int(p) for p in self.cfg.inference.public_service_ports_set),
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "enabled": bool(r.enabled),
                    "tag": r.tag,
                    "weight": int(r.weight),
                    "predicate_name": r.predicate.name,
                    "predicate_ports": tuple(int(p) for p in r.predicate.ports),
                    "predicate_tokens": tuple(str(t) for t in r.predicate.tokens),
                    "evidence": r.evidence,
                }
                for r in self.cfg.inference.rules
            ],
        }

        work_items: List[Tuple[str, List[str]]] = [(aid, fids) for aid, fids in asset_to_findings.items()]
        chunk_size = max(1, len(work_items) // num_workers)
        chunks = [work_items[i:i + chunk_size] for i in range(0, len(work_items), chunk_size)]

        inference_by_asset: Dict[str, ExposureInference] = {}
        findings_by_asset_ranked: Dict[str, Tuple[RankedFindingRef, ...]] = {}
        asset_rows: List[Tuple[float, int, int, int, str, Tuple[float, ...]]] = []
        global_candidates: List[Tuple[float, str, str, Dict[str, Any]]] = []

        try:
            with cf.ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = {
                    executor.submit(
                        _topn_asset_chunk_worker,
                        chunk,
                        scoring_data,
                        finding_attrs,
                        asset_obs_by_id,
                        inference_cfg,
                        rank_basis,
                        self.cfg.topn.max_findings_per_asset,
                        self.cfg.topn.k,
                        self.cfg.topn.decay,
                        self.cfg.topn.include_global_top_findings,
                        self.cfg.topn.global_top_findings,
                    ): index
                    for index, chunk in enumerate(chunks)
                }

                for future in cf.as_completed(futures):
                    payload = future.result()

                    for aid, inf in payload["inference"].items():
                        inference_by_asset[aid] = ExposureInference(
                            exposure_score=int(inf["exposure_score"]),
                            confidence=str(inf["confidence"]),
                            externally_facing_inferred=bool(inf["externally_facing_inferred"]),
                            public_service_ports_inferred=bool(inf["public_service_ports_inferred"]),
                            evidence=tuple(inf["evidence"]),
                        )

                    for aid, ranked_dicts in payload["findings"].items():
                        ranked_refs: List[RankedFindingRef] = []
                        for d in ranked_dicts:
                            ranked_refs.append(
                                RankedFindingRef(
                                    finding_id=d["finding_id"],
                                    asset_id=d["asset_id"],
                                    rank=int(d["rank"]),
                                    score_basis=d["score_basis"],
                                    score=float(d["score"]),
                                    risk_band=d["risk_band"],
                                    reasons=tuple(d["reasons"]),
                                    port=d["port"],
                                    proto=d["proto"],
                                    plugin_id=d["plugin_id"],
                                )
                            )
                        findings_by_asset_ranked[aid] = tuple(ranked_refs)

                    asset_rows.extend(payload["assets"])
                    global_candidates.extend(payload["global_candidates"])

        except Exception as exc:  # pylint: disable=broad-exception-caught
            ctx.logger.warning(
                "[pass:topn] process pool unavailable, falling back to sequential | reason=%s",
                exc,
                extra={"vp_label": "TopNPass"},
            )
            inference_by_asset = {}
            for asset_id, _ in asset_to_findings.items():
                obs = self._collect_asset_observation(scan, asset_id, finding_ids=asset_to_findings[asset_id], ctx=ctx)
                if obs is None:
                    continue
                inference_by_asset[asset_id] = self._infer_exposure(obs)

            findings_by_asset_ranked = {}
            for asset_id, fids in asset_to_findings.items():
                findings_by_asset_ranked[asset_id] = self._rank_findings_for_asset(
                    scan=scan,
                    scoring=scoring,
                    asset_id=asset_id,
                    finding_ids=fids,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.max_findings_per_asset,
                )

            ranked_assets = self._rank_assets(
                scan=scan,
                scoring=scoring,
                asset_to_findings=asset_to_findings,
                inference_by_asset=inference_by_asset,
                rank_basis=rank_basis,
                ctx=ctx,
            )
            ranked_assets = ranked_assets[: self.cfg.topn.max_assets]

            global_top: Tuple[RankedFindingRef, ...] = ()
            if self.cfg.topn.include_global_top_findings:
                global_top = self._rank_global_findings(
                    scan=scan,
                    scoring=scoring,
                    asset_to_findings=asset_to_findings,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.global_top_findings,
                )
            return inference_by_asset, findings_by_asset_ranked, ranked_assets, global_top

        asset_rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], x[4]))
        ranked_assets: List[RankedAssetRef] = []
        for i, (asset_score, _crit_high, _crit_rank, scorable_count, asset_id, top_scores) in enumerate(
            asset_rows[: self.cfg.topn.max_assets],
            start=1,
        ):
            ranked_assets.append(
                RankedAssetRef(
                    asset_id=asset_id,
                    rank=i,
                    score_basis=rank_basis,
                    score=float(asset_score),
                    top_scores=tuple(top_scores),
                    scored_findings=int(scorable_count),
                    inference=inference_by_asset.get(asset_id),
                )
            )

        global_top: Tuple[RankedFindingRef, ...] = ()
        if self.cfg.topn.include_global_top_findings:
            global_candidates.sort(key=lambda x: (-x[0], x[1], x[2]))
            selected = global_candidates[: self.cfg.topn.global_top_findings]
            refs: List[RankedFindingRef] = []
            for i, (_, _, _, d) in enumerate(selected, start=1):
                refs.append(
                    RankedFindingRef(
                        finding_id=d["finding_id"],
                        asset_id=d["asset_id"],
                        rank=i,
                        score_basis=d["score_basis"],
                        score=float(d["score"]),
                        risk_band=d["risk_band"],
                        reasons=tuple(d["reasons"]),
                        port=d["port"],
                        proto=d["proto"],
                        plugin_id=d["plugin_id"],
                    )
                )
            global_top = tuple(refs)

        return inference_by_asset, findings_by_asset_ranked, ranked_assets, global_top

    # -------------------------------------------
    # Core Plugs
    # -------------------------------------------

    def _get_scoring_output(self, scan: "ScanResult") -> DerivedPassResult | None:
        try:
            return scan.derived.passes["Scoring@1.0"]
        except (AttributeError, TypeError, KeyError):
            return None

    def _index_findings_by_asset(self, scan: "ScanResult") -> dict[str, List[str]]:
        maps: Dict[str, List[str]] = {}
        for asset in scan.assets:
            aid = getattr(asset, "asset_id", None)
            if aid is None:
                for finding in asset.findings:
                    aid = getattr(finding, "asset_id", None)
                    if aid:
                        break
            if not aid:
                continue
            for finding in asset.findings:
                maps.setdefault(aid, []).append(finding.finding_id)

        for aid, _ in maps.items():
            maps[aid].sort()
        return maps

    def _get_finding_score_record(self, scoring: "DerivedPassResult", finding_id: str) -> Optional[Dict[str, "ScoredFinding"]]:
        """
        Returns an obj/dict with:
         - raw_score: float
         - operational_score: float
         - band: str
         - reasons: tuple[str]
        """
        data = getattr(scoring, "data", None)

        if isinstance(data, dict):
            scored = data.get("scored_findings", {})
            if isinstance(scored, dict):
                return scored.get(finding_id)
            return None

        # fallback
        scored = getattr(data, "scored_findings", None)
        if isinstance(scored, dict):
            return scored.get(finding_id)

    def _collect_asset_observation(self, scan: "ScanResult", asset_id: str, *, finding_ids: List[str], ctx: Optional["RunContext"] = None) -> Optional[AssetObservation]:
        """
        Collect ip, hostname, and observed open ports for the given asset_id.
        """
        services = getattr(ctx, "services", None) if ctx is not None else None
        index = getattr(services, "post_enrichment_index", None) if services is not None else None

        asset = None
        for a in scan.assets:
            candidate_asset_id = getattr(a, "asset_id", None)
            if candidate_asset_id == asset_id:
                asset = a
                break

        current_criticality = getattr(asset, "criticality", None) if asset else None

        if index is not None:
            obs = index.get_asset_observation(asset_id)
            if obs is not None:
                return AssetObservation(
                    asset_id=obs.asset_id,
                    ip=obs.ip,
                    hostname=obs.hostname,
                    criticality=current_criticality if current_criticality is not None else obs.criticality,
                    open_ports=obs.open_ports,
                )

        ip = getattr(asset, "ip_address", None) if asset else None
        hostname = getattr(asset, "hostname", None) if asset else None

        # Gather open ports
        ports: List[int] = []
        for fid in finding_ids:
            f = self._get_finding_by_id(scan, fid, ctx)
            if not f:
                continue
            p = getattr(f, "affected_port", None)
            if isinstance(p, int):
                ports.append(p)

        ports = sorted(set(ports))
        crit = current_criticality
        return AssetObservation(asset_id=asset_id, ip=ip, hostname=hostname, criticality=crit, open_ports=tuple(ports))

    def _get_finding_by_id(self, scan: "ScanResult", finding_id: str, ctx: Optional["RunContext"] = None) -> Optional[Any]:
        """
        O(1) lookup for finding by ID using post-enrichment index if available.
        Falls back to sequential scan if index not available or ctx not provided.
        
        Args:
            scan: ScanResult (for fallback legacy path)
            finding_id: ID of finding to retrieve
            ctx: RunContext with services (optional, for indexed path)
            
        Returns:
            Finding object or None if not found
        """
        # Try indexed path first (O(1))
        services = getattr(ctx, "services", None) if ctx is not None else None
        index = getattr(services, "post_enrichment_index", None) if services is not None else None
        if index is not None:
            return index.get_finding(finding_id)
        
        # Fallback to sequential scan (O(n×m)) if index not available
        for a in scan.assets:
            for f in a.findings:
                if f.finding_id == finding_id:
                    return f
        return None


    # -------------------------------------------
    # Ranking Core
    # -------------------------------------------

    def _rank_findings_for_asset(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_id: str,
        finding_ids: List[str],
        rank_basis: str,
        ctx: Optional["RunContext"] = None,
        max_findings: int,
    ) -> tuple[RankedFindingRef, ...]:

        rows: List[Tuple[float, str, RankedFindingRef]] = []


        for fid in finding_ids:
            rec = self._get_finding_score_record(scoring, fid)
            if rec is None:
                continue

            raw = float(rec.get("raw_score", 0.0))
            op = float(rec.get("operational_score", raw))
            score = raw if rank_basis == "raw" else op

            band = str(rec.get("risk_band", "unknown"))
            reasons = tuple(rec.get("reason", ()).strip().split(";"))

            f = self._get_finding_by_id(scan, fid, ctx)
            port = getattr(f, "affected_port", None) if f else None
            proto = getattr(f, "protocol", None) if f else None
            plugin_id = getattr(f, "vuln_id", None) if f else None

            ref = RankedFindingRef(
                finding_id=fid,
                asset_id=asset_id,
                rank=0,
                score_basis=rank_basis,
                score=score,
                risk_band=band,
                reasons=reasons,
                port=port if isinstance(port, int) else None,
                proto=str(proto) if proto is not None else None,
                plugin_id=str(plugin_id) if plugin_id is not None else None
            )
            # Sort ley: score descending, then fid
            rows.append((score, fid, ref))

        rows.sort(key=lambda x: (-x[0], x[1]))

        output: List[RankedFindingRef] = []
        for i, (_, _, ref) in enumerate(rows[:max_findings], start=1):
            output.append(_replace_rank(ref, i))
        return tuple(output)

    def _rank_findings_parallel(
        self,
        *,
        ctx: "RunContext",
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        rank_basis: str,
    ) -> Dict[str, Tuple[RankedFindingRef, ...]]:
        """
        Use process pool to rank findings for all assets in parallel.
        Provides significant speedup for large workloads (20k+ findings).
        """
        cpu_total = os.cpu_count() or 1
        worker_cap = self.process_workers if self.process_workers is not None else cpu_total
        num_workers = max(1, min(worker_cap, cpu_total))
        
        # Prepare serializable scoring data
        scoring_data: Dict[str, Dict[str, Any]] = {}
        data = getattr(scoring, "data", None)
        if isinstance(data, dict):
            scored = data.get("scored_findings", {})
        else:
            scored = getattr(data, "scored_findings", {})
        
        if isinstance(scored, dict):
            for fid, rec in scored.items():
                scoring_data[fid] = {
                    "raw_score": rec.get("raw_score", 0.0),
                    "operational_score": rec.get("operational_score", 0.0),
                    "risk_band": rec.get("risk_band", "unknown"),
                    "reason": rec.get("reason", ""),
                }
        
        # Prepare finding attributes (port, proto, plugin_id)
        finding_attrs: Dict[str, Dict[str, Any]] = {}
        for asset in scan.assets:
            for f in asset.findings:
                finding_attrs[f.finding_id] = {
                    "port": getattr(f, "affected_port", None),
                    "proto": getattr(f, "protocol", None),
                    "plugin_id": getattr(f, "vuln_id", None),
                }

        # Prepare work chunks: [(asset_id, rank_basis, [fid, ...]), ...]
        work_items: List[Tuple[str, str, List[str]]] = []
        for asset_id, fids in asset_to_findings.items():
            work_items.append((asset_id, rank_basis, fids))
        
        # Split into chunks for workers
        chunk_size = max(1, len(work_items) // num_workers)
        chunks = [
            work_items[i:i + chunk_size]
            for i in range(0, len(work_items), chunk_size)
        ]
        
        findings_by_asset_ranked: Dict[str, Tuple[RankedFindingRef, ...]] = {}
        
        try:
            with cf.ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = {
                    executor.submit(
                        _rank_findings_chunk_worker,
                        chunk,
                        scoring_data,
                        finding_attrs,
                        self.cfg.topn.max_findings_per_asset,
                    ): index
                    for index, chunk in enumerate(chunks)
                }
                
                for future in cf.as_completed(futures):
                    chunk_results = future.result()
                    
                    for asset_id, ranked_dicts in chunk_results.items():
                        # Convert dicts back to RankedFindingRef objects
                        ranked_refs = []
                        for d in ranked_dicts:
                            ref = RankedFindingRef(
                                finding_id=d["finding_id"],
                                asset_id=d["asset_id"],
                                rank=d["rank"],
                                score_basis=d["score_basis"],
                                score=d["score"],
                                risk_band=d["risk_band"],
                                reasons=d["reasons"],
                                port=d["port"],
                                proto=d["proto"],
                                plugin_id=d["plugin_id"],
                            )
                            ranked_refs.append(ref)
                        findings_by_asset_ranked[asset_id] = tuple(ranked_refs)
            
            return findings_by_asset_ranked
            
        except Exception as exc:  # pylint: disable=broad-exception-caught
            ctx.logger.warning(
                f"[pass:topn] process pool unavailable, falling back to sequential | reason={exc}",
                extra={"vp_label": "TopNPass"},
            )
            # Fallback to sequential
            findings_by_asset_ranked = {}
            for asset_id, fids in asset_to_findings.items():
                ranked = self._rank_findings_for_asset(
                    scan=scan,
                    scoring=scoring,
                    asset_id=asset_id,
                    finding_ids=fids,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.max_findings_per_asset,
                )
                findings_by_asset_ranked[asset_id] = ranked
            return findings_by_asset_ranked

    def _rank_assets(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        inference_by_asset: Dict[str, ExposureInference],
        rank_basis: str,
        ctx: Optional["RunContext"] = None,
    ) -> List[RankedAssetRef]:
        decay = self.cfg.topn.decay
        k = self.cfg.topn.k

        rows: List[Tuple[float, int, int, int, str, RankedAssetRef]] = []


        for asset_id, fids, in asset_to_findings.items():
            scores: List[float] = []
            crit_high = 0
            scorable_count = 0

            for fid in fids:
                rec = self._get_finding_score_record(scoring, fid)
                if rec is None:
                    continue

                raw = float(rec.get("raw_score", 0.0))
                op = float(rec.get ("operational_score", raw))
                score = raw if rank_basis == "raw" else op
                scores.append(score)
                scorable_count += 1

                band = str(rec.get("risk_band", "unknown")).lower()
                if band in ("critical", "high"):
                    crit_high += 1

            obs = self._collect_asset_observation(scan, asset_id, finding_ids=fids, ctx=ctx)
            crit_label = (obs.criticality or "").strip().lower() if obs else ""
            crit_rank = {"extreme": 4, "high": 3, "medium": 2, "low": 1}.get(crit_label, 0)

            scores.sort(reverse=True)
            top_scores = tuple(scores[:k])
            # weighted aggregatio
            asset_score = 0.0
            for i, s in enumerate(top_scores):
                asset_score += s * decay[i]

            ref = RankedAssetRef(
                asset_id=asset_id,
                rank=0,
                score_basis=rank_basis,
                score=asset_score,
                top_scores=top_scores,
                scored_findings=scorable_count,
                inference=inference_by_asset.get(asset_id)
            )

            # tie-break: asset_score desc, band count desc, scorable count desc, asset id asc
            rows.append((asset_score, crit_high, crit_rank, scorable_count, asset_id, ref))

        rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], x[4]))

        output: List[RankedAssetRef] = []
        for i, (_, _, _, _, _, ref) in enumerate(rows, start=1):
            output.append(_replace_rank(ref, i))
        return output


    def _rank_global_findings(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        rank_basis: str,
        ctx: Optional["RunContext"] = None,
        max_findings: int,
    ) -> Tuple[RankedFindingRef, ...]:

        rows: List[Tuple[float, str, str, RankedFindingRef]] = []


        for asset_id, fids in asset_to_findings.items():
            for fid in fids:
                rec = self._get_finding_score_record(scoring, fid)
                if rec is None:
                    continue

                raw = float(rec.get("raw_score", 0.0))
                op = float(rec.get("operational_score", raw))
                score = raw if rank_basis == "raw" else op
                band = str(rec.get("risk_band", "unknown"))
                reasons = tuple(rec.get("reason", ()).strip().split(";"))

                f = self._get_finding_by_id(scan, fid, ctx)
                port = getattr(f, "affected_port", None) if f else None
                proto = getattr(f, "protocol", None) if f else None
                plugin_id = getattr(f, "vuln_id", None) if f else None

                ref = RankedFindingRef(
                    finding_id=fid,
                    asset_id=asset_id,
                    rank=0,
                    score_basis=rank_basis,
                    score=score,
                    risk_band=band,
                    reasons=reasons,
                    port=port if isinstance(port, int) else None,
                    proto=str(proto) if proto is not None else None,
                    plugin_id=str(plugin_id) if plugin_id is not None else None,
                )

                rows.append((score, asset_id, fid, ref))

        rows.sort(key=lambda x: (-x[0], x[1], x[2]))

        output: List[RankedFindingRef] = []
        for i, (_, _, _, ref) in enumerate(rows[:max_findings], start=1):
            output.append(_replace_rank(ref, i))
        return tuple(output)

    # -------------------------------------------
    # Inference execution
    # -------------------------------------------

    def _infer_exposure(self, obs: AssetObservation) -> ExposureInference:
        score = 0
        evidence: List[str] = []
        hit_tags = set()

        ip = (obs.ip or "").strip()
        hostname = (obs.hostname or "").strip().lower()
        criticality = (obs.criticality or "").strip().lower()
        ports_set = set(obs.open_ports)

        for rule in self.cfg.inference.rules:
            if not rule.enabled:
                continue
            if self._predicate_matches(rule.predicate, ip, hostname, criticality, ports_set):
                score += rule.weight
                hit_tags.add(rule.tag)
                ev = rule.evidence.strip() if rule.evidence else f"{rule.rule_id} ({rule.weight:+d})"
                evidence.append(ev)

        confidence = _bucket_confidence(score, self.cfg.inference.confidence_thresholds)

        externally = ("externally_facing" in hit_tags) and (confidence in ("medium", "high"))
        public_ports = "public_service_ports" in hit_tags

        #evidence order
        evidence_sorted = tuple(sorted(evidence))

        return ExposureInference(
            exposure_score=int(score),
            confidence=confidence,
            externally_facing_inferred=externally,
            public_service_ports_inferred=public_ports,
            evidence=evidence_sorted
        )

    def _predicate_matches(self, pred: ParsedPredicate, ip: str, hostname: str, criticality: str, ports_set: set[int]) -> bool:
        name = pred.name

        if name == "ip_is_public":
            return _is_public_ip(ip)
        if name == "ip_is_private":
            return _is_private_ip(ip)
        if name == "any_port_in_public_list":
            return any(p in self.cfg.inference.public_service_ports_set for p in ports_set)
        if name == "port_in":
            return any(p in ports_set for p in pred.ports)
        if name == "hostname_contains_any":
            return any(tok in hostname for tok in pred.tokens)
        if name == "criticality_is":
            return criticality in pred.tokens

        return False


# -------------------------------------------
# Small Helpers
# -------------------------------------------

def _replace_rank(obj: Dict, rank: int) -> Any:
    d = obj.__dict__.copy()
    d["rank"] = rank
    return obj.__class__(**d)

def _bucket_confidence(score: int, thresholds: "ConfidenceThreshold") -> str:
    if score >= thresholds.high:
        return "high"
    if score >= thresholds.medium:
        return "medium"
    return "low"
