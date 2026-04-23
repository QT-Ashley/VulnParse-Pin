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


def _coerce_score_trace(rec: Dict[str, Any]) -> Dict[str, Any]:
    trace = rec.get("score_trace", {}) if isinstance(rec, dict) else {}
    return trace if isinstance(trace, dict) else {}


def _score_trace_priority_signals(rec: Dict[str, Any]) -> Tuple[int, int, int]:
    trace = _coerce_score_trace(rec)
    contributors = trace.get("contributors")
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

    union_flags = trace.get("union_flags")
    if not isinstance(union_flags, dict):
        union_flags = {}

    if exploitable_cve_count == 0 and bool(union_flags.get("exploit", False)):
        exploitable_cve_count = 1
    if kev_cve_count == 0 and bool(union_flags.get("kev", False)):
        kev_cve_count = 1

    return exploitable_cve_count, kev_cve_count, cve_count_int


def _split_reason_text(reason_value: Any) -> Tuple[str, ...]:
    reason_text = str(reason_value or "").strip()
    if not reason_text:
        return tuple()
    return tuple(part.strip() for part in reason_text.split(";") if part.strip())


def _normalize_text_blob(text: str) -> str:
    return "".join(ch if ch.isalnum() else " " for ch in text.lower())


def _count_finding_text_token_hits(tokens: Tuple[str, ...], normalized_blob: str, blob_terms: set[str]) -> int:
    padded_blob = f" {normalized_blob} "
    hits = 0
    for tok in tokens:
        token = str(tok or "").strip().lower()
        if not token:
            continue
        if " " in token:
            if f" {token} " in padded_blob:
                hits += 1
        elif token in blob_terms:
            hits += 1
    return hits


def _count_conflict_token_hits(tokens: Tuple[str, ...], normalized_blob: str, blob_terms: set[str]) -> int:
    if not tokens:
        return 0
    padded_blob = f" {normalized_blob} "
    hits = 0
    for tok in tokens:
        token = str(tok or "").strip().lower()
        if not token:
            continue
        if " " in token:
            if f" {token} " in padded_blob:
                hits += 1
        elif token in blob_terms:
            hits += 1
    return hits


# -------------------------------------------
# TopN Pass
# -------------------------------------------

class TopNPass(Pass):
    name = "TopN"
    version: str = "1.0"
    requires_passes: tuple[str, ...] = ("Scoring@2.0", "ACI@1.0")

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
                    reason_text="TopN skipped because Scoring@2.0 output was missing.",
                    factor_refs=["dependency:Scoring@2.0"],
                    evidence={"status": "skipped", "missing_dependency": "Scoring@2.0"},
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
                "message": "Scoring@2.0 output not found; TopN ranking not executed.",
                "missing": ["Scoring@2.0"],
            }

            meta = PassMeta(
                name=self.name,
                version=self.version,
                created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                notes="TopN soft no-op due to missing Scoring pass output.",
            )
            return DerivedPassResult(meta=meta, data=data)

        aci = self._get_aci_output(scan)
        if aci is None:
            ctx.logger.error("Missing ACI output; cannot rank.", extra={"vp_label": "TopNPass"})
            services = getattr(ctx, "services", None)
            ledger = getattr(services, "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="TopN",
                    event_type="decision",
                    subject_ref="topn:summary",
                    reason_code=DecisionReasonCodes.TOPN_SKIPPED_MISSING_ACI,
                    reason_text="TopN skipped because ACI@1.0 output was missing.",
                    factor_refs=["dependency:ACI@1.0"],
                    evidence={"status": "skipped", "missing_dependency": "ACI@1.0"},
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
                "message": "ACI@1.0 output not found; TopN ranking not executed.",
                "missing": ["ACI@1.0"],
            }

            meta = PassMeta(
                name=self.name,
                version=self.version,
                created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                notes="TopN soft no-op due to missing ACI pass output.",
            )
            return DerivedPassResult(meta=meta, data=data)

        # 1 Build lookup index
        nmap_ctx_cfg = getattr(getattr(ctx, "services", None), "nmap_ctx_config", None) or {}
        nmap_open_ports_by_asset: Dict[str, set] = {}
        if nmap_ctx_cfg.get("port_tiebreak_enabled", True):
            nmap_open_ports_by_asset = self._get_nmap_open_ports_by_asset(scan)
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
                aci=aci,
                asset_to_findings=asset_to_findings,
                rank_basis=rank_basis,
                nmap_open_ports_by_asset=nmap_open_ports_by_asset,
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
                    aci=aci,
                    asset_id=asset_id,
                    finding_ids=fids,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.max_findings_per_asset,
                    nmap_confirmed_ports=nmap_open_ports_by_asset.get(asset_id, set()),
                )
                findings_by_asset_ranked[asset_id] = ranked

            # 4 Rank assets via Top-K (K=len(decay))
            ranked_assets = self._rank_assets(
                scan=scan,
                scoring=scoring,
                aci=aci,
                asset_to_findings=asset_to_findings,
                inference_by_asset=inference_by_asset,
                rank_basis=rank_basis,
                ctx=ctx,
                nmap_open_ports_by_asset=nmap_open_ports_by_asset,
            )

            # trim to max_assets
            ranked_assets = ranked_assets[: self.cfg.topn.max_assets]

            # 5 Optional global top findings
            global_top: Tuple[RankedFindingRef, ...] = ()
            if self.cfg.topn.include_global_top_findings:
                global_top = self._rank_global_findings(
                    scan=scan,
                    scoring=scoring,
                    aci=aci,
                    asset_to_findings=asset_to_findings,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.global_top_findings,
                    nmap_open_ports_by_asset=nmap_open_ports_by_asset,
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
        aci: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        rank_basis: str,
        nmap_open_ports_by_asset: Optional[Dict[str, set]] = None,
    ) -> Tuple[
        Dict[str, ExposureInference],
        Dict[str, Tuple[RankedFindingRef, ...]],
        List[RankedAssetRef],
        Tuple[RankedFindingRef, ...],
    ]:
        nmap_open_ports_by_asset = nmap_open_ports_by_asset or {}

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
                    "score_trace": rec.get("score_trace", {}),
                }

        aci_finding_data: Dict[str, Dict[str, Any]] = {}
        aci_asset_data: Dict[str, Dict[str, Any]] = {}
        aci_data = getattr(aci, "data", None)
        if isinstance(aci_data, dict):
            raw_findings = aci_data.get("finding_semantics", {})
            raw_assets = aci_data.get("asset_semantics", {})
            if isinstance(raw_findings, dict):
                for fid, rec in raw_findings.items():
                    if isinstance(rec, dict):
                        aci_finding_data[fid] = rec
            if isinstance(raw_assets, dict):
                for aid, rec in raw_assets.items():
                    if isinstance(rec, dict):
                        aci_asset_data[aid] = rec

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
                    "finding_text_blob": obs.finding_text_blob,
                    "finding_title_blob": obs.finding_title_blob,
                    "finding_description_blob": obs.finding_description_blob,
                    "finding_plugin_output_blob": obs.finding_plugin_output_blob,
                }
        else:
            for asset in scan.assets:
                aid = getattr(asset, "asset_id", None)
                ip_addr = getattr(asset, "ip_address", None)
                hostname = getattr(asset, "hostname", None)
                crit = getattr(asset, "criticality", None)
                open_ports: set[int] = set()
                title_parts: List[str] = []
                description_parts: List[str] = []
                plugin_output_parts: List[str] = []
                for finding in asset.findings:
                    if aid is None:
                        aid = getattr(finding, "asset_id", None)
                    port = getattr(finding, "affected_port", None)
                    if isinstance(port, int):
                        open_ports.add(port)
                    if getattr(finding, "title", None):
                        title_parts.append(str(getattr(finding, "title")))
                    if getattr(finding, "description", None):
                        description_parts.append(str(getattr(finding, "description")))
                    if getattr(finding, "plugin_output", None):
                        plugin_output_parts.append(str(getattr(finding, "plugin_output")))
                if aid is not None:
                    title_blob = " ".join(title_parts).lower()
                    description_blob = " ".join(description_parts).lower()
                    plugin_output_blob = " ".join(plugin_output_parts).lower()
                    asset_obs_by_id[aid] = {
                        "asset_id": aid,
                        "ip": ip_addr,
                        "hostname": hostname,
                        "criticality": crit,
                        "open_ports": tuple(sorted(open_ports)),
                        "finding_text_blob": " ".join((title_blob, description_blob, plugin_output_blob)).strip(),
                        "finding_title_blob": title_blob,
                        "finding_description_blob": description_blob,
                        "finding_plugin_output_blob": plugin_output_blob,
                    }

        inference_cfg = {
            "thresholds": {
                "medium": int(self.cfg.inference.confidence_thresholds.medium),
                "high": int(self.cfg.inference.confidence_thresholds.high),
            },
            "public_service_ports": tuple(int(p) for p in self.cfg.inference.public_service_ports_set),
            "finding_text_min_token_matches": int(self.cfg.inference.finding_text_min_token_matches),
            "finding_text_title_weight": int(self.cfg.inference.finding_text_title_weight),
            "finding_text_description_weight": int(self.cfg.inference.finding_text_description_weight),
            "finding_text_plugin_output_weight": int(self.cfg.inference.finding_text_plugin_output_weight),
            "finding_text_max_weighted_hits": int(self.cfg.inference.finding_text_max_weighted_hits),
            "finding_text_conflict_tokens": tuple(self.cfg.inference.finding_text_conflict_tokens),
            "finding_text_conflict_penalty": int(self.cfg.inference.finding_text_conflict_penalty),
            "finding_text_diminishing_factors": tuple(float(x) for x in self.cfg.inference.finding_text_diminishing_factors),
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
        asset_rows: List[Tuple[float, float, int, int, int, int, int, int, str, Tuple[float, ...]]] = []
        global_candidates: List[Tuple[float, float, str, str, int, int, int, int, Dict[str, Any]]] = []

        try:
            with cf.ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = {
                    executor.submit(
                        _topn_asset_chunk_worker,
                        chunk,
                        scoring_data,
                        finding_attrs,
                        aci_finding_data,
                        aci_asset_data,
                        bool(self.cfg.aci.enabled),
                        float(self.cfg.aci.min_confidence),
                        float(self.cfg.aci.max_uplift),
                        float(self.cfg.aci.asset_uplift_weight),
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
                            evidence_rule_ids=tuple(inf.get("evidence_rule_ids", ())),
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
                    aci=aci,
                    asset_id=asset_id,
                    finding_ids=fids,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.max_findings_per_asset,
                    nmap_confirmed_ports=nmap_open_ports_by_asset.get(asset_id, set()),
                )

            ranked_assets = self._rank_assets(
                scan=scan,
                scoring=scoring,
                aci=aci,
                asset_to_findings=asset_to_findings,
                inference_by_asset=inference_by_asset,
                rank_basis=rank_basis,
                ctx=ctx,
                nmap_open_ports_by_asset=nmap_open_ports_by_asset,
            )
            ranked_assets = ranked_assets[: self.cfg.topn.max_assets]

            global_top: Tuple[RankedFindingRef, ...] = ()
            if self.cfg.topn.include_global_top_findings:
                global_top = self._rank_global_findings(
                    scan=scan,
                    scoring=scoring,
                    aci=aci,
                    asset_to_findings=asset_to_findings,
                    rank_basis=rank_basis,
                    ctx=ctx,
                    max_findings=self.cfg.topn.global_top_findings,
                    nmap_open_ports_by_asset=nmap_open_ports_by_asset,
                )
            return inference_by_asset, findings_by_asset_ranked, ranked_assets, global_top

        asset_rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], -x[4], -x[5], -x[6], -x[7], x[8]))
        ranked_assets: List[RankedAssetRef] = []
        for i, (
            asset_score,
            _aci_asset_uplift,
            _crit_high,
            _exploitable_findings,
            _kev_findings,
            _cve_breadth,
            _crit_rank,
            scorable_count,
            asset_id,
            top_scores,
        ) in enumerate(
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
            global_candidates.sort(key=lambda x: (-x[0], -x[1], -x[4], -x[5], -x[6], -x[7], x[2], x[3]))
            selected = global_candidates[: self.cfg.topn.global_top_findings]
            refs: List[RankedFindingRef] = []
            for i, (_, _, _, _, _, _, _, _, d) in enumerate(selected, start=1):
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

    def _get_nmap_open_ports_by_asset(self, scan: "ScanResult") -> Dict[str, set]:
        """Load Nmap adapter open-port data keyed by asset_id. Returns {} if unavailable."""
        try:
            result = scan.derived.passes.get("nmap_adapter@1.0")
            if result is None:
                return {}
            data = getattr(result, "data", None)
            if not isinstance(data, dict) or data.get("status") != "enabled":
                return {}
            raw = data.get("asset_open_ports", {})
            if not isinstance(raw, dict):
                return {}
            return {aid: set(ports) for aid, ports in raw.items()}
        except (AttributeError, TypeError, KeyError):
            return {}

    def _get_scoring_output(self, scan: "ScanResult") -> DerivedPassResult | None:
        try:
            return scan.derived.passes["Scoring@2.0"]
        except (AttributeError, TypeError, KeyError):
            return None

    def _get_aci_output(self, scan: "ScanResult") -> DerivedPassResult | None:
        try:
            return scan.derived.passes["ACI@1.0"]
        except (AttributeError, TypeError, KeyError):
            return None

    def _get_finding_aci_record(self, aci: "DerivedPassResult", finding_id: str) -> Optional[Dict[str, Any]]:
        data = getattr(aci, "data", None)
        if not isinstance(data, dict):
            return None
        findings = data.get("finding_semantics", {})
        if not isinstance(findings, dict):
            return None
        rec = findings.get(finding_id)
        return rec if isinstance(rec, dict) else None

    def _get_asset_aci_record(self, aci: "DerivedPassResult", asset_id: str) -> Optional[Dict[str, Any]]:
        data = getattr(aci, "data", None)
        if not isinstance(data, dict):
            return None
        assets = data.get("asset_semantics", {})
        if not isinstance(assets, dict):
            return None
        rec = assets.get(asset_id)
        return rec if isinstance(rec, dict) else None

    def _compute_finding_aci_uplift(self, aci_rec: Optional[Dict[str, Any]]) -> float:
        if not self.cfg.aci.enabled or not isinstance(aci_rec, dict):
            return 0.0
        try:
            confidence = float(aci_rec.get("confidence", 0.0))
            uplift = float(aci_rec.get("rank_uplift", 0.0))
        except (TypeError, ValueError):
            return 0.0
        if confidence < float(self.cfg.aci.min_confidence):
            return 0.0
        return max(0.0, min(float(self.cfg.aci.max_uplift), uplift))

    def _compute_asset_aci_uplift(self, aci_rec: Optional[Dict[str, Any]]) -> float:
        if not self.cfg.aci.enabled or not isinstance(aci_rec, dict):
            return 0.0
        try:
            uplift = float(aci_rec.get("rank_uplift", 0.0))
        except (TypeError, ValueError):
            return 0.0
        weighted = uplift * float(self.cfg.aci.asset_uplift_weight)
        return max(0.0, min(float(self.cfg.aci.max_uplift), weighted))

    def _build_aci_reason_text(self, aci_rec: Optional[Dict[str, Any]], uplift: float) -> Optional[str]:
        if uplift <= 0.0 or not isinstance(aci_rec, dict):
            return None
        capabilities = aci_rec.get("capabilities", [])
        if not isinstance(capabilities, (list, tuple)):
            capabilities = []
        conf = aci_rec.get("confidence", 0.0)
        caps_preview = ",".join(str(c) for c in capabilities[:3]) if capabilities else "unspecified"
        return f"ACI Uplift (+{uplift:.2f}) conf={float(conf):.2f} caps={caps_preview}"

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
                    finding_text_blob=obs.finding_text_blob,
                    finding_title_blob=obs.finding_title_blob,
                    finding_description_blob=obs.finding_description_blob,
                    finding_plugin_output_blob=obs.finding_plugin_output_blob,
                )

        ip = getattr(asset, "ip_address", None) if asset else None
        hostname = getattr(asset, "hostname", None) if asset else None

        # Gather open ports
        ports: List[int] = []
        finding_text_parts: List[str] = []
        title_parts: List[str] = []
        description_parts: List[str] = []
        plugin_output_parts: List[str] = []
        for fid in finding_ids:
            f = self._get_finding_by_id(scan, fid, ctx)
            if not f:
                continue
            p = getattr(f, "affected_port", None)
            if isinstance(p, int):
                ports.append(p)
            for text_value in (
                getattr(f, "title", None),
                getattr(f, "description", None),
                getattr(f, "plugin_output", None),
            ):
                if text_value:
                    finding_text_parts.append(str(text_value))
            if getattr(f, "title", None):
                title_parts.append(str(getattr(f, "title")))
            if getattr(f, "description", None):
                description_parts.append(str(getattr(f, "description")))
            if getattr(f, "plugin_output", None):
                plugin_output_parts.append(str(getattr(f, "plugin_output")))

        ports = sorted(set(ports))
        crit = current_criticality
        return AssetObservation(
            asset_id=asset_id,
            ip=ip,
            hostname=hostname,
            criticality=crit,
            open_ports=tuple(ports),
            finding_text_blob=" ".join(finding_text_parts).lower(),
            finding_title_blob=" ".join(title_parts).lower(),
            finding_description_blob=" ".join(description_parts).lower(),
            finding_plugin_output_blob=" ".join(plugin_output_parts).lower(),
        )

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
        aci: "DerivedPassResult",
        asset_id: str,
        finding_ids: List[str],
        rank_basis: str,
        ctx: Optional["RunContext"] = None,
        max_findings: int = 0,
        nmap_confirmed_ports: set = frozenset(),
    ) -> tuple[RankedFindingRef, ...]:

        rows: List[Tuple[float, float, int, int, int, int, str, RankedFindingRef]] = []


        for fid in finding_ids:
            rec = self._get_finding_score_record(scoring, fid)
            if rec is None:
                continue

            raw = float(rec.get("raw_score", 0.0))
            op = float(rec.get("operational_score", raw))
            score = raw if rank_basis == "raw" else op

            band = str(rec.get("risk_band", "unknown"))
            reasons = _split_reason_text(rec.get("reason", ""))
            exploit_count, kev_count, cve_count = _score_trace_priority_signals(rec)
            aci_rec = self._get_finding_aci_record(aci, fid)
            aci_uplift = self._compute_finding_aci_uplift(aci_rec)
            aci_reason = self._build_aci_reason_text(aci_rec, aci_uplift)
            if aci_reason:
                reasons = tuple(list(reasons) + [aci_reason])

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
            # Sort key: score, combined-CVE exploit/KEV breadth, nmap confirmation, then stable ID.
            nmap_hit = 1 if isinstance(port, int) and port in nmap_confirmed_ports else 0
            rows.append((score, aci_uplift, exploit_count, kev_count, cve_count, nmap_hit, fid, ref))

        rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], -x[4], -x[5], x[6]))

        output: List[RankedFindingRef] = []
        for i, (_, _, _, _, _, _, _, ref) in enumerate(rows[:max_findings], start=1):
            output.append(_replace_rank(ref, i))
        return tuple(output)

    def _rank_findings_parallel(
        self,
        *,
        ctx: "RunContext",
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        aci: "DerivedPassResult",
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
                    "score_trace": rec.get("score_trace", {}),
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
                    aci=aci,
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
        aci: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        inference_by_asset: Dict[str, ExposureInference],
        rank_basis: str,
        ctx: Optional["RunContext"] = None,
        nmap_open_ports_by_asset: Optional[Dict[str, set]] = None,
    ) -> List[RankedAssetRef]:
        nmap_open_ports_by_asset = nmap_open_ports_by_asset or {}
        decay = self.cfg.topn.decay
        k = self.cfg.topn.k

        rows: List[Tuple[float, float, int, int, int, int, int, int, int, str, RankedAssetRef]] = []


        for asset_id, fids, in asset_to_findings.items():
            scores: List[float] = []
            crit_high = 0
            scorable_count = 0
            exploitable_findings = 0
            kev_findings = 0
            cve_breadth = 0

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

                exploit_count, kev_count, cve_count = _score_trace_priority_signals(rec)
                if exploit_count > 0:
                    exploitable_findings += 1
                if kev_count > 0:
                    kev_findings += 1
                cve_breadth += cve_count

            obs = self._collect_asset_observation(scan, asset_id, finding_ids=fids, ctx=ctx)
            crit_label = (obs.criticality or "").strip().lower() if obs else ""
            crit_rank = {"extreme": 4, "high": 3, "medium": 2, "low": 1}.get(crit_label, 0)
            aci_asset_rec = self._get_asset_aci_record(aci, asset_id)
            aci_asset_uplift = self._compute_asset_aci_uplift(aci_asset_rec)

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

            # tie-break: score desc, high/critical count, combined-CVE exploit/KEV breadth,
            # criticality rank, scored count, nmap confirmation, then asset ID asc.
            nmap_confirmed = 1 if nmap_open_ports_by_asset.get(asset_id) else 0
            rows.append(
                (
                    asset_score,
                    aci_asset_uplift,
                    crit_high,
                    exploitable_findings,
                    kev_findings,
                    cve_breadth,
                    crit_rank,
                    scorable_count,
                    nmap_confirmed,
                    asset_id,
                    ref,
                )
            )

        rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], -x[4], -x[5], -x[6], -x[7], -x[8], x[9]))

        output: List[RankedAssetRef] = []
        for i, (_, _, _, _, _, _, _, _, _, _, ref) in enumerate(rows, start=1):
            output.append(_replace_rank(ref, i))
        return output


    def _rank_global_findings(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        aci: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        rank_basis: str,
        ctx: Optional["RunContext"] = None,
        max_findings: int = 0,
        nmap_open_ports_by_asset: Optional[Dict[str, set]] = None,
    ) -> Tuple[RankedFindingRef, ...]:
        nmap_open_ports_by_asset = nmap_open_ports_by_asset or {}

        rows: List[Tuple[float, float, int, int, int, int, str, str, RankedFindingRef]] = []


        for asset_id, fids in asset_to_findings.items():
            for fid in fids:
                rec = self._get_finding_score_record(scoring, fid)
                if rec is None:
                    continue

                raw = float(rec.get("raw_score", 0.0))
                op = float(rec.get("operational_score", raw))
                score = raw if rank_basis == "raw" else op
                band = str(rec.get("risk_band", "unknown"))
                reasons = _split_reason_text(rec.get("reason", ""))
                exploit_count, kev_count, cve_count = _score_trace_priority_signals(rec)
                aci_rec = self._get_finding_aci_record(aci, fid)
                aci_uplift = self._compute_finding_aci_uplift(aci_rec)
                aci_reason = self._build_aci_reason_text(aci_rec, aci_uplift)
                if aci_reason:
                    reasons = tuple(list(reasons) + [aci_reason])

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

                nmap_ports = nmap_open_ports_by_asset.get(asset_id, set())
                nmap_hit = 1 if isinstance(port, int) and port in nmap_ports else 0
                rows.append((score, aci_uplift, exploit_count, kev_count, cve_count, nmap_hit, asset_id, fid, ref))

            rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], -x[4], -x[5], x[6], x[7]))

        output: List[RankedFindingRef] = []
        for i, (_, _, _, _, _, _, _, _, ref) in enumerate(rows[:max_findings], start=1):
            output.append(_replace_rank(ref, i))
        return tuple(output)

    # -------------------------------------------
    # Inference execution
    # -------------------------------------------

    def _infer_exposure(self, obs: AssetObservation) -> ExposureInference:
        score = 0
        evidence: List[str] = []
        evidence_rule_ids: List[str] = []
        hit_tags = set()

        ip = (obs.ip or "").strip()
        hostname = (obs.hostname or "").strip().lower()
        criticality = (obs.criticality or "").strip().lower()
        ports_set = set(obs.open_ports)
        finding_text_blob = str(obs.finding_text_blob or "").strip().lower()
        finding_title_blob = str(obs.finding_title_blob or "").strip().lower()
        finding_description_blob = str(obs.finding_description_blob or "").strip().lower()
        finding_plugin_output_blob = str(obs.finding_plugin_output_blob or "").strip().lower()
        normalized_text_blob = _normalize_text_blob(finding_text_blob)
        normalized_title_blob = _normalize_text_blob(finding_title_blob)
        normalized_description_blob = _normalize_text_blob(finding_description_blob)
        normalized_plugin_output_blob = _normalize_text_blob(finding_plugin_output_blob)
        text_terms = set(normalized_text_blob.split())
        title_terms = set(normalized_title_blob.split())
        description_terms = set(normalized_description_blob.split())
        plugin_output_terms = set(normalized_plugin_output_blob.split())

        for rule in self.cfg.inference.rules:
            if not rule.enabled:
                continue
            if rule.predicate.name == "finding_text_contains_any":
                matched, weighted_delta, trace = self._evaluate_finding_text_rule(
                    pred=rule.predicate,
                    normalized_text_blob=normalized_text_blob,
                    text_terms=text_terms,
                    normalized_title_blob=normalized_title_blob,
                    title_terms=title_terms,
                    normalized_description_blob=normalized_description_blob,
                    description_terms=description_terms,
                    normalized_plugin_output_blob=normalized_plugin_output_blob,
                    plugin_output_terms=plugin_output_terms,
                    base_weight=rule.weight,
                )
                if not matched:
                    continue
                score += weighted_delta
                hit_tags.add(rule.tag)
                evidence_rule_ids.append(rule.rule_id)
                ev_base = rule.evidence.strip() if rule.evidence else f"{rule.rule_id} ({weighted_delta:+d})"
                evidence.append(f"{ev_base} [{trace}]")
                continue
            if self._predicate_matches(
                rule.predicate,
                ip,
                hostname,
                criticality,
                ports_set,
                finding_text_blob,
                normalized_text_blob,
                text_terms,
            ):
                score += rule.weight
                hit_tags.add(rule.tag)
                evidence_rule_ids.append(rule.rule_id)
                ev = rule.evidence.strip() if rule.evidence else f"{rule.rule_id} ({rule.weight:+d})"
                evidence.append(ev)

        confidence = _bucket_confidence(score, self.cfg.inference.confidence_thresholds)

        externally = ("externally_facing" in hit_tags) and (confidence in ("medium", "high"))
        public_ports = "public_service_ports" in hit_tags

        #evidence order
        evidence_sorted = tuple(sorted(evidence))
        evidence_rule_ids_sorted = tuple(sorted(set(evidence_rule_ids)))

        return ExposureInference(
            exposure_score=int(score),
            confidence=confidence,
            externally_facing_inferred=externally,
            public_service_ports_inferred=public_ports,
            evidence=evidence_sorted,
            evidence_rule_ids=evidence_rule_ids_sorted,
        )

    def _evaluate_finding_text_rule(
        self,
        *,
        pred: ParsedPredicate,
        normalized_text_blob: str,
        text_terms: set[str],
        normalized_title_blob: str,
        title_terms: set[str],
        normalized_description_blob: str,
        description_terms: set[str],
        normalized_plugin_output_blob: str,
        plugin_output_terms: set[str],
        base_weight: int,
    ) -> Tuple[bool, int, str]:
        title_hits = _count_finding_text_token_hits(pred.tokens, normalized_title_blob, title_terms)
        description_hits = _count_finding_text_token_hits(pred.tokens, normalized_description_blob, description_terms)
        plugin_output_hits = _count_finding_text_token_hits(pred.tokens, normalized_plugin_output_blob, plugin_output_terms)
        total_hits = _count_finding_text_token_hits(pred.tokens, normalized_text_blob, text_terms)

        min_hits = int(self.cfg.inference.finding_text_min_token_matches)
        if total_hits < min_hits:
            return False, 0, f"token_hits={total_hits}, min_required={min_hits}"

        weighted_hits = (
            title_hits * int(self.cfg.inference.finding_text_title_weight)
            + description_hits * int(self.cfg.inference.finding_text_description_weight)
            + plugin_output_hits * int(self.cfg.inference.finding_text_plugin_output_weight)
        )
        weighted_hits = max(0, weighted_hits)

        max_weighted_hits = max(1, int(self.cfg.inference.finding_text_max_weighted_hits))
        factors = tuple(self.cfg.inference.finding_text_diminishing_factors) or (1.0,)

        effective_weighted = 0.0
        for idx in range(weighted_hits):
            factor = float(factors[min(idx, len(factors) - 1)])
            effective_weighted += max(0.0, factor)
            if effective_weighted >= float(max_weighted_hits):
                effective_weighted = float(max_weighted_hits)
                break

        scaled_weight = int(round(float(base_weight) * (effective_weighted / float(max_weighted_hits))))
        if scaled_weight <= 0 and total_hits >= min_hits:
            scaled_weight = 1

        conflict_tokens = tuple(self.cfg.inference.finding_text_conflict_tokens)
        conflict_hits = _count_conflict_token_hits(conflict_tokens, normalized_text_blob, text_terms)
        conflict_penalty = min(
            scaled_weight,
            int(self.cfg.inference.finding_text_conflict_penalty) * conflict_hits,
        )
        final_weight = scaled_weight - conflict_penalty

        trace = (
            f"token_hits={total_hits}, source_hits=title:{title_hits}|description:{description_hits}|plugin_output:{plugin_output_hits}, "
            f"weighted_hits={weighted_hits}, effective_weighted={effective_weighted:.2f}, conflict_hits={conflict_hits}, "
            f"applied_weight={final_weight:+d}"
        )
        return True, final_weight, trace

    def _predicate_matches(
        self,
        pred: ParsedPredicate,
        ip: str,
        hostname: str,
        criticality: str,
        ports_set: set[int],
        finding_text_blob: str,
        normalized_text_blob: str,
        text_terms: set[str],
    ) -> bool:
        _ = finding_text_blob
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
        if name == "finding_text_contains_any":
            min_hits = int(self.cfg.inference.finding_text_min_token_matches)
            return _count_finding_text_token_hits(pred.tokens, normalized_text_blob, text_terms) >= min_hits
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
