from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
from concurrent.futures import ProcessPoolExecutor, as_completed
import ipaddress
import os
import heapq

from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, PassMeta
from vulnparse_pin.core.passes.types import (
    ExposureInference,
    RankedAssetRef,
    RankedFindingRef,
    TopNPassOutput
)
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import TNTriageConfig, ParsedPredicate

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.passes.types import ScoredFinding
    from vulnparse_pin.core.passes.TopN.TN_triage_semantics import ConfidenceThreshold

# -------------------------------------------
# Process-safe worker functions for parallel execution
# -------------------------------------------

def _rank_findings_chunk_worker(
    chunk: List[Tuple[str, str, List[str]]],  # [(asset_id, rank_basis, [fid, fid, ...]), ...]
    scoring_data: Dict[str, Dict[str, Any]],  # {finding_id: {raw_score, operational_score, risk_band, reason}}
    finding_attrs: Dict[str, Dict[str, Any]],  # {finding_id: {port, proto, plugin_id}}
    max_findings: int,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Process worker: rank findings for a chunk of assets.
    Returns: {asset_id: [ranked_finding_dict, ...]}
    """
    results: Dict[str, List[Dict[str, Any]]] = {}
    
    for asset_id, rank_basis, finding_ids in chunk:
        rows: List[Tuple[float, str, Dict[str, Any]]] = []
        
        for fid in finding_ids:
            rec = scoring_data.get(fid)
            if rec is None:
                continue
                
            raw = float(rec.get("raw_score", 0.0))
            op = float(rec.get("operational_score", raw))
            score = raw if rank_basis == "raw" else op
            
            band = str(rec.get("risk_band", "unknown"))
            reasons = tuple(rec.get("reason", "").strip().split(";"))
            
            attrs = finding_attrs.get(fid, {})
            port = attrs.get("port")
            proto = attrs.get("proto")
            plugin_id = attrs.get("plugin_id")
            
            ref_dict = {
                "finding_id": fid,
                "asset_id": asset_id,
                "rank": 0,
                "score_basis": rank_basis,
                "score": score,
                "risk_band": band,
                "reasons": reasons,
                "port": port if isinstance(port, int) else None,
                "proto": str(proto) if proto is not None else None,
                "plugin_id": str(plugin_id) if plugin_id is not None else None,
            }
            
            rows.append((score, fid, ref_dict))
        
        # Sort by score descending, then by finding_id
        rows.sort(key=lambda x: (-x[0], x[1]))
        
        # Assign ranks and take top N
        ranked = []
        for i, (_, _, ref_dict) in enumerate(rows[:max_findings], start=1):
            ref_dict["rank"] = i
            ranked.append(ref_dict)
        
        results[asset_id] = ranked
    
    return results


def _bucket_confidence_worker(score: int, thresholds: Dict[str, int]) -> str:
    if score >= int(thresholds["high"]):
        return "high"
    if score >= int(thresholds["medium"]):
        return "medium"
    return "low"


def _predicate_matches_worker(
    pred_name: str,
    pred_ports: Tuple[int, ...],
    pred_tokens: Tuple[str, ...],
    ip: str,
    hostname: str,
    ports_set: set[int],
    public_service_ports_set: set[int],
) -> bool:
    if pred_name == "ip_is_public":
        return _is_public_ip(ip)
    if pred_name == "ip_is_private":
        return _is_private_ip(ip)
    if pred_name == "any_port_in_public_list":
        return any(p in public_service_ports_set for p in ports_set)
    if pred_name == "port_in":
        return any(p in ports_set for p in pred_ports)
    if pred_name == "hostname_contains_any":
        return any(tok in hostname for tok in pred_tokens)
    return False


def _infer_exposure_worker(
    obs: Dict[str, Any],
    inference_cfg: Dict[str, Any],
) -> Dict[str, Any]:
    score = 0
    evidence: List[str] = []
    hit_tags = set()

    ip = (obs.get("ip") or "").strip()
    hostname = (obs.get("hostname") or "").strip().lower()
    ports_set = set(obs.get("open_ports", ()))

    for rule in inference_cfg["rules"]:
        if not rule["enabled"]:
            continue
        if _predicate_matches_worker(
            rule["predicate_name"],
            tuple(rule["predicate_ports"]),
            tuple(rule["predicate_tokens"]),
            ip,
            hostname,
            ports_set,
            set(inference_cfg["public_service_ports"]),
        ):
            score += int(rule["weight"])
            hit_tags.add(rule["tag"])
            ev = rule["evidence"].strip() if rule["evidence"] else f"{rule['rule_id']} ({int(rule['weight']):+d})"
            evidence.append(ev)

    confidence = _bucket_confidence_worker(score, inference_cfg["thresholds"])
    externally = ("externally_facing" in hit_tags) and (confidence in ("medium", "high"))
    public_ports = "public_service_ports" in hit_tags

    return {
        "exposure_score": int(score),
        "confidence": confidence,
        "externally_facing_inferred": externally,
        "public_service_ports_inferred": public_ports,
        "evidence": tuple(sorted(evidence)),
    }


def _topn_asset_chunk_worker(
    chunk: List[Tuple[str, List[str]]],
    scoring_data: Dict[str, Dict[str, Any]],
    finding_attrs: Dict[str, Dict[str, Any]],
    asset_obs_by_id: Dict[str, Dict[str, Any]],
    inference_cfg: Dict[str, Any],
    rank_basis: str,
    max_findings_per_asset: int,
    k: int,
    decay: Tuple[float, ...],
    include_global_top: bool,
    global_top_max: int,
) -> Dict[str, Any]:
    out_inference: Dict[str, Dict[str, Any]] = {}
    out_findings: Dict[str, List[Dict[str, Any]]] = {}
    out_assets: List[Tuple[float, int, int, str, Tuple[float, ...]]] = []
    global_heap: List[Tuple[float, str, str, int, Dict[str, Any]]] = []
    entry_counter = 0  # Unique counter for heap tie-breaking

    for asset_id, finding_ids in chunk:
        obs = asset_obs_by_id.get(asset_id, {"asset_id": asset_id, "ip": None, "hostname": None, "open_ports": ()})
        out_inference[asset_id] = _infer_exposure_worker(obs, inference_cfg)

        rows: List[Tuple[float, str, Dict[str, Any]]] = []
        asset_scores: List[float] = []
        crit_high = 0
        scorable_count = 0

        for fid in finding_ids:
            rec = scoring_data.get(fid)
            if rec is None:
                continue

            raw = float(rec.get("raw_score", 0.0))
            op = float(rec.get("operational_score", raw))
            score = raw if rank_basis == "raw" else op
            band = str(rec.get("risk_band", "unknown"))
            reason_text = rec.get("reason", "")
            reasons = tuple(str(reason_text).strip().split(";")) if str(reason_text).strip() else tuple()

            attrs = finding_attrs.get(fid, {})
            port = attrs.get("port")
            proto = attrs.get("proto")
            plugin_id = attrs.get("plugin_id")

            ref_dict = {
                "finding_id": fid,
                "asset_id": asset_id,
                "rank": 0,
                "score_basis": rank_basis,
                "score": score,
                "risk_band": band,
                "reasons": reasons,
                "port": port if isinstance(port, int) else None,
                "proto": str(proto) if proto is not None else None,
                "plugin_id": str(plugin_id) if plugin_id is not None else None,
            }

            rows.append((score, fid, ref_dict))
            asset_scores.append(score)
            scorable_count += 1
            if band.lower() in ("critical", "high"):
                crit_high += 1

            if include_global_top:
                key = (score, asset_id, fid)
                if len(global_heap) < global_top_max:
                    heapq.heappush(global_heap, (key[0], key[1], key[2], entry_counter, ref_dict))
                    entry_counter += 1
                else:
                    min_key = (global_heap[0][0], global_heap[0][1], global_heap[0][2])
                    if key > min_key:
                        heapq.heapreplace(global_heap, (key[0], key[1], key[2], entry_counter, ref_dict))
                        entry_counter += 1

        rows.sort(key=lambda x: (-x[0], x[1]))
        ranked_findings: List[Dict[str, Any]] = []
        for i, (_, _, ref_dict) in enumerate(rows[:max_findings_per_asset], start=1):
            ref_dict["rank"] = i
            ranked_findings.append(ref_dict)
        out_findings[asset_id] = ranked_findings

        asset_scores.sort(reverse=True)
        top_scores = tuple(asset_scores[:k])
        asset_score = 0.0
        for i, value in enumerate(top_scores):
            if i < len(decay):
                asset_score += float(value) * float(decay[i])

        out_assets.append((asset_score, crit_high, scorable_count, asset_id, top_scores))

    global_candidates = [
        (score, asset_id, fid, ref_dict)
        for score, asset_id, fid, _, ref_dict in global_heap
    ]

    return {
        "inference": out_inference,
        "findings": out_findings,
        "assets": out_assets,
        "global_candidates": global_candidates,
    }

# -------------------------------------------
# Observation View
# -------------------------------------------

@dataclass(frozen=True)
class AssetObservation:
    asset_id: str
    ip: Optional[str]
    hostname: Optional[str]
    open_ports: Tuple[int, ...]


# -------------------------------------------
# TopN Pass
# -------------------------------------------

class TopNPass:
    name = "TopN"
    version: str = "1.0"

    def __init__(
        self, 
        triage_cfg: TNTriageConfig,
        process_pool_threshold: int = 20_000,
        process_workers: Optional[int] = None,
    ) -> None:
        self.cfg = triage_cfg
        self.process_pool_threshold = max(1, int(process_pool_threshold))
        self.process_workers = process_workers

    def run(self, ctx: "RunContext", scan: "ScanResult") -> "ScanResult":
        """
        Consumes scan result to include previous derived passes data.
        Produces:
         - topn derived key = TopNPassOutput
        """
        # 0 retrieve Scoring pass output for scoring results
        scoring = self._get_scoring_output(scan)                    # Returns Scoring Pass DerivedPassResult
        if scoring is None:
            ctx.logger.error("Missing scoring output; cannot rank.", extra={"vp_label": "TopNPass"})
            return scan

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
            for asset_id, _ in asset_to_findings.items(): #TODO: VERIFY
                obs = self._collect_asset_observation(scan, asset_id, finding_ids=asset_to_findings[asset_id])
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

        for asset in scan.assets:
            aid = None
            ip_addr = getattr(asset, "ip_address", None)
            hostname = getattr(asset, "hostname", None)
            open_ports: set[int] = set()
            for finding in asset.findings:
                if aid is None:
                    aid = getattr(finding, "asset_id", None)
                fid = finding.finding_id
                port = getattr(finding, "affected_port", None)
                if isinstance(port, int):
                    open_ports.add(port)
                finding_attrs[fid] = {
                    "port": port,
                    "proto": getattr(finding, "protocol", None),
                    "plugin_id": getattr(finding, "vuln_id", None),
                }
            if aid is not None:
                asset_obs_by_id[aid] = {
                    "asset_id": aid,
                    "ip": ip_addr,
                    "hostname": hostname,
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
        asset_rows: List[Tuple[float, int, int, str, Tuple[float, ...]]] = []
        global_candidates: List[Tuple[float, str, str, Dict[str, Any]]] = []

        try:
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
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

                for future in as_completed(futures):
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

        except Exception as exc:
            ctx.logger.warning(
                "[pass:topn] process pool unavailable, falling back to sequential | reason=%s",
                exc,
                extra={"vp_label": "TopNPass"},
            )
            inference_by_asset = {}
            for asset_id, _ in asset_to_findings.items():
                obs = self._collect_asset_observation(scan, asset_id, finding_ids=asset_to_findings[asset_id])
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
                    max_findings=self.cfg.topn.max_findings_per_asset,
                )

            ranked_assets = self._rank_assets(
                scan=scan,
                scoring=scoring,
                asset_to_findings=asset_to_findings,
                inference_by_asset=inference_by_asset,
                rank_basis=rank_basis,
            )
            ranked_assets = ranked_assets[: self.cfg.topn.max_assets]

            global_top: Tuple[RankedFindingRef, ...] = ()
            if self.cfg.topn.include_global_top_findings:
                global_top = self._rank_global_findings(
                    scan=scan,
                    scoring=scoring,
                    asset_to_findings=asset_to_findings,
                    rank_basis=rank_basis,
                    max_findings=self.cfg.topn.global_top_findings,
                )
            return inference_by_asset, findings_by_asset_ranked, ranked_assets, global_top

        asset_rows.sort(key=lambda x: (-x[0], -x[1], -x[2], x[3]))
        ranked_assets: List[RankedAssetRef] = []
        for i, (asset_score, _crit_high, scorable_count, asset_id, top_scores) in enumerate(
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
        except Exception:
            return None

    def _index_findings_by_asset(self, scan: "ScanResult") -> dict[str, List[str]]:
        maps: Dict[str, List[str]] = {}
        for asset in scan.assets:
            for finding in asset.findings:
                maps.setdefault(finding.asset_id, []).append(finding.finding_id)

        for aid, _ in maps.items(): # TODO:VERIFY
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

    def _collect_asset_observation(self, scan: "ScanResult", asset_id: str, *, finding_ids: List[str]) -> Optional[AssetObservation]:
        """
        Collect ip, hostname, and observed open ports for the given asset_id.
        """
        asset = None
        for a in scan.assets:
            for f in a.findings:
                if f.asset_id:
                    asset = a
                    break

        ip = getattr(asset, "ip", None) if asset else None
        hostname = getattr(asset, "hostname", None) if asset else None

        # Gather open ports
        ports: List[int] = []
        for fid in finding_ids:
            f = self._get_finding_by_id(scan, fid)
            if not f:
                continue
            p = getattr(f, "affected_port", None)
            if isinstance(p, int):
                ports.append(p)

        ports = sorted(set(ports))
        return AssetObservation(asset_id=asset_id, ip=ip, hostname=hostname, open_ports=tuple(ports))

    def _get_finding_by_id(self, scan: "ScanResult", finding_id: str) -> Optional[Any]:
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

            f = self._get_finding_by_id(scan, fid)
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
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
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
                
                for future in as_completed(futures):
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
            
        except Exception as exc:
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
    ) -> List[RankedAssetRef]:
        decay = self.cfg.topn.decay
        k = self.cfg.topn.k

        rows: List[Tuple[float, int, int, str, RankedAssetRef]] = []


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
            rows.append((asset_score, crit_high, scorable_count, asset_id, ref))

        rows.sort(key=lambda x: (-x[0], -x[1], -x[2], x[3]))

        output: List[RankedAssetRef] = []
        for i, (_, _, _, _, ref) in enumerate(rows, start=1):
            output.append(_replace_rank(ref, i))
        return output


    def _rank_global_findings(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        rank_basis: str,
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

                f = self._get_finding_by_id(scan, fid)
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
        ports_set = set(obs.open_ports)

        for rule in self.cfg.inference.rules:
            if not rule.enabled:
                continue
            if self._predicate_matches(rule.predicate, ip, hostname, ports_set):
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

    def _predicate_matches(self, pred: ParsedPredicate, ip: str, hostname: str, ports_set: set[int]) -> bool:
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

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except Exception:
        return False

def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except Exception:
        return False
