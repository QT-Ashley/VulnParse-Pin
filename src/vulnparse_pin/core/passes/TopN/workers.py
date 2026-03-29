from __future__ import annotations

import heapq
import ipaddress
from typing import Any, Dict, List, Tuple


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def _rank_findings_chunk_worker(
    chunk: List[Tuple[str, str, List[str]]],
    scoring_data: Dict[str, Dict[str, Any]],
    finding_attrs: Dict[str, Dict[str, Any]],
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

        rows.sort(key=lambda x: (-x[0], x[1]))

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
    criticality: str,
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
    if pred_name == "criticality_is":
        return criticality in pred_tokens
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
    criticality = str(obs.get("criticality") or "").strip().lower()
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
            criticality,
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
    out_assets: List[Tuple[float, int, int, int, str, Tuple[float, ...]]] = []
    global_heap: List[Tuple[float, str, str, int, Dict[str, Any]]] = []
    entry_counter = 0

    for asset_id, finding_ids in chunk:
        obs = asset_obs_by_id.get(asset_id, {"asset_id": asset_id, "ip": None, "hostname": None, "open_ports": ()})
        out_inference[asset_id] = _infer_exposure_worker(obs, inference_cfg)
        crit_label = str(obs.get("criticality") or "").strip().lower()
        crit_rank = {"extreme": 4, "high": 3, "medium": 2, "low": 1}.get(crit_label, 0)

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

        out_assets.append((asset_score, crit_high, crit_rank, scorable_count, asset_id, top_scores))

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
