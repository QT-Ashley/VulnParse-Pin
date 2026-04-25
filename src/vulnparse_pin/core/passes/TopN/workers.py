from __future__ import annotations

import heapq
import ipaddress
from typing import Any, Dict, List, Tuple


def _score_trace_priority_signals(rec: Dict[str, Any]) -> Tuple[int, int, int]:
    trace = rec.get("score_trace", {}) if isinstance(rec, dict) else {}
    if not isinstance(trace, dict):
        trace = {}

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
        rows: List[Tuple[float, int, int, int, str, Dict[str, Any]]] = []

        for fid in finding_ids:
            rec = scoring_data.get(fid)
            if rec is None:
                continue

            raw = float(rec.get("raw_score", 0.0))
            op = float(rec.get("operational_score", raw))
            score = raw if rank_basis == "raw" else op

            band = str(rec.get("risk_band", "unknown"))
            reasons = _split_reason_text(rec.get("reason", ""))
            exploit_count, kev_count, cve_count = _score_trace_priority_signals(rec)

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

            rows.append((score, exploit_count, kev_count, cve_count, fid, ref_dict))

        rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], x[4]))

        ranked = []
        for i, (_, _, _, _, _, ref_dict) in enumerate(rows[:max_findings], start=1):
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


def _normalize_text_blob_worker(text: str) -> str:
    return "".join(ch if ch.isalnum() else " " for ch in text.lower())


def _count_finding_text_token_hits_worker(
    pred_tokens: Tuple[str, ...],
    normalized_blob: str,
    blob_terms: set[str],
) -> int:
    padded_blob = f" {normalized_blob} "
    hits = 0
    for tok in pred_tokens:
        token = str(tok or "").strip().lower()
        if not token:
            continue
        if " " in token:
            if f" {token} " in padded_blob:
                hits += 1
        elif token in blob_terms:
            hits += 1
    return hits


def _count_conflict_token_hits_worker(
    conflict_tokens: Tuple[str, ...],
    normalized_blob: str,
    blob_terms: set[str],
) -> int:
    if not conflict_tokens:
        return 0
    padded_blob = f" {normalized_blob} "
    hits = 0
    for tok in conflict_tokens:
        token = str(tok or "").strip().lower()
        if not token:
            continue
        if " " in token:
            if f" {token} " in padded_blob:
                hits += 1
        elif token in blob_terms:
            hits += 1
    return hits


def _predicate_matches_worker(
    pred_name: str,
    pred_ports: Tuple[int, ...],
    pred_tokens: Tuple[str, ...],
    ip: str,
    hostname: str,
    criticality: str,
    ports_set: set[int],
    public_service_ports_set: set[int],
    finding_text_blob: str,
    normalized_text_blob: str,
    text_terms: set[str],
    finding_text_min_token_matches: int,
) -> bool:
    _ = finding_text_blob
    if pred_name == "ip_is_public":
        return _is_public_ip(ip)
    if pred_name == "ip_is_private":
        return _is_private_ip(ip)
    if pred_name == "ip_is_private_no_public_ports":
        return _is_private_ip(ip) and not any(p in public_service_ports_set for p in ports_set)
    if pred_name == "any_port_in_public_list":
        return any(p in public_service_ports_set for p in ports_set)
    if pred_name == "port_in":
        return any(p in ports_set for p in pred_ports)
    if pred_name == "hostname_contains_any":
        return any(tok in hostname for tok in pred_tokens)
    if pred_name == "finding_text_contains_any":
        return (
            _count_finding_text_token_hits_worker(pred_tokens, normalized_text_blob, text_terms)
            >= int(finding_text_min_token_matches)
        )
    if pred_name == "criticality_is":
        return criticality in pred_tokens
    return False


def _evaluate_finding_text_rule_worker(
    *,
    pred_tokens: Tuple[str, ...],
    normalized_text_blob: str,
    text_terms: set[str],
    normalized_title_blob: str,
    title_terms: set[str],
    normalized_description_blob: str,
    description_terms: set[str],
    normalized_plugin_output_blob: str,
    plugin_output_terms: set[str],
    min_token_matches: int,
    title_weight: int,
    description_weight: int,
    plugin_output_weight: int,
    max_weighted_hits: int,
    diminishing_factors: Tuple[float, ...],
    conflict_tokens: Tuple[str, ...],
    conflict_penalty: int,
    base_weight: int,
) -> Tuple[bool, int, str]:
    title_hits = _count_finding_text_token_hits_worker(pred_tokens, normalized_title_blob, title_terms)
    description_hits = _count_finding_text_token_hits_worker(pred_tokens, normalized_description_blob, description_terms)
    plugin_output_hits = _count_finding_text_token_hits_worker(pred_tokens, normalized_plugin_output_blob, plugin_output_terms)
    total_hits = _count_finding_text_token_hits_worker(pred_tokens, normalized_text_blob, text_terms)

    if total_hits < int(min_token_matches):
        return False, 0, f"token_hits={total_hits}, min_required={int(min_token_matches)}"

    weighted_hits = (
        title_hits * int(title_weight)
        + description_hits * int(description_weight)
        + plugin_output_hits * int(plugin_output_weight)
    )
    weighted_hits = max(0, weighted_hits)

    bounded_max_hits = max(1, int(max_weighted_hits))
    factors = tuple(diminishing_factors) or (1.0,)

    effective_weighted = 0.0
    for idx in range(weighted_hits):
        factor = float(factors[min(idx, len(factors) - 1)])
        effective_weighted += max(0.0, factor)
        if effective_weighted >= float(bounded_max_hits):
            effective_weighted = float(bounded_max_hits)
            break

    scaled_weight = int(round(float(base_weight) * (effective_weighted / float(bounded_max_hits))))
    if scaled_weight <= 0 and total_hits >= int(min_token_matches):
        scaled_weight = 1

    conflict_hits = _count_conflict_token_hits_worker(conflict_tokens, normalized_text_blob, text_terms)
    penalty = min(scaled_weight, int(conflict_penalty) * conflict_hits)
    final_weight = scaled_weight - penalty

    trace = (
        f"token_hits={total_hits}, source_hits=title:{title_hits}|description:{description_hits}|plugin_output:{plugin_output_hits}, "
        f"weighted_hits={weighted_hits}, effective_weighted={effective_weighted:.2f}, conflict_hits={conflict_hits}, "
        f"applied_weight={final_weight:+d}"
    )
    return True, final_weight, trace


def _infer_exposure_worker(
    obs: Dict[str, Any],
    inference_cfg: Dict[str, Any],
) -> Dict[str, Any]:
    score = 0
    evidence: List[str] = []
    evidence_rule_ids: List[str] = []
    hit_tags = set()

    ip = (obs.get("ip") or "").strip()
    hostname = (obs.get("hostname") or "").strip().lower()
    criticality = str(obs.get("criticality") or "").strip().lower()
    ports_set = set(obs.get("open_ports", ()))
    finding_text_blob = str(obs.get("finding_text_blob") or "").strip().lower()
    finding_title_blob = str(obs.get("finding_title_blob") or "").strip().lower()
    finding_description_blob = str(obs.get("finding_description_blob") or "").strip().lower()
    finding_plugin_output_blob = str(obs.get("finding_plugin_output_blob") or "").strip().lower()
    normalized_text_blob = _normalize_text_blob_worker(finding_text_blob)
    normalized_title_blob = _normalize_text_blob_worker(finding_title_blob)
    normalized_description_blob = _normalize_text_blob_worker(finding_description_blob)
    normalized_plugin_output_blob = _normalize_text_blob_worker(finding_plugin_output_blob)
    text_terms = set(normalized_text_blob.split())
    title_terms = set(normalized_title_blob.split())
    description_terms = set(normalized_description_blob.split())
    plugin_output_terms = set(normalized_plugin_output_blob.split())

    for rule in inference_cfg["rules"]:
        if not rule["enabled"]:
            continue
        if rule["predicate_name"] == "finding_text_contains_any":
            matched, weighted_delta, trace = _evaluate_finding_text_rule_worker(
                pred_tokens=tuple(rule["predicate_tokens"]),
                normalized_text_blob=normalized_text_blob,
                text_terms=text_terms,
                normalized_title_blob=normalized_title_blob,
                title_terms=title_terms,
                normalized_description_blob=normalized_description_blob,
                description_terms=description_terms,
                normalized_plugin_output_blob=normalized_plugin_output_blob,
                plugin_output_terms=plugin_output_terms,
                min_token_matches=int(inference_cfg.get("finding_text_min_token_matches", 2)),
                title_weight=int(inference_cfg.get("finding_text_title_weight", 3)),
                description_weight=int(inference_cfg.get("finding_text_description_weight", 2)),
                plugin_output_weight=int(inference_cfg.get("finding_text_plugin_output_weight", 1)),
                max_weighted_hits=int(inference_cfg.get("finding_text_max_weighted_hits", 4)),
                diminishing_factors=tuple(inference_cfg.get("finding_text_diminishing_factors", (1.0, 0.6, 0.4))),
                conflict_tokens=tuple(inference_cfg.get("finding_text_conflict_tokens", ())),
                conflict_penalty=int(inference_cfg.get("finding_text_conflict_penalty", 2)),
                base_weight=int(rule["weight"]),
            )
            if not matched:
                continue
            score += int(weighted_delta)
            hit_tags.add(rule["tag"])
            evidence_rule_ids.append(str(rule["rule_id"]))
            ev = rule["evidence"].strip() if rule["evidence"] else f"{rule['rule_id']} ({int(weighted_delta):+d})"
            evidence.append(f"{ev} [{trace}]")
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
            finding_text_blob,
            normalized_text_blob,
            text_terms,
            int(inference_cfg.get("finding_text_min_token_matches", 2)),
        ):
            score += int(rule["weight"])
            hit_tags.add(rule["tag"])
            evidence_rule_ids.append(str(rule["rule_id"]))
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
        "evidence_rule_ids": tuple(sorted(set(evidence_rule_ids))),
    }


def _topn_asset_chunk_worker(
    chunk: List[Tuple[str, List[str]]],
    scoring_data: Dict[str, Dict[str, Any]],
    finding_attrs: Dict[str, Dict[str, Any]],
    aci_finding_data: Dict[str, Dict[str, Any]],
    aci_asset_data: Dict[str, Dict[str, Any]],
    aci_enabled: bool,
    aci_min_confidence: float,
    aci_max_uplift: float,
    aci_asset_uplift_weight: float,
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
    out_assets: List[Tuple[float, float, int, int, int, int, int, int, str, Tuple[float, ...]]] = []
    global_heap: List[Tuple[float, float, str, str, int, int, int, int, Dict[str, Any]]] = []
    entry_counter = 0

    for asset_id, finding_ids in chunk:
        obs = asset_obs_by_id.get(asset_id, {"asset_id": asset_id, "ip": None, "hostname": None, "open_ports": ()})
        out_inference[asset_id] = _infer_exposure_worker(obs, inference_cfg)
        crit_label = str(obs.get("criticality") or "").strip().lower()
        crit_rank = {"extreme": 4, "high": 3, "medium": 2, "low": 1}.get(crit_label, 0)

        rows: List[Tuple[float, float, int, int, int, str, Dict[str, Any]]] = []
        asset_scores: List[float] = []
        crit_high = 0
        scorable_count = 0
        exploitable_findings = 0
        kev_findings = 0
        cve_breadth = 0

        for fid in finding_ids:
            rec = scoring_data.get(fid)
            if rec is None:
                continue

            raw = float(rec.get("raw_score", 0.0))
            op = float(rec.get("operational_score", raw))
            score = raw if rank_basis == "raw" else op
            band = str(rec.get("risk_band", "unknown"))
            reasons = _split_reason_text(rec.get("reason", ""))
            exploit_count, kev_count, cve_count = _score_trace_priority_signals(rec)

            aci_uplift = 0.0
            aci_rec = aci_finding_data.get(fid)
            if aci_enabled and isinstance(aci_rec, dict):
                try:
                    confidence = float(aci_rec.get("confidence", 0.0))
                    uplift = float(aci_rec.get("rank_uplift", 0.0))
                except (TypeError, ValueError):
                    confidence = 0.0
                    uplift = 0.0
                if confidence >= float(aci_min_confidence):
                    aci_uplift = max(0.0, min(float(aci_max_uplift), uplift))

            if aci_uplift > 0.0 and isinstance(aci_rec, dict):
                capabilities = aci_rec.get("capabilities", [])
                if not isinstance(capabilities, (list, tuple)):
                    capabilities = []
                conf = float(aci_rec.get("confidence", 0.0) or 0.0)
                caps_preview = ",".join(str(c) for c in capabilities[:3]) if capabilities else "unspecified"
                reasons = tuple(reasons) + (f"ACI Uplift (+{aci_uplift:.2f}) conf={conf:.2f} caps={caps_preview}",)

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

            rows.append((score, aci_uplift, exploit_count, kev_count, cve_count, fid, ref_dict))
            asset_scores.append(score)
            scorable_count += 1
            if band.lower() in ("critical", "high"):
                crit_high += 1
            if exploit_count > 0:
                exploitable_findings += 1
            if kev_count > 0:
                kev_findings += 1
            cve_breadth += cve_count

            if include_global_top:
                key = (score, aci_uplift, exploit_count, kev_count, cve_count, asset_id, fid)
                if len(global_heap) < global_top_max:
                    heapq.heappush(global_heap, (key[0], key[1], key[5], key[6], key[2], key[3], key[4], entry_counter, ref_dict))
                    entry_counter += 1
                else:
                    min_key = (
                        global_heap[0][0],
                        global_heap[0][1],
                        global_heap[0][4],
                        global_heap[0][5],
                        global_heap[0][6],
                        global_heap[0][2],
                        global_heap[0][3],
                    )
                    if key > min_key:
                        heapq.heapreplace(global_heap, (key[0], key[1], key[5], key[6], key[2], key[3], key[4], entry_counter, ref_dict))
                        entry_counter += 1

        rows.sort(key=lambda x: (-x[0], -x[1], -x[2], -x[3], -x[4], x[5]))
        ranked_findings: List[Dict[str, Any]] = []
        for i, (_, _, _, _, _, _, ref_dict) in enumerate(rows[:max_findings_per_asset], start=1):
            ref_dict["rank"] = i
            ranked_findings.append(ref_dict)
        out_findings[asset_id] = ranked_findings

        asset_scores.sort(reverse=True)
        top_scores = tuple(asset_scores[:k])
        asset_score = 0.0
        for i, value in enumerate(top_scores):
            if i < len(decay):
                asset_score += float(value) * float(decay[i])

        aci_asset_uplift = 0.0
        aci_asset_rec = aci_asset_data.get(asset_id)
        if aci_enabled and isinstance(aci_asset_rec, dict):
            try:
                aci_asset_uplift = float(aci_asset_rec.get("rank_uplift", 0.0))
            except (TypeError, ValueError):
                aci_asset_uplift = 0.0
            aci_asset_uplift = max(0.0, min(float(aci_max_uplift), aci_asset_uplift * float(aci_asset_uplift_weight)))

        out_assets.append(
            (
                asset_score,
                aci_asset_uplift,
                crit_high,
                exploitable_findings,
                kev_findings,
                cve_breadth,
                crit_rank,
                scorable_count,
                asset_id,
                top_scores,
            )
        )

    global_candidates = [
        (score, aci_uplift, asset_id, fid, exploit_count, kev_count, cve_count, entry_order, ref_dict)
        for score, aci_uplift, asset_id, fid, exploit_count, kev_count, cve_count, entry_order, ref_dict in global_heap
    ]

    return {
        "inference": out_inference,
        "findings": out_findings,
        "assets": out_assets,
        "global_candidates": global_candidates,
    }
