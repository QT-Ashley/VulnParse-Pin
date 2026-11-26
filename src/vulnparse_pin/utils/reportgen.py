# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict, fields, is_dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import textwrap
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import duckdb

from vulnparse_pin.storage.db import (
    _check_no_symlinks_or_loops,
    ensure_safe_dir_non_pfh,
    open_for_write_non_pfh,
)
from vulnparse_pin.utils.cvss_utils import resolve_effective_cvss_fields


_PRESENTATION_MODES = frozenset({"namespace", "namespaced", "flatten", "raw", "default"})


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj):
        return {f.name: getattr(obj, f.name) for f in fields(obj)}
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def _sanitize_json_value(val: Any) -> Any:
    if isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            return None
        return val
    if isinstance(val, dict):
        return {str(k): _sanitize_json_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_sanitize_json_value(x) for x in val]
    if is_dataclass(val):
        return _sanitize_json_value({f.name: getattr(val, f.name) for f in fields(val)})
    if isinstance(val, Path):
        return str(val)
    return val


def _json_loads_safe(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        loaded = json.loads(raw)
        return loaded if loaded is not None else default
    except Exception:
        return default


def _resolve_duckdb_conn(db: Any) -> duckdb.DuckDBPyConnection:
    if isinstance(db, duckdb.DuckDBPyConnection):
        return db
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    raise TypeError(f"Expected VppDatabase or DuckDBPyConnection, got {type(db).__name__}")


def _parse_version_tuple(v: str) -> Tuple[int, ...]:
    """
    Semantic version parser for sorting versions.
    Non-numeric parts ignored.
    """
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def _chosen_scoring_pass_key(derived_passes: Dict[str, Any], preferred_key: Optional[str]) -> Optional[str]:
    """
    Selects scoring pass key.
        - If preferred_key exists, use it.
        - Otherwise, pick the highest version among keys.
    """
    if not derived_passes:
        return None

    if preferred_key and preferred_key in derived_passes:
        return preferred_key

    candidates = []
    for k in derived_passes.keys():
        if k.startswith("Scoring@"):
            _, _, ver = k.partition("@")
            candidates.append((k, _parse_version_tuple(ver)))

    if not candidates:
        return None

    candidates.sort(key=lambda t: t[1], reverse=True)
    return candidates[0][0]


def _ensure_dict(obj: Any) -> Dict[str, Any]:
    """
    Ensure obj is a dictionary suitable for JSON serialization:
      - dataclass -> asdict
      - already dict -> returns
      - Other -> {}
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if is_dataclass(obj):
        return asdict(obj)
    to_dict = getattr(obj, "dict", None)
    if callable(to_dict):
        return to_dict()
    return {}


def _normalize_overlay_mode(overlay_mode: str) -> str:
    mode = str(overlay_mode or "flatten").strip().lower()
    if mode in ("namespace", "namespaced"):
        return "namespace"
    if mode == "flatten":
        return "flatten"
    raise ValueError(f"Unknown overlay_mode={overlay_mode}")


def materialize_presentation(
    scan_result: Any,
    *,
    scoring_pass_key: Optional[str] = None,
    overlay_mode: str = "flatten",  # 'flatten' or 'namespace'/'namespaced'
    include_meta: bool = True,
) -> Dict[str, Any]:
    """
    Produces a JSON-ready presentation object by overlaying derived scoring back onto findings.

    Does NOT mutate ScanResult object.

    overlay_mode:
      - 'flatten': writes scoring fields onto finding root keys (UX-friendly)
      - 'namespace' (alias 'namespaced'): writes scoring data under finding["derived"][scoring_key]
    """
    mode = _normalize_overlay_mode(overlay_mode)
    base = asdict(scan_result) if is_dataclass(scan_result) else _ensure_dict(scan_result)

    assets = base.get("assets") if isinstance(base, dict) else None
    if not isinstance(assets, list):
        return base

    derived = base.get("derived", {}) if isinstance(base, dict) else {}
    derived = _ensure_dict(derived)
    passes = _ensure_dict(derived.get("passes", {}))

    chosen_key = _chosen_scoring_pass_key(passes, scoring_pass_key)
    scoring_pass = _ensure_dict(passes.get(chosen_key)) if chosen_key else {}
    scoring_data = _ensure_dict(scoring_pass.get("data"))
    scored_findings = _ensure_dict(scoring_data.get("scored_findings"))
    scored_asset_criticality = _ensure_dict(scoring_data.get("asset_criticality"))
    scored_asset_band_counts = _ensure_dict(scoring_data.get("asset_band_counts"))

    sf_map: Dict[str, Dict[str, Any]] = {}
    for fid, rec in scored_findings.items():
        if isinstance(fid, str):
            sf_map[fid] = _ensure_dict(rec)

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        aid = asset.get("asset_id")
        if not isinstance(aid, str):
            continue

        asset_crit = scored_asset_criticality.get(aid)
        asset_counts = scored_asset_band_counts.get(aid)

        if mode == "namespace":
            a_derived = asset.get("derived")
            if not isinstance(a_derived, dict):
                a_derived = {}
                asset["derived"] = a_derived
            pass_key = chosen_key or "Scoring@?"
            scoped = a_derived.get(pass_key)
            if not isinstance(scoped, dict):
                scoped = {}
                a_derived[pass_key] = scoped
            if asset_crit is not None:
                scoped["asset_criticality"] = asset_crit
            if isinstance(asset_counts, dict):
                scoped["asset_band_counts"] = asset_counts
        elif mode == "flatten":
            if asset_crit is not None:
                asset["criticality"] = asset_crit
            if isinstance(asset_counts, dict):
                asset["asset_band_counts"] = asset_counts

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        findings = asset.get("findings")
        if not isinstance(findings, list):
            continue

        for f in findings:
            if not isinstance(f, dict):
                continue

            fid = f.get("finding_id")
            if not isinstance(fid, str):
                continue

            sf = sf_map.get(fid)
            if not sf:
                continue

            raw = sf.get("raw_score")
            op = sf.get("operational_score")
            band = sf.get("risk_band")
            reason = sf.get("reason")

            if mode == "namespace":
                f_derived = f.get("derived")
                if not isinstance(f_derived, dict):
                    f_derived = {}
                    f["derived"] = f_derived
                scoped_sf = dict(sf)
                if isinstance(scoped_sf.get("raw_score"), (int, float)):
                    scoped_sf["raw_score"] = round(scoped_sf["raw_score"], 2)
                if isinstance(scoped_sf.get("operational_score"), (int, float)):
                    scoped_sf["operational_score"] = round(scoped_sf["operational_score"], 2)
                f_derived[chosen_key or "Scoring@?"] = scoped_sf
            elif mode == "flatten":
                f["raw_risk_score"] = round(raw, 2) if isinstance(raw, (int, float)) else raw
                f["operational_score"] = round(op, 2) if isinstance(op, (int, float)) else op
                f["risk_score"] = round(op, 2) if isinstance(op, (int, float)) else op
                f["risk_band"] = band
                f["reason"] = reason

    if isinstance(base, dict):
        base.pop("derived", None)

    if include_meta and isinstance(base, dict):
        pres = base.get("presentation")
        if not isinstance(pres, dict):
            pres = {}
            base["presentation"] = pres

        pres["scoring_pass"] = chosen_key
        pres["band_source"] = "raw_score"
        pres["operational_scale"] = "0-10"
        pres["overlay_mode"] = mode
        cov = _ensure_dict(scoring_data.get("coverage"))
        if cov:
            pres["scoring_coverage"] = cov

    return base


def _estimate_value_size(value: Any, sample_size: int = 25, _depth: int = 0) -> int:
    """Estimate serialized JSON byte length without allocating full-payload JSON strings."""
    if value is None or isinstance(value, bool):
        return 5
    if isinstance(value, (int, float)):
        return 12
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="replace")) + 2
    if _depth >= 6:
        return 64

    if isinstance(value, (list, tuple)):
        n = len(value)
        if n == 0:
            return 2
        cap = max(1, min(n, sample_size))
        sample_total = sum(_estimate_value_size(value[i], sample_size=sample_size, _depth=_depth + 1) for i in range(cap))
        return int((sample_total / cap) * n) + n + 2

    if isinstance(value, dict):
        n = len(value)
        if n == 0:
            return 2
        cap = max(1, min(n, sample_size))
        total = 2
        for idx, (k, v) in enumerate(value.items()):
            if idx >= cap:
                return int((total / cap) * n)
            total += len(str(k).encode("utf-8", errors="replace")) + 4
            total += _estimate_value_size(v, sample_size=sample_size, _depth=_depth + 1)
        return total

    if is_dataclass(value):
        return _estimate_value_size(
            {f.name: getattr(value, f.name) for f in fields(value)},
            sample_size=sample_size,
            _depth=_depth + 1,
        )
    return len(str(value).encode("utf-8", errors="replace")) + 2


def _estimate_dict_size(data: Any, sample_size: int = 100) -> int:
    """
    Estimate serialized JSON size in bytes using bounded item sampling.
    Never calls full-payload `json.dumps(data)` in memory.
    """
    if not isinstance(data, (dict, list, tuple)) and not is_dataclass(data):
        return 0
    return _estimate_value_size(data, sample_size=max(1, min(int(sample_size), 100)), _depth=0)


def _stream_json_value(value: Any, file_obj: Any, indent: Optional[int], level: int) -> None:
    if isinstance(value, dict):
        if not value:
            file_obj.write("{}")
            return
        file_obj.write("{")
        first = True
        for k, v in value.items():
            if not first:
                file_obj.write(",")
            first = False
            if indent is not None:
                file_obj.write("\n" + (" " * (indent * (level + 1))))
            file_obj.write(json.dumps(str(k), ensure_ascii=True, allow_nan=False))
            file_obj.write(": " if indent is not None else ":")
            _stream_json_value(v, file_obj, indent, level + 1)
        if indent is not None:
            file_obj.write("\n" + (" " * (indent * level)))
        file_obj.write("}")
        return

    if isinstance(value, (list, tuple)):
        if not value:
            file_obj.write("[]")
            return
        file_obj.write("[")
        first = True
        for item in value:
            if not first:
                file_obj.write(",")
            first = False
            if indent is not None:
                file_obj.write("\n" + (" " * (indent * (level + 1))))
            _stream_json_value(item, file_obj, indent, level + 1)
        if indent is not None:
            file_obj.write("\n" + (" " * (indent * level)))
        file_obj.write("]")
        return

    if is_dataclass(value):
        _stream_json_value({f.name: getattr(value, f.name) for f in fields(value)}, file_obj, indent, level)
        return

    sanitized = _sanitize_json_value(value)
    file_obj.write(json.dumps(sanitized, default=_json_default, ensure_ascii=True, allow_nan=False))


def _stream_json_dump(data: Any, file_obj: Any, indent: Optional[int] = None) -> None:
    """
    Stream JSON output item-by-item (including nested lists such as `assets` and
    `findings`) without loading an entire serialized JSON string into RAM.
    """
    _stream_json_value(data, file_obj, indent, level=0)
    file_obj.write("\n")


def _normalize_duckdb_presentation(presentation: str) -> str:
    mode = str(presentation or "namespace").strip().lower()
    if mode not in _PRESENTATION_MODES:
        raise ValueError(
            f"Unknown presentation '{presentation}'. Expected one of {sorted(_PRESENTATION_MODES)}"
        )
    return "namespace" if mode == "namespaced" else mode


def _build_duckdb_finding_payload(
    rec: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    finding_cves: List[str],
    pres_mode: str,
) -> Dict[str, Any]:
    cves = _json_loads_safe(rec.get("cves_json"), [])
    cwes = _json_loads_safe(rec.get("cwes_json"), [])
    ghsa_ids = _json_loads_safe(rec.get("ghsa_ids_json"), [])
    refs = _json_loads_safe(rec.get("references_json"), [])
    tags = _json_loads_safe(rec.get("tags_json"), [])
    score_trace = _json_loads_safe(rec.get("score_trace_json"), {})
    assumed_state = _json_loads_safe(rec.get("assumed_state_json"), {})
    caps = _json_loads_safe(rec.get("capabilities_json"), [])
    chains = _json_loads_safe(rec.get("chains_json"), [])
    tokens = _json_loads_safe(rec.get("matched_tokens_json"), [])
    exploit_refs = _json_loads_safe(rec.get("exploit_refs_json"), [])
    enr_sources = _json_loads_safe(rec.get("sources_json"), [])

    trace_dict = score_trace if isinstance(score_trace, dict) else {}
    eff_cvss, eff_prov, eff_ver, eff_vec = resolve_effective_cvss_fields(
        snap_cvss=rec["cvss_score"],
        snap_prov=rec["cvss_provenance"],
        snap_ver=rec["cvss_version"],
        snap_vec=rec["cvss_vector"],
        scanner_cvss=rec["scanner_cvss_score"],
        scanner_vec=rec["scanner_cvss_vector"],
        score_trace=trace_dict,
    )
    in_kev_flag = bool(rec["in_kev"] or trace_dict.get("in_kev"))
    kev_added = rec["kev_date_added"] or (trace_dict.get("kev_date_added") if in_kev_flag else None)
    kev_due = rec["kev_due_date"] or (trace_dict.get("kev_due_date") if in_kev_flag else None)
    kev_ransom = rec["kev_ransomware"]
    if in_kev_flag and (kev_ransom is None or kev_ransom == ""):
        kev_ransom = trace_dict.get("kev_ransomware")
    eff_primary_cve = rec["primary_cve"] or trace_dict.get("primary_cve")

    base: Dict[str, Any] = {
        "finding_id": rec["finding_id"],
        "asset_id": rec["asset_id"],
        "scoring_track": rec["scoring_track"],
        "primary_cve": eff_primary_cve,
        "cves": finding_cves or cves,
        "cwes": cwes,
        "ghsa_ids": ghsa_ids,
        "title": rec["title"],
        "description": rec["description"],
        "solution": rec["solution"],
        "plugin_output": rec["plugin_output"],
        "affected_port": rec["affected_port"],
        "protocol": rec["protocol"],
        "service_name": rec["service_name"],
        "location_uri": rec["location_uri"],
        "line_number": rec["line_number"],
        "package_purl": rec["package_purl"],
        "scanner_severity": rec["scanner_severity"],
        "scanner_cvss_score": rec["scanner_cvss_score"],
        "scanner_cvss_vector": rec["scanner_cvss_vector"],
        "detection_mode": rec["detection_mode"],
        "signal_reliability": rec["signal_reliability"],
        "ingestion_confidence": rec["ingestion_confidence"],
        "fidelity_tier": rec["fidelity_tier"],
        "source_format": rec["source_format"],
        "references": refs,
        "tags": tags,
        "exploit_evidence": rec["exploit_evidence"],
        "is_deduplicated": bool(rec["is_deduplicated"]),
        "source_count": int(rec["source_count"] or 1),
        "evidence": evidence,
        "enrichment": {
            "cvss_score": eff_cvss,
            "cvss_vector": eff_vec,
            "cvss_version": eff_ver,
            "cvss_provenance": eff_prov,
            "epss_score": rec["epss_score"],
            "epss_percentile": rec["epss_percentile"],
            "epss_model_version": rec["epss_model_version"],
            "epss_date": rec["epss_date"],
            "in_kev": in_kev_flag,
            "kev_date_added": kev_added,
            "kev_due_date": kev_due,
            "kev_ransomware": kev_ransom,
            "verified_exploit": bool(rec["verified_exploit"]),
            "heuristic_exploit_mention": bool(rec["heuristic_exploit_mention"]),
            "exploit_refs": exploit_refs,
            "sources": enr_sources,
        },
    }

    scoring_overlay = {
        "raw_risk_score": rec["raw_risk_score"],
        "operational_score": rec["operational_score"],
        "risk_band": rec["risk_band"],
        "score_trace": score_trace if isinstance(score_trace, dict) else {},
    }
    triage_overlay = {
        "profile": rec["triage_profile"],
        "priority_tier": rec["priority_tier"],
        "oal_compat": rec["oal_compat"],
        "ssvc_action": rec["ssvc_action"],
        "sla_bucket": rec["sla_bucket"],
        "sla_days": rec["sla_days"],
        "decision_status": rec["decision_status"] or "active",
        "decision_id": rec["decision_id"],
        "assumed_state": assumed_state if isinstance(assumed_state, dict) else {},
        "rationale_summary": rec["rationale_summary"],
    }
    aci_overlay = {
        "capabilities": caps,
        "chains": chains,
        "matched_tokens": tokens,
        "confidence": rec["aci_confidence"],
        "uplift_score": rec["aci_uplift_score"],
    }

    if pres_mode == "namespace":
        base["derived"] = {
            "Scoring@3.0": scoring_overlay,
            "Triage@2.0": triage_overlay,
            "ACI@2.0": aci_overlay,
        }
    elif pres_mode == "flatten":
        base["raw_risk_score"] = rec["raw_risk_score"]
        base["operational_score"] = rec["operational_score"]
        base["risk_score"] = rec["operational_score"]
        base["risk_band"] = rec["risk_band"]
        base["score_trace"] = score_trace if isinstance(score_trace, dict) else {}
        base["priority_tier"] = rec["priority_tier"]
        base["oal_compat"] = rec["oal_compat"]
        base["ssvc_action"] = rec["ssvc_action"]
        base["sla_bucket"] = rec["sla_bucket"]
        base["sla_days"] = rec["sla_days"]
        base["decision_status"] = rec["decision_status"] or "active"
        base["decision_id"] = rec["decision_id"]
        base["rationale_summary"] = rec["rationale_summary"]
        base["aci_capabilities"] = caps
        base["aci_chains"] = chains
        base["aci_confidence"] = rec["aci_confidence"]
        base["aci_uplift_score"] = rec["aci_uplift_score"]

    return _sanitize_json_value(base)


def _write_asset_prefix(
    fh: Any,
    asset_rec: Dict[str, Any],
    aliases: List[Dict[str, str]],
    pres_mode: str,
    *,
    pretty_print: bool = False,
) -> None:
    payload: Dict[str, Any] = {
        "asset_id": asset_rec["asset_id"],
        "canonical_key": asset_rec["canonical_key"],
        "hostname": asset_rec["hostname"],
        "ip_address": asset_rec["ip_address"],
        "target_uri": asset_rec["target_uri"],
        "image_or_repo": asset_rec["image_or_repo"],
        "os": asset_rec["os"],
        "declared_criticality": asset_rec["declared_criticality"],
        "internet_facing": asset_rec["internet_facing"],
        "owner": asset_rec["owner"],
        "env_tags": _json_loads_safe(asset_rec.get("env_tags_json"), {}),
        "inventory_status": asset_rec["inventory_status"],
        "matched_rule_id": asset_rec["matched_rule_id"],
        "open_ports": _json_loads_safe(asset_rec.get("open_ports_json"), []),
        "aliases": aliases,
    }
    if pres_mode == "namespace":
        payload["derived"] = {
            "Scoring@3.0": {
                "asset_criticality": asset_rec["derived_criticality"],
            }
        }
    elif pres_mode == "flatten":
        payload["derived_criticality"] = asset_rec["derived_criticality"]
        payload["criticality"] = asset_rec["derived_criticality"] or asset_rec["declared_criticality"]

    if pretty_print:
        encoded = json.dumps(_sanitize_json_value(payload), ensure_ascii=True, allow_nan=False, indent=4)
        fh.write(textwrap.indent(encoded[:-2] + ',\n    "findings": [', "        "))
    else:
        encoded = json.dumps(_sanitize_json_value(payload), ensure_ascii=True, allow_nan=False)
        # Replace closing brace so we can stream `"findings":[...]` incrementally
        fh.write(encoded[:-1])
        fh.write(',"findings":[')


def export_duckdb_json(
    db: Any,
    run_id: str,
    out_path: Union[str, Path],
    *,
    presentation: str = "namespace",
    pfh: Optional[Any] = None,
    pretty_print: bool = False,
) -> Path:
    """
    Stream asset-by-asset and finding-by-finding from DuckDB into a valid JSON
    file without loading the entire run payload into memory.
    """
    pres_mode = _normalize_duckdb_presentation(presentation)
    conn = _resolve_duckdb_conn(db)
    rid = str(run_id)

    run_cur = conn.execute(
        """
        SELECT run_id, created_at_utc, vpp_version, profile,
               config_sha256, assets_sha256, decisions_sha256,
               intel_metadata_json, manifest_digest, input_files_json, baseline_run_id
        FROM runs
        WHERE run_id = ?
        """,
        [rid],
    )
    run_row = run_cur.fetchone()
    if run_row is None:
        has_assets = conn.execute("SELECT 1 FROM assets WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        has_findings = conn.execute("SELECT 1 FROM findings WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        if has_assets is None and has_findings is None:
            raise ValueError(f"Run '{rid}' does not exist in database.")
        run_meta: Dict[str, Any] = {
            "run_id": rid,
            "created_at_utc": _utc_now_z(),
            "vpp_version": None,
            "profile": "default",
            "intel_metadata": {},
            "input_files": [],
        }
    else:
        r_cols = [d[0] for d in run_cur.description]
        run_meta = dict(zip(r_cols, run_row))
        run_meta["intel_metadata"] = _json_loads_safe(run_meta.pop("intel_metadata_json", None), {})
        run_meta["input_files"] = _json_loads_safe(run_meta.pop("input_files_json", None), [])

    target = Path(out_path)
    if pfh is None:
        _check_no_symlinks_or_loops(target, label="JSON output path")
        ensure_safe_dir_non_pfh(target.parent, label="JSON output parent directory")
        _check_no_symlinks_or_loops(target, label="JSON output path")

    def _stream_to_handle(fh: Any) -> None:
        header_obj = _sanitize_json_value(
            {
                "schema_version": "2.0.0",
                "run_id": rid,
                "generated_at_utc": _utc_now_z(),
                "profile": run_meta.get("profile") or "default",
                "presentation": {
                    "overlay_mode": pres_mode,
                    "operational_scale": "0-10",
                    "streaming": True,
                },
                "run": run_meta,
            }
        )
        header_json = json.dumps(
            header_obj,
            ensure_ascii=True,
            allow_nan=False,
            indent=4 if pretty_print else None,
        )
        if pretty_print:
            fh.write(header_json[:-2] + ',\n    "assets": [')
        else:
            fh.write(header_json[:-1])
            fh.write(',"assets":[')

        asset_cur = conn.cursor()
        finding_cur = conn.cursor()
        first_asset = True
        try:
            asset_cur.execute(
                """
                SELECT asset_id, canonical_key, hostname, ip_address, target_uri,
                       image_or_repo, os, declared_criticality, derived_criticality,
                       internet_facing, owner, env_tags_json, inventory_status,
                       matched_rule_id, open_ports_json
                FROM assets
                WHERE run_id = ?
                ORDER BY asset_id ASC
                """,
                [rid],
            )
            a_cols = [d[0] for d in asset_cur.description]

            while True:
                asset_batch = asset_cur.fetchmany(200)
                if not asset_batch:
                    break

                asset_records = [dict(zip(a_cols, row)) for row in asset_batch]
                asset_ids = [a["asset_id"] for a in asset_records]
                placeholders = ", ".join("?" for _ in asset_ids)

                aliases_by_asset: Dict[str, List[Dict[str, str]]] = {aid: [] for aid in asset_ids}
                for aid, atype, aval in conn.execute(
                    f"""
                    SELECT asset_id, alias_type, alias_value
                    FROM asset_aliases
                    WHERE run_id = ? AND asset_id IN ({placeholders})
                    ORDER BY asset_id ASC, alias_type ASC, alias_value ASC
                    """,
                    [rid, *asset_ids],
                ).fetchall():
                    if aid in aliases_by_asset:
                        aliases_by_asset[aid].append({"alias_type": atype, "alias_value": aval})

                finding_cur.execute(
                    f"""
                    SELECT
                        f.finding_id, f.asset_id, f.scoring_track,
                        COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) AS primary_cve,
                        f.cves_json, f.cwes_json, f.ghsa_ids_json, f.title, f.description,
                        f.solution, f.plugin_output, f.affected_port, f.protocol,
                        f.service_name, f.location_uri, f.line_number, f.package_purl,
                        f.scanner_severity, f.scanner_cvss_score, f.scanner_cvss_vector,
                        f.detection_mode, f.signal_reliability, f.ingestion_confidence,
                        f.fidelity_tier, f.source_format, f.references_json, f.tags_json,
                        f.exploit_evidence, f.is_deduplicated, f.source_count,
                        e.cvss_score, e.cvss_vector, e.cvss_version, e.cvss_provenance,
                        e.epss_score, e.epss_percentile, e.epss_model_version, e.epss_date,
                        (
                            COALESCE(e.in_kev, FALSE)
                            OR COALESCE(fc_agg.fc_in_kev, FALSE)
                            OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                        ) AS in_kev,
                        CASE
                            WHEN (
                                COALESCE(e.in_kev, FALSE)
                                OR COALESCE(fc_agg.fc_in_kev, FALSE)
                                OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                            )
                            THEN COALESCE(
                                CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_date_added AS VARCHAR), '') END,
                                NULLIF(json_extract_string(s.score_trace_json, '$.kev_date_added'), ''),
                                fc_agg.fc_kev_date_added
                            )
                            ELSE e.kev_date_added
                        END AS kev_date_added,
                        CASE
                            WHEN (
                                COALESCE(e.in_kev, FALSE)
                                OR COALESCE(fc_agg.fc_in_kev, FALSE)
                                OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                            )
                            THEN COALESCE(
                                CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_due_date AS VARCHAR), '') END,
                                NULLIF(json_extract_string(s.score_trace_json, '$.kev_due_date'), ''),
                                fc_agg.fc_kev_due_date
                            )
                            ELSE e.kev_due_date
                        END AS kev_due_date,
                        CASE
                            WHEN (
                                COALESCE(e.in_kev, FALSE)
                                OR COALESCE(fc_agg.fc_in_kev, FALSE)
                                OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                            )
                            THEN COALESCE(
                                CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_ransomware AS VARCHAR), '') END,
                                NULLIF(json_extract_string(s.score_trace_json, '$.kev_ransomware'), ''),
                                fc_agg.fc_kev_ransomware
                            )
                            ELSE e.kev_ransomware
                        END AS kev_ransomware,
                        (
                            COALESCE(e.verified_exploit, FALSE)
                            OR COALESCE(fc_agg.fc_verified_exploit, FALSE)
                            OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.verified_exploit') AS BOOLEAN), FALSE)
                        ) AS verified_exploit,
                        (
                            COALESCE(e.heuristic_exploit_mention, FALSE)
                            OR COALESCE(fc_agg.fc_heuristic_exploit, FALSE)
                            OR COALESCE(f.exploit_evidence, FALSE)
                        ) AS heuristic_exploit_mention,
                        e.exploit_refs_json, e.sources_json,
                        s.raw_risk_score, s.operational_score, s.risk_band, s.score_trace_json,
                        td.profile AS triage_profile, td.priority_tier, td.oal_compat,
                        td.ssvc_action, td.sla_bucket, td.sla_days, td.decision_status,
                        td.decision_id, td.assumed_state_json, td.rationale_summary,
                        aci.capabilities_json, aci.chains_json, aci.matched_tokens_json,
                        aci.confidence AS aci_confidence, aci.uplift_score AS aci_uplift_score
                    FROM findings f
                    LEFT JOIN scores s
                        ON s.run_id = f.run_id AND s.finding_id = f.finding_id
                    LEFT JOIN enrichment_snapshots e
                        ON e.run_id = f.run_id
                        AND UPPER(e.cve_id) = COALESCE(
                            UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')),
                            UPPER(f.primary_cve)
                        )
                    LEFT JOIN (
                        SELECT
                            fc.finding_id,
                            BOOL_OR(COALESCE(es.in_kev, FALSE)) AS fc_in_kev,
                            BOOL_OR(COALESCE(es.verified_exploit, FALSE)) AS fc_verified_exploit,
                            BOOL_OR(COALESCE(es.heuristic_exploit_mention, FALSE)) AS fc_heuristic_exploit,
                            ARG_MIN(
                                NULLIF(CAST(es.kev_date_added AS VARCHAR), ''),
                                CASE
                                    WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_date_added AS VARCHAR), '') IS NOT NULL
                                    THEN UPPER(es.cve_id)
                                END
                            ) AS fc_kev_date_added,
                            ARG_MIN(
                                NULLIF(CAST(es.kev_due_date AS VARCHAR), ''),
                                CASE
                                    WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_due_date AS VARCHAR), '') IS NOT NULL
                                    THEN UPPER(es.cve_id)
                                END
                            ) AS fc_kev_due_date,
                            ARG_MIN(
                                NULLIF(CAST(es.kev_ransomware AS VARCHAR), ''),
                                CASE
                                    WHEN COALESCE(es.in_kev, FALSE) AND NULLIF(CAST(es.kev_ransomware AS VARCHAR), '') IS NOT NULL
                                    THEN UPPER(es.cve_id)
                                END
                            ) AS fc_kev_ransomware
                        FROM finding_cves fc
                        JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id)
                        WHERE fc.run_id = ?
                        GROUP BY fc.finding_id
                    ) fc_agg
                        ON fc_agg.finding_id = f.finding_id
                    LEFT JOIN triage_decisions td
                        ON td.run_id = f.run_id AND td.finding_id = f.finding_id
                    LEFT JOIN aci_signals aci
                        ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id
                    WHERE f.run_id = ? AND f.asset_id IN ({placeholders})
                    ORDER BY f.asset_id ASC, f.finding_id ASC
                    """,
                    [rid, rid, *asset_ids],
                )
                f_cols = [d[0] for d in finding_cur.description]

                asset_by_id = {a["asset_id"]: a for a in asset_records}
                emitted_asset_ids: set[str] = set()
                current_open_asset_id: Optional[str] = None
                first_finding_in_asset = True

                while True:
                    f_batch = finding_cur.fetchmany(500)
                    if not f_batch:
                        break
                    f_recs = [dict(zip(f_cols, row)) for row in f_batch]
                    fids = [r["finding_id"] for r in f_recs]
                    f_placeholders = ", ".join("?" for _ in fids)

                    ev_by_fid: Dict[str, List[Dict[str, Any]]] = {fid: [] for fid in fids}
                    ev_cur = conn.execute(
                        f"""
                        SELECT finding_id, evidence_idx, source_format, scanner_sig,
                               raw_severity, raw_cvss, raw_location, evidence_excerpt
                        FROM finding_evidence
                        WHERE run_id = ? AND finding_id IN ({f_placeholders})
                        ORDER BY finding_id ASC, evidence_idx ASC
                        """,
                        [rid, *fids],
                    )
                    ev_cols = [d[0] for d in ev_cur.description]
                    for ev_row in ev_cur.fetchall():
                        ev_dict = dict(zip(ev_cols, ev_row))
                        fid_key = ev_dict.pop("finding_id")
                        if fid_key in ev_by_fid:
                            ev_by_fid[fid_key].append(ev_dict)

                    cves_by_fid: Dict[str, List[str]] = {fid: [] for fid in fids}
                    for fid_k, cve_val in conn.execute(
                        f"""
                        SELECT finding_id, cve_id
                        FROM finding_cves
                        WHERE run_id = ? AND finding_id IN ({f_placeholders})
                        ORDER BY finding_id ASC, cve_id ASC
                        """,
                        [rid, *fids],
                    ).fetchall():
                        if fid_k in cves_by_fid and cve_val:
                            cves_by_fid[fid_k].append(cve_val)

                    for frec in f_recs:
                        target_aid = frec["asset_id"]
                        if current_open_asset_id != target_aid:
                            if current_open_asset_id is not None:
                                fh.write("\n            ]\n        }" if pretty_print else "]}")
                                current_open_asset_id = None

                            open_a = asset_by_id.get(target_aid) or {
                                "asset_id": target_aid,
                                "canonical_key": target_aid,
                                "hostname": None,
                                "ip_address": None,
                                "target_uri": None,
                                "image_or_repo": None,
                                "os": None,
                                "declared_criticality": None,
                                "derived_criticality": None,
                                "internet_facing": None,
                                "owner": None,
                                "env_tags_json": "{}",
                                "inventory_status": "unmatched_shadow",
                                "matched_rule_id": None,
                                "open_ports_json": "[]",
                            }
                            emitted_asset_ids.add(target_aid)
                            if not first_asset:
                                fh.write(",\n" if pretty_print else ",")
                            elif pretty_print:
                                fh.write("\n")
                            first_asset = False
                            _write_asset_prefix(
                                fh,
                                open_a,
                                aliases_by_asset.get(target_aid, []),
                                pres_mode,
                                pretty_print=pretty_print,
                            )
                            current_open_asset_id = target_aid
                            first_finding_in_asset = True

                        if not first_finding_in_asset:
                            fh.write(",\n" if pretty_print else ",")
                        elif pretty_print:
                            fh.write("\n")
                        first_finding_in_asset = False
                        f_payload = _build_duckdb_finding_payload(
                            frec,
                            ev_by_fid.get(frec["finding_id"], []),
                            cves_by_fid.get(frec["finding_id"], []),
                            pres_mode,
                        )
                        if pretty_print:
                            fh.write(
                                textwrap.indent(
                                    json.dumps(f_payload, ensure_ascii=True, allow_nan=False, indent=4),
                                    "                ",
                                )
                            )
                        else:
                            fh.write(json.dumps(f_payload, ensure_ascii=True, allow_nan=False))

                if current_open_asset_id is not None:
                    fh.write("\n            ]\n        }" if pretty_print else "]}")
                    current_open_asset_id = None

                for zero_a in asset_records:
                    if zero_a["asset_id"] in emitted_asset_ids:
                        continue
                    if not first_asset:
                        fh.write(",\n" if pretty_print else ",")
                    elif pretty_print:
                        fh.write("\n")
                    first_asset = False
                    _write_asset_prefix(
                        fh,
                        zero_a,
                        aliases_by_asset.get(zero_a["asset_id"], []),
                        pres_mode,
                        pretty_print=pretty_print,
                    )
                    fh.write("]\n        }" if pretty_print else "]}")

            if pretty_print:
                fh.write("]\n}\n" if first_asset else "\n    ]\n}\n")
            else:
                fh.write("]}\n")
        finally:
            try:
                finding_cur.close()
            except Exception:
                pass
            try:
                asset_cur.close()
            except Exception:
                pass

    if pfh is not None:
        resolved = pfh.ensure_writable_file(target, label="JSON Output File", create_parents=True, overwrite=True)
        with pfh.open_for_write(resolved, mode="w", encoding="utf-8", label="JSON Output") as fh:
            _stream_to_handle(fh)
        return Path(resolved)

    with open_for_write_non_pfh(target, label="JSON Output", encoding="utf-8") as fh:
        _stream_to_handle(fh)
    return target
