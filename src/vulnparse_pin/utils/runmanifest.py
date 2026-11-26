# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import duckdb

from vulnparse_pin import __version__
from vulnparse_pin.storage.db import open_for_write_non_pfh
from vulnparse_pin.utils.schema_validate import validate_runmanifest_schema


_HASH_CHUNK_BYTES = 1024 * 1024  # 1 MiB streaming hash chunks

VOLATILE_PATHS = {
    "generated_at_utc",
    "pass_summaries.started_at_utc",
    "pass_summaries.ended_at_utc",
    "decision_ledger.entries.ts",
}


def _sha256_bytes(payload: bytes) -> str:
    return f"sha256:{sha256(payload).hexdigest()}"


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _file_sha256(path: Optional[Union[Path, str]]) -> Optional[str]:
    if path is None:
        return None
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    digest = sha256()
    with p.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _get_conn(db: Any) -> duckdb.DuckDBPyConnection:
    if isinstance(db, duckdb.DuckDBPyConnection):
        return db
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    raise TypeError(f"Expected VppDatabase or DuckDBPyConnection, got {type(db).__name__}")


def _json_loads_safe(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        loaded = json.loads(raw)
        return loaded if loaded is not None else default
    except Exception:
        return default


def _coerce_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if is_dataclass(value):
        coerced = asdict(value)
        return coerced if isinstance(coerced, dict) else {}
    if hasattr(value, "__dict__"):
        return dict(getattr(value, "__dict__", {}))
    return {}


def _sequence_len(value: Any) -> int:
    if isinstance(value, (str, bytes, bytearray)):
        return 0
    try:
        return len(value)
    except TypeError:
        return 0


def _summarize_pass_metrics(pass_name: str, data: Any) -> Dict[str, Any]:
    data = _coerce_mapping(data)
    if not data:
        return {}

    name = str(pass_name or "").lower()

    if name == "scoring":
        coverage = data.get("coverage", {}) if isinstance(data.get("coverage"), dict) else {}
        scored_findings = data.get("scored_findings")
        asset_scores = data.get("asset_scores")
        asset_criticality = data.get("asset_criticality")
        whole_cve_traces = 0
        union_exploit_findings = 0
        union_kev_findings = 0
        if isinstance(scored_findings, dict):
            for rec in scored_findings.values():
                if not isinstance(rec, dict):
                    continue
                trace = rec.get("score_trace", {})
                if not isinstance(trace, dict):
                    continue
                if trace.get("aggregation_mode"):
                    whole_cve_traces += 1
                union = trace.get("union_flags", {})
                if isinstance(union, dict):
                    if bool(union.get("exploit", False)):
                        union_exploit_findings += 1
                    if bool(union.get("kev", False)):
                        union_kev_findings += 1
        metrics = {
            "total_findings": int(coverage.get("total_findings", 0) or 0),
            "scored_findings": int(
                coverage.get("scored_findings", len(scored_findings) if isinstance(scored_findings, dict) else 0) or 0
            ),
            "coverage_ratio": float(coverage.get("coverage_ratio", 0.0) or 0.0),
            "assets_scored": len(asset_scores) if isinstance(asset_scores, dict) else 0,
            "assets_with_criticality": len(asset_criticality) if isinstance(asset_criticality, dict) else 0,
            "highest_risk_asset": data.get("highest_risk_asset"),
            "highest_risk_asset_score": data.get("highest_risk_asset_score"),
            "avg_scored_risk": data.get("avg_scored_risk"),
            "avg_operational_risk": data.get("avg_operational_risk"),
            "whole_cve_trace_findings": whole_cve_traces,
            "union_exploit_findings": union_exploit_findings,
            "union_kev_findings": union_kev_findings,
        }
        return metrics

    if name == "topn":
        assets = data.get("assets")
        findings_by_asset = data.get("findings_by_asset")
        global_top = data.get("global_top_findings")
        error_block = data.get("error") if isinstance(data.get("error"), dict) else {}
        whole_cve_reason_mentions = 0
        if isinstance(findings_by_asset, dict):
            for ranked in findings_by_asset.values():
                if not isinstance(ranked, (list, tuple)):
                    continue
                for finding in ranked:
                    if not isinstance(finding, dict):
                        continue
                    reasons = finding.get("reasons", [])
                    if not isinstance(reasons, (list, tuple)):
                        continue
                    if any("Whole-of-CVEs Aggregated" in str(reason) for reason in reasons):
                        whole_cve_reason_mentions += 1
        return {
            "rank_basis": data.get("rank_basis"),
            "status": data.get("status", "ok"),
            "error_code": error_block.get("code"),
            "k": data.get("k"),
            "decay_weights": _sequence_len(data.get("decay")),
            "ranked_assets": _sequence_len(assets),
            "assets_with_ranked_findings": len(findings_by_asset) if isinstance(findings_by_asset, dict) else 0,
            "global_top_findings": _sequence_len(global_top),
            "whole_cve_reason_mentions": whole_cve_reason_mentions,
        }

    if name == "summary":
        overview = data.get("overview", {}) if isinstance(data.get("overview"), dict) else {}
        top_risks = data.get("top_risks")
        remediation = data.get("remediation_priorities", {}) if isinstance(data.get("remediation_priorities"), dict) else {}
        aggregated_top_risks = 0
        if isinstance(top_risks, (list, tuple)):
            for item in top_risks:
                if not isinstance(item, dict):
                    continue
                if item.get("aggregated_cve_count") is not None:
                    aggregated_top_risks += 1
        return {
            "total_assets": int(overview.get("total_assets", 0) or 0),
            "total_findings": int(overview.get("total_findings", 0) or 0),
            "top_risks": _sequence_len(top_risks),
            "top_risks_with_aggregated_context": aggregated_top_risks,
            "immediate_action": int(remediation.get("immediate_action", 0) or 0),
            "high_priority": int(remediation.get("high_priority", 0) or 0),
            "medium_priority": int(remediation.get("medium_priority", 0) or 0),
        }

    if name == "aci":
        metrics = data.get("metrics", {}) if isinstance(data.get("metrics"), dict) else {}
        caps = metrics.get("capabilities_detected", {}) if isinstance(metrics.get("capabilities_detected"), dict) else {}
        chains = metrics.get("chain_candidates_detected", {}) if isinstance(metrics.get("chain_candidates_detected"), dict) else {}
        conf = metrics.get("confidence_buckets", {}) if isinstance(metrics.get("confidence_buckets"), dict) else {}
        return {
            "total_findings": int(metrics.get("total_findings", 0) or 0),
            "inferred_findings": int(metrics.get("inferred_findings", 0) or 0),
            "coverage_ratio": float(metrics.get("coverage_ratio", 0.0) or 0.0),
            "uplifted_findings": int(metrics.get("uplifted_findings", 0) or 0),
            "capability_types": len(caps),
            "chain_types": len(chains),
            "confidence_low": int(conf.get("low", 0) or 0),
            "confidence_medium": int(conf.get("medium", 0) or 0),
            "confidence_high": int(conf.get("high", 0) or 0),
        }

    if name == "nmap_adapter":
        asset_open_ports = data.get("asset_open_ports") if isinstance(data.get("asset_open_ports"), dict) else {}
        nse_cves_by_asset = data.get("nse_cves_by_asset") if isinstance(data.get("nse_cves_by_asset"), dict) else {}
        unmatched_asset_ids = data.get("unmatched_asset_ids") if isinstance(data.get("unmatched_asset_ids"), (list, tuple)) else []

        open_port_bindings = 0
        for ports in asset_open_ports.values():
            if isinstance(ports, (list, tuple, set)):
                open_port_bindings += len(ports)

        nse_cve_bindings = 0
        for cves in nse_cves_by_asset.values():
            if isinstance(cves, (list, tuple, set)):
                nse_cve_bindings += len(cves)

        return {
            "status": data.get("status"),
            "source_file": data.get("source_file"),
            "host_count": int(data.get("host_count", 0) or 0),
            "matched_asset_count": int(data.get("matched_asset_count", 0) or 0),
            "unmatched_asset_count": len(unmatched_asset_ids),
            "assets_with_open_ports": len(asset_open_ports),
            "assets_with_nse_cves": len(nse_cves_by_asset),
            "open_port_bindings": open_port_bindings,
            "nse_cve_bindings": nse_cve_bindings,
        }

    return {}


def _build_pass_summaries(scan_result) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    derived = getattr(scan_result, "derived", None)
    passes = getattr(derived, "passes", {}) if derived is not None else {}
    for _, pass_result in passes.items():
        meta = getattr(pass_result, "meta", None)
        if meta is None:
            continue
        summaries.append(
            {
                "name": getattr(meta, "name", "unknown"),
                "version": getattr(meta, "version", "unknown"),
                "started_at_utc": getattr(meta, "created_at_utc", None),
                "ended_at_utc": getattr(meta, "created_at_utc", None),
                "metrics": _summarize_pass_metrics(getattr(meta, "name", "unknown"), getattr(pass_result, "data", {})),
            }
        )
    return summaries


def _remove_volatile_fields(payload: Any) -> Any:
    """Return copy suitable for deterministic digesting by removing volatile timestamps."""
    data = json.loads(json.dumps(payload))

    data.pop("generated_at_utc", None)
    for ps in data.get("pass_summaries", []):
        ps.pop("started_at_utc", None)
        ps.pop("ended_at_utc", None)
    for entry in data.get("decision_ledger", {}).get("entries", []):
        entry.pop("ts", None)
    return data


def _compute_manifest_digest(payload: Dict[str, Any]) -> str:
    working = json.loads(json.dumps(payload))
    verification = working.get("verification", {})
    if isinstance(verification, dict):
        verification["manifest_digest"] = None
    non_volatile = _remove_volatile_fields(working)
    return _sha256_text(_canonical_json(non_volatile))


def _collect_output_hashes(outputs: Dict[str, Optional[str]]) -> Dict[str, str]:
    """Compute SHA-256 digests for regular output artifacts that exist on disk."""
    hashes: Dict[str, str] = {}
    for key, raw_path in (outputs or {}).items():
        if not raw_path:
            continue
        out_path = Path(str(raw_path))
        if out_path.is_symlink() or not out_path.is_file():
            continue
        digest = _file_sha256(out_path)
        if digest:
            hashes[str(key)] = digest
    return hashes


def _collect_input_file_hashes(input_files: List[str]) -> Dict[str, Optional[str]]:
    """Compute per-file SHA-256 digests for recorded scan inputs."""
    hashes: Dict[str, Optional[str]] = {}
    for raw_path in input_files:
        p = Path(str(raw_path))
        hashes[str(raw_path)] = None if (p.is_symlink() or not p.is_file()) else _file_sha256(p)
    return hashes


def verify_runmanifest_integrity(manifest: Dict[str, Any]) -> None:
    ledger = manifest.get("decision_ledger", {})
    entries = ledger.get("entries", [])
    claimed_count = ledger.get("entry_count")
    if not isinstance(claimed_count, int) or isinstance(claimed_count, bool) or claimed_count != len(entries):
        raise ValueError(
            f"RunManifest integrity failed: entry_count ({claimed_count}) does not match entries length ({len(entries)})."
        )

    expected_prev = _sha256_text("vpp-ledger-empty-root-v1")

    for index, entry in enumerate(entries, start=1):
        if entry.get("seq") != index:
            raise ValueError(f"RunManifest integrity failed: non-sequential entry seq at index {index}.")

        if entry.get("prev_hash") != expected_prev:
            raise ValueError(f"RunManifest integrity failed: prev_hash mismatch at seq {index}.")

        hash_input = {
            "seq": entry.get("seq"),
            "ts": entry.get("ts"),
            "component": entry.get("component"),
            "event_type": entry.get("event_type"),
            "subject_ref": entry.get("subject_ref"),
            "why": entry.get("why"),
            "evidence_digest": entry.get("evidence_digest"),
            "prev_hash": entry.get("prev_hash"),
        }
        expected_entry_hash = _sha256_text(_canonical_json(hash_input))
        if entry.get("entry_hash") != expected_entry_hash:
            raise ValueError(f"RunManifest integrity failed: entry_hash mismatch at seq {index}.")

        expected_prev = expected_entry_hash

    chain_root = ledger.get("chain_root")
    if chain_root != expected_prev:
        raise ValueError("RunManifest integrity failed: chain_root does not match final entry hash.")

    claimed_digest = manifest.get("verification", {}).get("manifest_digest")
    expected_digest = _compute_manifest_digest(manifest)
    if claimed_digest != expected_digest:
        raise ValueError("RunManifest integrity failed: manifest_digest mismatch.")


def verify_runmanifest_file(path: Path) -> Dict[str, Any]:
    p = Path(path)
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"RunManifest validation failed: invalid JSON ({e.msg}).") from e

    if not isinstance(payload, dict):
        raise ValueError("RunManifest validation failed: top-level JSON value must be an object.")

    validate_runmanifest_schema(payload)
    verify_runmanifest_integrity(payload)
    return payload


def verify_runmanifest(manifest_or_path: Union[Dict[str, Any], Path, str]) -> Dict[str, Any]:
    """Verify a RunManifest dict or JSON file against schema and integrity digests."""
    if isinstance(manifest_or_path, (Path, str)):
        return verify_runmanifest_file(Path(manifest_or_path))
    if not isinstance(manifest_or_path, dict):
        raise ValueError("RunManifest validation failed: expected dict or file path.")
    validate_runmanifest_schema(manifest_or_path)
    verify_runmanifest_integrity(manifest_or_path)
    return manifest_or_path


def build_runmanifest(
    *,
    ctx,
    _args,
    scan_result,
    sources: dict,
    scanner_input: Path,
    output_paths: Optional[Dict[str, Optional[Path]]] = None,
) -> Dict[str, Any]:
    services = getattr(ctx, "services", None)
    ledger = getattr(services, "ledger", None) if services is not None else None
    ledger_snapshot = ledger.snapshot() if ledger is not None else None

    config_dir = Path(ctx.paths.config_dir)
    config_yaml = config_dir / "config.yaml"
    scoring_json = config_dir / "scoring.json"
    topn_json = config_dir / "tn_triage.json"

    pass_summaries = _build_pass_summaries(scan_result)
    runmanifest_mode = str(getattr(services, "runmanifest_mode", "compact") or "compact").lower()
    if runmanifest_mode not in {"compact", "expanded"}:
        runmanifest_mode = "compact"

    ledger_block: Dict[str, Any]
    if ledger_snapshot is None:
        ledger_block = {
            "chain_version": "1.0",
            "entry_count": 0,
            "chain_root": _sha256_text("vpp-ledger-empty-root-v1"),
            "entries": [],
        }
    else:
        ledger_block = {
            "chain_version": ledger_snapshot.chain_version,
            "entry_count": ledger_snapshot.entry_count,
            "chain_root": ledger_snapshot.chain_root,
            "entries": [asdict(e) for e in ledger_snapshot.entries],
        }

    outputs = {
        "json": str(output_paths.get("json")) if output_paths and output_paths.get("json") else None,
        "csv": str(output_paths.get("csv")) if output_paths and output_paths.get("csv") else None,
        "executive_markdown": str(output_paths.get("md")) if output_paths and output_paths.get("md") else None,
        "technical_markdown": str(output_paths.get("md_technical")) if output_paths and output_paths.get("md_technical") else None,
    }

    manifest: Dict[str, Any] = {
        "manifest_version": "1.0",
        "runmanifest_mode": runmanifest_mode,
        "run_id": _sha256_text(f"{scanner_input}:{_utc_now_z()}"),
        "generated_at_utc": _utc_now_z(),
        "runtime": {
            "vulnparse_version": __version__,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "inputs": {
            "target_path": str(scanner_input),
            "target_sha256": _file_sha256(scanner_input),
        },
        "config_hashes": {
            "config_yaml_sha256": _file_sha256(config_yaml),
            "scoring_json_sha256": _file_sha256(scoring_json),
            "tn_triage_json_sha256": _file_sha256(topn_json),
        },
        "outputs": outputs,
        "output_hashes": _collect_output_hashes(outputs),
        "enrichment_summary": {
            "kev_enabled": bool(sources.get("kev")),
            "epss_enabled": bool(sources.get("epss")),
            "nvd_enabled": sources.get("nvd"),
            "exploit_enabled": bool(sources.get("exploitdb")),
            "stats": dict(sources.get("stats", {})),
        },
        "pass_summaries": pass_summaries,
        "decision_ledger": ledger_block,
        "verification": {
            "canonicalization": "json-c14n-v1",
            "volatile_fields_excluded": sorted(VOLATILE_PATHS),
            "manifest_digest": None,
        },
    }

    digest = _compute_manifest_digest(manifest)
    manifest["verification"]["manifest_digest"] = digest
    return manifest


def _db_group_counts(conn: duckdb.DuckDBPyConnection, sql: str, run_id: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for k, cnt in conn.execute(sql, [run_id]).fetchall():
        if k is not None:
            out[str(k)] = int(cnt)
    return out


def _build_db_pass_summaries(
    conn: duckdb.DuckDBPyConnection,
    run_id: str,
    profile: Optional[str],
    created_at_utc: Optional[str],
    mode: str,
) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []

    aci_row = conn.execute(
        "SELECT COUNT(*), SUM(CASE WHEN capabilities_json != '[]' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN COALESCE(uplift_score, 0.0) > 0 THEN 1 ELSE 0 END) "
        "FROM aci_signals WHERE run_id = ?",
        [run_id],
    ).fetchone()
    if aci_row and int(aci_row[0] or 0) > 0:
        summaries.append(
            {
                "name": "ACI",
                "version": "2.0",
                "started_at_utc": created_at_utc,
                "ended_at_utc": created_at_utc,
                "metrics": {
                    "total_findings": int(aci_row[0] or 0),
                    "inferred_findings": int(aci_row[1] or 0),
                    "uplifted_findings": int(aci_row[2] or 0),
                },
            }
        )

    score_row = conn.execute(
        "SELECT COUNT(*), AVG(raw_risk_score), AVG(operational_score) FROM scores WHERE run_id = ?",
        [run_id],
    ).fetchone()
    total_findings = int((conn.execute("SELECT COUNT(*) FROM findings WHERE run_id = ?", [run_id]).fetchone() or (0,))[0] or 0)
    if score_row and int(score_row[0] or 0) > 0:
        sc_metrics: Dict[str, Any] = {
            "total_findings": total_findings,
            "scored_findings": int(score_row[0] or 0),
            "avg_raw_score": round(float(score_row[1]), 4) if score_row[1] is not None else None,
            "avg_operational_score": round(float(score_row[2]), 4) if score_row[2] is not None else None,
        }
        if mode == "expanded":
            sc_metrics["by_risk_band"] = _db_group_counts(
                conn, "SELECT risk_band, COUNT(*) FROM scores WHERE run_id = ? GROUP BY risk_band", run_id
            )
            sc_metrics["by_scoring_track"] = _db_group_counts(
                conn, "SELECT scoring_track, COUNT(*) FROM scores WHERE run_id = ? GROUP BY scoring_track", run_id
            )
        summaries.append(
            {
                "name": "Scoring",
                "version": "3.0",
                "started_at_utc": created_at_utc,
                "ended_at_utc": created_at_utc,
                "metrics": sc_metrics,
            }
        )

    triage_cnt = int((conn.execute("SELECT COUNT(*) FROM triage_decisions WHERE run_id = ?", [run_id]).fetchone() or (0,))[0] or 0)
    if triage_cnt > 0:
        by_tier = _db_group_counts(
            conn, "SELECT priority_tier, COUNT(*) FROM triage_decisions WHERE run_id = ? GROUP BY priority_tier", run_id
        )
        by_status = _db_group_counts(
            conn, "SELECT decision_status, COUNT(*) FROM triage_decisions WHERE run_id = ? GROUP BY decision_status", run_id
        )
        tr_metrics: Dict[str, Any] = {
            "profile": profile or "default",
            "triaged_findings": triage_cnt,
            "by_priority_tier": by_tier,
            "by_decision_status": by_status,
            "invalidated_decisions": int(
                by_status.get("deferred_invalidated", 0)
                + by_status.get("accepted_invalidated", 0)
                + by_status.get("mitigated_invalidated", 0)
            ),
        }
        if mode == "expanded":
            tr_metrics["by_sla_bucket"] = _db_group_counts(
                conn, "SELECT sla_bucket, COUNT(*) FROM triage_decisions WHERE run_id = ? GROUP BY sla_bucket", run_id
            )
        summaries.append(
            {
                "name": "Triage",
                "version": "2.0",
                "started_at_utc": created_at_utc,
                "ended_at_utc": created_at_utc,
                "metrics": tr_metrics,
            }
        )

    asset_row = conn.execute(
        "SELECT COUNT(*), SUM(CASE WHEN inventory_status = 'matched' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN inventory_status = 'unmatched_shadow' THEN 1 ELSE 0 END) "
        "FROM assets WHERE run_id = ?",
        [run_id],
    ).fetchone()
    kev_cnt = int(
        (
            conn.execute(
                "SELECT COUNT(*) "
                "FROM findings f "
                "LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id "
                "LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id "
                "AND UPPER(e.cve_id) = COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), UPPER(f.primary_cve)) "
                "LEFT JOIN ("
                "SELECT fc.finding_id, BOOL_OR(COALESCE(es.in_kev, FALSE)) AS fc_in_kev "
                "FROM finding_cves fc "
                "JOIN enrichment_snapshots es ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id) "
                "WHERE fc.run_id = ? "
                "GROUP BY fc.finding_id"
                ") fc_agg ON fc_agg.finding_id = f.finding_id "
                "WHERE f.run_id = ? AND ("
                "COALESCE(e.in_kev, FALSE) "
                "OR COALESCE(fc_agg.fc_in_kev, FALSE) "
                "OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)"
                ")",
                [run_id, run_id],
            ).fetchone()
            or (0,)
        )[0]
        or 0
    )
    summaries.append(
        {
            "name": "Summary",
            "version": "2.0",
            "started_at_utc": created_at_utc,
            "ended_at_utc": created_at_utc,
            "metrics": {
                "total_assets": int(asset_row[0] or 0) if asset_row else 0,
                "matched_assets": int(asset_row[1] or 0) if asset_row else 0,
                "shadow_assets": int(asset_row[2] or 0) if asset_row else 0,
                "total_findings": total_findings,
                "kev_findings": kev_cnt,
            },
        }
    )
    return summaries


def _load_db_ledger_block(conn: duckdb.DuckDBPyConnection, run_id: str) -> Dict[str, Any]:
    rows = conn.execute(
        """
        SELECT seq, ts, component, event_type, subject_ref, why, evidence_digest, prev_hash, entry_hash
        FROM ledger_events
        WHERE run_id = ?
        ORDER BY seq ASC
        """,
        [run_id],
    ).fetchall()

    empty_root = _sha256_text("vpp-ledger-empty-root-v1")
    if not rows:
        return {
            "chain_version": "1.0",
            "entry_count": 0,
            "chain_root": empty_root,
            "entries": [],
        }

    entries: List[Dict[str, Any]] = []
    expected_prev = empty_root
    for seq, ts, component, event_type, subject_ref, why_raw, ev_digest, prev_hash, entry_hash in rows:
        why_obj = _json_loads_safe(why_raw, None) if isinstance(why_raw, str) else why_raw
        if not isinstance(why_obj, dict):
            why_obj = {
                "reason_code": "LEDGER_EVENT",
                "reason_text": str(why_raw or ""),
                "factor_refs": [],
            }
        else:
            why_obj = dict(why_obj)
            why_obj.setdefault("reason_code", "LEDGER_EVENT")
            why_obj.setdefault("reason_text", "")
            refs = why_obj.get("factor_refs")
            why_obj["factor_refs"] = [str(x) for x in refs] if isinstance(refs, list) else []

        raw_ev_digest = "" if ev_digest is None else str(ev_digest)
        raw_prev = "" if prev_hash is None else str(prev_hash)
        raw_entry = "" if entry_hash is None else str(entry_hash)

        entries.append(
            {
                "seq": int(seq),
                "ts": str(ts),
                "component": str(component),
                "event_type": str(event_type),
                "subject_ref": str(subject_ref),
                "why": why_obj,
                "evidence_digest": raw_ev_digest,
                "prev_hash": raw_prev,
                "entry_hash": raw_entry,
            }
        )
        expected_prev = raw_entry or expected_prev

    return {
        "chain_version": "1.0",
        "entry_count": len(entries),
        "chain_root": entries[-1]["entry_hash"] if entries else empty_root,
        "entries": entries,
    }


def build_runmanifest_from_db(
    db: Any,
    run_id: str,
    *,
    config_hashes: Optional[Dict[str, Optional[str]]] = None,
    outputs: Optional[Dict[str, Optional[str]]] = None,
    mode: str = "compact",
) -> Dict[str, Any]:
    """
    Build a schema-validated, hash-chain-verifiable RunManifest v2 directly from
    DuckDB `.vpp.db` run tables (`runs`, `ledger_events`, `enrichment_snapshots`,
    `aci_signals`, `scores`, `triage_decisions`, `findings`, `assets`).
    """
    conn = _get_conn(db)
    rid = str(run_id)
    runmanifest_mode = str(mode or "compact").strip().lower()
    if runmanifest_mode not in {"compact", "expanded"}:
        raise ValueError(f"Invalid runmanifest mode '{mode}'. Expected 'compact' or 'expanded'.")

    run_row = conn.execute(
        """
        SELECT run_id, created_at_utc, vpp_version, profile,
               config_sha256, assets_sha256, decisions_sha256,
               intel_metadata_json, manifest_digest, input_files_json, baseline_run_id
        FROM runs
        WHERE run_id = ?
        """,
        [rid],
    ).fetchone()

    if run_row is None:
        has_assets = conn.execute("SELECT 1 FROM assets WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        has_findings = conn.execute("SELECT 1 FROM findings WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        if has_assets is None and has_findings is None:
            raise ValueError(f"Run '{rid}' does not exist in database.")
        created_at_utc = _utc_now_z()
        vpp_version = __version__
        profile: Optional[str] = "default"
        db_config_sha = None
        db_assets_sha = None
        db_decisions_sha = None
        intel_meta: Dict[str, Any] = {}
        input_files: List[str] = []
        baseline_run_id = None
    else:
        (
            _,
            created_at_utc,
            vpp_version,
            profile,
            db_config_sha,
            db_assets_sha,
            db_decisions_sha,
            intel_meta_raw,
            _,
            input_files_raw,
            baseline_run_id,
        ) = run_row
        vpp_version = vpp_version or __version__
        intel_meta = _json_loads_safe(intel_meta_raw, {})
        if not isinstance(intel_meta, dict):
            intel_meta = {}
        raw_files = _json_loads_safe(input_files_raw, [])
        input_files = [str(f) for f in raw_files] if isinstance(raw_files, list) else []

    cfg_h = dict(config_hashes or {})
    assets_sha = cfg_h.get("assets_sha256") or cfg_h.get("assets_yaml_sha256") or db_assets_sha
    decisions_sha = cfg_h.get("decisions_sha256") or cfg_h.get("decisions_yaml_sha256") or db_decisions_sha

    normalized_config_hashes: Dict[str, Optional[str]] = {
        "config_yaml_sha256": cfg_h.get("config_yaml_sha256", db_config_sha),
        "scoring_json_sha256": cfg_h.get("scoring_json_sha256"),
        "tn_triage_json_sha256": cfg_h.get("tn_triage_json_sha256"),
        "assets_sha256": assets_sha,
        "decisions_sha256": decisions_sha,
    }
    for k, v in cfg_h.items():
        if k not in normalized_config_hashes:
            normalized_config_hashes[str(k)] = v

    out_in = dict(outputs or {})
    normalized_outputs: Dict[str, Optional[str]] = {
        "json": str(out_in["json"]) if out_in.get("json") else None,
        "csv": str(out_in["csv"]) if out_in.get("csv") else None,
        "executive_markdown": str(out_in.get("executive_markdown") or out_in.get("md"))
        if (out_in.get("executive_markdown") or out_in.get("md"))
        else None,
        "technical_markdown": str(out_in.get("technical_markdown") or out_in.get("md_technical"))
        if (out_in.get("technical_markdown") or out_in.get("md_technical"))
        else None,
    }
    for k, v in out_in.items():
        if k not in {"json", "csv", "executive_markdown", "technical_markdown", "md", "md_technical"}:
            normalized_outputs[str(k)] = str(v) if v is not None else None

    target_path_str = ", ".join(input_files) if input_files else f"duckdb://{rid}"
    input_file_hashes = _collect_input_file_hashes(input_files)
    if len(input_files) == 1:
        target_sha = input_file_hashes.get(input_files[0])
    elif len(input_files) > 1 and all(input_file_hashes.get(f) for f in input_files):
        target_sha = _sha256_text(
            _canonical_json([{"path": f, "sha256": input_file_hashes[f]} for f in input_files])
        )
    else:
        target_sha = None
    output_hashes = _collect_output_hashes(normalized_outputs)

    snap_stats = conn.execute(
        """
        SELECT
            COUNT(*),
            SUM(CASE WHEN COALESCE(in_kev, FALSE) THEN 1 ELSE 0 END),
            SUM(CASE WHEN epss_score IS NOT NULL THEN 1 ELSE 0 END),
            SUM(CASE WHEN COALESCE(verified_exploit, FALSE) THEN 1 ELSE 0 END),
            SUM(CASE WHEN COALESCE(heuristic_exploit_mention, FALSE) THEN 1 ELSE 0 END),
            SUM(CASE WHEN LOWER(COALESCE(cvss_provenance, '')) = 'nvd' THEN 1 ELSE 0 END),
            MAX(epss_model_version),
            MAX(epss_date)
        FROM enrichment_snapshots
        WHERE run_id = ?
        """,
        [rid],
    ).fetchone()

    total_cves = int(snap_stats[0] or 0) if snap_stats else 0
    kev_hits = int(snap_stats[1] or 0) if snap_stats else 0
    epss_hits = int(snap_stats[2] or 0) if snap_stats else 0
    ver_exp_hits = int(snap_stats[3] or 0) if snap_stats else 0
    heur_exp_hits = int(snap_stats[4] or 0) if snap_stats else 0
    nvd_hits = int(snap_stats[5] or 0) if snap_stats else 0
    if snap_stats and snap_stats[6] and "epss_model_version" not in intel_meta:
        intel_meta["epss_model_version"] = snap_stats[6]
    if snap_stats and snap_stats[7] and "epss_score_date" not in intel_meta:
        intel_meta["epss_score_date"] = snap_stats[7]

    kev_enabled = bool(intel_meta.get("kev_catalog_version") or intel_meta.get("kev_sha256") or kev_hits > 0)
    epss_enabled = bool(intel_meta.get("epss_model_version") or intel_meta.get("epss_sha256") or epss_hits > 0)
    nvd_enabled: Any = intel_meta.get("nvd_status") if intel_meta.get("nvd_status") is not None else (nvd_hits > 0)
    exploit_enabled = bool(intel_meta.get("exploit_enabled") or ver_exp_hits > 0)
    ghsa_enabled = bool(intel_meta["ghsa_enabled"]) if intel_meta.get("ghsa_enabled") is not None else None
    osv_enabled = bool(intel_meta["osv_enabled"]) if intel_meta.get("osv_enabled") is not None else None

    pass_summaries = _build_db_pass_summaries(conn, rid, profile, created_at_utc, runmanifest_mode)
    ledger_block = _load_db_ledger_block(conn, rid)

    manifest: Dict[str, Any] = {
        "manifest_version": "2.0",
        "runmanifest_mode": runmanifest_mode,
        "run_id": rid,
        "profile": profile,
        "assets_sha256": assets_sha,
        "decisions_sha256": decisions_sha,
        "generated_at_utc": _utc_now_z(),
        "runtime": {
            "vulnparse_version": str(vpp_version),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "inputs": {
            "target_path": target_path_str,
            "target_sha256": target_sha,
            "input_files": input_files,
            "input_files_sha256": input_file_hashes,
            "baseline_run_id": baseline_run_id,
        },
        "config_hashes": normalized_config_hashes,
        "outputs": normalized_outputs,
        "output_hashes": output_hashes,
        "enrichment_summary": {
            "kev_enabled": kev_enabled,
            "epss_enabled": epss_enabled,
            "nvd_enabled": nvd_enabled,
            "exploit_enabled": exploit_enabled,
            "ghsa_enabled": ghsa_enabled,
            "osv_enabled": osv_enabled,
            "intel_metadata": intel_meta,
            "stats": {
                "snapshot_cves": total_cves,
                "kev_hits": kev_hits,
                "epss_hits": epss_hits,
                "verified_exploit_hits": ver_exp_hits,
                "heuristic_exploit_hits": heur_exp_hits,
                "nvd_cvss_hits": nvd_hits,
            },
        },
        "pass_summaries": pass_summaries,
        "decision_ledger": ledger_block,
        "verification": {
            "canonicalization": "json-c14n-v1",
            "volatile_fields_excluded": sorted(VOLATILE_PATHS),
            "manifest_digest": None,
        },
    }

    digest = _compute_manifest_digest(manifest)
    manifest["verification"]["manifest_digest"] = digest
    validate_runmanifest_schema(manifest)
    return manifest


def write_runmanifest(ctx, manifest: Dict[str, Any], output_path: Union[Path, str]) -> None:
    validate_runmanifest_schema(manifest)
    verify_runmanifest_integrity(manifest)
    out_p = Path(output_path)

    if ctx is None:
        with open_for_write_non_pfh(out_p, label="RunManifest output", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        return

    if hasattr(ctx, "open_for_write"):
        with ctx.open_for_write(out_p, mode="w", encoding="utf-8", label="RunManifest Output") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        return

    with ctx.pfh.open_for_write(out_p, mode="w", encoding="utf-8", label="RunManifest Output") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
