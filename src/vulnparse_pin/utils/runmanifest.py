from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import platform
from pathlib import Path
from typing import Any, Dict, Optional

from vulnparse_pin import __version__
from vulnparse_pin.utils.schema_validate import validate_runmanifest_schema


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


def _file_sha256(path: Optional[Path]) -> Optional[str]:
    if path is None:
        return None
    if not path.exists() or not path.is_file():
        return None
    return _sha256_bytes(path.read_bytes())


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


def verify_runmanifest_integrity(manifest: Dict[str, Any]) -> None:
    ledger = manifest.get("decision_ledger", {})
    entries = ledger.get("entries", [])
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
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"RunManifest validation failed: invalid JSON ({e.msg}).") from e

    if not isinstance(payload, dict):
        raise ValueError("RunManifest validation failed: top-level JSON value must be an object.")

    validate_runmanifest_schema(payload)
    verify_runmanifest_integrity(payload)
    return payload


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


def write_runmanifest(ctx, manifest: Dict[str, Any], output_path: Path) -> None:
    validate_runmanifest_schema(manifest)
    verify_runmanifest_integrity(manifest)
    with ctx.pfh.open_for_write(output_path, mode="w", encoding="utf-8", label="RunManifest Output") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
