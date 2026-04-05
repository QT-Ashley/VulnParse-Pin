from __future__ import annotations

from dataclasses import asdict
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


def _summarize_pass_metrics(pass_name: str, data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}

    name = str(pass_name or "").lower()

    if name == "scoring":
        coverage = data.get("coverage", {}) if isinstance(data.get("coverage"), dict) else {}
        scored_findings = data.get("scored_findings")
        asset_scores = data.get("asset_scores")
        asset_criticality = data.get("asset_criticality")
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
        }
        return metrics

    if name == "topn":
        assets = data.get("assets")
        findings_by_asset = data.get("findings_by_asset")
        global_top = data.get("global_top_findings")
        error_block = data.get("error") if isinstance(data.get("error"), dict) else {}
        return {
            "rank_basis": data.get("rank_basis"),
            "status": data.get("status", "ok"),
            "error_code": error_block.get("code"),
            "k": data.get("k"),
            "decay_weights": len(data.get("decay", [])) if isinstance(data.get("decay"), list) else 0,
            "ranked_assets": len(assets) if isinstance(assets, list) else 0,
            "assets_with_ranked_findings": len(findings_by_asset) if isinstance(findings_by_asset, dict) else 0,
            "global_top_findings": len(global_top) if isinstance(global_top, list) else 0,
        }

    if name == "summary":
        overview = data.get("overview", {}) if isinstance(data.get("overview"), dict) else {}
        top_risks = data.get("top_risks")
        return {
            "total_assets": int(overview.get("total_assets", 0) or 0),
            "total_findings": int(overview.get("total_findings", 0) or 0),
            "top_risks": len(top_risks) if isinstance(top_risks, list) else 0,
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
