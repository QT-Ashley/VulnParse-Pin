# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import inspect
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from vulnparse_pin.app.runtime_helpers import authorize_output_dir, authorize_output_path
from vulnparse_pin.cli.errors import VppError
from vulnparse_pin.core.classes.dataclass import Asset, Finding, ScanMetaData, ScanResult
from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.execution_manifest import EMPTY_LEDGER_ROOT
from vulnparse_pin.core.classes.pass_classes import DerivedContext, DerivedPassResult, PassMeta
from vulnparse_pin.core.config_validator import validate_webhook_https_url
from vulnparse_pin.storage.repositories import insert_ledger_events, query_findings_page
from vulnparse_pin.utils.csv_exporter import export_to_csv
from vulnparse_pin.utils.markdown_report import generate_markdown_report
from vulnparse_pin.utils.reportgen import materialize_presentation
from vulnparse_pin.utils.runmanifest import _canonical_json, build_runmanifest, write_runmanifest
from vulnparse_pin.utils.webhook_delivery import emit_configured_webhooks


_PRESENTATION_ONLY_FINDING_KEYS = (
    "raw_risk_score",
    "risk_score",
    "risk_band",
    "score_trace",
)


def _materialize_default_json(scan_result: Any) -> Any:
    """Build default JSON output while keeping score fields in derived passes only."""
    if is_dataclass(scan_result):
        out = asdict(scan_result)
    elif isinstance(scan_result, dict):
        out = deepcopy(scan_result)
    else:
        return scan_result

    assets = out.get("assets") if isinstance(out, dict) else None
    if not isinstance(assets, list):
        return out

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        findings = asset.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for key in _PRESENTATION_ONLY_FINDING_KEYS:
                finding.pop(key, None)
    return out


def _json_payload_for_output(args: Any, scan_result: Any) -> Any:
    if args.presentation:
        if not scan_result.derived.get("Scoring@2.0"):
            raise RuntimeError("Presentation overlay requested, but Scoring@2.0 pass result not found.")
        return materialize_presentation(scan_result, overlay_mode=args.overlay_mode, scoring_pass_key="Scoring@2.0")
    return _materialize_default_json(scan_result)


def write_text_via_pfh(pfh: Any, out_path: Path, text: str, *, label: str) -> Path:
    """Write text report via PermFileHandler using authorized explicit output path."""
    target = authorize_output_path(pfh, out_path, label=label)
    with pfh.open_for_write(target, mode="w", encoding="utf-8", label=label) as fh:
        fh.write(text)
    return target


def _load_renderer():
    from vulnparse_pin.reporting import renderer as _renderer

    return _renderer


_MAX_PRETTY_REFORMAT_BYTES = 50 * 1024 * 1024


def invoke_duckdb_json_export(
    export_json_fn: Callable[..., Any],
    db: Any,
    run_id: str,
    json_path: Path,
    *,
    presentation: str,
    pfh: Any = None,
    pretty_print: bool = False,
) -> None:
    """Invoke export_duckdb_json forwarding pretty_print when supported, with bounded fallback."""
    kwargs: Dict[str, Any] = {"presentation": presentation, "pfh": pfh}
    supports_pretty = False
    try:
        params = inspect.signature(export_json_fn).parameters
        supports_pretty = "pretty_print" in params or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
    except (TypeError, ValueError):
        supports_pretty = False

    if supports_pretty:
        kwargs["pretty_print"] = bool(pretty_print)
    export_json_fn(db, run_id, json_path, **kwargs)

    if pretty_print and not supports_pretty and json_path.is_file() and not json_path.is_symlink():
        if json_path.stat().st_size <= _MAX_PRETTY_REFORMAT_BYTES:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            pretty_text = json.dumps(payload, indent=4) + "\n"
            if pfh is not None:
                write_text_via_pfh(pfh, json_path, pretty_text, label="JSON Output File")
            else:
                json_path.write_text(pretty_text, encoding="utf-8")


def invoke_duckdb_csv_export(
    export_csv_fn: Callable[..., Any],
    db: Any,
    run_id: str,
    csv_path: Path,
    *,
    profile: str,
    pfh: Any = None,
    csv_sanitization: bool = True,
) -> None:
    """Invoke export_duckdb_csv forwarding csv_sanitization when supported."""
    kwargs: Dict[str, Any] = {"profile": profile, "pfh": pfh}
    try:
        params = inspect.signature(export_csv_fn).parameters
        if "csv_sanitization" in params or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        ):
            kwargs["csv_sanitization"] = bool(csv_sanitization)
    except (TypeError, ValueError):
        pass
    export_csv_fn(db, run_id, csv_path, **kwargs)


_SUPPRESSED_WEBHOOK_STATUSES = frozenset(
    {"deferred_valid", "accepted_valid", "mitigated", "deferred", "accepted"}
)


def validate_webhook_runtime_config(ctx: Any) -> None:
    """Fail closed when webhook delivery is enabled with invalid config or missing HMAC key."""
    services = getattr(ctx, "services", None)
    webhook_cfg = getattr(services, "webhook_config", None) if services is not None else None
    if webhook_cfg is None or not bool(getattr(webhook_cfg, "enabled", False)):
        return

    endpoints = list(getattr(webhook_cfg, "endpoints", ()) or ())
    enabled_endpoints = [ep for ep in endpoints if bool(getattr(ep, "enabled", False))]
    if not enabled_endpoints:
        raise VppError(
            "Webhook delivery is enabled, but no enabled webhook endpoints are configured.",
            exit_code=2,
        )

    for ep in enabled_endpoints:
        url = str(getattr(ep, "url", "") or "").strip()
        try:
            validate_webhook_https_url(url)
        except ValueError as exc:
            raise VppError(
                f"Invalid webhook endpoint URL '{url}': {exc}",
                exit_code=2,
            ) from exc

    signing_key_env = str(getattr(webhook_cfg, "signing_key_env", "VP_WEBHOOK_HMAC_KEY") or "VP_WEBHOOK_HMAC_KEY")
    if not os.getenv(signing_key_env):
        raise VppError(
            f"Webhook delivery is enabled, but signing key environment variable '{signing_key_env}' is not set.",
            exit_code=2,
        )


def _normalize_webhook_sla_bucket(sla_bucket: Optional[str]) -> Optional[str]:
    if not sla_bucket:
        return None
    low = str(sla_bucket).strip().lower()
    if low.startswith("3-day"):
        return "3-day"
    if low.startswith("14-day"):
        return "14-day"
    if low.startswith("60-day"):
        return "60-day"
    if "defer" in low or "fix on upgrade" in low:
        return "defer"
    return str(sla_bucket)


def _build_v2_webhook_scan_result(db: Any, run_id: str, args: Any) -> Tuple[ScanResult, Path]:
    """
    Build a ScanResult projection from DuckDB v2 tables for emit_configured_webhooks,
    excluding validly deferred/accepted/mitigated findings while retaining active and
    invalidated findings.
    """
    conn = getattr(db, "conn", db)

    run_row = conn.execute(
        "SELECT created_at_utc, input_files_json FROM runs WHERE run_id = ?",
        [str(run_id)],
    ).fetchone()
    scan_date = datetime.now(timezone.utc)
    input_files: List[str] = []
    if run_row is not None:
        if run_row[0]:
            try:
                raw_ts = str(run_row[0])
                iso = raw_ts[:-1] + "+00:00" if raw_ts.endswith("Z") else raw_ts
                scan_date = datetime.fromisoformat(iso)
            except ValueError:
                pass
        if run_row[1]:
            try:
                parsed_files = json.loads(run_row[1])
                if isinstance(parsed_files, list):
                    input_files = [str(x) for x in parsed_files if x]
            except Exception:
                pass

    scanner_input = Path(input_files[0]) if input_files else Path(getattr(args, "db", None) or f"{run_id}.vpp.db")

    all_rows: List[Dict[str, Any]] = []
    offset = 0
    page_size = 10_000
    while True:
        page, total_count = query_findings_page(db, str(run_id), limit=page_size, offset=offset)
        if not page:
            break
        all_rows.extend(page)
        offset += len(page)
        if offset >= total_count or len(page) < page_size:
            break

    asset_rows = conn.execute(
        "SELECT asset_id, hostname, ip_address, internet_facing FROM assets WHERE run_id = ?",
        [str(run_id)],
    ).fetchall()
    asset_meta: Dict[str, Tuple[str, str, bool]] = {
        str(aid): (str(host or ""), str(ip or ""), bool(facing))
        for aid, host, ip, facing in asset_rows
    }

    invalidated_reasons_map: Dict[str, List[str]] = {}
    for td_fid, assumed_raw in conn.execute(
        "SELECT finding_id, assumed_state_json FROM triage_decisions "
        "WHERE run_id = ? AND LOWER(COALESCE(decision_status, '')) LIKE '%invalidated'",
        [str(run_id)],
    ).fetchall():
        reasons_list: List[str] = []
        if assumed_raw:
            try:
                parsed_assumed = json.loads(assumed_raw)
            except Exception:
                parsed_assumed = {}
            if isinstance(parsed_assumed, dict):
                raw_reasons = parsed_assumed.get("reasons") or parsed_assumed.get("violated_predicates") or []
                if isinstance(raw_reasons, list):
                    reasons_list = [str(r) for r in raw_reasons if r]
        invalidated_reasons_map[str(td_fid)] = reasons_list

    findings_by_asset: Dict[str, List[Finding]] = {}
    asset_max_score: Dict[str, float] = {}
    global_top_findings: List[Dict[str, Any]] = []
    aci_semantics: Dict[str, Dict[str, Any]] = {}
    inferred_count = 0

    for row in all_rows:
        decision_status = str(row.get("decision_status") or "").strip().lower()
        if decision_status in _SUPPRESSED_WEBHOOK_STATUSES:
            continue

        fid = str(row["finding_id"])
        aid = str(row["asset_id"])
        op_score = float(row.get("operational_score") or 0.0)
        if op_score > asset_max_score.get(aid, -1.0):
            asset_max_score[aid] = op_score

        cves = list(row.get("cves") or [])
        if not cves and row.get("primary_cve"):
            cves = [str(row["primary_cve"])]

        in_kev_val = bool(row.get("in_kev", False))
        epss_val = row.get("epss_score")
        oal_val = row.get("oal_compat")
        ssvc_val = row.get("ssvc_action")
        raw_sla_label = row.get("sla_bucket")
        norm_sla = _normalize_webhook_sla_bucket(raw_sla_label)
        sla_label_val = raw_sla_label or norm_sla
        raw_decision_status = row.get("decision_status") or "active"
        inv_reasons = list(invalidated_reasons_map.get(fid, ()))
        if decision_status.endswith("invalidated") and not inv_reasons:
            fallback_reason = str(row.get("rationale_summary") or raw_decision_status).strip()
            if fallback_reason:
                inv_reasons = [fallback_reason]

        f_obj = Finding(
            finding_id=fid,
            vuln_id=fid,
            title=str(row.get("title") or ""),
            description=str(row.get("description") or ""),
            severity=str(row.get("scanner_severity") or ""),
            cves=cves,
            cvss_score=row.get("cvss_score"),
            epss_score=epss_val,
            cisa_kev=in_kev_val,
            exploit_available=bool(row.get("verified_exploit", False)),
            raw_risk_score=row.get("raw_risk_score"),
            risk_score=op_score,
            risk_band=row.get("risk_band"),
            affected_port=row.get("affected_port"),
            protocol=row.get("protocol"),
            asset_id=aid,
        )
        setattr(f_obj, "priority_tier", row.get("priority_tier"))
        setattr(f_obj, "sla_bucket", norm_sla)
        setattr(f_obj, "oal", oal_val)
        setattr(f_obj, "ssvc_action", ssvc_val)
        setattr(f_obj, "sla_label", sla_label_val)
        setattr(f_obj, "operational_score", op_score)
        setattr(f_obj, "in_kev", in_kev_val)
        setattr(f_obj, "decision_status", raw_decision_status)
        setattr(f_obj, "invalidated_reasons", inv_reasons)
        findings_by_asset.setdefault(aid, []).append(f_obj)

        chains = [str(c) for c in (row.get("chains") or []) if c]
        aci_conf = float(row.get("aci_confidence") or 0.0)
        if chains or aci_conf > 0.0:
            inferred_count += 1
            aci_semantics[fid] = {
                "confidence": aci_conf,
                "chain_candidates": chains,
            }

        global_top_findings.append(
            {
                "finding_id": fid,
                "asset_id": aid,
                "score": op_score,
                "operational_score": op_score,
                "risk_band": str(row.get("risk_band") or ""),
                "port": row.get("affected_port"),
                "proto": row.get("protocol"),
                "priority_tier": row.get("priority_tier"),
                "oal": oal_val,
                "ssvc_action": ssvc_val,
                "sla_bucket": norm_sla,
                "sla_label": sla_label_val,
                "in_kev": in_kev_val,
                "epss_score": epss_val,
                "decision_status": raw_decision_status,
                "invalidated_reasons": inv_reasons,
            }
        )

    assets: List[Asset] = []
    ranked_assets: List[Dict[str, Any]] = []
    sorted_aids = sorted(
        set(asset_meta.keys()) | set(findings_by_asset.keys()),
        key=lambda a: (-asset_max_score.get(a, 0.0), a),
    )
    for rank, aid in enumerate(sorted_aids, start=1):
        host, ip, facing = asset_meta.get(aid, ("", "", False))
        f_list = findings_by_asset.get(aid, [])
        assets.append(
            Asset(
                hostname=host,
                ip_address=ip,
                asset_id=aid,
                findings=f_list,
            )
        )
        ranked_assets.append(
            {
                "asset_id": aid,
                "rank": rank,
                "score": float(asset_max_score.get(aid, 0.0) if aid in asset_max_score else 0.0),
                "score_basis": "operational",
                "inference": {"externally_facing_inferred": facing},
            }
        )

    active_count = len(global_top_findings)
    derived = DerivedContext()
    ts_now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    derived = derived.put(
        DerivedPassResult(
            meta=PassMeta(name="TopN", version="1.0", created_at_utc=ts_now),
            data={
                "assets": ranked_assets,
                "global_top_findings": global_top_findings,
            },
        )
    )
    derived = derived.put(
        DerivedPassResult(
            meta=PassMeta(name="Summary", version="1.0", created_at_utc=ts_now),
            data={"overview": {"scored_findings": active_count}},
        )
    )
    derived = derived.put(
        DerivedPassResult(
            meta=PassMeta(name="ACI", version="1.0", created_at_utc=ts_now),
            data={
                "metrics": {
                    "inferred_findings": inferred_count,
                    "coverage_ratio": (inferred_count / active_count) if active_count else 0.0,
                },
                "finding_semantics": aci_semantics,
            },
        )
    )

    scan_result = ScanResult(
        scan_metadata=ScanMetaData(
            source="duckdb-v2",
            scan_date=scan_date,
            asset_count=len(assets),
            vulnerability_count=active_count,
            source_file=str(scanner_input),
        ),
        assets=assets,
        derived=derived,
    )
    return scan_result, scanner_input


def _flush_ledger_events_to_db(db: Any, run_id: str, ctx: Any) -> int:
    services = getattr(ctx, "services", None)
    ledger = getattr(services, "ledger", None) if services is not None else None
    if ledger is None or bool(getattr(db, "read_only", False)):
        return 0
    snap = ledger.snapshot()
    rows = [asdict(entry) for entry in snap.entries]
    db.execute("DELETE FROM ledger_events WHERE run_id = ?", [run_id])
    if not rows:
        return 0
    return insert_ledger_events(db, run_id, rows)


def _append_rechained_ledger_events_to_db(db: Any, run_id: str, ctx: Any) -> int:
    """Append ctx.services.ledger events onto existing run_id ledger_events preserving hash chain."""
    services = getattr(ctx, "services", None)
    ledger = getattr(services, "ledger", None) if services is not None else None
    if ledger is None or bool(getattr(db, "read_only", False)):
        return 0
    snap = ledger.snapshot()
    if not snap.entries:
        return 0

    conn = getattr(db, "conn", db)
    last_row = conn.execute(
        "SELECT seq, entry_hash FROM ledger_events WHERE run_id = ? ORDER BY seq DESC LIMIT 1",
        [run_id],
    ).fetchone()
    next_seq = (int(last_row[0]) + 1) if last_row else 1
    prev_hash = str(last_row[1]) if (last_row and last_row[1]) else EMPTY_LEDGER_ROOT

    rows: List[Dict[str, Any]] = []
    for entry in snap.entries:
        seq = next_seq
        next_seq += 1
        why_dict = asdict(entry.why)
        hash_input = {
            "seq": seq,
            "ts": entry.ts,
            "component": entry.component,
            "event_type": entry.event_type,
            "subject_ref": entry.subject_ref,
            "why": why_dict,
            "evidence_digest": entry.evidence_digest,
            "prev_hash": prev_hash,
        }
        entry_hash = f"sha256:{sha256(_canonical_json(hash_input).encode('utf-8')).hexdigest()}"
        rows.append(
            {
                "seq": seq,
                "ts": entry.ts,
                "component": entry.component,
                "event_type": entry.event_type,
                "subject_ref": entry.subject_ref,
                "why": why_dict,
                "evidence_digest": entry.evidence_digest,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
            }
        )
        prev_hash = entry_hash
    return insert_ledger_events(db, run_id, rows)


def record_deferral_db_update(
    db: Any,
    run_id: str,
    decisions_path: Path,
    ctx: Any,
    saved_decision: Dict[str, Any],
) -> int:
    """Update runs.decisions_sha256, clear stale runs.manifest_digest, and append deferral ledger event."""
    if bool(getattr(db, "read_only", False)):
        return 0
    pfh = getattr(ctx, "pfh", None)
    digest_h = sha256()
    if pfh is not None and hasattr(pfh, "open_for_read"):
        with pfh.open_for_read(decisions_path, mode="rb", label="Decisions Config", log=False) as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest_h.update(chunk)
    else:
        with open(decisions_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest_h.update(chunk)
    decisions_sha256 = f"sha256:{digest_h.hexdigest()}"

    conn = getattr(db, "conn", db)
    conn.execute(
        "UPDATE runs SET decisions_sha256 = ?, manifest_digest = NULL WHERE run_id = ?",
        [decisions_sha256, str(run_id)],
    )

    services = getattr(ctx, "services", None)
    ledger = getattr(services, "ledger", None) if services is not None else None
    if ledger is not None:
        ledger.append_event(
            component="Triage",
            event_type="DECISION_UPSERT",
            subject_ref=f"decision:{saved_decision.get('id', '')}",
            reason_code=DecisionReasonCodes.PASS_EXECUTION_COMPLETED,
            reason_text=(
                f"Updated decision '{saved_decision.get('id', '')}' ({saved_decision.get('status', '')}) "
                f"for {saved_decision.get('cve_or_rule_id', '')} on '{saved_decision.get('asset_pattern', '')}'."
            ),
            evidence={
                "decision_id": saved_decision.get("id"),
                "status": saved_decision.get("status"),
                "cve_or_rule_id": saved_decision.get("cve_or_rule_id"),
                "asset_pattern": saved_decision.get("asset_pattern"),
                "decisions_sha256": decisions_sha256,
            },
        )
    return _append_rechained_ledger_events_to_db(db, str(run_id), ctx)


def export_v2_outputs(
    *,
    ctx: Any,
    db: Any,
    run_id: str,
    args: Any,
    diff_report: Optional[Any] = None,
    config_hashes: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Optional[Path]]:
    """Export requested v2 DuckDB artifacts (dossier, html, md, csv, json, runmanifest)."""
    from vulnparse_pin.utils import csv_exporter as _csv_exp
    from vulnparse_pin.utils import reportgen as _reportgen
    from vulnparse_pin.utils import runmanifest as _rm

    pfh = ctx.pfh
    template_dir = getattr(args, "template_dir", None)
    written: Dict[str, Optional[Path]] = {
        "json": None,
        "csv": None,
        "executive_markdown": None,
        "technical_markdown": None,
        "dossier_markdown": None,
        "dossier_html": None,
        "runmanifest": None,
    }

    output_all = getattr(args, "output_all", None)
    stem = str(Path(output_all).with_suffix("")) if output_all else None

    json_req = getattr(args, "output", None) or (f"{stem}.json" if stem else None)
    csv_req = getattr(args, "output_csv", None) or (f"{stem}.csv" if stem else None)
    md_req = getattr(args, "output_md", None) or (f"{stem}_summary.md" if stem else None)
    md_tech_req = getattr(args, "output_md_technical", None) or (f"{stem}_technical.md" if stem else None)
    html_req = getattr(args, "output_html", None)
    dossier_req = getattr(args, "output_dossier", None) or (f"{stem}_dossier" if stem and not html_req else None)
    rm_req = getattr(args, "output_runmanifest", None) or (f"{stem}_runmanifest.json" if stem else None)

    csv_sanitization = not bool(getattr(args, "no_csv_sanitize", False))
    if not csv_sanitization and not bool(getattr(args, "confirm_unsafe_csv", False)):
        raise VppError(
            "Refusing to disable CSV cell sanitization without explicit --confirm-unsafe-csv.",
            exit_code=2,
        )
    pretty_print = bool(getattr(args, "pretty_print", False))

    if json_req:
        json_path = authorize_output_path(pfh, json_req, label="JSON Output File")
        pres_mode = (
            str(getattr(args, "overlay_mode", "namespace") or "namespace")
            if getattr(args, "presentation", False)
            else "namespace"
        )
        if pres_mode == "flatten" and not getattr(args, "presentation", False):
            pres_mode = "namespace"
        export_json_fn = getattr(_reportgen, "export_duckdb_json", None)
        if callable(export_json_fn):
            invoke_duckdb_json_export(
                export_json_fn,
                db,
                run_id,
                json_path,
                presentation=pres_mode,
                pfh=pfh,
                pretty_print=pretty_print,
            )
        written["json"] = json_path

    if csv_req:
        csv_path = authorize_output_path(pfh, csv_req, label="CSV Output File")
        csv_profile = str(getattr(args, "csv_profile", "full") or "full")
        export_csv_fn = getattr(_csv_exp, "export_duckdb_csv", None)
        if callable(export_csv_fn):
            invoke_duckdb_csv_export(
                export_csv_fn,
                db,
                run_id,
                csv_path,
                profile=csv_profile,
                pfh=pfh,
                csv_sanitization=csv_sanitization,
            )
        written["csv"] = csv_path

    if dossier_req:
        _renderer = _load_renderer()
        raw_dos = str(dossier_req)
        dos_path = Path(raw_dos)
        if raw_dos.endswith(("/", os.sep)) or (dos_path.exists() and dos_path.is_dir()):
            dos_dir = authorize_output_dir(pfh, dos_path, label="Dossier Output Directory")
            bundle = _renderer.export_dossier_bundle(
                db,
                run_id,
                dos_dir,
                diff_report=diff_report,
                template_dir=template_dir,
                pfh=pfh,
            )
            written["dossier_markdown"] = Path(bundle["markdown"])
            written["dossier_html"] = Path(bundle["html"])
        else:
            md_target = dos_path.with_suffix(".md")
            html_target = dos_path.with_suffix(".html")
            md_text = _renderer.render_dossier_markdown(
                db, run_id, diff_report=diff_report, template_dir=template_dir
            )
            html_text = _renderer.render_dossier_html(
                db, run_id, diff_report=diff_report, template_dir=template_dir
            )
            written["dossier_markdown"] = write_text_via_pfh(
                pfh, md_target, md_text, label="Dossier Markdown"
            )
            written["dossier_html"] = write_text_via_pfh(
                pfh, html_target, html_text, label="Dossier HTML"
            )

    if html_req:
        _renderer = _load_renderer()
        html_text = _renderer.render_dossier_html(
            db, run_id, diff_report=diff_report, template_dir=template_dir
        )
        written["dossier_html"] = write_text_via_pfh(
            pfh, Path(html_req), html_text, label="HTML Dossier Report"
        )

    if md_req:
        _renderer = _load_renderer()
        md_text = _renderer.render_executive_roadmap_markdown(
            db, run_id, diff_report=diff_report, template_dir=template_dir
        )
        written["executive_markdown"] = write_text_via_pfh(
            pfh, Path(md_req), md_text, label="Markdown Report"
        )

    if md_tech_req:
        _renderer = _load_renderer()
        md_tech_text = _renderer.render_dossier_markdown(
            db, run_id, diff_report=diff_report, template_dir=template_dir
        )
        written["technical_markdown"] = write_text_via_pfh(
            pfh, Path(md_tech_req), md_tech_text, label="Markdown Technical Report"
        )

    services = getattr(ctx, "services", None)
    webhook_cfg = getattr(services, "webhook_config", None) if services is not None else None
    if webhook_cfg is not None and bool(getattr(webhook_cfg, "enabled", False)):
        validate_webhook_runtime_config(ctx)
        webhook_scan, scanner_input = _build_v2_webhook_scan_result(db, run_id, args)
        webhook_outputs = {
            "json": written["json"],
            "csv": written["csv"],
            "md": written["executive_markdown"] or written["dossier_markdown"],
            "md_technical": written["technical_markdown"] or written["dossier_markdown"],
            "runmanifest": Path(rm_req) if rm_req else None,
        }
        webhook_summary = emit_configured_webhooks(
            ctx=ctx,
            scan_result=webhook_scan,
            scanner_input=scanner_input,
            output_paths=webhook_outputs,
        )
        ledger = getattr(services, "ledger", None)
        if ledger is not None:
            sent_n = int(webhook_summary.get("sent", 0) or 0)
            failed_n = int(webhook_summary.get("failed", 0) or 0)
            spooled_n = int(webhook_summary.get("spooled", 0) or 0)
            skipped_n = int(webhook_summary.get("skipped", 0) or 0)
            ledger.append_event(
                component="Webhook",
                event_type="WEBHOOK_DELIVERY",
                subject_ref=f"run:{run_id}",
                reason_code=(
                    DecisionReasonCodes.WEBHOOK_EMIT_SUCCEEDED
                    if failed_n == 0
                    else DecisionReasonCodes.WEBHOOK_EMIT_FAILED
                ),
                reason_text=(
                    f"Webhook delivery summary: sent={sent_n}, failed={failed_n}, "
                    f"spooled={spooled_n}, skipped={skipped_n}."
                ),
                evidence={
                    "sent": sent_n,
                    "failed": failed_n,
                    "spooled": spooled_n,
                    "skipped": skipped_n,
                },
            )
            _flush_ledger_events_to_db(db, run_id, ctx)
        if not bool(getattr(webhook_cfg, "allow_spool", True)) and int(webhook_summary.get("failed", 0) or 0) > 0:
            raise VppError("Webhook delivery failed and spooling is disabled.", exit_code=1)

    if rm_req:
        rm_path = authorize_output_path(pfh, rm_req, label="RunManifest Output File")
        outputs_meta = {
            "json": str(written["json"]) if written["json"] else None,
            "csv": str(written["csv"]) if written["csv"] else None,
            "executive_markdown": str(written["executive_markdown"] or written["dossier_markdown"])
            if (written["executive_markdown"] or written["dossier_markdown"])
            else None,
            "technical_markdown": str(written["technical_markdown"] or written["dossier_markdown"])
            if (written["technical_markdown"] or written["dossier_markdown"])
            else None,
            "dossier_markdown": str(written["dossier_markdown"]) if written["dossier_markdown"] else None,
            "dossier_html": str(written["dossier_html"]) if written["dossier_html"] else None,
        }
        build_rm_db = getattr(_rm, "build_runmanifest_from_db", None)
        if callable(build_rm_db):
            manifest = build_rm_db(
                db,
                run_id,
                config_hashes=config_hashes,
                outputs=outputs_meta,
                mode=str(getattr(args, "runmanifest_mode", "compact") or "compact"),
            )
            write_runmanifest(ctx, manifest, rm_path)
            digest = (manifest.get("verification") or {}).get("manifest_digest")
            if digest:
                try:
                    db.execute("UPDATE runs SET manifest_digest = ? WHERE run_id = ?", [digest, run_id])
                except Exception:
                    pass
            written["runmanifest"] = rm_path

    return written


def run_output_and_summary(
    args,
    ctx,
    scan_result,
    sources: dict,
    json_output,
    csv_output,
    md_output,
    md_tech_output,
    runmanifest_output,
    scanner_input: Path,
    csv_sanitization_enabled: bool,
    kev_source,
    epss_source,
    start_time: float,
    write_output_fn: Callable[..., Any],
    print_summary_banner_fn: Callable[..., Any],
    json_default_fn: Callable[..., Any],
    format_runtime_fn: Callable[[float], str],
) -> int:
    logger = ctx.logger

    if args.output or args.output_csv:
        logger.phase("Output")

    if args.output_all:
        out = _json_payload_for_output(args, scan_result)
        write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)
        export_to_csv(
            ctx,
            scan_result,
            csv_path=csv_output,
            csv_sanitization=csv_sanitization_enabled,
            csv_profile=getattr(args, "csv_profile", "full"),
        )
        generate_markdown_report(ctx, scan_result, md_output, report_type="executive", args=args)
        generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical", args=args)
    else:
        if args.output:
            out = _json_payload_for_output(args, scan_result)
            write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)

        if args.output_csv:
            export_to_csv(
                ctx,
                scan_result,
                csv_path=csv_output,
                csv_sanitization=csv_sanitization_enabled,
                csv_profile=getattr(args, "csv_profile", "full"),
            )

        if md_output:
            generate_markdown_report(ctx, scan_result, md_output, report_type="executive", args=args)

        if md_tech_output:
            generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical", args=args)

    emit_configured_webhooks(
        ctx=ctx,
        scan_result=scan_result,
        scanner_input=scanner_input,
        output_paths={
            "json": json_output,
            "csv": csv_output,
            "md": md_output,
            "md_technical": md_tech_output,
            "runmanifest": runmanifest_output,
        },
    )

    if runmanifest_output:
        runmanifest = build_runmanifest(
            ctx=ctx,
            _args=args,
            scan_result=scan_result,
            sources=sources,
            scanner_input=scanner_input,
            output_paths={
                "json": json_output,
                "csv": csv_output,
                "md": md_output,
                "md_technical": md_tech_output,
            },
        )
        write_runmanifest(ctx, runmanifest, runmanifest_output)
        logger.print_success(f"Run manifest generated: {runmanifest_output}", label="RunManifest")

    if args.pretty_print and not args.output:
        logger.print_info("Displaying results to console...")
        out = _json_payload_for_output(args, scan_result)
        print(json.dumps(out, indent=4, default=json_default_fn))

    if kev_source or epss_source:
        logger.phase("Summary")
        print_summary_banner_fn(ctx, scan_result, json_output if json_output else None, sources=sources)

    total_runtime = time.time() - start_time
    print(f"Total runtime: {format_runtime_fn(total_runtime)}")
    return 0
