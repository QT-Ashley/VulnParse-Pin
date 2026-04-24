from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any, Dict, Optional

import requests

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.utils.markdown_report import _operational_action_lane_for_finding, _resolve_triage_policy_from_ctx
from vulnparse_pin.utils.runmanifest import _canonical_json


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _coerce_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if is_dataclass(value):
        coerced = asdict(value)
        return coerced if isinstance(coerced, dict) else {}
    if hasattr(value, "__dict__"):
        return dict(getattr(value, "__dict__", {}))
    return {}


def _finding_lookup(scan_result: Any) -> dict[str, Any]:
    lookup: dict[str, Any] = {}
    for asset in getattr(scan_result, "assets", []) or []:
        for finding in getattr(asset, "findings", []) or []:
            finding_id = str(getattr(finding, "finding_id", "") or "").strip()
            if finding_id:
                lookup[finding_id] = finding
    return lookup


def _asset_lookup(scan_result: Any) -> dict[str, Any]:
    lookup: dict[str, Any] = {}
    for asset in getattr(scan_result, "assets", []) or []:
        asset_id = str(getattr(asset, "asset_id", "") or "").strip()
        if asset_id:
            lookup[asset_id] = asset
    return lookup


def _lane_matches(filter_name: str, lane_name: str) -> bool:
    if filter_name == "all":
        return True
    lane = str(lane_name or "").strip()
    if filter_name == "P1":
        return lane == "OAL-1 Immediate Exploitable"
    if filter_name == "P1b":
        return lane == "OAL-2 High-Confidence Chain Path"
    if filter_name == "P2":
        return lane == "OAL-3 Remaining High Risk"
    return False


def _build_compact_payload(
    *,
    ctx: Any,
    scan_result: Any,
    scanner_input: Path,
    output_paths: Dict[str, Optional[Path]],
    endpoint: Any,
) -> dict[str, Any]:
    derived = getattr(scan_result, "derived", None)
    getter = getattr(derived, "get", None)
    topn_result = getter("TopN@1.0") if callable(getter) else None
    summary_result = getter("Summary@1.0") if callable(getter) else None
    aci_result = getter("ACI@1.0") if callable(getter) else None

    topn_data = _coerce_mapping(getattr(topn_result, "data", None))
    summary_data = _coerce_mapping(getattr(summary_result, "data", None))
    aci_data = _coerce_mapping(getattr(aci_result, "data", None))

    ranked_assets = topn_data.get("assets", []) or []
    global_top_findings = topn_data.get("global_top_findings", []) or []
    aci_findings = aci_data.get("finding_semantics", {}) if isinstance(aci_data.get("finding_semantics"), dict) else {}
    triage_policy = _resolve_triage_policy_from_ctx(ctx)

    asset_lookup = _asset_lookup(scan_result)
    finding_lookup = _finding_lookup(scan_result)
    asset_exposure_map: dict[str, bool] = {}
    for ranked in ranked_assets:
        if not isinstance(ranked, dict):
            continue
        asset_id = str(ranked.get("asset_id", "") or "").strip()
        inference = ranked.get("inference", {}) if isinstance(ranked.get("inference"), dict) else {}
        if asset_id:
            asset_exposure_map[asset_id] = bool(inference.get("externally_facing_inferred", False))

    filtered_top_findings: list[dict[str, Any]] = []
    for finding_ref in global_top_findings:
        if not isinstance(finding_ref, dict):
            continue
        finding_id = str(finding_ref.get("finding_id", "") or "").strip()
        asset_id = str(finding_ref.get("asset_id", "") or "").strip()
        if not finding_id:
            continue
        finding_obj = finding_lookup.get(finding_id)
        aci_rec = aci_findings.get(finding_id, {}) if isinstance(aci_findings.get(finding_id), dict) else {}
        chain_candidates = [str(value) for value in (aci_rec.get("chain_candidates", []) or [])]
        confidence = float(aci_rec.get("confidence", 0.0) or 0.0)
        lane_name = _operational_action_lane_for_finding(
            risk_band=str(finding_ref.get("risk_band", "")),
            exploit_available=bool(getattr(finding_obj, "exploit_available", False)) if finding_obj is not None else False,
            cisa_kev=bool(getattr(finding_obj, "cisa_kev", False)) if finding_obj is not None else False,
            chain_candidates=chain_candidates,
            confidence=confidence,
            externally_facing=bool(asset_exposure_map.get(asset_id, False)),
            policy=triage_policy,
        )
        if not _lane_matches(str(getattr(endpoint, "oal_filter", "all")), lane_name):
            continue
        filtered_top_findings.append(
            {
                "finding_id": finding_id,
                "asset_id": asset_id,
                "title": str(getattr(finding_obj, "title", "") or ""),
                "score": float(finding_ref.get("score", 0.0) or 0.0),
                "risk_band": str(finding_ref.get("risk_band", "") or ""),
                "lane": lane_name,
                "port": finding_ref.get("port"),
                "protocol": finding_ref.get("proto"),
                "exploit_available": bool(getattr(finding_obj, "exploit_available", False)) if finding_obj is not None else False,
                "cisa_kev": bool(getattr(finding_obj, "cisa_kev", False)) if finding_obj is not None else False,
            }
        )

    top_assets: list[dict[str, Any]] = []
    for ranked in ranked_assets[:10]:
        if not isinstance(ranked, dict):
            continue
        asset_id = str(ranked.get("asset_id", "") or "").strip()
        asset_obj = asset_lookup.get(asset_id)
        top_assets.append(
            {
                "asset_id": asset_id,
                "hostname": str(getattr(asset_obj, "hostname", "") or ""),
                "ip_address": str(getattr(asset_obj, "ip_address", "") or ""),
                "rank": int(ranked.get("rank", 0) or 0),
                "score": float(ranked.get("score", 0.0) or 0.0),
                "score_basis": str(ranked.get("score_basis", "") or ""),
                "externally_facing": bool((ranked.get("inference", {}) or {}).get("externally_facing_inferred", False)) if isinstance(ranked.get("inference"), dict) else False,
            }
        )

    overview = summary_data.get("overview", {}) if isinstance(summary_data.get("overview"), dict) else {}
    aci_metrics = aci_data.get("metrics", {}) if isinstance(aci_data.get("metrics"), dict) else {}
    services = getattr(ctx, "services", None)
    ledger = getattr(services, "ledger", None) if services is not None else None
    chain_root = ledger.snapshot().chain_root if ledger is not None else None

    return {
        "schema_version": "v1",
        "event_type": "vpp.topn.summary",
        "sent_at": _utc_now_z(),
        "tool_version": getattr(__import__("vulnparse_pin"), "__version__", None),
        "scanner_input_name": scanner_input.name,
        "decision_chain_root_pre_emit": chain_root,
        "oal_filter_applied": str(getattr(endpoint, "oal_filter", "all")),
        "asset_count": int(getattr(getattr(scan_result, "scan_metadata", None), "asset_count", len(getattr(scan_result, "assets", []) or [])) or 0),
        "finding_count": int(getattr(getattr(scan_result, "scan_metadata", None), "vulnerability_count", 0) or 0),
        "scored_count": int(overview.get("scored_findings", 0) or 0),
        "top_findings": filtered_top_findings,
        "top_assets": top_assets,
        "aci_summary": {
            "inferred_findings": int(aci_metrics.get("inferred_findings", 0) or 0),
            "coverage_ratio": float(aci_metrics.get("coverage_ratio", 0.0) or 0.0),
        },
        "artifact_refs": {
            key: path.name if isinstance(path, Path) else None
            for key, path in output_paths.items()
        },
    }


def _sign_body(secret_env: str, body: str) -> str:
    raw_secret = os.getenv(secret_env)
    if not raw_secret:
        raise RuntimeError(f"Webhook signing secret environment variable is not set: {secret_env}")
    digest = hmac.new(raw_secret.encode("utf-8"), body.encode("utf-8"), sha256).hexdigest()
    return f"sha256={digest}"


def _spool_delivery(ctx: Any, *, payload: dict[str, Any], endpoint: Any, error_text: str) -> Path:
    services = getattr(ctx, "services", None)
    webhook_cfg = getattr(services, "webhook_config", None) if services is not None else None
    output_dir = Path(ctx.paths.output_dir)
    spool_subdir = getattr(webhook_cfg, "spool_subdir", "webhook_spool") if webhook_cfg is not None else "webhook_spool"
    nonce = secrets.token_hex(8)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    spool_path = ctx.pfh.ensure_writable_file(
        output_dir / spool_subdir / f"webhook_{ts}_{nonce}.json",
        label="Webhook Spool File",
        create_parents=True,
        overwrite=True,
    )
    spool_payload = {
        "spooled_at": _utc_now_z(),
        "endpoint": str(getattr(endpoint, "url", "") or ""),
        "oal_filter": str(getattr(endpoint, "oal_filter", "all") or "all"),
        "error": error_text,
        "payload": payload,
    }
    with ctx.pfh.open_for_write(spool_path, mode="w", encoding="utf-8", label="Webhook Spool File") as handle:
        json.dump(spool_payload, handle, indent=2)
        handle.write("\n")
    return Path(spool_path)


def emit_configured_webhooks(
    *,
    ctx: Any,
    scan_result: Any,
    scanner_input: Path,
    output_paths: Dict[str, Optional[Path]],
) -> dict[str, int]:
    services = getattr(ctx, "services", None)
    webhook_cfg = getattr(services, "webhook_config", None) if services is not None else None
    ledger = getattr(services, "ledger", None) if services is not None else None

    if webhook_cfg is None or not getattr(webhook_cfg, "enabled", False):
        if ledger is not None:
            ledger.append_event(
                component="Webhook",
                event_type="emit_skip",
                subject_ref="webhook:disabled",
                reason_code=DecisionReasonCodes.WEBHOOK_EMIT_SKIPPED_DISABLED,
                reason_text="Webhook delivery is disabled by configuration.",
                evidence={"enabled": False},
            )
        return {"sent": 0, "failed": 0, "spooled": 0, "skipped": 1}

    summary = {"sent": 0, "failed": 0, "spooled": 0, "skipped": 0}
    logger = ctx.logger
    for endpoint in getattr(webhook_cfg, "endpoints", ()):
        if not getattr(endpoint, "enabled", False):
            continue

        payload = _build_compact_payload(
            ctx=ctx,
            scan_result=scan_result,
            scanner_input=scanner_input,
            output_paths=output_paths,
            endpoint=endpoint,
        )
        if not payload.get("top_findings"):
            summary["skipped"] += 1
            if ledger is not None:
                ledger.append_event(
                    component="Webhook",
                    event_type="emit_skip",
                    subject_ref=f"webhook:{endpoint.url}",
                    reason_code=DecisionReasonCodes.WEBHOOK_EMIT_SKIPPED_POLICY,
                    reason_text="Webhook payload was empty after applying the lane filter.",
                    evidence={"endpoint": endpoint.url, "oal_filter": endpoint.oal_filter},
                )
            continue

        body = _canonical_json(payload)
        body_size = len(body.encode("utf-8"))
        timestamp = _utc_now_z()
        nonce = secrets.token_hex(16)
        if ledger is not None:
            ledger.append_event(
                component="Webhook",
                event_type="emit_start",
                subject_ref=f"webhook:{endpoint.url}",
                reason_code=DecisionReasonCodes.WEBHOOK_EMIT_STARTED,
                reason_text="Attempting secure webhook delivery.",
                evidence={"endpoint": endpoint.url, "oal_filter": endpoint.oal_filter, "payload_bytes": body_size},
            )

        try:
            if body_size > int(getattr(webhook_cfg, "max_payload_bytes", 262144)):
                raise RuntimeError("Webhook payload exceeds configured max_payload_bytes.")
            signature = _sign_body(str(getattr(webhook_cfg, "signing_key_env", "VP_WEBHOOK_HMAC_KEY")), body)
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"VulnParse-Pin/{getattr(__import__('vulnparse_pin'), '__version__', 'unknown')}",
                "X-VPP-Event": "vpp.topn.summary",
                "X-VPP-Timestamp": timestamp,
                "X-VPP-Nonce": nonce,
                "X-VPP-Key-Id": str(getattr(webhook_cfg, "key_id", "primary")),
                "X-VPP-Signature": signature,
            }
            response = requests.post(
                endpoint.url,
                data=body.encode("utf-8"),
                headers=headers,
                timeout=(
                    int(getattr(webhook_cfg, "connect_timeout_seconds", 3)),
                    int(getattr(webhook_cfg, "read_timeout_seconds", 5)),
                ),
                allow_redirects=False,
            )
            if str(getattr(response, "url", endpoint.url)) != str(endpoint.url):
                raise RuntimeError("Webhook delivery encountered an unexpected redirect target.")
            response.raise_for_status()
            summary["sent"] += 1
            logger.print_success(f"Webhook delivered: {endpoint.url}", label="Webhook")
            if ledger is not None:
                ledger.append_event(
                    component="Webhook",
                    event_type="emit_success",
                    subject_ref=f"webhook:{endpoint.url}",
                    reason_code=DecisionReasonCodes.WEBHOOK_EMIT_SUCCEEDED,
                    reason_text="Webhook delivery completed successfully.",
                    evidence={"endpoint": endpoint.url, "status_code": getattr(response, "status_code", None)},
                )
        except (requests.RequestException, RuntimeError, ValueError, OSError) as exc:
            summary["failed"] += 1
            logger.print_warning(f"Webhook delivery failed: {endpoint.url} ({exc})", label="Webhook")
            spool_path = None
            if bool(getattr(webhook_cfg, "allow_spool", True)):
                spool_path = _spool_delivery(ctx, payload=payload, endpoint=endpoint, error_text=str(exc))
                summary["spooled"] += 1
                if ledger is not None:
                    ledger.append_event(
                        component="Webhook",
                        event_type="emit_spooled",
                        subject_ref=f"webhook:{endpoint.url}",
                        reason_code=DecisionReasonCodes.WEBHOOK_EMIT_SPOOLED_FOR_RETRY,
                        reason_text="Webhook delivery failed and payload was spooled for later replay.",
                        evidence={"endpoint": endpoint.url, "spool_path": str(spool_path)},
                    )
            if ledger is not None:
                ledger.append_event(
                    component="Webhook",
                    event_type="emit_failure",
                    subject_ref=f"webhook:{endpoint.url}",
                    reason_code=DecisionReasonCodes.WEBHOOK_EMIT_FAILED,
                    reason_text="Webhook delivery failed.",
                    evidence={"endpoint": endpoint.url, "error": str(exc), "spooled": spool_path is not None},
                )

    return summary