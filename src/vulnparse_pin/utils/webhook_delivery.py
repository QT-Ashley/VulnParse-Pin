# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

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
from vulnparse_pin.core.config_validator import (
    validate_webhook_https_url,
    validate_webhook_resolved_dns,
)
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


_SLA_ALIASES = {
    "3-day": "3-day",
    "3d": "3-day",
    "3_day": "3-day",
    "3day": "3-day",
    "14-day": "14-day",
    "14d": "14-day",
    "14_day": "14-day",
    "14day": "14-day",
    "60-day": "60-day",
    "60d": "60-day",
    "60_day": "60-day",
    "60day": "60-day",
    "defer": "defer",
}


def _normalize_sla_bucket(value: Optional[str]) -> str:
    raw = str(value or "").strip().lower()
    return _SLA_ALIASES.get(raw, raw)


def _normalize_priority_tier(value: Optional[str]) -> str:
    raw = str(value or "").strip().upper()
    if raw in {"P1", "P1B", "P2", "P3", "P4"}:
        return "P1b" if raw == "P1B" else raw
    return ""


def _resolve_priority_tier(
    *,
    lane_name: str,
    risk_band: str = "",
    cisa_kev: bool = False,
    exploit_available: bool = False,
    externally_facing: bool = False,
    explicit_tier: Optional[str] = None,
) -> str:
    normalized_explicit = _normalize_priority_tier(explicit_tier)
    if normalized_explicit in {"P1", "P2", "P3", "P4"}:
        return normalized_explicit

    lane = str(lane_name or "").strip()
    band = str(risk_band or "").strip().lower()
    if lane == "OAL-1 Immediate Exploitable" or (
        band == "critical" and (cisa_kev or exploit_available) and externally_facing
    ):
        return "P1"
    if lane == "OAL-2 High-Confidence Chain Path" or cisa_kev or (
        band in {"critical", "high"} and lane == "OAL-3 Remaining High Risk"
    ):
        return "P2"
    if band == "medium" or (lane == "OAL-3 Remaining High Risk" and band not in {"low", "informational", "info"}):
        return "P3"
    if band in {"low", "informational", "info"}:
        return "P4"
    return "P3"


def _resolve_sla_bucket(
    *,
    lane_name: str,
    risk_band: str = "",
    cisa_kev: bool = False,
    exploit_available: bool = False,
    externally_facing: bool = False,
    explicit_sla: Optional[str] = None,
) -> str:
    normalized_explicit = _normalize_sla_bucket(explicit_sla)
    if normalized_explicit in {"3-day", "14-day", "60-day", "defer"}:
        return normalized_explicit

    lane = str(lane_name or "").strip()
    band = str(risk_band or "").strip().lower()
    if cisa_kev and externally_facing:
        return "3-day"
    if cisa_kev or (
        externally_facing and (exploit_available or lane.startswith("OAL-1") or lane.startswith("OAL-2"))
    ):
        return "14-day"
    if band in {"critical", "high", "medium"} or exploit_available or lane.startswith("OAL-2"):
        return "60-day"
    return "defer"


def _lane_matches(
    filter_name: str,
    lane_name: str,
    *,
    risk_band: str = "",
    cisa_kev: bool = False,
    exploit_available: bool = False,
    externally_facing: bool = False,
    priority_tier: Optional[str] = None,
    sla_bucket: Optional[str] = None,
) -> bool:
    raw_filter = str(filter_name or "").strip()
    lowered = raw_filter.lower()
    if not lowered or lowered == "all":
        return True

    lane = str(lane_name or "").strip()

    # OAL lane matching (short OAL-1/2/3 and full canonical names)
    if lowered in {"oal-1", "oal-1 immediate exploitable"}:
        return lane.startswith("OAL-1")
    if lowered in {"oal-2", "oal-2 high-confidence chain path"}:
        return lane.startswith("OAL-2")
    if lowered in {"oal-3", "oal-3 remaining high risk"}:
        return lane.startswith("OAL-3")

    # Legacy P1b specifically targets OAL-2
    if lowered == "p1b":
        return lane == "OAL-2 High-Confidence Chain Path"

    # BOD 26-04 SLA buckets
    sla_target = _normalize_sla_bucket(lowered)
    if sla_target in {"3-day", "14-day", "60-day"}:
        resolved_sla = _resolve_sla_bucket(
            lane_name=lane,
            risk_band=risk_band,
            cisa_kev=cisa_kev,
            exploit_available=exploit_available,
            externally_facing=externally_facing,
            explicit_sla=sla_bucket,
        )
        return resolved_sla == sla_target

    # Priority tiers P1/P2/P3/P4
    tier_target = _normalize_priority_tier(raw_filter)
    if tier_target in {"P1", "P2", "P3", "P4"}:
        if not priority_tier and not risk_band and not cisa_kev and not exploit_available and not externally_facing:
            # Backward compatibility for simple 2-arg lane checks
            if tier_target == "P1":
                return lane == "OAL-1 Immediate Exploitable"
            if tier_target == "P2":
                return lane == "OAL-3 Remaining High Risk"
            return False

        resolved_tier = _resolve_priority_tier(
            lane_name=lane,
            risk_band=risk_band,
            cisa_kev=cisa_kev,
            exploit_available=exploit_available,
            externally_facing=externally_facing,
            explicit_tier=priority_tier,
        )
        return resolved_tier == tier_target

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
        risk_band = str(finding_ref.get("risk_band", ""))
        exploit_available = bool(getattr(finding_obj, "exploit_available", False)) if finding_obj is not None else False
        cisa_kev = bool(getattr(finding_obj, "cisa_kev", False)) if finding_obj is not None else False
        externally_facing = bool(asset_exposure_map.get(asset_id, False))
        explicit_tier = finding_ref.get("priority_tier") or (
            getattr(finding_obj, "priority_tier", None) if finding_obj is not None else None
        )
        explicit_sla = (
            finding_ref.get("sla_bucket")
            or finding_ref.get("bod_26_04_sla")
            or (
                getattr(finding_obj, "sla_bucket", None)
                or getattr(finding_obj, "bod_26_04_sla", None)
                if finding_obj is not None
                else None
            )
        )
        lane_name = _operational_action_lane_for_finding(
            risk_band=risk_band,
            exploit_available=exploit_available,
            cisa_kev=cisa_kev,
            chain_candidates=chain_candidates,
            confidence=confidence,
            externally_facing=externally_facing,
            policy=triage_policy,
        )
        if not _lane_matches(
            str(getattr(endpoint, "oal_filter", "all")),
            lane_name,
            risk_band=risk_band,
            cisa_kev=cisa_kev,
            exploit_available=exploit_available,
            externally_facing=externally_facing,
            priority_tier=explicit_tier,
            sla_bucket=explicit_sla,
        ):
            continue
        priority_tier = _resolve_priority_tier(
            lane_name=lane_name,
            risk_band=risk_band,
            cisa_kev=cisa_kev,
            exploit_available=exploit_available,
            externally_facing=externally_facing,
            explicit_tier=explicit_tier,
        )
        sla_bucket = _resolve_sla_bucket(
            lane_name=lane_name,
            risk_band=risk_band,
            cisa_kev=cisa_kev,
            exploit_available=exploit_available,
            externally_facing=externally_facing,
            explicit_sla=explicit_sla,
        )
        item: dict[str, Any] = {
            "finding_id": finding_id,
            "asset_id": asset_id,
            "title": str(getattr(finding_obj, "title", "") or ""),
            "score": float(finding_ref.get("score", 0.0) or 0.0),
            "risk_band": str(finding_ref.get("risk_band", "") or ""),
            "lane": lane_name,
            "priority_tier": priority_tier,
            "sla_bucket": sla_bucket,
            "port": finding_ref.get("port"),
            "protocol": finding_ref.get("proto"),
            "exploit_available": exploit_available,
            "cisa_kev": cisa_kev,
        }
        _sentinel = object()
        for field_name in (
            "oal",
            "ssvc_action",
            "sla_label",
            "operational_score",
            "in_kev",
            "epss_score",
            "decision_status",
            "invalidated_reasons",
        ):
            if field_name in finding_ref:
                item[field_name] = finding_ref[field_name]
            elif finding_obj is not None:
                obj_val = getattr(finding_obj, field_name, _sentinel)
                if obj_val is not _sentinel and (field_name != "epss_score" or obj_val is not None):
                    item[field_name] = obj_val
        filtered_top_findings.append(item)

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


def _resolve_signing_secret(secret_env: str) -> str:
    raw_secret = os.getenv(secret_env)
    if not raw_secret:
        raise RuntimeError(f"Webhook signing secret environment variable is not set: {secret_env}")
    return raw_secret


def _sign_body(
    secret: str,
    body_bytes: bytes | str,
    timestamp: Optional[str] = None,
    nonce: Optional[str] = None,
) -> str:
    if not secret:
        raise RuntimeError("Webhook signing secret must not be empty.")
    payload_bytes = (
        bytes(body_bytes)
        if isinstance(body_bytes, (bytes, bytearray))
        else str(body_bytes).encode("utf-8")
    )
    if timestamp is not None or nonce is not None:
        ts = "" if timestamp is None else str(timestamp)
        nc = "" if nonce is None else str(nonce)
        signing_input = f"{ts}.{nc}.".encode("utf-8") + payload_bytes
    else:
        signing_input = payload_bytes
    digest = hmac.new(secret.encode("utf-8"), signing_input, sha256).hexdigest()
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
        body_bytes = body.encode("utf-8")
        body_size = len(body_bytes)
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
            validate_webhook_https_url(str(getattr(endpoint, "url", "") or ""))
            if body_size > int(getattr(webhook_cfg, "max_payload_bytes", 262144)):
                raise RuntimeError("Webhook payload exceeds configured max_payload_bytes.")
            secret = _resolve_signing_secret(
                str(getattr(webhook_cfg, "signing_key_env", "VP_WEBHOOK_HMAC_KEY"))
            )
            signature = _sign_body(secret, body_bytes, timestamp, nonce)
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"VulnParse-Pin/{getattr(__import__('vulnparse_pin'), '__version__', 'unknown')}",
                "X-VPP-Event": "vpp.topn.summary",
                "X-VPP-Timestamp": timestamp,
                "X-VPP-Nonce": nonce,
                "X-VPP-Key-Id": str(getattr(webhook_cfg, "key_id", "primary")),
                "X-VPP-Signature": signature,
            }
            max_retries = max(int(getattr(webhook_cfg, "max_retries", 2)), 0)
            last_exc: Exception | None = None
            response = None
            for attempt in range(max_retries + 1):
                try:
                    validate_webhook_resolved_dns(str(endpoint.url))
                    response = requests.post(
                        endpoint.url,
                        data=body_bytes,
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
                    last_exc = None
                    break
                except (requests.RequestException, RuntimeError, ValueError, OSError) as exc:
                    last_exc = exc
                    if attempt >= max_retries:
                        raise
            if response is None or last_exc is not None:
                raise last_exc or RuntimeError("Webhook delivery failed without a response.")
            summary["sent"] += 1
            logger.print_success(f"Webhook delivered: {endpoint.url}", label="Webhook")
            if ledger is not None:
                ledger.append_event(
                    component="Webhook",
                    event_type="emit_success",
                    subject_ref=f"webhook:{endpoint.url}",
                    reason_code=DecisionReasonCodes.WEBHOOK_EMIT_SUCCEEDED,
                    reason_text="Webhook delivery completed successfully.",
                    evidence={
                        "endpoint": endpoint.url,
                        "status_code": getattr(response, "status_code", None),
                        "attempts": attempt + 1,
                    },
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