# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

"""
Markdown report generator for executive and technical audiences.

"""

from datetime import datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.io.pfhandler import PathLike


def _ghsa_reference_metrics(scan: Any) -> tuple[int, int]:
    """Return (findings_with_ghsa_reference, total_ghsa_references)."""
    if scan is None:
        return 0, 0

    findings_with_ghsa = 0
    total_ghsa_refs = 0
    assets = getattr(scan, "assets", []) or []
    for asset in assets:
        findings = getattr(asset, "findings", []) or []
        for finding in findings:
            refs = getattr(finding, "references", []) or []
            ghsa_refs = [r for r in refs if "GHSA-" in str(r)]
            if ghsa_refs:
                findings_with_ghsa += 1
                total_ghsa_refs += len(ghsa_refs)
    return findings_with_ghsa, total_ghsa_refs


_ACI_STRONG_SEMANTIC_TERMS = (
    "remote code execution",
    "rce",
    "command injection",
    "sql injection",
    "authentication bypass",
    "credential",
    "password",
    "hash",
    "information disclosure",
    "sensitive data",
    "leak",
    "exploit",
)


def _enrichment_source_status(args: Any) -> dict[str, tuple[bool, str]]:
    """Return enrichment source status keyed by source name."""
    if args is None:
        return {
            "KEV": (True, "Status unavailable (no runtime args provided)"),
            "EPSS": (True, "Status unavailable (no runtime args provided)"),
            "Exploit-DB": (True, "Status unavailable (no runtime args provided)"),
            "NVD": (True, "Status unavailable (no runtime args provided)"),
            "GHSA": (True, "Status unavailable (no runtime args provided)"),
        }

    kev_enabled = not bool(getattr(args, "no_kev", False))
    epss_enabled = not bool(getattr(args, "no_epss", False))
    exploit_enabled = not bool(getattr(args, "no_exploit", False))
    nvd_enabled = not bool(getattr(args, "no_nvd", False))
    ghsa_value = getattr(args, "ghsa", None)
    ghsa_enabled = ghsa_value is not None

    return {
        "KEV": (kev_enabled, "Enabled" if kev_enabled else "Disabled by CLI (--no-kev)"),
        "EPSS": (epss_enabled, "Enabled" if epss_enabled else "Disabled by CLI (--no-epss)"),
        "Exploit-DB": (exploit_enabled, "Enabled" if exploit_enabled else "Disabled by CLI (--no-exploit)"),
        "NVD": (nvd_enabled, "Enabled" if nvd_enabled else "Disabled by CLI (--no-nvd)"),
        "GHSA": (ghsa_enabled, "Enabled" if ghsa_enabled else "Disabled (no --ghsa flag)"),
    }


def _scan_contains_strong_aci_terms(scan: Any) -> bool:
    if scan is None:
        return False

    for asset in getattr(scan, "assets", []) or []:
        for finding in getattr(asset, "findings", []) or []:
            for value in (
                getattr(finding, "title", None),
                getattr(finding, "description", None),
                getattr(finding, "plugin_output", None),
            ):
                if not isinstance(value, str):
                    continue
                lowered = value.lower()
                if any(term in lowered for term in _ACI_STRONG_SEMANTIC_TERMS):
                    return True
    return False


def _aci_zero_inference_diagnostics(scan: Any, args: Any, aci_metrics: dict[str, Any]) -> list[str]:
    if not aci_metrics.get("available"):
        return []
    if int(aci_metrics.get("inferred_findings", 0) or 0) > 0:
        return []

    diagnostics = ["No findings met the ACI inference threshold for this run."]

    source_status = _enrichment_source_status(args)
    disabled_sources = [name for name, status in source_status.items() if not status[0]]
    if disabled_sources:
        diagnostics.append(
            "Enrichment inputs were disabled for: " + ", ".join(disabled_sources) + "."
        )

    if not _scan_contains_strong_aci_terms(scan):
        diagnostics.append(
            "Finding text did not contain stronger exploit semantics such as remote code execution, injection, auth bypass, credential, leak, or exploit markers."
        )

    return diagnostics


def _aci_metrics_snapshot(scan: Any) -> dict[str, Any]:
    """Return normalized ACI metric snapshot with safe defaults."""
    snapshot = {
        "available": False,
        "total_findings": 0,
        "inferred_findings": 0,
        "coverage_ratio": 0.0,
        "uplifted_findings": 0,
        "capabilities_detected": {},
        "chain_candidates_detected": {},
        "confidence_buckets": {"low": 0, "medium": 0, "high": 0},
    }
    if scan is None:
        return snapshot

    derived = getattr(scan, "derived", None)
    if derived is None:
        return snapshot

    aci_pass = None
    getter = getattr(derived, "get", None)
    if callable(getter):
        aci_pass = getter("ACI@1.0")
    if aci_pass is None:
        passes = getattr(derived, "passes", None)
        if isinstance(passes, dict):
            aci_pass = passes.get("ACI@1.0")
    if aci_pass is None:
        return snapshot

    data = getattr(aci_pass, "data", None)
    if not isinstance(data, dict):
        return snapshot

    metrics = data.get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}

    capabilities = metrics.get("capabilities_detected", {})
    chains = metrics.get("chain_candidates_detected", {})
    confidence = metrics.get("confidence_buckets", {})

    if not isinstance(capabilities, dict):
        capabilities = {}
    if not isinstance(chains, dict):
        chains = {}
    if not isinstance(confidence, dict):
        confidence = {}

    snapshot.update(
        {
            "available": True,
            "total_findings": int(metrics.get("total_findings", 0) or 0),
            "inferred_findings": int(metrics.get("inferred_findings", 0) or 0),
            "coverage_ratio": float(metrics.get("coverage_ratio", 0.0) or 0.0),
            "uplifted_findings": int(metrics.get("uplifted_findings", 0) or 0),
            "capabilities_detected": capabilities,
            "chain_candidates_detected": chains,
            "confidence_buckets": {
                "low": int(confidence.get("low", 0) or 0),
                "medium": int(confidence.get("medium", 0) or 0),
                "high": int(confidence.get("high", 0) or 0),
            },
        }
    )
    return snapshot


def _asset_lookup_by_id(scan: Any) -> dict[str, Any]:
    lookup: dict[str, Any] = {}
    if scan is None:
        return lookup
    for asset in getattr(scan, "assets", []) or []:
        asset_id = getattr(asset, "asset_id", None)
        if asset_id:
            lookup[str(asset_id)] = asset
    return lookup


def _finding_lookup_by_id(scan: Any) -> dict[str, Any]:
    lookup: dict[str, Any] = {}
    if scan is None:
        return lookup
    for asset in getattr(scan, "assets", []) or []:
        for finding in getattr(asset, "findings", []) or []:
            fid = getattr(finding, "finding_id", None)
            if fid:
                lookup[str(fid)] = finding
    return lookup


def _asset_summary_lookup(summary: Any) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    if summary is None:
        return lookup
    asset_summary = getattr(summary, "asset_summary", None)
    if not isinstance(asset_summary, dict):
        return lookup
    for asset in asset_summary.get("assets", []) or []:
        if not isinstance(asset, dict):
            continue
        asset_id = str(asset.get("asset_id", "")).strip()
        if asset_id:
            lookup[asset_id] = asset
    return lookup


def _resolve_triage_policy_from_ctx(ctx: Any) -> dict[str, Any]:
    defaults = {
        "enabled": True,
        "oal1_risk_bands": ("critical", "high"),
        "oal1_require_public_exposure": True,
        "oal1_require_exploit_or_kev": True,
        "oal2_risk_bands": ("critical", "high", "medium"),
        "oal2_min_aci_confidence": 0.8,
        "oal2_require_chain_candidate": True,
        "oal2_require_public_exposure": True,
        "preserve_oal1_precedence": True,
    }

    services = getattr(ctx, "services", None)
    topn_cfg = getattr(services, "topn_config", None)
    triage = getattr(topn_cfg, "triage_policy", None)
    if triage is None:
        return defaults

    def _get(name: str, fallback: Any) -> Any:
        return getattr(triage, name, fallback)

    def _get_alias(primary: str, legacy: str, fallback: Any) -> Any:
        if hasattr(triage, primary):
            return getattr(triage, primary)
        if hasattr(triage, legacy):
            return getattr(triage, legacy)
        return fallback

    oal1_bands = tuple(
        str(x).strip().lower()
        for x in (_get_alias("oal1_risk_bands", "p1_risk_bands", defaults["oal1_risk_bands"]) or defaults["oal1_risk_bands"])
    )
    oal2_bands = tuple(
        str(x).strip().lower()
        for x in (_get_alias("oal2_risk_bands", "p1b_risk_bands", defaults["oal2_risk_bands"]) or defaults["oal2_risk_bands"])
    )

    return {
        "enabled": bool(_get("enabled", defaults["enabled"])),
        "oal1_risk_bands": oal1_bands or defaults["oal1_risk_bands"],
        "oal1_require_public_exposure": bool(_get_alias("oal1_require_public_exposure", "p1_require_public_exposure", defaults["oal1_require_public_exposure"])),
        "oal1_require_exploit_or_kev": bool(_get_alias("oal1_require_exploit_or_kev", "p1_require_exploit_or_kev", defaults["oal1_require_exploit_or_kev"])),
        "oal2_risk_bands": oal2_bands or defaults["oal2_risk_bands"],
        "oal2_min_aci_confidence": float(_get_alias("oal2_min_aci_confidence", "p1b_min_aci_confidence", defaults["oal2_min_aci_confidence"])),
        "oal2_require_chain_candidate": bool(_get_alias("oal2_require_chain_candidate", "p1b_require_chain_candidate", defaults["oal2_require_chain_candidate"])),
        "oal2_require_public_exposure": bool(_get_alias("oal2_require_public_exposure", "p1b_require_public_exposure", defaults["oal2_require_public_exposure"])),
        "preserve_oal1_precedence": bool(_get_alias("preserve_oal1_precedence", "preserve_p1_precedence", defaults["preserve_oal1_precedence"])),
    }


def _operational_action_lane_for_finding(
    *,
    risk_band: str,
    exploit_available: bool,
    cisa_kev: bool,
    chain_candidates: list[str],
    confidence: float,
    externally_facing: bool,
    policy: dict[str, Any],
) -> str:
    if not bool(policy.get("enabled", True)):
        return "OAL Disabled"

    band = str(risk_band or "").strip().lower()
    oal1_bands = set(policy.get("oal1_risk_bands", ("critical", "high")))
    oal2_bands = set(policy.get("oal2_risk_bands", ("critical", "high", "medium")))

    oal1_match = (
        band in oal1_bands
        and (externally_facing or not bool(policy.get("oal1_require_public_exposure", True)))
        and ((exploit_available or cisa_kev) or not bool(policy.get("oal1_require_exploit_or_kev", True)))
    )

    oal2_match = (
        band in oal2_bands
        and float(confidence) >= float(policy.get("oal2_min_aci_confidence", 0.8))
        and (bool(chain_candidates) or not bool(policy.get("oal2_require_chain_candidate", True)))
        and (externally_facing or not bool(policy.get("oal2_require_public_exposure", True)))
    )

    if oal1_match and bool(policy.get("preserve_oal1_precedence", True)):
        return "OAL-1 Immediate Exploitable"
    if oal2_match:
        return "OAL-2 High-Confidence Chain Path"
    if oal1_match:
        return "OAL-1 Immediate Exploitable"
    return "OAL-3 Remaining High Risk"


def _asset_context_tags(
    *,
    asset_id: str,
    exposure_signals: dict[str, Any],
    asset_summary_row: dict[str, Any] | None,
    top_concentration_ids: set[str],
    finding_rows: list[dict[str, Any]],
) -> list[str]:
    tags: list[str] = []

    def _lane_rank(lane: str) -> int:
        value = str(lane or "").strip()
        if value == "OAL-1 Immediate Exploitable":
            return 3
        if value == "OAL-2 High-Confidence Chain Path":
            return 2
        if value == "OAL-3 Remaining High Risk":
            return 1
        return 0

    externally_facing = bool(exposure_signals.get("externally_facing", False))
    public_service_ports = bool(exposure_signals.get("public_service_ports", False))
    confidence = str(exposure_signals.get("confidence", "")).strip().lower()

    if externally_facing:
        tags.append("Externally-Facing Inferred")
    if public_service_ports:
        tags.append("Public-Service Ports Inferred")
    if confidence:
        tags.append(f"Exposure Confidence: {confidence.title()}")

    if isinstance(asset_summary_row, dict):
        criticality = str(asset_summary_row.get("criticality", "")).strip()
        if criticality:
            tags.append(f"Criticality: {criticality}")
        if int(asset_summary_row.get("critical_findings", 0) or 0) > 0:
            tags.append("Critical Findings Present")
        elif int(asset_summary_row.get("high_findings", 0) or 0) > 0:
            tags.append("High Findings Present")

    if asset_id in top_concentration_ids:
        tags.append("Top Risk Concentration")

    oal_lanes = {str(f.get("policy_lane", "")).strip() for f in finding_rows if isinstance(f, dict)}
    if "OAL-1 Immediate Exploitable" in oal_lanes:
        tags.append("Contains OAL-1 Findings")
    if "OAL-2 High-Confidence Chain Path" in oal_lanes:
        tags.append("Contains OAL-2 Findings")

    oal2_rows = [
        f for f in finding_rows
        if isinstance(f, dict) and str(f.get("policy_lane", "")).strip() == "OAL-2 High-Confidence Chain Path"
    ]
    if oal2_rows:
        top_oal2 = max(oal2_rows, key=lambda row: float(row.get("confidence", 0.0) or 0.0))
        top_oal2_conf = float(top_oal2.get("confidence", 0.0) or 0.0)
        if top_oal2_conf >= 0.9:
            tags.append("OAL-2 Priority: Immediate Analyst Validation")
        elif top_oal2_conf >= 0.8:
            tags.append("OAL-2 Priority: Validate Next")
        else:
            tags.append("OAL-2 Priority: Monitor")

        has_chain = any(bool(row.get("chain_candidates")) for row in oal2_rows)
        if has_chain:
            tags.append("OAL-2 Chain-Corroborated")

        oal2_max_rank = max(_lane_rank(row.get("policy_lane", "")) for row in finding_rows if isinstance(row, dict))
        if oal2_max_rank >= 3:
            tags.append("OAL-2 Coexists With OAL-1")

    deduped: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if tag in seen:
            continue
        seen.add(tag)
        deduped.append(tag)
    return deduped


def _aci_asset_finding_map(
    scan: Any,
    summary: Any,
    triage_policy: dict[str, Any],
    max_assets: int = 5,
    max_findings_per_asset: int = 5,
) -> list[dict[str, Any]]:
    """Build top-asset mapping of findings to inferred ACI capabilities."""
    if scan is None:
        return []

    derived = getattr(scan, "derived", None)
    if derived is None:
        return []

    getter = getattr(derived, "get", None)
    topn_pass = getter("TopN@1.0") if callable(getter) else None
    aci_pass = getter("ACI@1.0") if callable(getter) else None

    if topn_pass is None:
        passes = getattr(derived, "passes", None)
        if isinstance(passes, dict):
            topn_pass = passes.get("TopN@1.0")
            if aci_pass is None:
                aci_pass = passes.get("ACI@1.0")

    topn_data = getattr(topn_pass, "data", None)
    aci_data = getattr(aci_pass, "data", None)
    if not isinstance(topn_data, dict) or not isinstance(aci_data, dict):
        return []

    ranked_assets = topn_data.get("assets", [])
    findings_by_asset = topn_data.get("findings_by_asset", {})
    aci_findings = aci_data.get("finding_semantics", {})

    if not isinstance(ranked_assets, (list, tuple)) or not isinstance(findings_by_asset, dict):
        return []
    if not isinstance(aci_findings, dict):
        aci_findings = {}

    asset_lookup = _asset_lookup_by_id(scan)
    finding_lookup = _finding_lookup_by_id(scan)
    asset_summary_lookup = _asset_summary_lookup(summary)
    rows: list[dict[str, Any]] = []

    asset_exposure_map: dict[str, bool] = {}
    asset_exposure_signals_by_id: dict[str, dict[str, Any]] = {}
    for ranked in ranked_assets:
        if not isinstance(ranked, dict):
            continue
        asset_id = str(ranked.get("asset_id", "")).strip()
        if not asset_id:
            continue
        inference = ranked.get("inference", {}) if isinstance(ranked, dict) else {}
        signals = {
            "externally_facing": bool(inference.get("externally_facing_inferred", False)) if isinstance(inference, dict) else False,
            "public_service_ports": bool(inference.get("public_service_ports_inferred", False)) if isinstance(inference, dict) else False,
            "confidence": str(inference.get("confidence", "")).strip().lower() if isinstance(inference, dict) else "",
        }
        asset_exposure_signals_by_id[asset_id] = signals
        asset_exposure_map[asset_id] = bool(signals.get("externally_facing", False))

    top_concentration_ids = {
        str(ranked.get("asset_id", "")).strip()
        for ranked in ranked_assets[:3]
        if isinstance(ranked, dict) and str(ranked.get("asset_id", "")).strip()
    }

    for ranked in ranked_assets[:max_assets]:
        if not isinstance(ranked, dict):
            continue
        asset_id = str(ranked.get("asset_id", "")).strip()
        if not asset_id:
            continue

        asset_obj = asset_lookup.get(asset_id)
        hostname = getattr(asset_obj, "hostname", None) if asset_obj is not None else None
        ip_address = getattr(asset_obj, "ip_address", None) if asset_obj is not None else None

        finding_rows: list[dict[str, Any]] = []
        for finding_ref in (findings_by_asset.get(asset_id) or [])[:max_findings_per_asset]:
            if not isinstance(finding_ref, dict):
                continue
            fid = str(finding_ref.get("finding_id", "")).strip()
            if not fid:
                continue
            aci_rec = aci_findings.get(fid, {}) if isinstance(aci_findings.get(fid, {}), dict) else {}
            capabilities = aci_rec.get("capabilities", [])
            if not isinstance(capabilities, (list, tuple)):
                capabilities = []
            chain_candidates = aci_rec.get("chain_candidates", [])
            if not isinstance(chain_candidates, (list, tuple)):
                chain_candidates = []
            confidence = aci_rec.get("confidence", 0.0)
            try:
                confidence_value = float(confidence)
            except (TypeError, ValueError):
                confidence_value = 0.0

            finding_obj = finding_lookup.get(fid)
            exploit_available = bool(getattr(finding_obj, "exploit_available", False)) if finding_obj is not None else False
            cisa_kev = bool(getattr(finding_obj, "cisa_kev", False)) if finding_obj is not None else False
            finding_title = str(getattr(finding_obj, "title", "") or "").strip() if finding_obj is not None else ""
            policy_lane = _operational_action_lane_for_finding(
                risk_band=str(finding_ref.get("risk_band", "")),
                exploit_available=exploit_available,
                cisa_kev=cisa_kev,
                chain_candidates=[str(x) for x in chain_candidates],
                confidence=confidence_value,
                externally_facing=bool(asset_exposure_map.get(asset_id, False)),
                policy=triage_policy,
            )

            finding_rows.append(
                {
                    "finding_id": fid,
                    "finding_title": finding_title or "N/A",
                    "risk_band": str(finding_ref.get("risk_band", "N/A")),
                    "score": float(finding_ref.get("score", 0.0) or 0.0),
                    "capabilities": [str(x) for x in capabilities],
                    "chain_candidates": [str(x) for x in chain_candidates],
                    "confidence": confidence_value,
                    "policy_lane": policy_lane,
                }
            )

        rows.append(
            {
                "asset_id": asset_id,
                "hostname": hostname if hostname else "N/A",
                "ip_address": ip_address if ip_address else "N/A",
                "context_tags": _asset_context_tags(
                    asset_id=asset_id,
                    exposure_signals=asset_exposure_signals_by_id.get(asset_id, {}),
                    asset_summary_row=asset_summary_lookup.get(asset_id),
                    top_concentration_ids=top_concentration_ids,
                    finding_rows=finding_rows,
                ),
                "findings": finding_rows,
            }
        )

    return rows


def _aci_asset_map_all_none_inferred(aci_asset_map: list[dict[str, Any]]) -> bool:
    """Return True when mapped findings exist but none carry inferred capabilities."""
    if not aci_asset_map:
        return False

    has_rows = False
    for asset in aci_asset_map:
        findings = asset.get("findings", []) if isinstance(asset, dict) else []
        for finding in findings:
            has_rows = True
            capabilities = finding.get("capabilities", []) if isinstance(finding, dict) else []
            if capabilities:
                return False
    return has_rows


def generate_markdown_report(
    ctx: "RunContext",
    scan: "ScanResult",
    output_path: "PathLike",
    report_type: str = "executive",
    args: Any = None,
) -> None:
    """
    Generate a Markdown report from scan results.
    
    Args:
        ctx: Runtime context with logger and PFH
        scan: Processed scan results
        output_path: Destination file path
        report_type: "executive" or "technical"
    
    Raises:
        ValueError: If Summary@1.0 pass has not run or invalid report_type
    """
    summary_data = scan.derived.get("Summary@1.0")
    if not summary_data:
        raise ValueError("Summary@1.0 pass must run before generating Markdown report")
    
    summary = summary_data.data
    triage_policy = _resolve_triage_policy_from_ctx(ctx)
    
    if report_type == "executive":
        content = _generate_executive_report(scan, summary, args=args, triage_policy=triage_policy)
    elif report_type == "technical":
        content = _generate_technical_report(scan, summary, args=args, triage_policy=triage_policy)
    else:
        raise ValueError(f"Unknown report type: {report_type}. Expected 'executive' or 'technical'.")

    # Caller provides the target path (io_resolution sets distinct exec/technical names).
    target = ctx.pfh.ensure_writable_file(
        output_path,
        label=f"{report_type.capitalize()} Markdown Report",
        create_parents=True,
        overwrite=True
    )
    
    with ctx.pfh.open_for_write(target, mode="w", encoding="utf-8", label="Markdown Report") as f:
        f.write(content)
    
    ctx.logger.print_success(
        f"{report_type.capitalize()} report generated: {ctx.pfh.format_for_log(target)}",
        label="Markdown Report"
    )


def _generate_executive_report(
    _scan: "ScanResult",
    summary: Any,
    args: Any = None,
    triage_policy: dict[str, Any] | None = None,
) -> str:
    """
    Generate executive-level summary report.

    Focused on:
    - High-level metrics
    - Risk distribution
    - Immediate action items
    - Remediation priorities
    """
    overview = summary.overview
    risk_dist = summary.risk_distribution
    top_risks = summary.top_risks
    remediation = summary.remediation_priorities
    asset_summary = summary.asset_summary
    enrichment = summary.enrichment_metrics
    decision_trace = getattr(summary, "decision_trace_summary", {}) or {}
    source_status = _enrichment_source_status(args)
    ghsa_findings, ghsa_refs = _ghsa_reference_metrics(_scan)
    aci_metrics = _aci_metrics_snapshot(_scan)
    aci_zero_notes = _aci_zero_inference_diagnostics(_scan, args, aci_metrics)
    top_capabilities = sorted(
        aci_metrics["capabilities_detected"].items(),
        key=lambda kv: (-int(kv[1]), str(kv[0])),
    )[:5]
    aci_asset_map = _aci_asset_finding_map(_scan, summary, triage_policy=triage_policy or {})

    assets = asset_summary.get('assets', []) if isinstance(asset_summary, dict) else []
    total_critical_findings = sum(int(a.get('critical_findings', 0) or 0) for a in assets)
    total_high_findings = sum(int(a.get('high_findings', 0) or 0) for a in assets)
    top_assets = assets[:3]
    top3_critical = sum(int(a.get('critical_findings', 0) or 0) for a in top_assets)
    top3_high = sum(int(a.get('high_findings', 0) or 0) for a in top_assets)
    top3_critical_pct = (top3_critical / total_critical_findings * 100.0) if total_critical_findings else 0.0
    top3_high_pct = (top3_high / total_high_findings * 100.0) if total_high_findings else 0.0

    def _risk_drivers(risk: Any) -> str:
        drivers: list[str] = []
        if risk.get('kev_listed'):
            drivers.append('KEV')
        if risk.get('exploit_available'):
            drivers.append('Public Exploit')
        epss_val = risk.get('epss_score')
        if isinstance(epss_val, (int, float)) and epss_val >= 0.50:
            drivers.append('EPSS>=0.50')
        return ", ".join(drivers) if drivers else "Risk Score Driven"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = f"""# Vulnerability Scan Executive Summary

**Generated:** {timestamp}  
**Scan Period:** {overview.get('scan_timestamp', 'N/A')}

---

## 🎯 Key Findings

| Metric | Value |
|--------|-------|
| **Total Assets Scanned** | {overview['total_assets']:,} |
| **Total Vulnerabilities** | {overview['total_findings']:,} |
| **Average Asset Risk Score** | {overview['average_asset_risk']:.2f} |
| **Exploitable Vulnerabilities** | {overview['exploitable_findings']:,} |
| **CISA KEV Listed** | {overview['kev_listed_findings']:,} |
| **GHSA Advisory Matches** | {ghsa_findings:,} findings ({ghsa_refs:,} references) |

---

## 🧠 Decision Context

- CVE rows are ranked by **Finding Risk (Raw)** from derived scoring outputs.
- For near-tied rows, contributor-breadth signals are applied to keep ordering deterministic.
- **Finding Agg CVEs** is a finding-level contributor-breadth signal, not an asset-level aggregate.

---

## ✅ Data Quality Scorecard

| Signal | Value |
|--------|-------|
| Scored Findings Coverage | {risk_dist['total_scored']:,}/{overview['total_findings']:,} |
| Enriched Findings Coverage | {enrichment['enriched_findings']:,}/{enrichment['total_findings']:,} ({enrichment['enrichment_coverage']:.1%}) |
| KEV-listed Findings | {overview['kev_listed_findings']:,} |
| Public Exploit Findings | {overview['exploitable_findings']:,} |
| GHSA Advisory Matches | {ghsa_findings:,} findings ({ghsa_refs:,} references) |

Enrichment runtime mode:

| Source | Status |
|--------|--------|
| KEV | {source_status['KEV'][1]} |
| EPSS | {source_status['EPSS'][1]} |
| Exploit-DB | {source_status['Exploit-DB'][1]} |
| NVD | {source_status['NVD'][1]} |
| GHSA | {source_status['GHSA'][1]} |

---

## 🧩 Attack Capability Snapshot

| ACI Signal | Value |
|-----------|-------|
| ACI Available | {"Yes" if aci_metrics["available"] else "No"} |
| Total Findings Observed | {aci_metrics['total_findings']:,} |
| Inferred Findings | {aci_metrics['inferred_findings']:,}/{aci_metrics['total_findings']:,} |
| Coverage Ratio | {aci_metrics['coverage_ratio']:.1%} |
| Uplifted Findings | {aci_metrics['uplifted_findings']:,} |
| Capability Types | {len(aci_metrics['capabilities_detected']):,} |
| Chain Types | {len(aci_metrics['chain_candidates_detected']):,} |

Top capability signals:

"""

    if top_capabilities:
        for cap, count in top_capabilities:
            md += f"- `{cap}`: {int(count):,}\n"
    else:
        md += "- ACI data unavailable or no capability signals inferred.\n"

    md += """

Interpretation notes:

- `Inferred Findings` is threshold-qualified (`confidence >= min_confidence`).
- `Top capability signals` counts capability tags across all findings and can exceed `Inferred Findings` because one finding may have multiple capabilities.
- Findings below threshold can still appear in capability counts, but they do not increment `Inferred Findings`.

"""

    if aci_zero_notes:
        md += "ACI zero-inference diagnostic:\n\n"
        for note in aci_zero_notes:
            md += f"- {note}\n"
        md += "\n"

    if isinstance(decision_trace, dict) and decision_trace:
        exposure_conf = decision_trace.get("exposure_confidence_counts", {})
        if not isinstance(exposure_conf, dict):
            exposure_conf = {}
        top_rules = decision_trace.get("exposure_rule_hit_counts", {})
        if not isinstance(top_rules, dict):
            top_rules = {}
        risk_band_counts = decision_trace.get("findings_by_risk_band", {})
        if not isinstance(risk_band_counts, dict):
            risk_band_counts = {}
        md += "Decision trace snapshot:\n\n"
        md += (
            f"- Assets with exposure inference: {int(decision_trace.get('assets_with_exposure_inference', 0) or 0):,}\n"
            f"- Exposure confidence buckets: high={int(exposure_conf.get('high', 0) or 0):,}, "
            f"medium={int(exposure_conf.get('medium', 0) or 0):,}, low={int(exposure_conf.get('low', 0) or 0):,}\n"
            f"- ACI inferred findings: {int(decision_trace.get('aci_inferred_findings', 0) or 0):,}\n"
        )
        if risk_band_counts:
            band_parts = ", ".join(f"{b}={int(c):,}" for b, c in risk_band_counts.items())
            md += f"- Findings by risk band: {band_parts}\n"
        if top_rules:
            md += "- Top exposure rule hits:\n"
            for rid, count in list(top_rules.items())[:5]:
                md += f"  - `{rid}`: {int(count):,}\n"
        md += "\n"

    md += """

---

## 🗺️ Top Assets: Findings to Inferred Capabilities

This view maps top-ranked assets to their top-ranked findings and inferred attack capabilities.

**Disclaimer:** Attack capabilities below are inferred from available evidence and model rules. Treat them as decision-support signals and perform due diligence to validate recommendations before operational action.

**OAL = Operational Action Lane.** This is the config-backed analyst action recommendation for the finding under the current triage policy.

"""

    if aci_asset_map:
        oal2_legend_emitted = False
        if _aci_asset_map_all_none_inferred(aci_asset_map):
            md += (
                "Analyst note: Ranked findings are shown for context, but all mapped entries are `None inferred` "
                "because no finding met current ACI semantic and confidence criteria for this run.\n\n"
            )
        for asset in aci_asset_map:
            tags = asset.get("context_tags", []) if isinstance(asset, dict) else []
            md += (
                f"### Asset `{asset['asset_id']}` ({asset['hostname']} / {asset['ip_address']})\n\n"
            )
            if tags:
                md += f"Context Tags: {' | '.join(tags)}\n\n"
                has_oal2_priority_tags = any(
                    str(tag).startswith("OAL-2 Priority:") for tag in tags
                )
                if has_oal2_priority_tags and not oal2_legend_emitted:
                    md += (
                        "OAL-2 tag legend: `Immediate Analyst Validation` = confidence >= 0.90, "
                        "`Validate Next` = confidence >= 0.80 and < 0.90, `Monitor` = lower-confidence OAL-2.\n\n"
                    )
                    oal2_legend_emitted = True
            md += (
                "| Finding (ID / Title) | Risk Band | Finding Risk | Inferred Capabilities | Chain Candidates | Confidence | OAL |\n"
                "|----------------------|-----------|--------------|-----------------------|------------------|------------|-----|\n"
            )
            if asset["findings"]:
                for finding in asset["findings"]:
                    capabilities = ", ".join(finding["capabilities"]) if finding["capabilities"] else "None inferred"
                    chains = ", ".join(finding["chain_candidates"]) if finding["chain_candidates"] else "None"
                    md += (
                        f"| {finding['finding_id']} ({finding['finding_title']}) | {finding['risk_band']} | {finding['score']:.2f} | "
                        f"{capabilities} | {chains} | {finding['confidence']:.2f} | {finding['policy_lane']} |\n"
                    )
            else:
                md += "| _No ranked findings available_ | N/A | N/A | None inferred | None | 0.00 | N/A |\n"
            md += "\n"
    else:
        md += "No TopN/ACI mapping data available for asset-level capability projection.\n\n"

    md += f"""

---

## 📊 Risk Distribution

Derived risk bands below are calculated by VulnParse-Pin scoring and should be used for remediation prioritization.

| Risk Band | Count |
|-----------|-------|
| 🔴 **Critical** | {risk_dist['by_risk_band']['Critical']:,} |
| 🟠 **High** | {risk_dist['by_risk_band']['High']:,} |
| 🟡 **Medium** | {risk_dist['by_risk_band']['Medium']:,} |
| 🟢 **Low** | {risk_dist['by_risk_band']['Low']:,} |
| ⚪ **Informational** | {risk_dist['by_risk_band']['Informational']:,} |

---

## ⚠️ Immediate Action Required

**{remediation['immediate_action']} vulnerabilities** require immediate remediation due to:
- Critical risk rating
- Known exploitation in the wild (KEV) or public exploits available

### Top Priority CVEs:

"""

    for i, cve in enumerate(remediation['immediate_cves'][:5], 1):
        md += f"{i}. `{cve}`\n"

    if not remediation['immediate_cves']:
        md += "- No immediate-action CVEs detected in this scan window.\n"

    md += f"""

---

## 📈 Top {len(top_risks)} Highest Risk CVEs (De-duplicated, Derived Risk)

| CVE | Finding Risk (Raw) | Band | Exploit? | KEV? | Finding Agg CVEs | Agg Exploitable | Agg KEV | CVSS | Occurrences | Primary Drivers |
|-----|---------------------|------|----------|------|----------|-----------------|---------|------|-------------|-----------------|
"""

    for risk in top_risks:
        exploit_icon = "✅" if risk['exploit_available'] else "❌"
        kev_icon = "✅" if risk['kev_listed'] else "❌"
        cvss = risk.get('cvss_base_score', 'N/A')
        occurrences = risk.get('occurrence_count', 1)
        agg_count = int(risk.get('aggregated_cve_count', 1) or 1)
        agg_exploit = int(risk.get('aggregated_exploitable_cve_count', 0) or 0)
        agg_kev = int(risk.get('aggregated_kev_cve_count', 0) or 0)

        md += (
            f"| {risk['cve']} | {risk['finding_risk_score']:.2f} | {risk['risk_band']} | "
            f"{exploit_icon} | {kev_icon} | {agg_count:,} | {agg_exploit:,} | {agg_kev:,} | "
            f"{cvss} | {occurrences:,} | {_risk_drivers(risk)} |\n"
        )

    md += """

---

## 🧭 Recommended Asset Target List (Patching Priority)

These are the recommended most vulnerable assets to target first for patching based on derived scoring and asset criticality.

| Asset ID | Hostname | Criticality | Critical (Derived) | High (Derived) | #1 CVE |
|----------|----------|-------------|--------------------|----------------|--------|
"""

    for asset in asset_summary['assets'][:10]:
        md += (
            f"| {asset.get('asset_id', 'N/A')} | {asset.get('hostname') or 'N/A'} | "
            f"{asset.get('criticality') or 'N/A'} | {asset.get('critical_findings', 0):,} | "
            f"{asset.get('high_findings', 0):,} | {asset.get('top_cve', 'N/A')} |\n"
        )

    md += f"""

### Executive SLA Recommendation

- **Extreme criticality assets:** Patch critical findings within **24-48 hours**
- **High criticality assets:** Patch critical/high findings within **7 days**
- **Medium/Low criticality assets:** Patch according to standard change windows (up to **30 days**)

---

## ⏱️ Remediation Plan by Time Horizon

| Horizon | Focus | Count |
|---------|-------|-------|
| 24-48 hours | Immediate-action vulnerabilities | {remediation['immediate_action']:,} |
| 7 days | High-priority vulnerabilities | {remediation['high_priority']:,} |
| 30 days | Medium-priority vulnerabilities | {remediation['medium_priority']:,} |

Immediate-action CVE shortlist:

"""

    if remediation['immediate_cves']:
        for i, cve in enumerate(remediation['immediate_cves'][:5], 1):
            md += f"{i}. `{cve}`\n"
    else:
        md += "- No immediate-action CVEs detected in this scan window.\n"

    md += f"""

---

## 🎯 Risk Concentration

| Concentration Signal | Value |
|----------------------|-------|
| Top 3 assets critical-share | {top3_critical:,}/{total_critical_findings:,} ({top3_critical_pct:.1f}%) |
| Top 3 assets high-share | {top3_high:,}/{total_high_findings:,} ({top3_high_pct:.1f}%) |
| Assets considered in concentration view | {len(top_assets):,} of {len(assets):,} |

Interpretation: higher concentration usually means faster risk reduction when remediation starts with the top exposed assets.

---

## 🛡️ Remediation Priority Breakdown

| Priority | Count | Recommended Timeframe |
|----------|-------|----------------------|
| **Immediate** | {remediation['immediate_action']:,} | Within 24-48 hours |
| **High** | {remediation['high_priority']:,} | Within 1 week |
| **Medium** | {remediation['medium_priority']:,} | Within 30 days |

---

## 📝 Recommendations

1. **Immediate Focus:** Address the {remediation['immediate_action']} critical vulnerabilities with known exploits
2. **Asset Prioritization:** Focus on the highest risk assets identified in the technical report
3. **Patch Management:** Implement a regular patching cycle for the {remediation['high_priority']} high-priority findings
4. **Monitoring:** Deploy detection rules for CVEs listed in CISA KEV catalog
5. **Interpretation Note:** Treat scanner severity as input signal; use derived risk band and raw score to break ties within large critical buckets
6. **Aggregation Context:** Where Finding Agg CVEs > 1, prioritize remediation by addressing primary shared root-cause components first

---

## 📚 Metric Definitions (ACI)

Use these definitions when interpreting ACI-driven sections:

| Term | Meaning |
|------|---------|
| Total Findings Observed | All findings processed by ACI for this run. |
| Inferred Findings | Findings that have at least one capability and meet threshold (`confidence >= min_confidence`). |
| Coverage Ratio | `Inferred Findings / Total Findings Observed`. |
| Capability Distribution | Non-exclusive counts of matched capability labels; one finding can contribute to multiple capability counts. |
| Chain Candidate Distribution | Non-exclusive counts of matched chain labels; one finding can contribute to multiple chain counts. |
| Confidence Distribution | Bucketed confidence counts across all findings observed by ACI, including findings below inference threshold. |
| Uplifted Findings | Findings where computed ACI rank uplift is greater than zero. |

Analyst reminder:

- A finding can appear in capability counts even when it is not included in `Inferred Findings`.
- Capability and chain counts are expected to exceed inferred counts in datasets with multi-capability findings.

---

*Report generated by VulnParse-Pin - Automated Vulnerability Intelligence*
"""

    return md


def _generate_technical_report(
    _scan: "ScanResult",
    summary: Any,
    args: Any = None,
    triage_policy: dict[str, Any] | None = None,
) -> str:
    """
    Generate detailed technical report for vulnerability engineers.

    Includes:
    - Detailed asset breakdown
    - Finding-level analysis
    - Enrichment statistics
    - Top risk CVEs with full context
    """
    overview = summary.overview
    asset_summary = summary.asset_summary
    finding_summary = summary.finding_summary
    risk_dist = summary.risk_distribution
    top_risks = summary.top_risks
    enrichment = summary.enrichment_metrics
    decision_trace = getattr(summary, "decision_trace_summary", {}) or {}
    source_status = _enrichment_source_status(args)
    ghsa_findings, ghsa_refs = _ghsa_reference_metrics(_scan)
    aci_metrics = _aci_metrics_snapshot(_scan)
    aci_zero_notes = _aci_zero_inference_diagnostics(_scan, args, aci_metrics)
    top_capabilities = sorted(
        aci_metrics["capabilities_detected"].items(),
        key=lambda kv: (-int(kv[1]), str(kv[0])),
    )
    top_chains = sorted(
        aci_metrics["chain_candidates_detected"].items(),
        key=lambda kv: (-int(kv[1]), str(kv[0])),
    )
    aci_asset_map = _aci_asset_finding_map(_scan, summary, triage_policy=triage_policy or {})

    def _risk_drivers(risk: Any) -> str:
        drivers: list[str] = []
        if risk.get('kev_listed'):
            drivers.append('KEV')
        if risk.get('exploit_available'):
            drivers.append('Public Exploit')
        epss_val = risk.get('epss_score')
        if isinstance(epss_val, (int, float)) and epss_val >= 0.50:
            drivers.append('EPSS>=0.50')
        return ", ".join(drivers) if drivers else "Risk Score Driven"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = f"""# Vulnerability Scan Technical Report

**Generated:** {timestamp}  
**Assets Analyzed:** {overview['total_assets']:,}  
**Total Findings:** {overview['total_findings']:,}

---

## 📋 Table of Contents

1. [Scan Overview](#scan-overview)
2. [Asset Analysis](#asset-analysis)
3. [Scanner Severity Breakdown](#scanner-severity-breakdown)
4. [Derived Risk Breakdown](#derived-risk-breakdown)
5. [Top Risk Findings](#top-risk-findings)
6. [Tie-Break Explainability](#tie-break-explainability)
7. [Attack Capability Evidence](#attack-capability-evidence)
8. [Top Asset Capability Mapping](#top-asset-capability-mapping)
9. [Enrichment Coverage](#enrichment-coverage)
10. [Analyst Caveats](#analyst-caveats)
11. [Trust and Provenance](#trust-and-provenance)

---

## 🔍 Scan Overview

| Metric | Value |
|--------|-------|
| Total Assets | {overview['total_assets']:,} |
| Total Findings | {overview['total_findings']:,} |
| Average Risk Score | {overview['average_asset_risk']:.2f} |
| Exploitable (Public PoC) | {overview['exploitable_findings']:,} |
| CISA KEV Listed | {overview['kev_listed_findings']:,} |
| GHSA Advisory Matches | {ghsa_findings:,} findings ({ghsa_refs:,} references) |
| Scan Timestamp | {overview.get('scan_timestamp', 'N/A')} |

---

## 💻 Asset Analysis

### Top {len(asset_summary['assets'])} Highest Risk Assets

| Asset ID | IP Address | Hostname | Criticality | Findings | Risk Score | Critical | High |
|----------|------------|----------|-------------|----------|------------|----------|------|
"""

    for asset in asset_summary['assets'][:20]:  # Limit for readability
        md += (
            f"| {asset['asset_id']} | {asset['ip'] or 'N/A'} | {asset['hostname'] or 'N/A'} | "
            f"{asset.get('criticality') or 'N/A'} | {asset['total_findings']:,} | {asset['risk_score']:.2f} | "
            f"{asset['critical_findings']:,} | {asset['high_findings']:,} |\n"
        )

    md += f"""

**Total Assets Evaluated:** {asset_summary['total_assets']:,}

---

## 🐛 Scanner Severity Breakdown

### By Severity (Scanner Classification, Unadjusted)

Scanner severity is the source tool's native rating and can overstate operational priority at scale.

| Severity | Count |
|----------|-------|
| Critical | {finding_summary['by_severity']['Critical']:,} |
| High | {finding_summary['by_severity']['High']:,} |
| Medium | {finding_summary['by_severity']['Medium']:,} |
| Low | {finding_summary['by_severity']['Low']:,} |
| Informational | {finding_summary['by_severity']['Informational']:,} |

**Total:** {finding_summary['total']:,} findings

---

## 🎯 Derived Risk Breakdown

### By Risk Band (Scoring Output)

Use this distribution for remediation prioritization and queue ordering.

| Risk Band | Count |
|-----------|-------|
| Critical | {risk_dist['by_risk_band']['Critical']:,} |
| High | {risk_dist['by_risk_band']['High']:,} |
| Medium | {risk_dist['by_risk_band']['Medium']:,} |
| Low | {risk_dist['by_risk_band']['Low']:,} |
| Informational | {risk_dist['by_risk_band']['Informational']:,} |

**Total Scored:** {risk_dist['total_scored']:,} findings

---

## ⚠️ Top Risk Findings (Detailed)

### Top {len(top_risks)} CVEs by Finding Risk Score (Raw, Derived)

| # | CVE | Finding Risk (Raw) | Band | CVSS | EPSS | Exploit | KEV | Finding Agg CVEs | Agg Exploitable | Agg KEV | Occurrences | Primary Drivers |
|---|-----|---------------------|------|------|------|---------|-----|----------|-----------------|---------|-------------|-----------------|
"""

    for i, risk in enumerate(top_risks, 1):
        exploit = "✅ Yes" if risk['exploit_available'] else "❌ No"
        kev = "✅ Yes" if risk['kev_listed'] else "❌ No"
        epss = f"{risk.get('epss_score', 0.0):.4f}" if risk.get('epss_score') else "N/A"
        cvss = risk.get('cvss_base_score', 'N/A')
        occurrences = risk.get('occurrence_count', 1)
        agg_count = int(risk.get('aggregated_cve_count', 1) or 1)
        agg_exploit = int(risk.get('aggregated_exploitable_cve_count', 0) or 0)
        agg_kev = int(risk.get('aggregated_kev_cve_count', 0) or 0)

        md += (
            f"| {i} | `{risk['cve']}` | {risk['finding_risk_score']:.2f} | {risk['risk_band']} | "
            f"{cvss} | {epss} | {exploit} | {kev} | {agg_count:,} | {agg_exploit:,} | {agg_kev:,} | "
            f"{occurrences:,} | {_risk_drivers(risk)} |\n"
        )

    md += f"""

---

## 🧷 Tie-Break Explainability

- Rankings are ordered by **Finding Risk (Raw)** first.
- For near-equal scores, contributor-breadth signals are used to keep ordering deterministic.
- **Finding Agg CVEs**, **Agg Exploitable**, and **Agg KEV** provide contributor-breadth context for each representative finding row.

---

## 🧩 Attack Capability Evidence

| ACI Metric | Value |
|------------|-------|
| ACI Available | {"Yes" if aci_metrics["available"] else "No"} |
| Total Findings Observed | {aci_metrics['total_findings']:,} |
| Inferred Findings | {aci_metrics['inferred_findings']:,} |
| Coverage Ratio | {aci_metrics['coverage_ratio']:.1%} |
| Uplifted Findings | {aci_metrics['uplifted_findings']:,} |

Interpretation notes:

- `Inferred Findings` is threshold-qualified (`confidence >= min_confidence`).
- Capability and chain distributions count matched semantics and are not mutually exclusive per finding.
- Confidence buckets below include all findings observed by ACI, not only threshold-qualified inferred findings.

"""

    if aci_zero_notes:
        md += "### Zero-Inference Diagnostic\n\n"
        for note in aci_zero_notes:
            md += f"- {note}\n"
        md += "\n"

    md += """

### Capability Distribution

| Capability | Findings |
|------------|----------|
"""

    if top_capabilities:
        for cap, count in top_capabilities[:10]:
            md += f"| {cap} | {int(count):,} |\n"
    else:
        md += "| _No capability signals inferred_ | 0 |\n"

    md += """

### Chain Candidate Distribution

| Chain Rule | Findings |
|------------|----------|
"""

    if top_chains:
        for chain, count in top_chains[:10]:
            md += f"| {chain} | {int(count):,} |\n"
    else:
        md += "| _No chain candidates inferred_ | 0 |\n"

    md += f"""

### Confidence Distribution

All-finding confidence bucket counts (includes findings that did not meet inference threshold).

| Bucket | Count |
|--------|-------|
| High | {aci_metrics['confidence_buckets']['high']:,} |
| Medium | {aci_metrics['confidence_buckets']['medium']:,} |
| Low | {aci_metrics['confidence_buckets']['low']:,} |

---

## 🧾 Decision Trace Snapshot

| Trace Signal | Value |
|-------------|-------|
| Assets with Exposure Inference | {int((decision_trace.get('assets_with_exposure_inference', 0) if isinstance(decision_trace, dict) else 0) or 0):,} |
| ACI Inferred Findings | {int((decision_trace.get('aci_inferred_findings', 0) if isinstance(decision_trace, dict) else 0) or 0):,} |

Findings by risk band:

"""

    _dts_risk_bands = (decision_trace.get("findings_by_risk_band", {}) if isinstance(decision_trace, dict) else {}) or {}
    if isinstance(_dts_risk_bands, dict) and _dts_risk_bands:
        for band, count in _dts_risk_bands.items():
            md += f"- **{band.title()}**: {int(count):,}\n"
    else:
        md += "- No ranked finding data available.\n"

    md += "\nTop exposure inference rule hits:\n\n"

    if isinstance(decision_trace, dict) and isinstance(decision_trace.get("exposure_rule_hit_counts", {}), dict) and decision_trace.get("exposure_rule_hit_counts"):
        for rid, count in list(decision_trace.get("exposure_rule_hit_counts", {}).items())[:10]:
            md += f"- `{rid}`: {int(count):,}\n"
    else:
        md += "- No exposure rule-hit trace data available.\n"

    md += """

---

## 🗺️ Top Asset Capability Mapping

This section maps top-ranked assets to top-ranked findings and their inferred attack capabilities for triage handoff.

**Disclaimer:** Capabilities are inferred signals, not ground truth exploit paths. Analysts should perform due diligence and independent verification before executing remediation or response actions.

**OAL = Operational Action Lane.** This is the config-backed analyst action recommendation for the finding under the current triage policy.

"""

    if aci_asset_map:
        oal2_legend_emitted = False
        if _aci_asset_map_all_none_inferred(aci_asset_map):
            md += (
                "Analyst note: Ranked findings are shown for context, but all mapped entries are `None inferred` "
                "because no finding met current ACI semantic and confidence criteria for this run.\n\n"
            )
        for asset in aci_asset_map:
            tags = asset.get("context_tags", []) if isinstance(asset, dict) else []
            md += (
                f"### Asset `{asset['asset_id']}` ({asset['hostname']} / {asset['ip_address']})\n\n"
            )
            if tags:
                md += f"Context Tags: {' | '.join(tags)}\n\n"
                has_oal2_priority_tags = any(
                    str(tag).startswith("OAL-2 Priority:") for tag in tags
                )
                if has_oal2_priority_tags and not oal2_legend_emitted:
                    md += (
                        "OAL-2 tag legend: `Immediate Analyst Validation` = confidence >= 0.90, "
                        "`Validate Next` = confidence >= 0.80 and < 0.90, `Monitor` = lower-confidence OAL-2.\n\n"
                    )
                    oal2_legend_emitted = True
            md += (
                "| Finding (ID / Title) | Risk Band | Finding Risk | Inferred Capabilities | Chain Candidates | Confidence | OAL |\n"
                "|----------------------|-----------|--------------|-----------------------|------------------|------------|-----|\n"
            )
            if asset["findings"]:
                for finding in asset["findings"]:
                    capabilities = ", ".join(finding["capabilities"]) if finding["capabilities"] else "None inferred"
                    chains = ", ".join(finding["chain_candidates"]) if finding["chain_candidates"] else "None"
                    md += (
                        f"| {finding['finding_id']} ({finding['finding_title']}) | {finding['risk_band']} | {finding['score']:.2f} | "
                        f"{capabilities} | {chains} | {finding['confidence']:.2f} | {finding['policy_lane']} |\n"
                    )
            else:
                md += "| _No ranked findings available_ | N/A | N/A | None inferred | None | 0.00 | N/A |\n"
            md += "\n"
    else:
        md += "No TopN/ACI mapping data available for asset-level capability projection.\n\n"

    md += f"""

---

## 📊 Enrichment Coverage

| Metric | Value |
|--------|-------|
| Total Findings | {enrichment['total_findings']:,} |
| Total CVEs | {enrichment['total_cves']:,} |
| Enriched Findings | {enrichment['enriched_findings']:,} |
| **Enrichment Coverage** | **{enrichment['enrichment_coverage']:.1%}** |

### Data Sources

| Source | Runtime Status |
|--------|----------------|
| CISA Known Exploited Vulnerabilities (KEV) | {source_status['KEV'][1]} |
| FIRST Exploit Prediction Scoring System (EPSS) | {source_status['EPSS'][1]} |
| Exploit-DB Public Exploits | {source_status['Exploit-DB'][1]} |
| GitHub Security Advisories (GHSA) | {source_status['GHSA'][1]} |
| National Vulnerability Database (NVD) | {source_status['NVD'][1]} |

---

## ⚖️ Analyst Caveats

- "Finding Risk (Raw)" is finding-level and should not be treated as an asset aggregate.
- "Finding Agg CVEs" describes score-trace contributor breadth for the representative finding row.
- "Occurrences" captures recurrence of the displayed CVE in the de-duplicated top-risk set.
- Scanner severity is intentionally separated from derived risk to avoid queue-ordering bias.

---

## 🔐 Trust and Provenance

| Signal | Value |
|--------|-------|
| Report Generated At | {timestamp} |
| Scan Timestamp | {overview.get('scan_timestamp', 'N/A')} |
| Integrity Reference | Use runmanifest verification for artifact-level trust validation |

Provenance note: this markdown report summarizes derived outputs; verifiable integrity and decision-chain validation are provided by the runmanifest artifact when generated.

---

## 🔧 Technical Notes

- "Finding Risk (Raw)" is the highest per-finding score observed for that CVE (not an asset aggregate score)
- Risk scores are calculated using CVSS base scores, EPSS probability, and evidence-based factors (KEV listing, exploit availability)
- Asset risk is aggregated from individual finding scores using configured policy
- Scanner severity and derived risk band are intentionally shown separately to reduce prioritization ambiguity
- Findings with CVSS v3.1 scores are prioritized; v2.0 used as fallback
- Exploit availability indicates public proof-of-concept code exists
- "Finding Agg CVEs" indicates whole-of-CVEs aggregation breadth from score_trace contributors for the representative finding shown on that row

---

## 📚 Metric Definitions (ACI)

Use these definitions when interpreting ACI-driven sections:

| Term | Meaning |
|------|---------|
| Total Findings Observed | All findings processed by ACI for this run. |
| Inferred Findings | Findings that have at least one capability and meet threshold (`confidence >= min_confidence`). |
| Coverage Ratio | `Inferred Findings / Total Findings Observed`. |
| Capability Distribution | Non-exclusive counts of matched capability labels; one finding can contribute to multiple capability counts. |
| Chain Candidate Distribution | Non-exclusive counts of matched chain labels; one finding can contribute to multiple chain counts. |
| Confidence Distribution | Bucketed confidence counts across all findings observed by ACI, including findings below inference threshold. |
| Uplifted Findings | Findings where computed ACI rank uplift is greater than zero. |

Analyst reminder:

- A finding can appear in capability counts even when it is not included in `Inferred Findings`.
- Capability and chain counts are expected to exceed inferred counts in datasets with multi-capability findings.

---

*For detailed finding-level data, refer to the JSON/CSV output files.*
"""

    return md
