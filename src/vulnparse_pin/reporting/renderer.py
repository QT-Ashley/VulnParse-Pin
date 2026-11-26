# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import duckdb
from jinja2 import (
    ChoiceLoader,
    Environment,
    FileSystemLoader,
    PackageLoader,
    select_autoescape,
)

from vulnparse_pin import __version__
from vulnparse_pin.storage.db import (
    _check_no_symlinks_or_loops,
    ensure_safe_dir_non_pfh,
    open_for_write_non_pfh,
)
from vulnparse_pin.storage.repositories import get_run_summary_counts, get_shadow_assets
from vulnparse_pin.utils.cvss_utils import resolve_effective_cvss_fields


_SAFE_STEM_RE = re.compile(r"[^A-Za-z0-9._-]+")
_INVALIDATED_STATUSES = frozenset({"deferred_invalidated", "accepted_invalidated", "mitigated_invalidated"})
_VALID_SUPPRESSED_STATUSES = frozenset({"deferred_valid", "accepted_valid", "mitigated", "deferred", "accepted"})
_KNOWN_TIERS = frozenset(
    {
        "P1",
        "P1B",
        "P2",
        "P3",
        "P4",
        "OAL-1",
        "OAL-2",
        "OAL-3",
        "OAL-4",
        "ACT",
        "ATTEND",
        "TRACK",
        "TRACK*",
        "DEPRIORITIZED",
        "LOW",
    }
)
_PRIORITIZED_TIERS = frozenset({"P1", "P1B", "P2", "OAL-1", "OAL-2", "ACT", "ATTEND"})
_KNOWN_OALS = frozenset({"OAL-1", "OAL-2", "OAL-3", "OAL-4"})
_PRIORITIZED_OALS = frozenset({"OAL-1", "OAL-2"})
_KNOWN_SSVC = frozenset({"act", "attend", "track", "track*"})
_PRIORITIZED_SSVC = frozenset({"act", "attend"})
_PRIORITIZED_SLAS = frozenset({"3-day + forensic triage", "3-day", "14-day", "60-day"})

_ACTIVE_PRIORITIZED_SQL = """
    CASE
        WHEN LOWER(TRIM(COALESCE(td.sla_bucket, ''))) LIKE '3-day%' THEN TRUE
        WHEN UPPER(TRIM(COALESCE(td.priority_tier, ''))) IN ('P1', 'P1B', 'P2', 'OAL-1', 'OAL-2', 'ACT', 'ATTEND') THEN TRUE
        WHEN UPPER(TRIM(COALESCE(td.priority_tier, ''))) IN ('P3', 'P4', 'OAL-3', 'OAL-4', 'TRACK', 'TRACK*', 'DEPRIORITIZED', 'LOW') THEN FALSE
        WHEN UPPER(TRIM(COALESCE(td.oal_compat, ''))) IN ('OAL-1', 'OAL-2') THEN TRUE
        WHEN UPPER(TRIM(COALESCE(td.oal_compat, ''))) IN ('OAL-3', 'OAL-4') THEN FALSE
        WHEN LOWER(TRIM(COALESCE(td.ssvc_action, ''))) IN ('act', 'attend') THEN TRUE
        WHEN LOWER(TRIM(COALESCE(td.ssvc_action, ''))) IN ('track', 'track*') THEN FALSE
        WHEN LOWER(TRIM(COALESCE(td.sla_bucket, ''))) IN ('3-day + forensic triage', '3-day', '14-day', '60-day')
             OR LOWER(TRIM(COALESCE(td.sla_bucket, ''))) LIKE '14-day%'
             OR LOWER(TRIM(COALESCE(td.sla_bucket, ''))) LIKE '60-day%' THEN TRUE
        WHEN LOWER(TRIM(COALESCE(td.sla_bucket, ''))) LIKE '%fix on upgrade%'
             OR LOWER(TRIM(COALESCE(td.sla_bucket, ''))) LIKE '90-day%'
             OR LOWER(TRIM(COALESCE(td.sla_bucket, ''))) LIKE '180-day%' THEN FALSE
        ELSE (
            NULLIF(TRIM(COALESCE(td.priority_tier, '')), '') IS NULL
            AND (LOWER(COALESCE(s.risk_band, '')) IN ('critical', 'high') OR COALESCE(s.operational_score, 0.0) >= 6.5)
        )
    END
"""

_DEFAULT_DOSSIER_PRIORITIZED_LIMIT = 500
_DEFAULT_DOSSIER_DEPRIORITIZED_LIMIT = 200
_DEFAULT_ROADMAP_BUCKET_FINDINGS_LIMIT = 15


def _get_conn(db: Any) -> duckdb.DuckDBPyConnection:
    if isinstance(db, duckdb.DuckDBPyConnection):
        return db
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    raise TypeError(f"Expected VppDatabase or DuckDBPyConnection, got {type(db).__name__}")


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_loads_safe(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        loaded = json.loads(raw)
        return loaded if loaded is not None else default
    except Exception:
        return default


def _safe_float(val: Any) -> Optional[float]:
    if val is None or val == "":
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _safe_int(val: Any) -> Optional[int]:
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _ordinal(n: int) -> str:
    val = int(n)
    if 10 <= (val % 100) <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(val % 10, "th")
    return f"{val}{suffix}"


def _format_epss_display(epss_score: Optional[float], epss_percentile: Optional[float]) -> Optional[str]:
    score = _safe_float(epss_score)
    pct = _safe_float(epss_percentile)
    if score is None and pct is None:
        return None
    pct_str: Optional[str] = None
    if pct is not None:
        pct_num = int(round(pct * 100.0 if pct <= 1.0 else pct))
        pct_num = max(0, min(100, pct_num))
        pct_str = _ordinal(pct_num)
    if score is not None:
        p = max(0.0, min(1.0, score))
        base = f"{p * 100.0:.1f}%"
        return f"{base} / {pct_str}" if pct_str is not None else base
    return f"N/A / {pct_str}"


def md_escape(value: Any) -> str:
    """
    Escape untrusted text for safe inclusion inside Markdown table cells and prose.

    Neutralizes line breaks (CRLF/LF/CR/tabs), backslashes (first, so escapes
    cannot un-escape subsequent tokens), HTML angle brackets, pipe table
    delimiters, backticks, link/image brackets, and exclamation marks.
    """
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    s = s.replace("\\", "\\\\")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("|", "\\|")
    s = s.replace("`", "\\`")
    s = s.replace("[", "\\[").replace("]", "\\]")
    s = s.replace("!", "\\!")
    return s


def _fmt_score(value: Any, decimals: int = 2) -> str:
    num = _safe_float(value)
    if num is None:
        return "N/A"
    return f"{num:.{int(decimals)}f}"


def _fmt_epss(value: Any, percentile: Any = None) -> str:
    formatted = _format_epss_display(_safe_float(value), _safe_float(percentile))
    return formatted if formatted is not None else "N/A"


def _fmt_pct(value: Any) -> str:
    num = _safe_float(value)
    if num is None:
        return "N/A"
    pct_val = num * 100.0 if num <= 1.0 else num
    return f"{pct_val:.1f}%"


def _json_pretty(value: Any) -> str:
    try:
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, default=str)
    except Exception:
        return str(value)


def _validate_template_dir(template_dir: Union[str, Path]) -> Path:
    raw = Path(template_dir)
    _check_no_symlinks_or_loops(raw, label="template directory")
    resolved = raw.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Template directory does not exist: {resolved}")
    if not resolved.is_dir():
        raise ValueError(f"Template directory is not a directory: {resolved}")
    for child in resolved.iterdir():
        if child.is_symlink():
            raise ValueError(f"Refusing symlink template file: {child}")
    return resolved


def _build_jinja_env(template_dir: Optional[Union[str, Path]] = None) -> Environment:
    pkg_loader = PackageLoader("vulnparse_pin.reporting", "templates")
    if template_dir is not None:
        resolved_dir = _validate_template_dir(template_dir)
        loader: Any = ChoiceLoader([FileSystemLoader(str(resolved_dir)), pkg_loader])
    else:
        loader = pkg_loader

    env = Environment(
        loader=loader,
        autoescape=select_autoescape(["html", "xml", "html.j2", "xml.j2", "htm", "htm.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["md_escape"] = md_escape
    env.filters["fmt_score"] = _fmt_score
    env.filters["fmt_epss"] = _fmt_epss
    env.filters["fmt_pct"] = _fmt_pct
    env.filters["json_pretty"] = _json_pretty
    return env


def _safe_filename_stem(raw_id: str) -> str:
    cleaned = _SAFE_STEM_RE.sub("_", str(raw_id).strip()).lstrip(".")
    return cleaned or "finding"


def _write_text_safe(
    target_path: Path,
    content: str,
    *,
    pfh: Optional[Any] = None,
    label: str = "Report Output",
) -> Path:
    if pfh is not None:
        with pfh.open_for_write(target_path, mode="w", encoding="utf-8", label=label) as fh:
            fh.write(content)
        return Path(target_path)

    with open_for_write_non_pfh(target_path, label=label, encoding="utf-8") as fh:
        fh.write(content)
    return Path(target_path)


def _coerce_mapping(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "__dict__"):
        return dict(vars(obj))
    return obj


def _coerce_diff_report(diff_report: Any) -> Optional[Dict[str, Any]]:
    if diff_report is None:
        return None
    raw = _coerce_mapping(diff_report)
    if not isinstance(raw, dict):
        raise TypeError(f"Expected DiffReport or dict, got {type(diff_report).__name__}")

    def _norm_list(items: Any) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in items or []:
            mapped = _coerce_mapping(item)
            if isinstance(mapped, dict):
                out.append(mapped)
        return out

    shadow_raw = _coerce_mapping(raw.get("shadow_assets_delta")) or {}
    if not isinstance(shadow_raw, dict):
        shadow_raw = {}
    summary_raw = _coerce_mapping(raw.get("summary")) or {}
    if not isinstance(summary_raw, dict):
        summary_raw = {}
    meta_raw = _coerce_mapping(raw.get("metadata_delta")) or {}
    if not isinstance(meta_raw, dict):
        meta_raw = {}

    newly_high = _norm_list(raw.get("newly_introduced_high_risk"))
    escalated = _norm_list(raw.get("threat_intel_escalated"))
    remediated = _norm_list(raw.get("verified_remediated"))
    invalidated = _norm_list(raw.get("invalidated_assumptions"))

    shadow_delta = {
        "newly_observed": _norm_list(shadow_raw.get("newly_observed")),
        "resolved": _norm_list(shadow_raw.get("resolved")),
        "became_shadow": _norm_list(shadow_raw.get("became_shadow")),
    }

    if not summary_raw:
        summary_raw = {
            "base_run_id": raw.get("base_run_id"),
            "target_run_id": raw.get("target_run_id"),
            "base_total_findings": 0,
            "target_total_findings": 0,
            "persisting_findings": 0,
            "newly_introduced_all": int(raw.get("newly_introduced_all") or len(newly_high)),
            "newly_introduced_high_risk": len(newly_high),
            "threat_intel_escalated": len(escalated),
            "verified_remediated": len(remediated),
            "verified_remediated_confirmed": sum(1 for x in remediated if x.get("asset_still_present")),
            "verified_remediated_asset_missing": sum(1 for x in remediated if not x.get("asset_still_present")),
            "invalidated_assumptions": len(invalidated),
            "shadow_assets_new": len(shadow_delta["newly_observed"]) + len(shadow_delta["became_shadow"]),
            "shadow_assets_resolved": len(shadow_delta["resolved"]),
        }

    return {
        "diff_id": raw.get("diff_id") or "diff_v2",
        "base_run_id": raw.get("base_run_id") or summary_raw.get("base_run_id") or "base",
        "target_run_id": raw.get("target_run_id") or summary_raw.get("target_run_id") or "target",
        "generated_at_utc": raw.get("generated_at_utc") or _utc_now_z(),
        "summary": summary_raw,
        "metadata_delta": meta_raw,
        "newly_introduced_all": int(raw.get("newly_introduced_all") if raw.get("newly_introduced_all") is not None else summary_raw.get("newly_introduced_all", len(newly_high))),
        "newly_introduced_active_kev_count": int(raw.get("newly_introduced_active_kev_count") or 0),
        "newly_introduced_high_risk": newly_high,
        "threat_intel_escalated": escalated,
        "verified_remediated": remediated,
        "invalidated_assumptions": invalidated,
        "shadow_assets_delta": shadow_delta,
    }


def _load_run_context(conn: duckdb.DuckDBPyConnection, run_id: str) -> Dict[str, Any]:
    rid = str(run_id)
    cur = conn.execute(
        """
        SELECT
            run_id, created_at_utc, vpp_version, profile,
            config_sha256, assets_sha256, decisions_sha256,
            intel_metadata_json, manifest_digest, input_files_json,
            baseline_run_id
        FROM runs
        WHERE run_id = ?
        """,
        [rid],
    )
    row = cur.fetchone()
    if row is None:
        has_assets = conn.execute("SELECT 1 FROM assets WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        has_findings = conn.execute("SELECT 1 FROM findings WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        if has_assets is None and has_findings is None:
            raise ValueError(f"Run '{rid}' does not exist in database.")
        run_ctx: Dict[str, Any] = {
            "run_id": rid,
            "created_at_utc": _utc_now_z(),
            "vpp_version": __version__,
            "profile": "default",
            "config_sha256": None,
            "assets_sha256": None,
            "decisions_sha256": None,
            "intel_metadata": {},
            "manifest_digest": None,
            "input_files": [],
            "baseline_run_id": None,
        }
    else:
        cols = [d[0] for d in cur.description]
        run_ctx = dict(zip(cols, row))
        run_ctx["intel_metadata"] = _json_loads_safe(run_ctx.pop("intel_metadata_json", None), {})
        if not isinstance(run_ctx["intel_metadata"], dict):
            run_ctx["intel_metadata"] = {}
        run_ctx["input_files"] = _json_loads_safe(run_ctx.pop("input_files_json", None), [])
        if not isinstance(run_ctx["input_files"], list):
            run_ctx["input_files"] = []
        run_ctx["vpp_version"] = run_ctx.get("vpp_version") or __version__
        run_ctx["profile"] = run_ctx.get("profile") or "default"

    # Enrich intel_metadata fallback from enrichment_snapshots if epss fields absent
    intel = run_ctx["intel_metadata"]
    if "epss_model_version" not in intel or "epss_score_date" not in intel:
        snap_row = conn.execute(
            "SELECT MAX(epss_model_version), MAX(epss_date) FROM enrichment_snapshots WHERE run_id = ?",
            [rid],
        ).fetchone()
        if snap_row:
            if snap_row[0] and not intel.get("epss_model_version"):
                intel["epss_model_version"] = snap_row[0]
            if snap_row[1] and not intel.get("epss_score_date"):
                intel["epss_score_date"] = snap_row[1]

    if not run_ctx.get("manifest_digest"):
        run_ctx["manifest_digest"] = None

    return run_ctx


_EFFECTIVE_PRIMARY_CVE_SQL = (
    "COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), UPPER(f.primary_cve))"
)

_ENRICHMENT_JOIN_SQL = f"""
    LEFT JOIN enrichment_snapshots e
        ON e.run_id = f.run_id AND UPPER(e.cve_id) = {_EFFECTIVE_PRIMARY_CVE_SQL}
"""

_FINDING_CVE_AGG_JOIN_SQL = """
    LEFT JOIN (
        SELECT
            fc.run_id,
            fc.finding_id,
            BOOL_OR(COALESCE(ec.in_kev, FALSE)) AS any_in_kev,
            BOOL_OR(COALESCE(ec.verified_exploit, FALSE)) AS any_verified_exploit,
            ARG_MIN(
                NULLIF(CAST(ec.kev_date_added AS VARCHAR), ''),
                CASE
                    WHEN COALESCE(ec.in_kev, FALSE) AND NULLIF(CAST(ec.kev_date_added AS VARCHAR), '') IS NOT NULL
                    THEN UPPER(ec.cve_id)
                END
            ) AS fc_kev_date_added,
            ARG_MIN(
                NULLIF(CAST(ec.kev_due_date AS VARCHAR), ''),
                CASE
                    WHEN COALESCE(ec.in_kev, FALSE) AND NULLIF(CAST(ec.kev_due_date AS VARCHAR), '') IS NOT NULL
                    THEN UPPER(ec.cve_id)
                END
            ) AS fc_kev_due_date,
            ARG_MIN(
                NULLIF(CAST(ec.kev_ransomware AS VARCHAR), ''),
                CASE
                    WHEN COALESCE(ec.in_kev, FALSE) AND NULLIF(CAST(ec.kev_ransomware AS VARCHAR), '') IS NOT NULL
                    THEN UPPER(ec.cve_id)
                END
            ) AS fc_kev_ransomware
        FROM finding_cves fc
        LEFT JOIN enrichment_snapshots ec
            ON ec.run_id = fc.run_id AND UPPER(ec.cve_id) = UPPER(fc.cve_id)
        GROUP BY fc.run_id, fc.finding_id
    ) fc_agg
        ON fc_agg.run_id = f.run_id AND fc_agg.finding_id = f.finding_id
"""

_EFFECTIVE_IN_KEV_SQL = (
    "(COALESCE(e.in_kev, FALSE) OR COALESCE(fc_agg.any_in_kev, FALSE) "
    "OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE))"
)

_EFFECTIVE_VERIFIED_EXPLOIT_SQL = (
    "(COALESCE(e.verified_exploit, FALSE) OR COALESCE(fc_agg.any_verified_exploit, FALSE) "
    "OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.verified_exploit') AS BOOLEAN), FALSE))"
)

_EFFECTIVE_KEV_DATE_ADDED_SQL = (
    f"CASE WHEN {_EFFECTIVE_IN_KEV_SQL} THEN COALESCE("
    "CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_date_added AS VARCHAR), '') END, "
    "NULLIF(json_extract_string(s.score_trace_json, '$.kev_date_added'), ''), "
    "fc_agg.fc_kev_date_added"
    ") ELSE e.kev_date_added END"
)

_EFFECTIVE_KEV_DUE_DATE_SQL = (
    f"CASE WHEN {_EFFECTIVE_IN_KEV_SQL} THEN COALESCE("
    "CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_due_date AS VARCHAR), '') END, "
    "NULLIF(json_extract_string(s.score_trace_json, '$.kev_due_date'), ''), "
    "fc_agg.fc_kev_due_date"
    ") ELSE e.kev_due_date END"
)

_EFFECTIVE_KEV_RANSOMWARE_SQL = (
    f"CASE WHEN {_EFFECTIVE_IN_KEV_SQL} THEN COALESCE("
    "CASE WHEN COALESCE(e.in_kev, FALSE) THEN NULLIF(CAST(e.kev_ransomware AS VARCHAR), '') END, "
    "NULLIF(json_extract_string(s.score_trace_json, '$.kev_ransomware'), ''), "
    "fc_agg.fc_kev_ransomware"
    ") ELSE e.kev_ransomware END"
)

_FINDING_JOIN_SELECT = f"""
    SELECT
        f.run_id, f.finding_id, f.asset_id, f.scoring_track,
        COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) AS primary_cve,
        f.cves_json, f.cwes_json, f.ghsa_ids_json, f.title, f.description, f.solution,
        f.plugin_output, f.affected_port, f.protocol, f.service_name, f.location_uri,
        f.line_number, f.package_purl, f.scanner_severity, f.scanner_cvss_score,
        f.scanner_cvss_vector, f.detection_mode, f.signal_reliability,
        f.ingestion_confidence, f.fidelity_tier, f.source_format, f.references_json,
        f.tags_json, f.exploit_evidence, f.is_deduplicated, f.source_count,
        a.canonical_key, a.hostname, a.ip_address, a.target_uri, a.image_or_repo,
        a.os, a.declared_criticality, a.derived_criticality, a.internet_facing,
        a.owner, a.env_tags_json, a.inventory_status, a.matched_rule_id, a.open_ports_json,
        e.cvss_score, e.cvss_vector, e.cvss_version, e.cvss_provenance,
        e.epss_score, e.epss_percentile, e.epss_model_version, e.epss_date,
        {_EFFECTIVE_IN_KEV_SQL} AS in_kev,
        {_EFFECTIVE_KEV_DATE_ADDED_SQL} AS kev_date_added,
        {_EFFECTIVE_KEV_DUE_DATE_SQL} AS kev_due_date,
        {_EFFECTIVE_KEV_RANSOMWARE_SQL} AS kev_ransomware,
        e.kev_required_action, {_EFFECTIVE_VERIFIED_EXPLOIT_SQL} AS verified_exploit, e.heuristic_exploit_mention,
        e.exploit_refs_json, e.ghsa_ids_json AS enriched_ghsa_ids_json,
        e.osv_ids_json, e.enrichment_confidence, e.sources_json,
        s.raw_risk_score, s.operational_score, s.risk_band, s.score_trace_json,
        td.profile AS triage_profile, td.priority_tier, td.oal_compat, td.ssvc_action,
        td.sla_bucket, td.sla_days, td.decision_status, td.decision_id,
        td.assumed_state_json, td.rationale_summary,
        aci.capabilities_json, aci.chains_json, aci.matched_tokens_json,
        aci.confidence AS aci_confidence, aci.uplift_score AS aci_uplift_score
    FROM findings f
    LEFT JOIN assets a
        ON a.run_id = f.run_id AND a.asset_id = f.asset_id
    LEFT JOIN scores s
        ON s.run_id = f.run_id AND s.finding_id = f.finding_id
    {_ENRICHMENT_JOIN_SQL}
    {_FINDING_CVE_AGG_JOIN_SQL}
    LEFT JOIN triage_decisions td
        ON td.run_id = f.run_id AND td.finding_id = f.finding_id
    LEFT JOIN aci_signals aci
        ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id
"""


def _enrich_finding_row(raw_row: Dict[str, Any], run_intel_meta: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(raw_row)
    item["cves"] = _json_loads_safe(item.pop("cves_json", None), [])
    item["cwes"] = _json_loads_safe(item.pop("cwes_json", None), [])
    item["ghsa_ids"] = _json_loads_safe(item.pop("ghsa_ids_json", None), [])
    item["references"] = _json_loads_safe(item.pop("references_json", None), [])
    item["tags"] = _json_loads_safe(item.pop("tags_json", None), [])
    item["env_tags"] = _json_loads_safe(item.pop("env_tags_json", None), {})
    item["open_ports"] = _json_loads_safe(item.pop("open_ports_json", None), [])
    item["exploit_refs"] = _json_loads_safe(item.pop("exploit_refs_json", None), [])
    item["enriched_ghsa_ids"] = _json_loads_safe(item.pop("enriched_ghsa_ids_json", None), [])
    item["osv_ids"] = _json_loads_safe(item.pop("osv_ids_json", None), [])
    item["enrichment_sources"] = _json_loads_safe(item.pop("sources_json", None), [])
    score_trace = _json_loads_safe(item.pop("score_trace_json", None), {})
    if not isinstance(score_trace, dict):
        score_trace = {}
    item["score_trace"] = score_trace

    assumed_state = _json_loads_safe(item.pop("assumed_state_json", None), {})
    if not isinstance(assumed_state, dict):
        assumed_state = {}
    item["assumed_state"] = assumed_state

    caps = _json_loads_safe(item.pop("capabilities_json", None), [])
    chains = _json_loads_safe(item.pop("chains_json", None), [])
    toks = _json_loads_safe(item.pop("matched_tokens_json", None), [])
    if not caps and isinstance(score_trace.get("aci_capabilities"), list):
        caps = list(score_trace["aci_capabilities"])
    if not chains and isinstance(score_trace.get("aci_chains"), list):
        chains = list(score_trace["aci_chains"])
    item["capabilities"] = caps if isinstance(caps, list) else []
    item["chains"] = chains if isinstance(chains, list) else []
    item["matched_tokens"] = toks if isinstance(toks, list) else []

    asset_display = (
        item.get("hostname")
        or item.get("ip_address")
        or item.get("target_uri")
        or item.get("image_or_repo")
        or item.get("canonical_key")
        or item.get("asset_id")
        or "unknown-asset"
    )
    item["asset_display"] = str(asset_display)

    # Resolve effective CVSS + version + provenance
    eff_cvss, eff_prov, eff_ver, eff_vec = resolve_effective_cvss_fields(
        snap_cvss=item.get("cvss_score"),
        snap_prov=item.get("cvss_provenance"),
        snap_ver=item.get("cvss_version"),
        snap_vec=item.get("cvss_vector"),
        scanner_cvss=item.get("scanner_cvss_score"),
        scanner_vec=item.get("scanner_cvss_vector"),
        score_trace=score_trace,
    )

    item["effective_cvss"] = eff_cvss
    item["effective_cvss_version"] = eff_ver
    item["effective_cvss_provenance"] = str(eff_prov)
    item["effective_cvss_vector"] = eff_vec

    # Resolve effective EPSS raw + percentile + display + model date
    eff_epss = _safe_float(item.get("epss_score"))
    if eff_epss is None:
        eff_epss = _safe_float(score_trace.get("epss_score"))
    eff_pct = _safe_float(item.get("epss_percentile"))
    if eff_pct is None:
        eff_pct = _safe_float(score_trace.get("epss_percentile"))
    epss_display = score_trace.get("epss_display") or _format_epss_display(eff_epss, eff_pct)
    item["epss_score"] = eff_epss
    item["epss_percentile"] = eff_pct
    item["epss_display"] = epss_display or "N/A"
    item["epss_model_version"] = (
        item.get("epss_model_version")
        or score_trace.get("epss_model_version")
        or run_intel_meta.get("epss_model_version")
    )
    item["epss_date"] = (
        item.get("epss_date")
        or score_trace.get("epss_date")
        or run_intel_meta.get("epss_score_date")
    )

    in_kev = bool(item.get("in_kev") or score_trace.get("in_kev"))
    item["in_kev"] = in_kev
    if in_kev:
        item["kev_date_added"] = item.get("kev_date_added") or score_trace.get("kev_date_added")
        item["kev_due_date"] = item.get("kev_due_date") or score_trace.get("kev_due_date")
        if item.get("kev_ransomware") is None or item.get("kev_ransomware") == "":
            item["kev_ransomware"] = score_trace.get("kev_ransomware")

    item["verified_exploit"] = bool(item.get("verified_exploit") or score_trace.get("verified_exploit"))
    item["heuristic_exploit_mention"] = bool(
        item.get("heuristic_exploit_mention") or score_trace.get("heuristic_exploit_mention") or item.get("exploit_evidence")
    )
    item["internet_facing"] = bool(item.get("internet_facing"))
    item["signal_reliability"] = _safe_float(item.get("signal_reliability"))
    if item["signal_reliability"] is None:
        item["signal_reliability"] = _safe_float(score_trace.get("signal_reliability"))

    breakdown = score_trace.get("breakdown")
    item["score_breakdown"] = breakdown if isinstance(breakdown, dict) else {}
    item["ssvc_path"] = assumed_state.get("ssvc_path")
    item["ssvc_inputs"] = assumed_state.get("ssvc_inputs") if isinstance(assumed_state.get("ssvc_inputs"), dict) else {}
    item["sast_p1_capped"] = bool(assumed_state.get("sast_p1_capped"))

    dec_status = str(item.get("decision_status") or assumed_state.get("decision_status") or "active").strip().lower()
    item["decision_status"] = dec_status
    item["is_invalidated"] = dec_status in _INVALIDATED_STATUSES
    item["is_validly_suppressed"] = dec_status in _VALID_SUPPRESSED_STATUSES
    item["violated_predicates"] = list(assumed_state.get("violated_predicates") or [])
    item["decision_reasons"] = list(assumed_state.get("reasons") or [])
    item["decision_owner"] = assumed_state.get("owner") or item.get("owner")
    item["decision_expires_at"] = assumed_state.get("expires_at")
    item["assumed_predicates"] = (
        assumed_state.get("assumed_state")
        if isinstance(assumed_state.get("assumed_state"), dict)
        else {}
    )

    tier_u = str(item.get("priority_tier") or "").strip().upper()
    oal_u = str(item.get("oal_compat") or "").strip().upper()
    sla_l = str(item.get("sla_bucket") or "").strip().lower()
    ssvc_l = str(item.get("ssvc_action") or "").strip().lower()
    band_l = str(item.get("risk_band") or "").strip().lower()
    op_score = _safe_float(item.get("operational_score")) or 0.0

    if item["is_invalidated"]:
        item["is_prioritized"] = True
    elif item["is_validly_suppressed"]:
        item["is_prioritized"] = False
    else:
        if sla_l in {"3-day + forensic triage", "3-day"} or sla_l.startswith("3-day"):
            item["is_prioritized"] = True
        elif tier_u in _KNOWN_TIERS:
            item["is_prioritized"] = tier_u in _PRIORITIZED_TIERS
        elif oal_u in _KNOWN_OALS:
            item["is_prioritized"] = oal_u in _PRIORITIZED_OALS
        elif ssvc_l in _KNOWN_SSVC:
            item["is_prioritized"] = ssvc_l in _PRIORITIZED_SSVC
        elif sla_l in _PRIORITIZED_SLAS or sla_l.startswith("14-day") or sla_l.startswith("60-day"):
            item["is_prioritized"] = True
        elif "fix on upgrade" in sla_l or sla_l.startswith("90-day") or sla_l.startswith("180-day"):
            item["is_prioritized"] = False
        else:
            item["is_prioritized"] = bool(
                not tier_u and (band_l in ("critical", "high") or op_score >= 6.5)
            )

    dep_reasons: List[str] = []
    if item["is_validly_suppressed"]:
        dec_id = item.get("decision_id") or "policy"
        dep_reasons.append(f"Explicitly {dec_status} under decision {dec_id}")
        if item.get("rationale_summary"):
            dep_reasons.append(str(item["rationale_summary"]))
    elif not item["is_prioritized"]:
        if eff_epss is not None and eff_epss < 0.04:
            dep_reasons.append(f"Low exploit probability (EPSS {item['epss_display']})")
        elif eff_epss is None and item.get("scoring_track") == "cve_threat":
            dep_reasons.append("No elevated EPSS signal")
        if not in_kev and item.get("scoring_track") == "cve_threat":
            dep_reasons.append("Not listed in CISA KEV")
        if not item["internet_facing"]:
            dep_reasons.append("Asset is internal / not internet-facing")
        if item.get("detection_mode") == "static_sast" and (item["signal_reliability"] or 1.0) < 0.85:
            dep_reasons.append(f"Static SAST reliability weighting ({item['signal_reliability']:.2f})")
        if item["sast_p1_capped"]:
            dep_reasons.append("SAST P1-cap guardrail applied")
        if item.get("rationale_summary"):
            dep_reasons.append(str(item["rationale_summary"]))
    item["deprioritization_reasons"] = dep_reasons

    # Preserve defaults populated later by batch queries
    item.setdefault("evidence", [])
    item.setdefault("finding_cves", [])
    return item


def _attach_evidence_and_cves(
    conn: duckdb.DuckDBPyConnection,
    run_id: str,
    findings: List[Dict[str, Any]],
) -> None:
    if not findings:
        return
    fids = [f["finding_id"] for f in findings]
    by_fid: Dict[str, Dict[str, Any]] = {f["finding_id"]: f for f in findings}
    for f in findings:
        f["evidence"] = []
        f["finding_cves"] = []

    chunk_size = 500
    for i in range(0, len(fids), chunk_size):
        chunk = fids[i : i + chunk_size]
        placeholders = ", ".join("?" for _ in chunk)
        ev_cur = conn.execute(
            f"""
            SELECT finding_id, evidence_idx, source_format, scanner_sig,
                   raw_severity, raw_cvss, raw_location, evidence_excerpt
            FROM finding_evidence
            WHERE run_id = ? AND finding_id IN ({placeholders})
            ORDER BY finding_id ASC, evidence_idx ASC
            """,
            [run_id, *chunk],
        )
        ev_cols = [d[0] for d in ev_cur.description]
        for r in ev_cur.fetchall():
            rec = dict(zip(ev_cols, r))
            target = by_fid.get(rec["finding_id"])
            if target is not None:
                target["evidence"].append(rec)

        fc_cur = conn.execute(
            f"""
            SELECT finding_id, cve_id
            FROM finding_cves
            WHERE run_id = ? AND finding_id IN ({placeholders})
            ORDER BY finding_id ASC, cve_id ASC
            """,
            [run_id, *chunk],
        )
        for fid, cve in fc_cur.fetchall():
            target = by_fid.get(fid)
            if target is not None and cve:
                target["finding_cves"].append(cve)


def _fetch_dossier_findings(
    conn: duckdb.DuckDBPyConnection,
    run_id: str,
    run_intel_meta: Dict[str, Any],
    *,
    finding_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fetch prioritized, invalidated, validly deferred/accepted, and deprioritized
    findings for the Decision Defense Dossier.
    """
    rid = str(run_id)
    if finding_id is not None:
        cur = conn.execute(
            f"{_FINDING_JOIN_SELECT} WHERE f.run_id = ? AND f.finding_id = ?",
            [rid, str(finding_id)],
        )
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        if not rows:
            raise ValueError(f"Finding '{finding_id}' not found in run '{rid}'.")
        enriched = [_enrich_finding_row(dict(zip(cols, r)), run_intel_meta) for r in rows]
        _attach_evidence_and_cves(conn, rid, enriched)
        prioritized = [f for f in enriched if f["is_prioritized"]]
        invalidated = [f for f in enriched if f["is_invalidated"]]
        deferred = [f for f in enriched if f["is_validly_suppressed"]]
        deprioritized = [f for f in enriched if not f["is_prioritized"] and not f["is_validly_suppressed"]]
        return enriched, prioritized, invalidated, deferred, deprioritized

    # Full run mode: bounded SQL queries to remain fast even on 500k+ DBs
    prio_sql = f"""
        {_FINDING_JOIN_SELECT}
        WHERE f.run_id = ?
          AND (
            LOWER(COALESCE(td.decision_status, 'active')) IN ('deferred_invalidated', 'accepted_invalidated', 'mitigated_invalidated')
            OR (
                LOWER(COALESCE(td.decision_status, 'active')) NOT IN ('deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted')
                AND (
                    {_ACTIVE_PRIORITIZED_SQL}
                )
            )
          )
        ORDER BY
            CASE WHEN LOWER(COALESCE(td.decision_status, 'active')) IN ('deferred_invalidated', 'accepted_invalidated', 'mitigated_invalidated') THEN 0 ELSE 1 END ASC,
            CASE UPPER(COALESCE(td.priority_tier, 'ZZZZ'))
                WHEN 'P1' THEN 1
                WHEN 'P1B' THEN 2
                WHEN 'P2' THEN 3
                ELSE 50
            END ASC,
            s.operational_score DESC NULLS LAST,
            e.epss_score DESC NULLS LAST,
            f.finding_id ASC
        LIMIT ?
    """
    prio_cur = conn.execute(prio_sql, [rid, _DEFAULT_DOSSIER_PRIORITIZED_LIMIT])
    prio_cols = [d[0] for d in prio_cur.description]
    prio_rows = [_enrich_finding_row(dict(zip(prio_cols, r)), run_intel_meta) for r in prio_cur.fetchall()]

    supp_sql = f"""
        {_FINDING_JOIN_SELECT}
        WHERE f.run_id = ?
          AND LOWER(COALESCE(td.decision_status, 'active')) IN (
            'deferred_invalidated', 'accepted_invalidated', 'mitigated_invalidated',
            'deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted'
          )
        ORDER BY
            CASE WHEN LOWER(COALESCE(td.decision_status, 'active')) IN ('deferred_invalidated', 'accepted_invalidated', 'mitigated_invalidated') THEN 0 ELSE 1 END ASC,
            s.operational_score DESC NULLS LAST,
            f.finding_id ASC
        LIMIT ?
    """
    supp_cur = conn.execute(supp_sql, [rid, _DEFAULT_DOSSIER_DEPRIORITIZED_LIMIT])
    supp_cols = [d[0] for d in supp_cur.description]
    supp_rows = [_enrich_finding_row(dict(zip(supp_cols, r)), run_intel_meta) for r in supp_cur.fetchall()]

    dep_sql = f"""
        {_FINDING_JOIN_SELECT}
        WHERE f.run_id = ?
          AND LOWER(COALESCE(td.decision_status, 'active')) NOT IN (
            'deferred_invalidated', 'accepted_invalidated', 'mitigated_invalidated',
            'deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted'
          )
          AND NOT (
            {_ACTIVE_PRIORITIZED_SQL}
          )
        ORDER BY
            COALESCE(
                CASE WHEN LOWER(TRIM(COALESCE(e.cvss_provenance, ''))) != 'missing' THEN e.cvss_score END,
                f.scanner_cvss_score,
                0.0
            ) DESC,
            s.operational_score DESC NULLS LAST,
            f.finding_id ASC
        LIMIT ?
    """
    dep_cur = conn.execute(dep_sql, [rid, _DEFAULT_DOSSIER_DEPRIORITIZED_LIMIT])
    dep_cols = [d[0] for d in dep_cur.description]
    dep_rows = [_enrich_finding_row(dict(zip(dep_cols, r)), run_intel_meta) for r in dep_cur.fetchall()]

    # Deduplicate by finding_id across slices when attaching evidence
    all_by_id: Dict[str, Dict[str, Any]] = {}
    for row in [*prio_rows, *supp_rows, *dep_rows]:
        all_by_id.setdefault(row["finding_id"], row)
    unique_rows = list(all_by_id.values())
    _attach_evidence_and_cves(conn, rid, unique_rows)

    invalidated = [r for r in supp_rows if r["is_invalidated"]]
    deferred = [r for r in supp_rows if r["is_validly_suppressed"]]
    # Ensure invalidated also appears in prioritized list if not already
    prio_ids = {r["finding_id"] for r in prio_rows}
    for inv in invalidated:
        if inv["finding_id"] not in prio_ids:
            prio_rows.insert(0, inv)
            prio_ids.add(inv["finding_id"])

    return unique_rows, prio_rows, invalidated, deferred, dep_rows


def _build_dossier_context(
    db: Any,
    run_id: str,
    *,
    finding_id: Optional[str] = None,
    diff_report: Optional[Any] = None,
) -> Dict[str, Any]:
    conn = _get_conn(db)
    rid = str(run_id)
    run_ctx = _load_run_context(conn, rid)
    summary = get_run_summary_counts(conn, rid)
    shadow_assets = get_shadow_assets(conn, rid)

    all_findings, prioritized, invalidated, deferred, deprioritized = _fetch_dossier_findings(
        conn,
        rid,
        run_ctx["intel_metadata"],
        finding_id=finding_id,
    )
    high_cvss_deprioritized = [
        f
        for f in deprioritized
        if (f.get("effective_cvss") is not None and float(f["effective_cvss"]) >= 7.0)
        or str(f.get("scanner_severity") or "").strip().lower() in ("critical", "high")
    ]

    return {
        "generated_at_utc": _utc_now_z(),
        "run": run_ctx,
        "summary": summary,
        "shadow_assets": shadow_assets,
        "single_finding_mode": finding_id is not None,
        "requested_finding_id": finding_id,
        "all_findings": all_findings,
        "prioritized_findings": prioritized,
        "invalidated_findings": invalidated,
        "deferred_findings": deferred,
        "deprioritized_findings": deprioritized,
        "high_cvss_deprioritized": high_cvss_deprioritized,
        "diff": _coerce_diff_report(diff_report),
    }


def _build_roadmap_context(
    db: Any,
    run_id: str,
    *,
    diff_report: Optional[Any] = None,
) -> Dict[str, Any]:
    conn = _get_conn(db)
    rid = str(run_id)
    run_ctx = _load_run_context(conn, rid)
    summary = get_run_summary_counts(conn, rid)
    shadow_assets = get_shadow_assets(conn, rid)

    agg_row = conn.execute(
        f"""
        SELECT
            AVG(s.operational_score),
            MAX(s.operational_score),
            SUM(CASE WHEN {_EFFECTIVE_VERIFIED_EXPLOIT_SQL} THEN 1 ELSE 0 END)
        FROM findings f
        LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
        {_ENRICHMENT_JOIN_SQL}
        {_FINDING_CVE_AGG_JOIN_SQL}
        WHERE f.run_id = ?
        """,
        [rid],
    ).fetchone()
    avg_op_score = round(float(agg_row[0]), 2) if agg_row and agg_row[0] is not None else 0.0
    max_op_score = round(float(agg_row[1]), 2) if agg_row and agg_row[1] is not None else 0.0
    verified_exploit_findings = int(agg_row[2] or 0) if agg_row else 0

    by_status = summary.get("by_decision_status", {})
    invalidated_count = int(
        by_status.get("deferred_invalidated", 0)
        + by_status.get("accepted_invalidated", 0)
        + by_status.get("mitigated_invalidated", 0)
    )
    by_tier = summary.get("by_priority_tier", {})
    by_sla = summary.get("by_sla_bucket", {})

    # SLA Bucket Roadmap
    sla_rows = conn.execute(
        f"""
        SELECT
            COALESCE(td.sla_bucket, td.priority_tier, 'Unclassified') AS bucket,
            COALESCE(td.ssvc_action, 'Review') AS ssvc_action,
            MIN(td.sla_days) AS sla_days,
            COUNT(*) AS finding_count,
            COUNT(DISTINCT f.asset_id) AS asset_count,
            SUM(CASE WHEN {_EFFECTIVE_IN_KEV_SQL} THEN 1 ELSE 0 END) AS kev_count,
            MAX(s.operational_score) AS max_score
        FROM findings f
        LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
        LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
        {_ENRICHMENT_JOIN_SQL}
        {_FINDING_CVE_AGG_JOIN_SQL}
        WHERE f.run_id = ?
          AND LOWER(COALESCE(td.decision_status, 'active')) NOT IN ('deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted')
        GROUP BY 1, 2
        """,
        [rid],
    ).fetchall()

    bucket_order = {
        "3-day + forensic triage": 1,
        "3-day": 1,
        "14-day": 2,
        "60-day": 3,
        "fix on upgrade": 4,
    }
    sla_roadmap: List[Dict[str, Any]] = []
    for bucket, ssvc_action, sla_days, f_cnt, a_cnt, kev_cnt, m_score in sla_rows:
        top_cur = conn.execute(
            f"""
            SELECT
                f.finding_id, f.title, {_EFFECTIVE_PRIMARY_CVE_SQL} AS primary_cve, f.asset_id,
                COALESCE(a.hostname, a.ip_address, a.target_uri, a.image_or_repo, a.asset_id) AS asset_display,
                a.owner, s.operational_score, td.priority_tier, td.decision_status,
                {_EFFECTIVE_IN_KEV_SQL} AS in_kev
            FROM findings f
            LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
            LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
            LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id
            {_ENRICHMENT_JOIN_SQL}
            {_FINDING_CVE_AGG_JOIN_SQL}
            WHERE f.run_id = ?
              AND COALESCE(td.sla_bucket, td.priority_tier, 'Unclassified') = ?
              AND COALESCE(td.ssvc_action, 'Review') = ?
              AND LOWER(COALESCE(td.decision_status, 'active')) NOT IN ('deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted')
            ORDER BY s.operational_score DESC NULLS LAST, e.epss_score DESC NULLS LAST, f.finding_id ASC
            LIMIT ?
            """,
            [rid, bucket, ssvc_action, _DEFAULT_ROADMAP_BUCKET_FINDINGS_LIMIT],
        )
        t_cols = [d[0] for d in top_cur.description]
        top_items = [dict(zip(t_cols, r)) for r in top_cur.fetchall()]
        sla_roadmap.append(
            {
                "sla_bucket": bucket,
                "ssvc_action": ssvc_action,
                "sla_days": sla_days,
                "finding_count": int(f_cnt or 0),
                "asset_count": int(a_cnt or 0),
                "kev_count": int(kev_cnt or 0),
                "max_operational_score": round(float(m_score or 0.0), 2),
                "top_findings": top_items,
            }
        )
    sla_roadmap.sort(
        key=lambda b: (
            bucket_order.get(str(b["sla_bucket"]).strip().lower(), 50),
            -b["max_operational_score"],
            str(b["sla_bucket"]),
        )
    )

    # Owner-grouped remediation batches
    owner_rows = conn.execute(
        f"""
        SELECT
            COALESCE(NULLIF(TRIM(a.owner), ''), 'Unassigned / Shadow Assets') AS owner_name,
            COUNT(*) AS finding_count,
            COUNT(DISTINCT f.asset_id) AS asset_count,
            SUM(CASE WHEN UPPER(COALESCE(td.priority_tier, '')) IN ('P1', 'P1B') THEN 1 ELSE 0 END) AS p1_count,
            SUM(CASE WHEN UPPER(COALESCE(td.priority_tier, '')) = 'P2' THEN 1 ELSE 0 END) AS p2_count,
            SUM(CASE WHEN {_EFFECTIVE_IN_KEV_SQL} THEN 1 ELSE 0 END) AS kev_count,
            SUM(CASE WHEN LOWER(COALESCE(td.decision_status, '')) IN ('deferred_invalidated', 'accepted_invalidated', 'mitigated_invalidated') THEN 1 ELSE 0 END) AS invalidated_count,
            MAX(s.operational_score) AS max_score
        FROM findings f
        LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id
        LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
        LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
        {_ENRICHMENT_JOIN_SQL}
        {_FINDING_CVE_AGG_JOIN_SQL}
        WHERE f.run_id = ?
          AND LOWER(COALESCE(td.decision_status, 'active')) NOT IN ('deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted')
        GROUP BY 1
        ORDER BY p1_count DESC, kev_count DESC, max_score DESC NULLS LAST, owner_name ASC
        LIMIT 50
        """,
        [rid],
    ).fetchall()

    owner_batches: List[Dict[str, Any]] = []
    for owner_name, f_cnt, a_cnt, p1_cnt, p2_cnt, kev_cnt, inv_cnt, m_score in owner_rows:
        top_owner_cur = conn.execute(
            f"""
            SELECT
                f.finding_id, f.title, {_EFFECTIVE_PRIMARY_CVE_SQL} AS primary_cve, f.solution,
                COALESCE(a.hostname, a.ip_address, a.target_uri, a.image_or_repo, a.asset_id) AS asset_display,
                td.priority_tier, td.sla_bucket, s.operational_score,
                {_EFFECTIVE_IN_KEV_SQL} AS in_kev
            FROM findings f
            LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id
            LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
            LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
            {_ENRICHMENT_JOIN_SQL}
            {_FINDING_CVE_AGG_JOIN_SQL}
            WHERE f.run_id = ?
              AND COALESCE(NULLIF(TRIM(a.owner), ''), 'Unassigned / Shadow Assets') = ?
              AND LOWER(COALESCE(td.decision_status, 'active')) NOT IN ('deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted')
            ORDER BY
                CASE UPPER(COALESCE(td.priority_tier, 'P4'))
                    WHEN 'P1' THEN 1
                    WHEN 'P1B' THEN 2
                    WHEN 'P2' THEN 3
                    WHEN 'P3' THEN 4
                    ELSE 5
                END ASC,
                s.operational_score DESC NULLS LAST,
                f.finding_id ASC
            LIMIT 10
            """,
            [rid, owner_name],
        )
        o_cols = [d[0] for d in top_owner_cur.description]
        owner_batches.append(
            {
                "owner": owner_name,
                "finding_count": int(f_cnt or 0),
                "asset_count": int(a_cnt or 0),
                "p1_count": int(p1_cnt or 0),
                "p2_count": int(p2_cnt or 0),
                "kev_count": int(kev_cnt or 0),
                "invalidated_count": int(inv_cnt or 0),
                "max_operational_score": round(float(m_score or 0.0), 2),
                "top_findings": [dict(zip(o_cols, r)) for r in top_owner_cur.fetchall()],
            }
        )

    # Top quick-win fixes (grouped root cause reducing max findings/assets)
    qw_cur = conn.execute(
        f"""
        SELECT
            COALESCE(NULLIF({_EFFECTIVE_PRIMARY_CVE_SQL}, ''), f.title) AS fix_key,
            MAX(f.title) AS title,
            MAX(NULLIF(TRIM(f.solution), '')) AS solution,
            COUNT(*) AS finding_count,
            COUNT(DISTINCT f.asset_id) AS asset_count,
            MAX(s.operational_score) AS max_operational_score,
            MAX(CASE WHEN {_EFFECTIVE_IN_KEV_SQL} THEN 1 ELSE 0 END) AS in_kev_int,
            MIN(td.priority_tier) AS priority_tier,
            MIN(td.sla_bucket) AS sla_bucket
        FROM findings f
        LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
        LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
        {_ENRICHMENT_JOIN_SQL}
        {_FINDING_CVE_AGG_JOIN_SQL}
        WHERE f.run_id = ?
          AND LOWER(COALESCE(td.decision_status, 'active')) NOT IN ('deferred_valid', 'accepted_valid', 'mitigated', 'deferred', 'accepted')
        GROUP BY 1
        ORDER BY in_kev_int DESC, asset_count DESC, max_operational_score DESC NULLS LAST, fix_key ASC
        LIMIT 10
        """,
        [rid],
    )
    qw_cols = [d[0] for d in qw_cur.description]
    quick_wins: List[Dict[str, Any]] = []
    for r in qw_cur.fetchall():
        item = dict(zip(qw_cols, r))
        item["in_kev"] = bool(item.pop("in_kev_int", 0))
        item["max_operational_score"] = round(float(item.get("max_operational_score") or 0.0), 2)
        quick_wins.append(item)

    # Invalidated findings list
    inv_cur = conn.execute(
        f"""
        {_FINDING_JOIN_SELECT}
        WHERE f.run_id = ?
          AND LOWER(COALESCE(td.decision_status, 'active')) IN ('deferred_invalidated', 'accepted_invalidated', 'mitigated_invalidated')
        ORDER BY s.operational_score DESC NULLS LAST, f.finding_id ASC
        LIMIT 50
        """,
        [rid],
    )
    inv_cols = [d[0] for d in inv_cur.description]
    invalidated_findings = [_enrich_finding_row(dict(zip(inv_cols, r)), run_ctx["intel_metadata"]) for r in inv_cur.fetchall()]

    kpis = {
        "total_assets": summary.get("total_assets", 0),
        "matched_assets": summary.get("matched_assets", 0),
        "shadow_assets": summary.get("shadow_assets", 0),
        "total_findings": summary.get("total_findings", 0),
        "cve_findings": summary.get("cve_findings", 0),
        "exposure_findings": summary.get("exposure_findings", 0),
        "kev_findings": summary.get("kev_findings", 0),
        "verified_exploit_findings": verified_exploit_findings,
        "p1_count": int(by_tier.get("P1", 0) + by_tier.get("P1B", 0)),
        "p2_count": int(by_tier.get("P2", 0)),
        "p3_count": int(by_tier.get("P3", 0)),
        "p4_count": int(by_tier.get("P4", 0)),
        "invalidated_count": invalidated_count,
        "avg_operational_score": avg_op_score,
        "max_operational_score": max_op_score,
        "by_sla_bucket": by_sla,
        "by_risk_band": summary.get("by_risk_band", {}),
        "by_decision_status": by_status,
    }

    return {
        "generated_at_utc": _utc_now_z(),
        "run": run_ctx,
        "kpis": kpis,
        "summary": summary,
        "sla_roadmap": sla_roadmap,
        "owner_batches": owner_batches,
        "quick_wins": quick_wins,
        "shadow_assets": shadow_assets,
        "invalidated_findings": invalidated_findings,
        "diff": _coerce_diff_report(diff_report),
    }


def render_dossier_markdown(
    db: Any,
    run_id: str,
    *,
    finding_id: Optional[str] = None,
    diff_report: Optional[Any] = None,
    template_dir: Optional[Union[str, Path]] = None,
) -> str:
    """Render the Decision Defense Dossier in Markdown for a run or single finding."""
    env = _build_jinja_env(template_dir)
    ctx = _build_dossier_context(db, run_id, finding_id=finding_id, diff_report=diff_report)
    return env.get_template("dossier.md.j2").render(**ctx)


def render_dossier_html(
    db: Any,
    run_id: str,
    *,
    finding_id: Optional[str] = None,
    diff_report: Optional[Any] = None,
    template_dir: Optional[Union[str, Path]] = None,
) -> str:
    """Render a self-contained offline Decision Defense Dossier in HTML."""
    env = _build_jinja_env(template_dir)
    ctx = _build_dossier_context(db, run_id, finding_id=finding_id, diff_report=diff_report)
    return env.get_template("dossier.html.j2").render(**ctx)


def render_executive_roadmap_markdown(
    db: Any,
    run_id: str,
    *,
    diff_report: Optional[Any] = None,
    template_dir: Optional[Union[str, Path]] = None,
) -> str:
    """Render the Wedge A Executive Summary & Client Remediation Roadmap in Markdown."""
    env = _build_jinja_env(template_dir)
    ctx = _build_roadmap_context(db, run_id, diff_report=diff_report)
    return env.get_template("executive_roadmap.md.j2").render(**ctx)


def render_executive_roadmap_html(
    db: Any,
    run_id: str,
    *,
    diff_report: Optional[Any] = None,
    template_dir: Optional[Union[str, Path]] = None,
) -> str:
    """Render a self-contained offline Executive Summary & Client Roadmap in HTML."""
    env = _build_jinja_env(template_dir)
    ctx = _build_roadmap_context(db, run_id, diff_report=diff_report)
    return env.get_template("executive_roadmap.html.j2").render(**ctx)


def render_diff_pr_comment(
    diff_report: Any,
    *,
    template_dir: Optional[Union[str, Path]] = None,
) -> str:
    """Render a concise CI pull-request summary Markdown comment from a DiffReport."""
    if diff_report is None:
        raise ValueError("diff_report must not be None.")
    env = _build_jinja_env(template_dir)
    diff_ctx = _coerce_diff_report(diff_report)
    return env.get_template("diff_pr_comment.md.j2").render(
        generated_at_utc=_utc_now_z(),
        diff=diff_ctx,
    )


def export_dossier_bundle(
    db: Any,
    run_id: str,
    output_dir: Union[str, Path],
    *,
    finding_id: Optional[str] = None,
    diff_report: Optional[Any] = None,
    template_dir: Optional[Union[str, Path]] = None,
    pfh: Optional[Any] = None,
) -> Dict[str, Path]:
    """
    Write Decision Defense Dossier Markdown and HTML files into `output_dir` and
    return `{"markdown": path_md, "html": path_html}`.
    """
    out_dir = Path(output_dir)
    if pfh is None:
        ensure_safe_dir_non_pfh(out_dir, label="dossier bundle output directory")

    prefix = f"{_safe_filename_stem(finding_id)}_dossier" if finding_id is not None else "dossier"
    path_md = out_dir / f"{prefix}.md"
    path_html = out_dir / f"{prefix}.html"

    # Compute context once so both artifacts carry consistent data and timestamps
    env = _build_jinja_env(template_dir)
    ctx = _build_dossier_context(db, run_id, finding_id=finding_id, diff_report=diff_report)
    md_text = env.get_template("dossier.md.j2").render(**ctx)
    html_text = env.get_template("dossier.html.j2").render(**ctx)

    written_md = _write_text_safe(path_md, md_text, pfh=pfh, label="Dossier Markdown")
    written_html = _write_text_safe(path_html, html_text, pfh=pfh, label="Dossier HTML")
    return {"markdown": written_md, "html": written_html}
