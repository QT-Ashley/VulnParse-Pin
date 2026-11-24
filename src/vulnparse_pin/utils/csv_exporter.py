# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from collections.abc import Sequence
import csv
import json
import os
import re
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
import unicodedata

import duckdb

from vulnparse_pin.core.classes.dataclass import ScanResult, RunContext
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult
from vulnparse_pin.core.passes.types import ScoredFinding
from vulnparse_pin.storage.db import (
    _check_no_symlinks_or_loops,
    ensure_safe_dir_non_pfh,
    open_for_write_non_pfh,
)
from vulnparse_pin.utils.cvss_utils import resolve_effective_cvss_fields

_DANGEROUS_PREFIXES = ("=", "-", "+", "@")

_LEADING_STRIP_RE = re.compile(r"^[\s\u00A0\u2000-\u200B\u202F\u205F\u3000]+")

SENTINEL_SCORE = -1.0

_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0E-\x1F\x7F]")

CSV_PROFILES = {"full", "analyst", "audit"}

FULL_PROFILE_COLUMNS = [
    "asset_id",
    "asset_hostname",
    "asset_ip",
    "asset_criticality",
    "asset_avg_risk_score",
    "finding_id",
    "vuln_id",
    "title",
    "severity",
    "source_format",
    "fidelity_tier",
    "ingestion_confidence",
    "degraded_input",
    "missing_fields",
    "authoritative_cve",
    "cves",
    "cvss_score",
    "cvss_vector",
    "epss_score",
    "cisa_kev",
    "exploit_available",
    "exploit_ids",
    "exploit_titles",
    "exploit_urls",
    "affected_port",
    "protocol",
    "solution",
    "description",
    "raw_score",
    "operational_score",
    "risk_band",
    "score_reason(s)",
    "topn_rank_basis",
    "topn_asset_rank",
    "topn_weighted_asset_score",
    "topn_finding_rank",
    "topn_global_rank",
    "topn_exposure_score",
    "topn_exposure_confidence",
    "topn_externally_facing_inferred",
    "topn_public_service_ports_inferred",
    "topn_inference_evidence",
]

ANALYST_PROFILE_COLUMNS = [
    "scan_source",
    "scan_timestamp",
    "asset_id",
    "asset_hostname",
    "asset_ip",
    "asset_criticality",
    "finding_id",
    "vuln_id",
    "title",
    "severity",
    "fidelity_tier",
    "ingestion_confidence",
    "degraded_input",
    "authoritative_cve",
    "display_cve",
    "raw_score",
    "operational_score",
    "risk_band",
    "exploit_available_union",
    "kev_union",
    "ghsa_advisory_match",
    "ghsa_reference_count",
    "cvss_score",
    "epss_score",
    "affected_port",
    "protocol",
    "topn_asset_rank",
    "topn_finding_rank",
    "topn_global_rank",
    "topn_externally_facing_inferred",
    "topn_exposure_confidence",
    "remediation_bucket",
]

AUDIT_PROFILE_COLUMNS = ANALYST_PROFILE_COLUMNS + [
    "aggregation_mode",
    "decay_factor",
    "aggregated_cve_count",
    "included_contributors",
    "aggregated_exploitable_cve_count",
    "aggregated_kev_cve_count",
    "primary_cve",
    "nmap_open_port_union",
    "score_reason(s)",
    "top_contributor_1_cve",
    "top_contributor_1_raw_contribution",
    "top_contributor_2_cve",
    "top_contributor_2_raw_contribution",
    "ghsa_references",
    "topn_inference_evidence",
    "topn_inference_rule_hits",
]


def _profile_columns(csv_profile: str) -> List[str]:
    if csv_profile == "full":
        return list(FULL_PROFILE_COLUMNS)
    if csv_profile == "analyst":
        return list(ANALYST_PROFILE_COLUMNS)
    if csv_profile == "audit":
        return list(AUDIT_PROFILE_COLUMNS)
    raise ValueError(f"Unknown csv_profile '{csv_profile}'. Expected one of {sorted(CSV_PROFILES)}")


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _remediation_bucket(risk_band: str, kev_union: bool, exploit_union: bool) -> str:
    band = str(risk_band or "").strip().lower()
    if band == "critical" and (kev_union or exploit_union):
        return "immediate"
    if band in ("critical", "high"):
        return "high"
    if band == "medium":
        return "medium"
    return "low"

def _flatten_exploits(exploit_refs: Any) -> tuple[str, str, str]:
    """
    Flatten exploit refs into semicolon-separated strings.

    Returns:
        (ids, titles, urls) as strings
    """
    if not exploit_refs:
        return ("", "", "")


    ids: List[str] = []
    titles: List[str] = []
    urls: List[str] = []

    # New shape (v1.0.3+): list[dict] with optional ref['cve']
    if isinstance(exploit_refs, list):
        for ref in exploit_refs:
            if not isinstance(ref, dict):
                continue
            cve = str(ref.get("cve") or "")
            prefix = f"{cve}:" if cve else ""
            ids.append(f"{prefix}{ref.get('exploit_id', '')}")
            titles.append(f"{prefix}{ref.get('title', '')}")
            urls.append(f"{prefix}{ref.get('url', '')}")
        return ";".join(ids), ";".join(titles), ";".join(urls)

    # Legacy shape: dict[cve -> list[dict]]
    if isinstance(exploit_refs, dict):
        for cve, refs in exploit_refs.items():
            if not refs or not isinstance(refs, list):
                continue

            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                ids.append(f"{cve}:{ref.get('exploit_id', '')}")
                titles.append(f"{cve}:{ref.get('title', '')}")
                urls.append(f"{cve}:{ref.get('url', '')}")
        return ";".join(ids), ";".join(titles), ";".join(urls)

    return ";".join(ids), ";".join(titles), ";".join(urls)

def _sanitize_csv_cell(value: str) -> Any:
    """
    Sanitize a single CSV cell to mitigate CSV/formula injection.

    If the cell begins with a dangerous character, prefix with single quote to avoid spreadsheets treating it as a formula.

    Args:
        value (str): Cell value to sanitize.
    """
    if value is None or not isinstance(value, str) or value == "":
        return value

    s = value

    s = unicodedata.normalize("NFC",  s)
    # Replace CR/LR
    s = s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    # Remove control chars
    s = _CONTROL_RE.sub("", s)

    stripped = _LEADING_STRIP_RE.sub("", s)
    if stripped and stripped[0] in _DANGEROUS_PREFIXES:
        leading_len = len(s) - len(stripped)
        leading = s[:leading_len]
        return leading + "'" + stripped

    if s and s[0] == "\t":
        return "'" + s

    return s

def _sanitize_csv_row(row: Dict[str, Any]) -> Dict:
    """
    Return a copy of the row with CSV-injection-safe values.
    Only string fields are sanitized.
    """
    safe: Dict = {}
    for key, value in row.items():
        safe[key] = _sanitize_csv_cell(value) if isinstance(value, str) else value
    return safe

def _resolve_pass(scan: ScanResult, prefix: str) -> Optional[Dict[str, DerivedPassResult]]:
    """
    Resolve a derived pass by key prefix.
    Returns the pass dictionary obj.
    """
    passes = scan.derived.passes
    if not isinstance(passes, dict):
        return None

    preferred = f"{prefix}2.0"
    if preferred in passes:
        return passes[preferred]

    # Fallback lookup
    for k, v in passes.items():
        if isinstance(k, str) and k.startswith(prefix):
            return v

def export_to_csv(
    ctx: "RunContext",
    scan_result: ScanResult,
    *,
    csv_path: str | Path,
    csv_sanitization: bool = True,
    csv_profile: str = "full",
) -> None:
    """
    Export scan findings to a CSV file with streaming output.

    Args:
        scan_result (ScanResult): Parsed & enriched results
        csv_path (str): Destination CSV file path
        csv_sanitization (bool): Whether to sanitize CSV cells for Excel compatibility
        csv_profile (str): CSV view profile. One of: full, analyst, audit
    """

    profile = str(csv_profile or "full").strip().lower()
    if profile not in CSV_PROFILES:
        raise ValueError(f"Unknown csv_profile '{csv_profile}'. Expected one of {sorted(CSV_PROFILES)}")

    # ------- derived overlays --------
    scoring_pass = _resolve_pass(scan_result, "Scoring@")
    topn_pass = _resolve_pass(scan_result, "TopN@")

    scored_findings: Dict[str, ScoredFinding] = {}

    if scoring_pass:
        data = getattr(scoring_pass, "data", {})
        if isinstance(data, dict):
            sf = data.get("scored_findings")
            if isinstance(sf, dict):
                scored_findings = sf

    topn_asset_rank: Dict[str, Dict[str, Any]] = {}
    topn_finding_rank: Dict[str, Dict[str, Any]] = {}
    global_rank: Dict[str, int] = {}
    topn_rank_basis: str = ""

    if topn_pass:
        data = getattr(topn_pass, "data")
        if isinstance(data, dict):
            topn_rank_basis = str(data.get("rank_basis") or "")

            assets = data.get("assets", [])
            if isinstance(assets, Sequence):
                for a in assets:
                    if isinstance(a, dict) and a.get("asset_id"):
                        topn_asset_rank[str(a["asset_id"])] = a

            fba = data.get("findings_by_asset", {})
            if isinstance(fba, dict):
                for _, flist in fba.items():
                    if not isinstance(flist, Sequence):
                        continue
                    for frec in flist:
                        if isinstance(frec, dict) and frec.get("finding_id"):
                            topn_finding_rank[str(frec["finding_id"])] = frec

            gtf = data.get("global_top_findings", [])
            if isinstance(gtf, Sequence):
                for frec in gtf:
                    if isinstance(frec, dict) and frec.get("finding_id") and isinstance(frec.get("rank"), int):
                        global_rank[str(frec["finding_id"])] = int(frec["rank"])

    # Count total findings for progress logging
    total_findings = sum(len(asset.findings) for asset in scan_result.assets)

    if total_findings == 0:
        ctx.logger.warning("No findings to export. Skipping CSV write.", extra={"vp_label": "CSV Exporter"})
        return

    ctx.logger.debug(f"Streaming CSV export for {total_findings} findings", extra={"vp_label": "CSV Exporter"})

    fieldnames = _profile_columns(profile)
    scan_metadata = getattr(scan_result, "scan_metadata", None)
    scan_source = getattr(scan_metadata, "source", "") if scan_metadata is not None else ""
    scan_timestamp_raw = getattr(scan_metadata, "scan_date", None) if scan_metadata is not None else None
    scan_timestamp = str(scan_timestamp_raw) if scan_timestamp_raw is not None else ""

    # Stream CSV output - write header first, then process findings one by one
    with ctx.pfh.open_for_write(csv_path, mode = "w", encoding = "utf-8", label = "CSV-Output", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        rows_written = 0

        for asset in scan_result.assets:
            for finding in asset.findings:
                # Build row data for this finding
                row = _build_csv_row(
                    asset,
                    finding,
                    scored_findings,
                    topn_asset_rank,
                    topn_finding_rank,
                    global_rank,
                    topn_rank_basis,
                    scan_source,
                    scan_timestamp,
                )

                # Write the row immediately
                sanitized_row = _sanitize_csv_row(row) if csv_sanitization else row
                writer.writerow(sanitized_row)
                rows_written += 1

                # Progress logging for large exports (every 1000 rows)
                if rows_written % 1000 == 0:
                    ctx.logger.debug(f"CSV export progress: {rows_written}/{total_findings} rows", extra={"vp_label": "CSV Exporter"})

    ctx.logger.print_success(f"Results exported to CSV: {csv_path.name} ({rows_written} rows)")


def _build_csv_row(
    asset,
    finding,
    scored_findings,
    topn_asset_rank,
    topn_finding_rank,
    global_rank,
    topn_rank_basis,
    scan_source: str,
    scan_timestamp: str,
):
    """
    Build a single CSV row dictionary for a finding.
    Extracted for clarity and to enable streaming.
    """
    exploit_ids, exploit_titles, exploit_urls = _flatten_exploits(finding.exploit_references)

    fid = getattr(finding, "finding_id", "") or ""
    aid = getattr(asset, "asset_id", "") or getattr(finding, "asset_id", "") or ""

    srec = scored_findings.get(fid) if fid else None
    topn_frec = topn_finding_rank.get(fid) if fid else None
    topn_arec = topn_asset_rank.get(aid) if aid else None
    inf = topn_arec.get("inference") if isinstance(topn_arec, dict) else None
    if not isinstance(inf, dict):
        inf = {}

    # Scoring Overlay
    # Coerce None to SENTINEL_SCORE before rounding to prevent TypeError
    raw_score_val = srec.get("raw_score") if isinstance(srec, dict) else SENTINEL_SCORE
    raw_score = round(raw_score_val if raw_score_val is not None else SENTINEL_SCORE, 4)
    operational_score_val = srec.get("operational_score") if isinstance(srec, dict) else SENTINEL_SCORE
    operational_score = round(operational_score_val if operational_score_val is not None else SENTINEL_SCORE, 4)
    risk_band = srec.get("risk_band") if isinstance(srec, dict) else ""
    score_reason = srec.get("reason") if isinstance(srec, dict) else ""
    score_trace = srec.get("score_trace", {}) if isinstance(srec, dict) else {}
    if not isinstance(score_trace, dict):
        score_trace = {}
    union_flags = score_trace.get("union_flags", {})
    if not isinstance(union_flags, dict):
        union_flags = {}
    contributors = score_trace.get("contributors", [])
    if not isinstance(contributors, list):
        contributors = []

    display_cve = (
        score_trace.get("display_cve")
        or getattr(finding, "enrichment_source_cve", "")
        or (getattr(finding, "cves", [""])[0] if getattr(finding, "cves", None) else "")
    )
    primary_cve = score_trace.get("primary_cve") or ""
    aggregation_mode = score_trace.get("aggregation_mode") or ""
    decay_factor = score_trace.get("decay_factor")
    aggregated_cve_count = _to_int(score_trace.get("cve_count"), default=0)
    included_contributors = _to_int(score_trace.get("included_contributors"), default=0)
    exploit_count = 0
    kev_count = 0
    for c in contributors:
        if not isinstance(c, dict):
            continue
        if bool(c.get("exploit_available", False)):
            exploit_count += 1
        if bool(c.get("cisa_kev", False)):
            kev_count += 1

    exploit_union = bool(getattr(finding, "exploit_available", False) or union_flags.get("exploit", False))
    kev_union = bool(getattr(finding, "cisa_kev", False) or union_flags.get("kev", False))

    aggregated_exploitable_cve_count = exploit_count if exploit_count > 0 else (1 if exploit_union else 0)
    aggregated_kev_cve_count = kev_count if kev_count > 0 else (1 if kev_union else 0)

    top_contrib_1 = contributors[0] if len(contributors) > 0 and isinstance(contributors[0], dict) else {}
    top_contrib_2 = contributors[1] if len(contributors) > 1 and isinstance(contributors[1], dict) else {}

    # TopN Overlay
    topn_asset_rank_v = topn_arec.get("rank") if isinstance(topn_arec, dict) else None
    topn_asset_score_val = topn_arec.get("score") if isinstance(topn_arec, dict) else SENTINEL_SCORE
    topn_asset_score = round(topn_asset_score_val if topn_asset_score_val is not None else SENTINEL_SCORE, 4)
    topn_finding_rank_v = topn_frec.get("rank") if isinstance(topn_frec, dict) else None
    topn_global_rank_v = global_rank.get(fid) if fid else None
    topn_exposure_score = inf.get("exposure_score")
    topn_exposure_conf = inf.get("confidence") or ""
    topn_externally_facing_inferred = inf.get("externally_facing_inferred")
    topn_public_service_ports = inf.get("public_service_ports_inferred")
    ev = inf.get("evidence")
    if isinstance(ev, (list, tuple)):
        topn_inference_evidence = ";".join(str(x) for x in ev if x is not None)
    else:
        topn_inference_evidence = ""

    rids = inf.get("evidence_rule_ids")
    if isinstance(rids, (list, tuple)):
        topn_inference_rule_hits = "|".join(str(x) for x in rids if x is not None)
    else:
        topn_inference_rule_hits = ""

    _avg_risk = getattr(asset, "avg_risk_score", None)
    _cvss = getattr(finding, "cvss_score", None)
    _epss = getattr(finding, "epss_score", None)
    finding_refs = getattr(finding, "references", []) or []
    ghsa_refs = [str(r) for r in finding_refs if "GHSA-" in str(r)]
    ghsa_match = len(ghsa_refs) > 0

    return {
        # ----- Scan Context -----
        "scan_source": scan_source,
        "scan_timestamp": scan_timestamp,

        # ----- Asset Truth -----
        "asset_id": aid,
        "asset_hostname": getattr(asset, "hostname", "") or "",
        "asset_ip": getattr(asset, "ip_address", "") or "",
        "asset_criticality": getattr(asset, "criticality", "") or "",
        "asset_avg_risk_score": _avg_risk if _avg_risk is not None else SENTINEL_SCORE,

        # ---- Finding Truth/Enrichment ----
        "finding_id": fid,
        "vuln_id": getattr(finding, "vuln_id", "") or "",
        "title": getattr(finding, "title", "") or "",
        "severity": getattr(finding, "severity", "") or "",
        "source_format": getattr(finding, "source_format", "") or "",
        "fidelity_tier": getattr(finding, "fidelity_tier", "") or "",
        "ingestion_confidence": round(float(getattr(finding, "ingestion_confidence", SENTINEL_SCORE) if getattr(finding, "ingestion_confidence", None) is not None else SENTINEL_SCORE), 4),
        "degraded_input": bool(getattr(finding, "degraded_input", False)),
        "missing_fields": ";".join([str(x) for x in (getattr(finding, "missing_fields", []) or [])]),
        "authoritative_cve": getattr(finding, "enrichment_source_cve", "") or "",
        "display_cve": display_cve,
        "cves": ";".join(map(str, getattr(finding, "cves", []) or [])),
        "cvss_score": _cvss if _cvss is not None else SENTINEL_SCORE,
        "cvss_vector": getattr(finding, "cvss_vector", "") or "",
        "epss_score": _epss if _epss is not None else SENTINEL_SCORE,
        "cisa_kev": bool(getattr(finding, "cisa_kev", False)),
        "exploit_available": bool(getattr(finding, "exploit_available", False) or getattr(finding, "cisa_kev", False)),
        "kev_union": kev_union,
        "exploit_available_union": exploit_union,
        "ghsa_advisory_match": ghsa_match,
        "ghsa_reference_count": len(ghsa_refs),
        "exploit_ids": exploit_ids,
        "exploit_titles": exploit_titles,
        "exploit_urls": exploit_urls,
        "affected_port": getattr(finding, "affected_port", None),
        "protocol": getattr(finding, "protocol", "") or "",

        "solution": getattr(finding, "solution", "") or "",
        "description": getattr(finding, "description", "") or "",

        # ---- Scoring Overlay ----
        "raw_score": raw_score,
        "operational_score": operational_score,
        "risk_band": risk_band,
        "score_reason(s)": score_reason,
        "aggregation_mode": aggregation_mode,
        "decay_factor": _to_float(decay_factor, default=0.0) if decay_factor is not None else SENTINEL_SCORE,
        "aggregated_cve_count": aggregated_cve_count,
        "included_contributors": included_contributors,
        "aggregated_exploitable_cve_count": aggregated_exploitable_cve_count,
        "aggregated_kev_cve_count": aggregated_kev_cve_count,
        "primary_cve": primary_cve,
        "nmap_open_port_union": bool(union_flags.get("nmap_open_port", False)),
        "top_contributor_1_cve": top_contrib_1.get("cve_id", ""),
        "top_contributor_1_raw_contribution": _to_float(top_contrib_1.get("raw_contribution"), default=SENTINEL_SCORE),
        "top_contributor_2_cve": top_contrib_2.get("cve_id", ""),
        "top_contributor_2_raw_contribution": _to_float(top_contrib_2.get("raw_contribution"), default=SENTINEL_SCORE),
        "ghsa_references": ";".join(ghsa_refs),
        "remediation_bucket": _remediation_bucket(risk_band, kev_union, exploit_union),

        # ---- TopN Overlay ----
        "topn_rank_basis": topn_rank_basis,
        "topn_asset_rank": topn_asset_rank_v,
        "topn_weighted_asset_score": topn_asset_score,
        "topn_finding_rank": topn_finding_rank_v,
        "topn_global_rank": topn_global_rank_v,
        "topn_exposure_score": topn_exposure_score,
        "topn_exposure_confidence": topn_exposure_conf,
        "topn_externally_facing_inferred": topn_externally_facing_inferred,
        "topn_public_service_ports_inferred": topn_public_service_ports,
        "topn_inference_evidence": topn_inference_evidence,
        "topn_inference_rule_hits": topn_inference_rule_hits,
    }


V2_ANALYST_PROFILE_COLUMNS = [
    "run_id",
    "asset_id",
    "asset_hostname",
    "asset_ip",
    "target_uri",
    "image_or_repo",
    "inventory_status",
    "owner",
    "internet_facing",
    "asset_criticality",
    "finding_id",
    "title",
    "severity",
    "scoring_track",
    "detection_mode",
    "signal_reliability",
    "ingestion_confidence",
    "fidelity_tier",
    "source_format",
    "primary_cve",
    "cvss_score",
    "cvss_version",
    "cvss_provenance",
    "epss_score",
    "epss_percentile",
    "cisa_kev",
    "verified_exploit",
    "raw_score",
    "operational_score",
    "risk_band",
    "priority_tier",
    "oal_compat",
    "ssvc_action",
    "sla_bucket",
    "sla_days",
    "decision_status",
    "affected_port",
    "protocol",
    "is_deduplicated",
    "source_count",
]

V2_FULL_PROFILE_COLUMNS = V2_ANALYST_PROFILE_COLUMNS + [
    "canonical_key",
    "cves",
    "cwes",
    "ghsa_ids",
    "cvss_vector",
    "kev_date_added",
    "kev_due_date",
    "kev_ransomware",
    "heuristic_exploit_mention",
    "package_purl",
    "location_uri",
    "line_number",
    "service_name",
    "open_ports",
    "aci_capabilities",
    "aci_chains",
    "aci_confidence",
    "aci_uplift_score",
    "description",
    "solution",
]

V2_AUDIT_PROFILE_COLUMNS = V2_FULL_PROFILE_COLUMNS + [
    "matched_rule_id",
    "decision_id",
    "rationale_summary",
    "epss_model_version",
    "epss_date",
    "enrichment_sources",
    "score_trace_json",
    "assumed_state_json",
]


def _v2_profile_columns(csv_profile: str) -> List[str]:
    if csv_profile == "full":
        return list(V2_FULL_PROFILE_COLUMNS)
    if csv_profile == "analyst":
        return list(V2_ANALYST_PROFILE_COLUMNS)
    if csv_profile == "audit":
        return list(V2_AUDIT_PROFILE_COLUMNS)
    raise ValueError(f"Unknown csv_profile '{csv_profile}'. Expected one of {sorted(CSV_PROFILES)}")


def _resolve_duckdb_conn(db: Any) -> duckdb.DuckDBPyConnection:
    if isinstance(db, duckdb.DuckDBPyConnection):
        return db
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    raise TypeError(f"Expected VppDatabase or DuckDBPyConnection, got {type(db).__name__}")


def _json_list_to_joined(raw: Optional[str]) -> str:
    if not raw or raw == "[]":
        return ""
    try:
        loaded = json.loads(raw)
        if isinstance(loaded, list):
            return ";".join(str(x) for x in loaded if x is not None)
    except Exception:
        pass
    return str(raw)


def _json_obj_safe(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def export_duckdb_csv(
    db: Any,
    run_id: str,
    out_path: Union[str, Path],
    *,
    profile: str = "full",
    pfh: Optional[Any] = None,
    csv_sanitization: bool = True,
) -> Path:
    """
    Stream findings for `run_id` directly from DuckDB cursor into a CSV file,
    applying `_sanitize_csv_cell` to every exported cell when `csv_sanitization` is enabled.
    """
    prof = str(profile or "full").strip().lower()
    fieldnames = _v2_profile_columns(prof)
    conn = _resolve_duckdb_conn(db)
    rid = str(run_id)

    has_run = conn.execute("SELECT 1 FROM runs WHERE run_id = ? LIMIT 1", [rid]).fetchone()
    if has_run is None:
        has_findings = conn.execute("SELECT 1 FROM findings WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        has_assets = conn.execute("SELECT 1 FROM assets WHERE run_id = ? LIMIT 1", [rid]).fetchone()
        if has_findings is None and has_assets is None:
            raise ValueError(f"Run '{rid}' does not exist in database.")

    target = Path(out_path)
    if pfh is None:
        _check_no_symlinks_or_loops(target, label="CSV output path")
        ensure_safe_dir_non_pfh(target.parent, label="CSV output parent directory")
        _check_no_symlinks_or_loops(target, label="CSV output path")

    sql = """
        SELECT
            f.run_id,
            f.asset_id,
            a.hostname AS asset_hostname,
            a.ip_address AS asset_ip,
            a.target_uri,
            a.image_or_repo,
            a.inventory_status,
            a.owner,
            a.internet_facing,
            COALESCE(a.derived_criticality, a.declared_criticality) AS asset_criticality,
            f.finding_id,
            f.title,
            f.scanner_severity AS severity,
            f.scoring_track,
            f.detection_mode,
            f.signal_reliability,
            f.ingestion_confidence,
            f.fidelity_tier,
            f.source_format,
            COALESCE(UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')), f.primary_cve) AS primary_cve,
            e.cvss_score AS snap_cvss_score,
            f.scanner_cvss_score,
            e.cvss_version AS snap_cvss_version,
            e.cvss_provenance AS snap_cvss_provenance,
            e.cvss_vector AS snap_cvss_vector,
            f.scanner_cvss_vector,
            e.epss_score,
            e.epss_percentile,
            e.epss_model_version,
            e.epss_date,
            (
                COALESCE(e.in_kev, FALSE)
                OR COALESCE(fc_agg.fc_in_kev, FALSE)
                OR COALESCE(TRY_CAST(json_extract_string(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
            ) AS cisa_kev,
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
            s.raw_risk_score AS raw_score,
            s.operational_score,
            s.risk_band,
            s.score_trace_json,
            td.priority_tier,
            td.oal_compat,
            td.ssvc_action,
            td.sla_bucket,
            td.sla_days,
            COALESCE(td.decision_status, 'active') AS decision_status,
            td.decision_id,
            td.rationale_summary,
            td.assumed_state_json,
            f.affected_port,
            f.protocol,
            f.is_deduplicated,
            f.source_count,
            a.canonical_key,
            f.cves_json,
            f.cwes_json,
            f.ghsa_ids_json,
            f.package_purl,
            f.location_uri,
            f.line_number,
            f.service_name,
            a.open_ports_json,
            a.matched_rule_id,
            aci.capabilities_json,
            aci.chains_json,
            aci.confidence AS aci_confidence,
            aci.uplift_score AS aci_uplift_score,
            f.description,
            f.solution,
            e.sources_json
        FROM findings f
        LEFT JOIN assets a ON a.run_id = f.run_id AND a.asset_id = f.asset_id
        LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
        LEFT JOIN enrichment_snapshots e ON e.run_id = f.run_id
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
        ) fc_agg ON fc_agg.finding_id = f.finding_id
        LEFT JOIN triage_decisions td ON td.run_id = f.run_id AND td.finding_id = f.finding_id
        LEFT JOIN aci_signals aci ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id
        WHERE f.run_id = ?
        ORDER BY
            CASE UPPER(COALESCE(td.priority_tier, 'ZZZZ'))
                WHEN 'P1' THEN 1
                WHEN 'P1B' THEN 2
                WHEN 'P2' THEN 3
                WHEN 'P3' THEN 4
                WHEN 'P4' THEN 5
                ELSE 99
            END ASC,
            s.operational_score DESC NULLS LAST,
            e.epss_score DESC NULLS LAST,
            f.finding_id ASC
    """

    cursor = conn.cursor()
    try:
        cursor.execute(sql, [rid, rid])
        cols = [d[0] for d in cursor.description]

        def _write_rows(fh: Any) -> None:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            while True:
                batch = cursor.fetchmany(5000)
                if not batch:
                    break
                for raw_tuple in batch:
                    rec = dict(zip(cols, raw_tuple))
                    trace = _json_obj_safe(rec.get("score_trace_json"))

                    cvss_score, cvss_prov, cvss_ver, eff_vec = resolve_effective_cvss_fields(
                        snap_cvss=rec["snap_cvss_score"],
                        snap_prov=rec["snap_cvss_provenance"],
                        snap_ver=rec["snap_cvss_version"],
                        snap_vec=rec["snap_cvss_vector"],
                        scanner_cvss=rec["scanner_cvss_score"],
                        scanner_vec=rec["scanner_cvss_vector"],
                        score_trace=trace,
                    )
                    cvss_vec = eff_vec or ""
                    kev_added = rec["kev_date_added"] or (trace.get("kev_date_added") if rec["cisa_kev"] else None) or ""
                    kev_due = rec["kev_due_date"] or (trace.get("kev_due_date") if rec["cisa_kev"] else None) or ""
                    kev_ransom = rec["kev_ransomware"]
                    if rec["cisa_kev"] and (kev_ransom is None or kev_ransom == ""):
                        kev_ransom = trace.get("kev_ransomware")
                    kev_ransom_str = "" if kev_ransom is None else kev_ransom

                    epss_score = rec["epss_score"] if rec["epss_score"] is not None else trace.get("epss_score")
                    epss_pct = rec["epss_percentile"] if rec["epss_percentile"] is not None else trace.get("epss_percentile")

                    row_dict: Dict[str, Any] = {
                        "run_id": rec["run_id"] or rid,
                        "asset_id": rec["asset_id"] or "",
                        "asset_hostname": rec["asset_hostname"] or "",
                        "asset_ip": rec["asset_ip"] or "",
                        "target_uri": rec["target_uri"] or "",
                        "image_or_repo": rec["image_or_repo"] or "",
                        "inventory_status": rec["inventory_status"] or "",
                        "owner": rec["owner"] or "",
                        "internet_facing": rec["internet_facing"],
                        "asset_criticality": rec["asset_criticality"] or "",
                        "finding_id": rec["finding_id"] or "",
                        "title": rec["title"] or "",
                        "severity": rec["severity"] or "",
                        "scoring_track": rec["scoring_track"] or "",
                        "detection_mode": rec["detection_mode"] or "",
                        "signal_reliability": rec["signal_reliability"],
                        "ingestion_confidence": rec["ingestion_confidence"],
                        "fidelity_tier": rec["fidelity_tier"] or "",
                        "source_format": rec["source_format"] or "",
                        "primary_cve": rec["primary_cve"] or "",
                        "cvss_score": cvss_score,
                        "cvss_version": cvss_ver or "",
                        "cvss_provenance": cvss_prov,
                        "epss_score": epss_score,
                        "epss_percentile": epss_pct,
                        "cisa_kev": bool(rec["cisa_kev"]),
                        "verified_exploit": bool(rec["verified_exploit"]),
                        "raw_score": rec["raw_score"],
                        "operational_score": rec["operational_score"],
                        "risk_band": rec["risk_band"] or "",
                        "priority_tier": rec["priority_tier"] or "",
                        "oal_compat": rec["oal_compat"] or "",
                        "ssvc_action": rec["ssvc_action"] or "",
                        "sla_bucket": rec["sla_bucket"] or "",
                        "sla_days": rec["sla_days"],
                        "decision_status": rec["decision_status"] or "active",
                        "affected_port": rec["affected_port"],
                        "protocol": rec["protocol"] or "",
                        "is_deduplicated": bool(rec["is_deduplicated"]),
                        "source_count": rec["source_count"],
                        "canonical_key": rec["canonical_key"] or "",
                        "cves": _json_list_to_joined(rec["cves_json"]),
                        "cwes": _json_list_to_joined(rec["cwes_json"]),
                        "ghsa_ids": _json_list_to_joined(rec["ghsa_ids_json"]),
                        "cvss_vector": cvss_vec,
                        "kev_date_added": kev_added,
                        "kev_due_date": kev_due,
                        "kev_ransomware": kev_ransom_str,
                        "heuristic_exploit_mention": bool(rec["heuristic_exploit_mention"]),
                        "package_purl": rec["package_purl"] or "",
                        "location_uri": rec["location_uri"] or "",
                        "line_number": rec["line_number"],
                        "service_name": rec["service_name"] or "",
                        "open_ports": _json_list_to_joined(rec["open_ports_json"]),
                        "aci_capabilities": _json_list_to_joined(rec["capabilities_json"]),
                        "aci_chains": _json_list_to_joined(rec["chains_json"]),
                        "aci_confidence": rec["aci_confidence"],
                        "aci_uplift_score": rec["aci_uplift_score"],
                        "description": rec["description"] or "",
                        "solution": rec["solution"] or "",
                        "matched_rule_id": rec["matched_rule_id"] or "",
                        "decision_id": rec["decision_id"] or "",
                        "rationale_summary": rec["rationale_summary"] or "",
                        "epss_model_version": rec["epss_model_version"] or trace.get("epss_model_version") or "",
                        "epss_date": rec["epss_date"] or trace.get("epss_date") or "",
                        "enrichment_sources": _json_list_to_joined(rec["sources_json"]),
                        "score_trace_json": rec["score_trace_json"] or "",
                        "assumed_state_json": rec["assumed_state_json"] or "",
                    }
                    row_out = (
                        {col: _sanitize_csv_cell(row_dict.get(col)) for col in fieldnames}
                        if csv_sanitization
                        else {col: row_dict.get(col) for col in fieldnames}
                    )
                    writer.writerow(row_out)

        if pfh is not None:
            resolved = pfh.ensure_writable_file(target, label="CSV-Output", create_parents=True, overwrite=True)
            with pfh.open_for_write(resolved, mode="w", encoding="utf-8", label="CSV-Output", newline="") as fh:
                _write_rows(fh)
            return Path(resolved)

        with open_for_write_non_pfh(target, label="CSV-Output", encoding="utf-8", newline="") as fh:
            _write_rows(fh)
        return target
    finally:
        try:
            cursor.close()
        except Exception:
            pass
