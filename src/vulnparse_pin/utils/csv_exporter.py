# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from collections.abc import Sequence
import csv
import re
from typing import Any, Dict, List, Optional
from pathlib import Path
import unicodedata

from vulnparse_pin.core.classes.dataclass import ScanResult, RunContext
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult
from vulnparse_pin.core.passes.types import ScoredFinding

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
    with ctx.pfh.open_for_write(csv_path, mode = "w", encoding = "utf-8", label = "CSV-Output") as f:
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