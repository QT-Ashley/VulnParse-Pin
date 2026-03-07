# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

import hashlib
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import gzip
import csv
import re
import os
import json
import requests
from vulnparse_pin.utils.logger import SEVERITY_COLOR, EnrichmentMissLogger, colorize
from vulnparse_pin.utils.enrichment_stats import stats
from vulnparse_pin.utils.cve_selector import select_authoritative_cve
from vulnparse_pin.utils.cvss_utils import detect_cvss_version, is_valid_cvss_vector, parse_cvss_vector
from vulnparse_pin.core.classes.dataclass import Finding, RunContext, ScanResult
from vulnparse_pin import UA

# ------------- Globals -----------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}$")

# ----------------------------------------

#'''TODO: def enrich_with_shodan(ip_address):
#    Query Shodan with API Key
#    parse results: open ports, services, vulns, org
#    return {
#         "open_ports": [22, 80, 443],
#         "services": ["SSH", "HTTP", "HTTPS"],
#         "org": Example.org,
#         "shodan_tag": ["ics", "vpn"]
#    }
#    '''


def load_epss(ctx: RunContext, *, path_url: str, force_refresh: bool, allow_regen: bool, timeout: int = 7, user_agent: Optional[str] = UA) -> Dict[str, float]:
    '''
    Load EPSS data from a CSV file or URL into a dict {cve: epss}.
    CSV assumed to have columns: 'cve', 'epss'

    Source:
        - URL (default): streamed download of .csv.gz
        - Local file: .csv.gz OR .csv

    Cache:
        - Always stores decompressed CSV as epss_cache.csv
        - Gives sidecars .sha256 .meta.json
        - TTL enforced only for URL sources

    :returns Dict[str, float]: epss_data
    '''
    key = "epss"
    fc = ctx.services.feed_cache
    cache_path, _, _ = fc.resolve(key)
    path_url_str = str(path_url)

    # -----------------------------------
    #   CSV Parser
    # -----------------------------------

    def parse_csv(feed_path: Path) -> Dict[str, float]:
        out: Dict[str, float] = {}

        with ctx.pfh.open_for_read(feed_path, "r", label = "EPSS Cache (.csv)") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve = (row.get("cve") or row.get("CVE") or "").strip()
                if not cve:
                    for header in row:
                        if re.search(r"model_version", header, re.IGNORECASE):
                            cve = row.get(header)
                            break

                score_raw = (row.get("epss") or row.get("epss_score") or row.get("score") or "").strip()
                if not score_raw:
                    for header in row:
                        if re.search(r"score_date", header, re.IGNORECASE):
                            score_raw = row.get(header)
                            break

                if not cve or not score_raw:
                    continue
                try:
                    out[cve.upper()] = float(score_raw)
                except ValueError:
                    continue
        return out

    # Download or open local .gz file
    # ----------------------------
    # Online Mode
    # ----------------------------
    if path_url_str.startswith("http"):
        if (not force_refresh) and cache_path.exists() and fc.is_fresh(key):
            ctx.logger.print_info("Using cached EPSS (TTL valid).", label="EPSS Loader")
            fc.ensure_feed_checksum(key, allow_regen = allow_regen)
            fc.print_cache_metadata(key)
            return parse_csv(cache_path)

        ctx.logger.print_info(f"Fetching EPSS from {path_url} (streamed).", label="EPSS Loader")
        headers = {"User-Agent": user_agent}

        try:
            fc.write_atomic_stream_gunzip(
                key,
                source_url=path_url_str,
                mode = "Online",
                validated = False,
                checksum_src = "Local",
                timeout = timeout,
                headers = headers,
                extra_meta = {
                    "content_encoding": "gzip",
                    "stored_as": "csv",
                    "source_type": "url",
                },
            )

            fc.ensure_feed_checksum(key, allow_regen = True)
            fc.print_cache_metadata(key)
            return parse_csv(cache_path)
        except Exception as e:
            ctx.logger.exception("EPSS update failed %s", e)

            # Fallback to existing cache if available
            if cache_path.exists():
                ctx.logger.print_warning("Falling back to existing cached EPSS.", label="EPSS Loader")
                fc.ensure_feed_checksum(key, allow_regen = allow_regen)
                return parse_csv(cache_path)
            return {}

    # ----------------------------
    # Local/Offline Mode
    # ----------------------------
    src_path = Path(path_url_str)
    if src_path.exists():

        ctx.logger.print_info(f"Importing local EPPS source {ctx.pfh.format_for_log(src_path)}", label="EPSS Loader")

        # Read the raw bytes
        with ctx.pfh.open_for_read(src_path, mode = "rb", label = "Local EPSS Source") as r:
            raw = r.read()

        # Decompress if necessary
        if src_path.suffix.lower().endswith(".gz"):
            try:
                with gzip.GzipFile(fileobj=BytesIO(raw), mode = "rb") as gz:
                    raw_csv = gz.read()
                content_encoding = "gzip"
            except Exception as e:
                raise RuntimeError(f"Failed to decompressed local EPSS .gz file: {e}") from e
        else:
            raw_csv = raw
            content_encoding = "none"

        # Skip re-import if unchanged
        try:
            local_digest = hashlib.sha256(raw_csv).hexdigest()
            if cache_path.exists():
                cache_digest = fc.compute_checksum(key)
                if cache_digest == local_digest and fc.load_meta(key):
                    ctx.logger.print_info("Local EPSS matches cache; skipping import.", label="EPSS Loader")
                    return parse_csv(cache_path)
        except Exception:
            pass

        # Import decompressed CSV into managed cache
        fc.write_atomic(
            key,
            raw_csv,
            source_url = f"file://{src_path.as_posix()}",
            mode = "Offline-Import",
            validated = False,
            checksum_src = "Local",
            extra_meta = {
                "content-encoding": content_encoding,
                "stored_as": "csv",
                "source_type": "local",
            }
        )
        fc.ensure_feed_checksum(key, allow_regen=True)
        fc.print_cache_metadata(key)
        return parse_csv(cache_path)

    # -----------------------------
    # INVALID PATH
    # -----------------------------
    raise FileNotFoundError(f"EPSS Source not found or invalid: {ctx.pfh.format_for_log(path_url)}")


def load_kev(ctx: RunContext, path_url: str, *, force_refresh: bool, allow_regen: bool, timeout: int = 7, user_agent: Optional[str] = UA) -> Dict[str, bool]:
    '''
    Load CISA KEV data from a JSON file or URL into a dict {cve: True}.
    JSON assumed to have CVE's under a 'cveID' or 'CVE' key in each entry
    Caches URL fetches under ctx.services.feed_cache ("kev")

    :returns: dict {"cveID": True}
    '''
    kev_data: Dict[str, bool] = {}
    key = "kev"
    fc = ctx.services.feed_cache
    path_url_str = str(path_url)

    def parse_json(feed_path: Path):
        # Handle .gz and .json
        if str(feed_path).endswith(".gz"):
            with ctx.pfh.open_for_read(feed_path, mode = "rb", label = "KEV Feed (.gz)") as rb:
                with gzip.open(rb, "rt", encoding = "utf-8") as f:
                    data = json.load(f)
        else:
            with ctx.pfh.open_for_read(feed_path, mode = "r", label = "KEV Feed (.json)") as f:
                data = json.load(f)

        vulns = data.get('vulnerabilities', [])
        for entry in vulns:
            cve = entry.get('cveID') or entry.get('CVE')
            if cve:
                kev_data[cve.upper()] = True

    # ----------------------------
    # Online Mode    (URL)
    # ----------------------------
    if path_url_str.startswith('http'):
        data_path, _, _ = fc.resolve(key)


        # ------------------------- Cached Path -------------------------
        if (not force_refresh) and data_path.exists() and fc.is_fresh(key):
            ctx.logger.print_info("Using cached CISA KEV feed (TTL Valid).", label = "KEV Loader")

            # Integrity enforcement
            fc.ensure_feed_checksum(key, allow_regen = allow_regen)

            fc.print_cache_metadata(key)
            parse_json(data_path)
            ctx.logger.print_success(f"Loaded KEV data from {ctx.pfh.format_for_log(data_path)}")
            return kev_data

        # ------------------------- Refresh Path -------------------------
        ctx.logger.print_info(f"Downloading CISA KEV feed from {path_url_str}...", label = "KEV Loader")
        headers = {"User-Agent": user_agent}

        try:
            resp = requests.get(path_url_str, allow_redirects = True, timeout = timeout, headers = headers)
            resp.raise_for_status()
            raw = resp.content
        except requests.RequestException as e:
            ctx.logger.exception(f"KEV Loader Failed to retrieve KEV feed: {e}")

            # Fallback to existing cache if it exists
            if data_path.exists():
                ctx.logger.print_warning("Upstream fetch failed; attempting fallback to local cache.", label = "KEV Loader")
                try:
                    fc.ensure_feed_checksum(key, allow_regen = allow_regen)
                    parse_json(data_path)
                    ctx.logger.print_warning("Using fallback cached KEV.")
                    return kev_data
                except Exception as e2:
                    raise RuntimeError(f"KEV upstream fetch failed and cache fallback failed: {e2}") from e
            return {}

        # Cache it
        fc.write_atomic( # type: ignore
            key,
            raw,
            source_url = path_url_str,
            mode = "Online",
            validated = False,
            checksum_src = "Local",
        )

        # Verify
        fc.ensure_feed_checksum(key, allow_regen = True) # type: ignore
        fc.update_cache_meta(key) # type: ignore
        fc.print_cache_metadata(key) # type: ignore

        # Parse
        data_path, _, _ = fc.resolve(key) # type: ignore
        parse_json(data_path)
        ctx.logger.print_success(f"Loaded KEV data from {ctx.pfh.format_for_log(data_path)}", label = "KEV Loader")
        return kev_data

    # -----------------------------
    # Offline / LOCAL
    # -----------------------------
    if os.path.exists(path_url_str):
        # For local-only file, TTL doesn't matter; validate or regen checksum
        try:
            feed_path = ctx.pfh.ensure_readable_file(path_url_str, label = "Local KEV Cache")
        except Exception as e:
            raise FileNotFoundError(f"Local KEV file not readable: {ctx.pfh.format_for_log(path_url_str)}") from e

        if feed_path.suffix.lower() == ".gz":
            raise RuntimeError(
                "Local KEV file is .gz, but cache target is kev_cache.json. "
                "Unzip the JSON KEV file or change cache filename to .json.gz."
            )

        with ctx.pfh.open_for_read(feed_path, "rb", label = "Local KEV Cache") as r:
            raw = r.read()

        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"Local KEV file is not valid JSON: {ctx.pfh.format_for_log(feed_path)} Trace = {e}") from e

        if not isinstance(parsed, dict):
            raise RuntimeError("Local KEV JSON must be an object at top-level.")

        # Skip re-import if unchanged
        fc = ctx.services.feed_cache # type: ignore
        cache_path, _, _ = fc.resolve("kev") # type: ignore

        try:
            local_digest = hashlib.sha256(raw).hexdigest()

            if cache_path.exists():
                cache_digest = fc.compute_checksum("kev") # type: ignore
                if cache_digest == local_digest and fc.load_meta("kev"): # type: ignore
                    ctx.logger.print_info(
                        "Local KEV matches existing cache; skipping re-import."
                    )
                    parse_json(cache_path)
                    return kev_data
        except Exception:
            pass

        # Import into managed cache directory
        fc.write_atomic( # type: ignore
            "kev",
            raw,
            source_url = f"file://{feed_path.as_posix()}",
            mode = "Offline-Import",
            validated = False,
            checksum_src = "Local"
        )

        # Enforce checksum/meta on cached copy.
        fc.ensure_feed_checksum("kev", allow_regen = allow_regen) # type: ignore
        fc.print_cache_metadata("kev") # type: ignore

        # Parse
        data_path, _, _ = fc.resolve("kev") # type: ignore
        parse_json(data_path)

        ctx.logger.print_success(f"Loaded KEV data from local file {ctx.pfh.format_for_log(data_path)}")
        return kev_data

    # -----------------------------
    # Invalid Path or File Not Found
    # -----------------------------
    else:
        raise FileNotFoundError(f'File or URL not found: {path_url_str}')
def calculate_risk_score(cvss_score: float, exploit_available: bool, cisa_kev: bool, epss_score: float, score_config: dict):
    weights = score_config["weights"]
    risk_cap = score_config["risk_cap"]

    raw_risk_score = cvss_score

    # Add enrichment weights based on config

    if exploit_available:
        raw_risk_score += weights["exploit_available"]
    if cisa_kev:
        raw_risk_score += weights["cisa_kev"]
    if epss_score >= 0.8:
        raw_risk_score += weights["epss_score_high"]
    elif epss_score >= 0.5:
        raw_risk_score += weights["epss_score_medium"]

    # Cap raw risk at configured max
    if raw_risk_score > risk_cap["max_raw_risk_score"]:
        raw_risk_score = risk_cap["max_raw_risk_score"]

    # Derived capped 0-10 operational risk score
    risk_score = min(raw_risk_score, risk_cap["max_operational_risk_score"])

    # Determine risk band
    risk_band = determine_risk_band(raw_risk_score)

    return raw_risk_score, risk_score, risk_band

def determine_risk_band(raw_risk_score):
    if raw_risk_score >= 10:
        return "Critical+"
    elif raw_risk_score >= 8:
        return "High"
    elif raw_risk_score >= 5:
        return "Medium"
    elif raw_risk_score >= 3:
        return "Low"
    else:
        return "Informational"


def update_enrichment_status(finding):
    if finding.exploit_available or finding.epss_score or finding.cisa_kev:
        finding.enriched = True
    else:
        finding.enriched = False

def prefer_vector(vectors):
    order = {"CVSS:3.1": 1, "CVSS:3.0": 2, "CVSS:2.0": 3}
    def rank(v):
        for prefix, score in order.items():
            if v.startswith(prefix):
                return score
        return 99
    return sorted(vectors, key=rank)[0]

def log_finding_summary(logger, finding: Finding):
    severity = finding.risk_band
    sev_label = colorize(severity, SEVERITY_COLOR.get(severity, "white")) # type: ignore
    msg = (
        f"[RiskCalc] "
        f"{sev_label} "
        f"Asset={finding.asset_id}; "
        f"Finding={finding.title}; "
        f"CVE={getattr(finding, 'enrichment_source_cve', None) or 'SENTINEL(No_CVE_Listed)'}; "
        f"Score={(getattr(finding, 'risk_score', None))}; "
        f"Band={getattr(finding, 'risk_band', 'N/A')}; "
        f"Triage={getattr(finding, 'triage_priority', 'N/A')}; "
        f"KEV={bool(getattr(finding, 'cisa_kev', False))}; "
        f"Exploit={bool(getattr(finding, 'exploit_available', False))}"
    )
    logger.debug(msg)

def resolve_cvss_vector(ctx: "RunContext", scanner_vector: str, auth_cve: str, nvd_cache: dict, current_score: float = 0.0) -> Tuple[str, float]:
    """
    Resolve a CVSS vector for a finding using a priority pipeline:
    1. Use scanner-provided
    2. Fall back to NVD cache vector for auth CVE
    3. If only a base score exists, return scoreonly
    4. Othewise mark as Attempted_NotFound sentinel.
    
    Note: Uses aggregate statistics tracking for batch logging optimization.
    Check EnrichmentStats for resolution path counters.
    """
    # Guard
    if not auth_cve or auth_cve.startswith("SENTINEL:"):
        stats.cvss_no_cve_skipped += 1
        # Preserve critical warning for first few findings
        if stats.cvss_no_cve_skipped <= 3:
            ctx.logger.warning("[CVSSVector] Skipping CVSS resolution because no real CVE is associated with this finding.")
        return "SENTINEL:NoCVE", current_score

    version = detect_cvss_version(scanner_vector)

    # Case 1: Trust scanner vector if valid
    if scanner_vector and version in ("v2", "v3"):
        # If CVSSv3 vector, send it to parser and reconcile score.
        if version == "v3":
            try:
                base_score = parse_cvss_vector(ctx, scanner_vector)[0] # type: ignore
            except Exception as e:
                stats.cvss_parse_errors += 1
                # Preserve error logs (critical issues)
                ctx.logger.error(f"[CVSSVector] Error parsing CVSS v3 vector '{scanner_vector}': {e}. "
                                    f"Keeping existing score {current_score}")
                return scanner_vector, current_score

            if abs(base_score - current_score) > 0.1: # type: ignore
                current_score = base_score # type: ignore
            
            stats.cvss_scanner_v3_used += 1
            return scanner_vector, current_score
        
        # v2: Don't feed into CVSS3 Lib - trust scanner score.
        if version == "v2":
            try:
                base_score = parse_cvss_vector(ctx, scanner_vector)[0] # type: ignore
            except Exception as e:
                stats.cvss_parse_errors += 1
                # Preserve error logs (critical issues)
                ctx.logger.error(f"[CVSSVector] Error parsing CVSS v2 vector '{scanner_vector}': {e}. "
                                    f"Keeping existing score {current_score}")
                return scanner_vector, current_score

            if abs(base_score - current_score) > 0.1: # type: ignore
                current_score = base_score # type: ignore
            
            stats.cvss_scanner_v2_used += 1
            #TODO: LAter plug in a CVSS2 Vector parser
            return scanner_vector, current_score

    # Case 2: Fallback to NVD
    if nvd_cache and auth_cve:
        nvd_record = nvd_cache.get(auth_cve)
        if nvd_record:
            nvd_vector = nvd_record.get("cvss_vector")
            if nvd_vector and is_valid_cvss_vector(nvd_vector):
                base_score = parse_cvss_vector(ctx, nvd_vector)[0] # type: ignore
                stats.cvss_nvd_fallback += 1
                return nvd_vector, base_score # type: ignore

            # Case 3: Score-only fallback
            nvd_score = nvd_record.get("cvss_score")
            if nvd_score is not None:
                stats.cvss_score_only += 1
                # Preserve warning for first few score-only cases
                if stats.cvss_score_only <= 3:
                    ctx.logger.print_warning(f"[CVSSVector] No valid vector for {auth_cve}," f"using ScoreOnly sentinel with base score {nvd_score}")
                return f"SENTINEL:ScoreOnly:{nvd_score}", nvd_score

    # Case 4: Nothing
    stats.cvss_not_found += 1
    return "SENTINEL:Attempted_NotFound", current_score

def enrich_scan_results(
    ctx: "RunContext",
    results: ScanResult,
    kev_data: Optional[Dict[str, bool]] = None,
    epss_data: Optional[Dict[str, float]] = None,
    offline_mode: bool = False,
    nvd_cache: Optional[Any] = None,
) -> None:  # type: ignore
    '''
    Enrich the findings in a ScanResult object with EPSS Score, CISA KEV status, exploit indicators, and recalculate triage priority.

    Args:
        results (ScanResult Obj): The parsed vulnerability scan results.
        kev_data (Dict[str, bool], Optional): Mapping of CVE IDs to CISA KEV status.
        epss_data (Dict[str, float], Optional): Mapping of CVE IDs to EPSS Scores.
        offline_mode (Bool): If True, will ignore online fetches for enrichment data pulls.
        nvd_cache (Optional[Any]): Optional parameter, if supplied, will utilize NVD feed cache module for CVE data.
    '''
    miss_logger = EnrichmentMissLogger(ctx)

    baseline_risk_count = 0

    kev_lookup: Dict[str, bool] = {
        str(cve).upper(): bool(flag)
        for cve, flag in (kev_data or {}).items()
    }

    epss_lookup: Dict[str, float] = {}
    for cve, score in (epss_data or {}).items():
        try:
            epss_lookup[str(cve).upper()] = float(score)
        except (TypeError, ValueError):
            continue

    nvd_get = getattr(nvd_cache, "get", None) if nvd_cache is not None else None
    nvd_record_cache: Dict[str, Any] = {}
    parsed_vector_score_cache: Dict[str, Optional[float]] = {}
    no_record = object()

    finding_counter = 0

    for asset in results.assets:
        for finding in asset.findings:
            finding_counter += 1
            enrichment_attempted = False
            any_kev_hit = False
            any_epss_hit = False
            enrichment_map: Dict[str, Dict[str, Any]] = {}

            cves: List[str] = []
            for raw_cve in getattr(finding, "cves", []) or []:
                cve_upper = str(raw_cve).upper().strip()
                if CVE_RE.match(cve_upper):
                    cves.append(cve_upper)

            if cves:
                enrichment_attempted = True
                stats.total_cves += len(cves)

                for cve in cves:
                    kev_hit = kev_lookup.get(cve, False)
                    if kev_hit:
                        stats.kev_hits += 1
                        any_kev_hit = True
                    else:
                        miss_logger.log_miss(cve, cisa_kev=False, epss_score=None)

                    epss_score = epss_lookup.get(cve)
                    if epss_score is None:
                        stats.epss_misses += 1
                        miss_logger.log_miss(cve, cisa_kev=kev_hit, epss_score=None)
                    else:
                        if epss_score > 0.1:
                            any_epss_hit = True

                    nvd_vector = None
                    nvd_score = None
                    if nvd_get is not None:
                        record = nvd_record_cache.get(cve, no_record)
                        if record is no_record:
                            record = nvd_get(cve)
                            nvd_record_cache[cve] = record

                        if record:
                            vector = record.get("cvss_vector")
                            if vector and is_valid_cvss_vector(vector):
                                score_cached = parsed_vector_score_cache.get(vector)
                                if score_cached is None:
                                    try:
                                        score_cached = parse_cvss_vector(ctx, vector)[0]  # type: ignore
                                    except Exception:
                                        score_cached = None
                                    parsed_vector_score_cache[vector] = score_cached
                                if score_cached is not None:
                                    nvd_vector = vector
                                    nvd_score = score_cached
                            elif record.get("cvss_score") is not None:
                                nvd_score = record.get("cvss_score")

                    enrichment_map[cve] = {
                        "epss_score": epss_score,
                        "cisa_kev": kev_hit,
                        "exploit_available": bool(getattr(finding, "exploit_available", False)),
                        "cvss_score": nvd_score,
                        "cvss_vector": nvd_vector,
                    }

                authoritative_cve = select_authoritative_cve(cves, enrichment_map)
                if authoritative_cve:
                    best = enrichment_map[authoritative_cve]
                    epss_c = best.get("epss_score")
                    finding.epss_score = epss_c if epss_c is not None else None
                    finding.cisa_kev = bool(best.get("cisa_kev", False) or any(v.get("cisa_kev", False) for v in enrichment_map.values()))
                    finding.cvss_vector, finding.cvss_score = resolve_cvss_vector(
                        ctx,
                        scanner_vector=finding.cvss_vector,  # type: ignore
                        auth_cve=authoritative_cve,
                        nvd_cache=nvd_cache,  # type: ignore
                        current_score=best.get("cvss_score") or finding.cvss_score or 0.0,
                    )

                    kev_flag = any(v.get("cisa_kev", False) for v in enrichment_map.values())
                    exploit_flag = any(v.get("exploit_available", False) for v in enrichment_map.values())
                    finding.exploit_available = bool(finding.exploit_references) or exploit_flag or kev_flag
                    finding.enrichment_source_cve = authoritative_cve

            if finding.cvss_vector and not finding.cvss_vector.startswith("SENTINEL:"):
                stats.cvss_vectors_assigned += 1
                stats.cvss_vectors_validated += 1

            cvss = finding.cvss_score or -1.0
            if cvss == 0.0 and (finding.exploit_available or finding.severity in ["Critical", "High"]):
                baseline_risk_count += 1

            finding.raw_risk_score = None
            finding.risk_score = None
            finding.risk_band = None

            finding.enriched = enrichment_attempted and (
                any_kev_hit or
                any_epss_hit or
                bool(finding.exploit_available)
            )

            if finding_counter <= 20 or finding_counter % 100000 == 0:
                log_finding_summary(ctx.logger, finding)

        asset.avg_risk_score = None


    print("="*25 + "[Enrichment Summary]" + "="*25)
    ctx.logger.print_info(f"   Total CVEs Processed : {stats.total_cves:,}")
    ctx.logger.print_info(f"   Total CISA KEV Hits : {stats.kev_hits:,}")
    ctx.logger.print_info(f"   Total CVSS Vectors Assigned : {stats.cvss_vectors_assigned:,}")
    ctx.logger.print_info(f"   Total CVSS Vectors Validated : {stats.cvss_vectors_validated:,}")
    ctx.logger.print_info(f"   Total EPSS Misses : {stats.epss_misses:,}")
    ctx.logger.print_info(f"   Total Findings Rx Baseline Risk Adjustment: {baseline_risk_count:,}")
    
    # CVSSVector Resolution Summary (batch logging optimization)
    total_cvss_resolutions = (
        stats.cvss_scanner_v3_used + stats.cvss_scanner_v2_used + 
        stats.cvss_nvd_fallback + stats.cvss_score_only + 
        stats.cvss_not_found + stats.cvss_no_cve_skipped
    )
    if total_cvss_resolutions > 0:
        ctx.logger.print_info("   CVSSVector Resolution Summary:")
        ctx.logger.print_info(f"      Scanner V3: {stats.cvss_scanner_v3_used:,} | Scanner V2: {stats.cvss_scanner_v2_used:,}")
        ctx.logger.print_info(f"      NVD Fallback: {stats.cvss_nvd_fallback:,} | Score Only: {stats.cvss_score_only:,}")
        ctx.logger.print_info(f"      Not Found: {stats.cvss_not_found:,} | No CVE: {stats.cvss_no_cve_skipped:,}")
        if stats.cvss_parse_errors > 0:
            ctx.logger.print_info(f"      Parse Errors: {stats.cvss_parse_errors:,} (check ERROR logs)")
    
    print("="*25 + "[Enrichment Summary End]" + "="*25)

    miss_logger.write_log()
