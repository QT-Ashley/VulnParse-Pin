# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from functools import cache
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
import vulnparse_pin.utils.logger_instance as log
from vulnparse_pin.utils.enrichment_stats import stats
from vulnparse_pin.utils.cve_selector import select_authoritative_cve
from vulnparse_pin.utils.triage_priority_helper import determine_triage_priority
from vulnparse_pin.utils.cvss_utils import detect_cvss_version, is_valid_cvss_vector, parse_cvss_vector
from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult, TriageConfig
from vulnparse_pin import UA

# ------------- Globals -----------------

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}$")

# ----------------------------------------

def get_epss_score(cves: List[str], epss_data: Dict[str, float]) -> float:
    '''Let's return the highest EPSS score found for a list of CVES.'''
    scores = [epss_data.get(cve, 0) for cve in cves]
    return max(scores) if scores else 0

def is_cisa_kev(cves: List[str], kev_data: Dict[str, bool]) -> bool:
    """Check if any CVE is in the CISA KEV list. Return a boolean."""
    return any(cve in kev_data for cve in cves)

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

    # -----------------------------------
    #   CSV Parser
    # -----------------------------------

    def parse_csv(feed_path: Path) -> Dict[str, float]:
        out: Dict[str, float] = {}
        feed_path = ctx.pfh.ensure_readable_file(feed_path, label = "EPSS Cache (.csv)")

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
    if path_url.startswith("http"):
        if (not force_refresh) and cache_path.exists() and fc.is_fresh(key):
            ctx.logger.print_info("Using cached EPSS (TTL valid).", label = "[Enrich-EPSS]")
            fc.ensure_feed_checksum(key, allow_regen = allow_regen)
            fc.print_cache_metadata(key)
            return parse_csv(cache)

        ctx.logger.print_info(f"Fetching EPSS from {path_url} (streamed).", label = "[Enrich-EPSS]")
        headers = {"User-Agent": user_agent}

        try:
            fc.write_atomic_stream_gunzip(
                key,
                source_url=path_url,
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
                ctx.logger.print_warning("Falling back to existing cached EPSS.", label = "[Enrich-EPSS]")
                fc.ensure_feed_checksum(key, allow_regen = allow_regen)
                return parse_csv(cache_path)
            return {}

    # ----------------------------
    # Local/Offline Mode
    # ----------------------------
    src_path = Path(path_url)
    if src_path.exists():

        src_path = ctx.pfh.ensure_readable_file(src_path, label = "Local EPSS Source")

        ctx.logger.print_info(f"Importing local EPPS source {ctx.pfh.format_for_log(src_path)}")

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
                    ctx.logger.print_info("Local EPSS matches cache; skipping import.")
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

    def parse_json(feed_path: Path):
        # Handle .gz and .json
        if str(feed_path).endswith(".gz"):
            feed_path = ctx.pfh.ensure_readable_file(feed_path, label = "KEV Feed (.gz)")
            with ctx.pfh.open_for_read(feed_path, mode = "rb", label = "KEV Feed (.gz)") as rb:
                with gzip.open(rb, "rt", encoding = "utf-8") as f:
                    data = json.load(f)
        else:
            feed_path = ctx.pfh.ensure_readable_file(feed_path, label = "KEV Feed (.json)")
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
    if path_url.startswith('http'):
        data_path, _, _ = fc.resolve(key)


        # ------------------------- Cached Path -------------------------
        if (not force_refresh) and data_path.exists() and fc.is_fresh(key):
            ctx.logger.print_info("Using cached CISA KEV feed (TTL Valid).", label = "[Enrich-KEV]")

            # Integrity enforcement
            fc.ensure_feed_checksum(key, allow_regen = allow_regen)

            fc.print_cache_metadata(key)
            parse_json(data_path)
            ctx.logger.print_success(f"Loaded KEV data from {ctx.pfh.format_for_log(data_path)}")
            return kev_data

        # ------------------------- Refresh Path -------------------------
        ctx.logger.print_info(f"Downloading CISA KEV feed from {path_url}...", label = "[Enrich-KEV]")
        headers = {"User-Agent": user_agent}

        try:
            resp = requests.get(path_url, allow_redirects = True, timeout = timeout, headers = headers)
            resp.raise_for_status()
            raw = resp.content()
        except requests.RequestException as e:
            ctx.logger.exception(f"[Enrich-KEV] Failed to retrieve KEV feed: {e}")

            # Fallback to existing cache if it exists
            if data_path.exists():
                ctx.logger.print_warning("Upstream fetch failed; attempting fallback to local cache.", label = "[Enrich-KEV]")
                try:
                    fc.ensure_feed_checksum(key, allow_regen = allow_regen)
                    parse_json(data_path)
                    ctx.logger.print_warning("Using fallback cached KEV.")
                    return kev_data
                except Exception as e2:
                    raise RuntimeError(f"KEV upstream fetch failed and cache fallback failed: {e2}") from e
            return {}

        # Cache it
        fc.write_atomic(
            key,
            raw,
            source_url = path_url,
            mode = "Online",
            validated = False,
            checksum_src = "Local",
        )

        # Verify
        fc.ensure_feed_checksum(key, allow_regen = True)
        fc.update_cache_meta(key)
        fc.print_cache_metadata(key)

        # Parse
        data_path, _, _ = fc.resolve(key)
        parse_json(data_path)
        ctx.logger.print_success(f"Loaded KEV data from {ctx.pfh.format_for_log(data_path)}", label = "[Enrich-KEV]")
        return kev_data

    # -----------------------------
    # Offline / LOCAL
    # -----------------------------
    if os.path.exists(path_url):
        # For local-only file, TTL doesn't matter; validate or regen checksum
        try:
            feed_path = ctx.pfh.ensure_readable_file(path_url, label = "Local KEV Cache")
        except Exception as e:
            raise FileNotFoundError(f"Local KEV file not readable: {ctx.pfh.format_for_log(path_url)}") from e

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
        fc = ctx.services.feed_cache
        cache_path, _, _ = fc.resolve("kev")

        try:
            local_digest = hashlib.sha256(raw).hexdigest()

            if cache_path.exists():
                cache_digest = fc.compute_checksum("kev")
                if cache_digest == local_digest and fc.load_meta("kev"):
                    ctx.logger.print_info(
                        "Local KEV matches existing cache; skipping re-import."
                    )
                    parse_json(cache_path)
                    return kev_data
        except Exception:
            pass

        # Import into managed cache directory
        fc.write_atomic(
            "kev",
            raw,
            source_url = f"file://{feed_path.as_posix()}",
            mode = "Offline-Import",
            validated = False,
            checksum_src = "Local"
        )

        # Enforce checksum/meta on cached copy.
        fc.ensure_feed_checksum("kev", allow_regen = allow_regen)
        fc.print_cache_metadata("kev")

        # Parse
        data_path, _, _ = fc.resolve("kev")
        parse_json(data_path)

        ctx.logger.print_success(f"Loaded KEV data from local file {ctx.pfh.format_for_log(data_path)}")
        return kev_data

    # -----------------------------
    # Invalid Path or File Not Found
    # -----------------------------
    else:
        raise FileNotFoundError(f'File or URL not found: {path_url}')

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

def log_finding_summary(logger, finding):
    severity = finding.risk_band
    sev_label = colorize(severity, SEVERITY_COLOR.get(severity, "white"))
    msg = (
        f"[RiskCalc] "
        f"{sev_label} "
        f"Asset={finding.assetid}; "
        f"Finding={finding.title}; "
        f"CVE={getattr(finding, 'authoritative_cve', None) or 'N/A'}; "
        f"Score={(getattr(finding, 'risk_score', None))}; "
        f"Band={getattr(finding, 'risk_band', 'N/A')}; "
        f"Triage={getattr(finding, 'triage_priority', 'N/A')}; "
        f"KEV={bool(getattr(finding, 'cisa_kev', False))}; "
        f"Exploit={bool(getattr(finding, 'exploit_available', False))}"
    )
    logger.print_info(msg)

def resolve_cvss_vector(scanner_vector: str, auth_cve: str, nvd_cache: dict, current_score: float = 0.0) -> Tuple[str, float]:
    """
    Resolve a CVSS vector for a finding using a priority pipeline:
    1. Use scanner-provided
    2. Fall back to NVD cache vector for auth CVE
    3. If only a base score exists, return scoreonly
    4. Othewise mark as Attempted_NotFound sentinel.
    """
    # Guard
    if not auth_cve or auth_cve.startswith("SENTINEL:"):
        log.log.logger.warning("[CVSSVector] Skipping CVSS resolution because no real CVE is associated with this finding.")
        return "SENTINEL:NoCVE", current_score

    version = detect_cvss_version(scanner_vector)

    # Case 1: Trust scanner vector if valid
    if scanner_vector and version in ("v2", "v3"):
        # If CVSSv3 vector, send it to parser and reconcile score.
        if version == "v3":
            try:
                base_score = parse_cvss_vector(scanner_vector)[0]
            except Exception as e:
                log.log.logger.error(f"[CVSSVector] Error parsing CVSS v3 vector '{scanner_vector}': {e}. "
                                    f"Keeping existing score {current_score}")
                log.log.logger.debug(f"[CVSSVector] Using scanner vector without recalculated score: {scanner_vector}")
                return scanner_vector, current_score

            if abs(base_score - current_score) > 0.1:
                log.log.print_warning(f"[CVSSVector] Score mismatch (scanner {base_score} vs stored {current_score}), reconciling...")
                current_score = base_score
            log.log.logger.debug(f"[CVSSVector] Using valid scanner CVSS V3 vector: {scanner_vector}")
            return scanner_vector, current_score
        # v2: Don't feed into CVSS3 Lib - trust scanner score.
        if version == "v2":
            log.log.logger.debug(f"[CVSSVector] "
                                  f"Using scanner CVSS v2 vector: {scanner_vector} (score={current_score})")
            #TODO: LAter plug in a CVSS2 Vector parser
            return scanner_vector, current_score

    # Case 2: Fallback to NVD
    if nvd_cache and auth_cve:
        nvd_record = nvd_cache.get(auth_cve)
        if nvd_record:
            nvd_vector = nvd_record.get("cvss_vector")
            if nvd_vector and is_valid_cvss_vector(nvd_vector):
                base_score = parse_cvss_vector(nvd_vector)[0]
                log.log.print_success(f"[CVSSVector] Using NVD vector for {auth_cve}: {nvd_vector}")
                return nvd_vector, base_score

            # Case 3: Score-only fallback
            nvd_score = nvd_record.get("cvss_score")
            if nvd_score is not None:
                log.log.print_warning(f"[CVSSVector] No valid vector for {auth_cve}," f"using ScoreOnly sentinel with base score {nvd_score}")
                return f"SENTINEL:ScoreOnly:{nvd_score}", nvd_score

    # Case 4: Nothing
    log.log.print_warning(f"[CVSSVector] No CVSS vector available for {auth_cve or 'Unknown'}." " Marking as 'Attempted_NotFound'")
    return "SENTINEL:Attempted_NotFound", current_score

def enrich_scan_results(results: ScanResult, kev_data: Dict[str, bool] = None, epss_data: Dict[str, float] = None, offline_mode: bool = False, score_cfg: Dict[Dict[str, float]] = None, nvd_cache: Optional[Any] = None) -> None:
    '''
    Enrich the findings in a ScanResult object with EPSS Score, CISA KEV status, exploit indicators, and recalculate triage priority.

    Args:
        results (ScanResult Obj): The parsed vulnerability scan results.
        kev_data (Dict[str, bool], Optional): Mapping of CVE IDs to CISA KEV status.
        epss_data (Dict[str, float], Optional): Mapping of CVE IDs to EPSS Scores.
        offline_mode (Bool): If True, will ignore online fetches for enrichment data pulls.
        nvd_cache (Optional[Any]): Optional parameter, if supplied, will utilize NVD feed cache module for CVE data.
    '''
    miss_logger = EnrichmentMissLogger()

    baseline_risk_count = 0


    kev_data = kev_data or {}
    epss_data = epss_data or {}

    enrichment_map = {}


    for asset in results.assets:
        for finding in asset.findings:
            cisa_hits = []
            epss_scores = []
            enrichment_attempted = False
            enrichment_map.clear()
            if kev_data is not None and epss_data is not None:
                for cve in finding.cves:
                    if not CVE_RE.match(cve):
                        continue
                    stats.total_cves += 1
                    enrichment_attempted = True


                    # CISA KEV Enrichment
                    kev_hit = kev_data.get(cve.upper(), False)
                    cisa_hits.append(kev_hit)


                    if kev_hit:
                        stats.kev_hits += 1
                        log.log.logger.debug(f"[Enrichment] {cve} found in CISA KEV")
                    else:
                        log.log.logger.warning(f"[Enrichment] No CISA KEV record for {cve}.")
                        miss_logger.log_miss(cve, cisa_kev=False, epss_score=None)


                    # EPSS Score Enrichment
                    epss_score = epss_data.get(cve)
                    if epss_score is not None:
                        epss_scores.append(epss_score)
                        log.log.logger.debug(f"[Enrichment] {cve} EPSS Score: {epss_score}")
                    else:
                        log.log.logger.warning(f"[Enrichment] No EPSS Score for {cve}")
                        epss_scores.append(0.0)
                        stats.epss_misses += 1
                        miss_logger.log_miss(cve, cisa_kev=kev_hit, epss_score=None)

                    #TODO: Build small dict of enriched cve info

                    enrichment_map[cve] = {
                        "epss_score": epss_data.get(cve, 0.0),
                        "cisa_kev": kev_data.get(cve.upper(), False),
                        "exploit_available": getattr(finding, "exploit_available", False),
                        "cvss_score": 0.0,
                        "cvss_vector": None
                    }

                    # Fetch nvd_data as secondary source
                    if nvd_cache:
                        nvd_record = nvd_cache.get(cve)
                        if nvd_record:
                            vector = nvd_record.get("cvss_vector")
                            if vector and is_valid_cvss_vector(vector):
                                enrichment_map[cve]["cvss_vector"] = vector
                                enrichment_map[cve]["cvss_score"] = parse_cvss_vector(vector)[0]
                                log.log.logger.debug(f"[NVD_Data] CVSS Vector Found in NVD Cache for {cve} - Mapping vector")
                            elif nvd_record.get("cvss_score") is not None:
                                enrichment_map[cve]["cvss_score"] = nvd_record["cvss_score"]
                                log.log.logger.warning(f"[NVD_Data] No vector, but base score found for {cve}: {nvd_record['cvss_score']}")
                        else:
                            log.log.logger.warning(f"[NVD_Data] No usable CVSS vector found for {cve} in NVD Cache")

                authoritative_cve = select_authoritative_cve(list(enrichment_map.keys()), enrichment_map)

                if authoritative_cve:
                    best = enrichment_map[authoritative_cve]
                    finding.epss_score = best["epss_score"]
                    finding.cisa_kev = best["cisa_kev"] or any(cve_data["cisa_kev"] for cve_data in enrichment_map.values())
                    finding.cvss_vector, finding.cvss_score = resolve_cvss_vector(
                        scanner_vector=finding.cvss_vector,
                        auth_cve=authoritative_cve,
                        nvd_cache=nvd_cache,
                        current_score=finding.cvss_score or 0.0
                    )

                    # Aggregate exploit refs and KEV flag across all CVES
                    kev_flag = False
                    exploit_flag = False

                    for cve, cve_data in enrichment_map.items():
                        if cve_data.get("cisa_kev"):
                            kev_flag = True
                        if cve_data.get("exploit_available"):
                            exploit_flag = True

                    finding.exploit_available = bool(finding.exploit_references) or exploit_flag or kev_flag


                    finding.enrichment_source_cve = authoritative_cve
                    log.log.logger.info(
                        f"[Enrichment] "
                        f"Authoritative CVE: {authoritative_cve} => "
                        f"EPSS={best['epss_score']} | KEV={best['cisa_kev']} | Exploit={finding.exploit_available}"
                    )
                else:
                    log.log.logger.debug(f"[Enrichment] No authoritative CVE selected for Vuln ID: {finding.vuln_id}")


            # Stats Vector Tracking
            if finding.cvss_vector:
                if finding.cvss_vector.startswith("SENTINEL:"):
                    log.log.logger.debug(f"[CVSSVector] Skipping validation for sentinel state: "f"{finding.cvss_vector}")
                else:
                    stats.cvss_vectors_assigned += 1
                    stats.cvss_vectors_validated += 1
                    log.log.logger.info(f"[CVSSVector] "f"Validated vector for {finding.vuln_id}: {finding.cvss_vector}")



            # Calculate Risk_Score
            cvss = finding.cvss_score or 0.0
            epss = finding.epss_score or 0.01 # Prevent zero-risk bias

            # Baseline risk adjustment if missing CVSS but has exploit/high+ severity or risk band
            if cvss == 0.0 and (finding.exploit_available or finding.severity in ['Critical', 'High']):
                baseline_risk_count += 1
                baseline_risk = 7
                log.log.logger.warning(f"[RiskCalc] Missing CVSS for {finding.vuln_id}, setting baseline risk {baseline_risk} due to exploit/high-critical severity")
                cvss = baseline_risk

            # Risk Calculation
            raw_risk_score, risk_score, risk_band = calculate_risk_score(
                cvss_score = cvss,
                exploit_available = finding.exploit_available,
                cisa_kev = finding.cisa_kev,
                epss_score = epss,
                score_config = score_cfg
            )
            if raw_risk_score > 10.0:
                log.log.logger.warning(f"[RiskCalc] Risk Score for {finding.vuln_id} capped at 10.0 (Raw Score: {raw_risk_score})")
            else:
                log.log.logger.debug(f"[RiskCalc] {finding.vuln_id} Raw Risk Score: {raw_risk_score}")
            log.log.logger.debug(f"[RiskCalc] {finding.vuln_id} Final Risk Score: {risk_score} | Triage Priority: {risk_band} | ")

            # Set risk score attribs
            finding.raw_risk_score=raw_risk_score
            finding.risk_score=risk_score
            finding.risk_band=risk_band


            # Recalculate Triage Priority
            finding.triage_priority = determine_triage_priority(
                raw_score=raw_risk_score,
                severity=finding.severity,
                epss_score=epss,
                cisa_kev=finding.cisa_kev,
                exploit_available=finding.exploit_available,
                cfg=TriageConfig()
            )

            # Update enrichment flag
            finding.enriched = enrichment_attempted and (
                any(cisa_hits) or
                any(score > 0.1 for score in epss_scores) or
                finding.exploit_available)

            # Log Summary For Finding
            log_finding_summary(log.log, finding)

        asset.avg_risk_score = round(
            sum(f.risk_score for f in asset.findings) / len(asset.findings), 2
        ) if asset.findings else 0.0


    print("==============[Enrichment Summary]==============")
    log.log.print_info(f"   Total CVEs Processed : {stats.total_cves:,}")
    log.log.print_info(f"   Total CISA KEV Hits : {stats.kev_hits:,}")
    log.log.print_info(f"   Total CVSS Vectors Assigned : {stats.cvss_vectors_assigned:,}")
    log.log.print_info(f"   Total CVSS Vectors Validated : {stats.cvss_vectors_validated:,}")
    log.log.print_info(f"   Total EPSS Misses : {stats.epss_misses:,}")
    log.log.print_info(f"   Total Findings Rx Baseline Risk Adjustment: {baseline_risk_count:,}")
    print("============[Enrichment Summary End]============")

    miss_logger.write_log()