from datetime import datetime, timedelta, timezone
from functools import cache
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import gzip
import io
import csv
import requests
import os
import json
import re
from utils.enrichment_stats import stats

from utils.cve_selector import select_authoritative_cve
from utils.feed_cache import FeedCache
from .cvss_utils import detect_cvss_version, is_valid_cvss_vector, parse_cvss_vector
from classes.dataclass import ScanResult, TriageConfig
from utils.triage_priority_helper import determine_triage_priority
from .logger import *
from . import logger_instance as log
# ------------- Globals -----------------

triagecfg = TriageConfig()
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}$")

# ----------------------------------------

def get_epss_score(cves: List[str], epss_data: Dict[str, float]) -> float:
    # Let's return the highest EPSS score found for a list of CVES.
    scores = [epss_data.get(cve, 0) for cve in cves]
    return max(scores) if scores else 0

def is_cisa_kev(cves: List[str], kev_data: Dict[str, bool]) -> bool:
    # Check if any CVE is in the CISA KEV list. Return a boolean.
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

def print_cache_metadata(cache_path: str):
    meta_path = cache_path + ".meta"
    if not os.path.exists(meta_path):
        log.log.print_warning(
        f"[Enrich-Cache] No meta file found for {os.path.basename(cache_path)}; "
        f"metadata unavailable.")
        return
    try:
        with open(meta_path, 'r', encoding="utf-8") as f:
            meta = json.load(f)
    except Exception as e:
        log.log.logger.warning(f"[Enrich-Cache] Failed to read meta file {meta_path}: {e}")
        return
    
    # Safely extract fields
    last_updated = meta.get("last_updated")
    created_at = meta.get("created_at")
    
    if last_updated:
        log.log.print_info(f"{os.path.basename(cache_path)} last updated: {meta['last_updated']}")
    elif created_at:
        log.log.print_info(f"{os.path.basename(cache_path)} created at: {meta['created_at']} (no last_updated yet)")
    else:
        log.log.logger.warning(f"[Enrich-Cache] Meta file for {os.path.basename(cache_path)} exists, "
                        f"but contains no timestamp fields.")

def update_cache_meta(meta_path: Path):
    """
    Update the meta file by adding/updating 'last_updated' without overwriting the original 'created_at'.
    """
    now = datetime.now(timezone.utc).isoformat()
    
    # If a file exists, load. If not, start minimal skeleton.
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            # Corrupted meta -> build fresh
            meta = {}
    else:
        meta = {}
        
    # Ensure created_at exists
    if "created_at" not in meta:
        meta["created_at"] = now
    
    # Always refresh 'last_updated'
    meta["last_updated"] = now
    
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

def save_metadata_file(cache_path: str, source_url: str, feed_name: str, mode: str, validated: bool, checksum_source: str):
    meta_path = cache_path + ".meta"
    metadata = {
        "feed": feed_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode, 
        "checksum_source": checksum_source,
        "source_url": source_url,
        "fetched_by": "vulnparse-pin v1.0RC",
        "validated_against_remote": validated
    }
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    log.log.print_info(f"Metadata written to {meta_path}")

def save_with_checksum(data_byes: bytes, cache_path: str):
    # Save the data
    with open(cache_path, 'wb') as f:
        f.write(data_byes)
        
    # Save checksum
    sha256 = hashlib.sha256(data_byes).hexdigest()
    with open(cache_path + ".sha256", 'w') as f:
        f.write(sha256)

def validate_checksum(cache_path: str) -> bool:
    '''
    Validates the checksum of a cached file (either .json or .csv.gz) using corresponding .sha256 file.
    
    Args:
        cache_path (str): Base path without extension.
        
    Returns:
        bool: True if checksum is valid, False otherwise.
    '''
    
    if not os.path.exists(cache_path):
        log.log.print_error(f"File not found: {cache_path}")
        return False

    checksum_path = cache_path + ".sha256"
    
    if not os.path.exists(checksum_path):
        log.log.print_warning(f"No checksum found for cache file: {cache_path}")
        return False
    
    try:
        with open(cache_path, 'rb') as f:
            file_data = f.read()
            computed_hash = hashlib.sha256(file_data).hexdigest()
            
        with open(checksum_path, 'r') as f:
            expected_hash = f.read().strip()
            
        if computed_hash == expected_hash:
            log.log.print_success(f"Checksum valid for {cache_path}!")
            return True
        else:
            log.log.print_error(f"Checksum mismatch for {cache_path}")
            log.log.print_error(f"Expected: {expected_hash}")
            log.log.print_error(f"Computed: {computed_hash}")
            return False
        
    except Exception as e:
        log.log.print_error(f"Error validating checksum for {cache_path}")
        return False

def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def ensure_feed_checksum(feed_path: Path, sha_path: Path, meta_path: Path, logger, allow_regen: bool, offline_mode: bool) -> bool:
    """
    Ensure checksum + meta exist and are consistent with the feed.
    
    Returns True if checksum was verified against an existing .sha256,
    False if it has to generate local state (best-effort).
    Raises error on hard mismatch.
    """
    if not feed_path.exists():
        raise FileNotFoundError(f"Feed not found: {feed_path}")
    
    if sha_path.exists():
        # Validate the checksum
        expected = sha_path.read_text(encoding="utf-8").strip().split()[0]
        actual = compute_sha256(feed_path)
        
        # Diff Check
        if expected != actual:
            logger.print_error(f"[Enrich-Cache] Checksum mismatch for {feed_path.name}! " 
                               f"expected={expected}. "
                               f"Redownload with --refresh-cache or replace the cache.")
            # Refuse to use cache.
            raise RuntimeError(
                f"Checksum mismatch for {feed_path}. "
                f"Re-download with --refresh-cache or replace the cache."
            )

        logger.print_success(f"[Enrich-Cache] Checksum valid for {feed_path.name}.")
        return True
    
    # No .sha256 file present
    if not allow_regen:
        logger.print_warning(f"[Enrich-Cache] No checksum file for {feed_path.name}. "
                             f"Proceeding WITHOUT integrity validation.")
        return False
    
    # Regenerate checksum + minimal meta
    actual = compute_sha256(feed_path)
    sha_path.write_text(f"{actual}  {feed_path.name}\n", encoding="utf-8")
    
    update_cache_meta(meta_path)
        
    logger.print_warning(
        f"[Enrich-Cache] No checksum file found for {feed_path.name}. "
        f"Generated LOCAL checksum {actual}. "
        f"Integrity vs upstream CANNOT be verified — using best-effort offline cache."
    )
    return False

def is_cache_stale(meta_path: Path, max_age_hours: int) -> bool:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        created = datetime.fromisoformat(meta["created_at"])
    except Exception as e:
        # No meta or unreadable meta -> stale buddy.
        log.log.print_warning(f"[Enrich-Cache] Unable to read .meta file. {e}")
        return True
    
    age = datetime.now(created.tzinfo) - created
    return age > timedelta(hours=max_age_hours)


def load_epss_from_csv(path_url: str, cache_path: str = "./data/epss_cache.csv.gz", *, feed_cache: dict, force_refresh: bool) -> Dict[str, float]:
    '''
    Load EPSS data from a CSV file or URL into a dict {cve: epss_score}.
    CSV assumed to have columns: 'cve', 'epss_score'
    '''
    epss_data: Dict[str, float] = {}
    
    def parse_csv(reader):
        for row in reader:
            cve = row.get('cve') or row.get('CVE')
            
            if not cve:
                for header in row:
                    if re.search(r"model_version", header, re.IGNORECASE):
                        cve = row.get(header)
                        break
            score_str = row.get('epss_score') or row.get('EPSScore') or row.get('score') or row.get('epss')
            
            if not score_str:
                for header in row:
                    if re.search(r"score_date", header, re.IGNORECASE):
                        score_str = row.get(header)
                        break
            if cve and score_str:
                try:
                    epss_data[cve.upper()] = float(score_str)
                except ValueError:
                    continue
    
    # Download or open local .gz file
    # ----------------------------
    # Online Mode
    # ----------------------------
    if path_url.startswith("http"):
        feed_path = Path(cache_path)
        ttl_hours = int(feed_cache.get("epss", 6))
        
        cache = FeedCache(
            name="EPSS",
            data_path=feed_path,
            ttl_hours=ttl_hours,
            logger=log.log,
        )
        
        # Cached Path (TTL + no force_refresh)
        if cache.should_use_cached(force_refresh=force_refresh):
            log.log.print_info(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} Using cached EPSS feed (TTL still valid).")
            try:
                cache.ensure_feed_checksum(allow_regen=False)
            except RuntimeError as e:
                if force_refresh:
                    log.log.print_warning(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} "
                                          f"Checksum error on cached feed; Re-downloading due to --refresh-cache.")
                else:
                    raise
            else:
                cache.print_cache_metadata()
                # Open gzip or .csv from cache
                if str(feed_path).endswith(".gz"):
                    with gzip.open(feed_path, mode="rt", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        parse_csv(reader)
                else:
                    with feed_path.open("r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        parse_csv(reader)
                        
                if not epss_data:
                    log.log.print_warning(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} EPSS cache parsed but no data found.")
                log.log.print_success(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} Loaded EPSS data from {Fore.LIGHTYELLOW_EX}{feed_path}{Style.RESET_ALL}")
                return epss_data
        
        # Refresh Path
        log.log.print_info(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} Downloading EPSS feed from {path_url}...")
        try:
            response = requests.get(path_url, timeout=5, allow_redirects=True, headers={
                "User-Agent": "VulnParse-PinV1.0RC"
            })
            response.raise_for_status()
        except requests.RequestException as e:
            log.log.logger.exception(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} Failed to retrieve EPSS feed: {e}")
            return {}
        
        feed_path.parent.mkdir(parents=True, exist_ok=True)
        feed_path.write_bytes(response.content)
        log.log.print_success(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} EPSS feed cached locally at {feed_path}")
        
        # Save metadata
        cache.save_metadata_file(
            source_url=path_url,
            mode="Online",
            validated=True,
            checksum_src="Remote",
        )
        # Create Checksum — for online mirror fetches/first time.
        cache.create_cs()
        # Ensure checksum
        cache.ensure_feed_checksum(allow_regen=True)
        cache.update_cache_meta()
        cache.print_cache_metadata()
        
        # Parse from on-disk cache (handle .gz or .csv)
        if str(feed_path).endswith(".gz"):
            with gzip.open(feed_path, "rt", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
        else:
            with feed_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
        
        if not epss_data:
            log.log.print_warning(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} EPSS feed fetched but no data parsed.")
        log.log.print_success(f"{Fore.BLUE}{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL}{Style.RESET_ALL} Loaded EPSS data from {Fore.LIGHTYELLOW_EX}{feed_path}{Style.RESET_ALL}")
        return epss_data
               
    # ----------------------------
    # Local/Offline Mode
    # ----------------------------
    elif os.path.exists(path_url):
        
        feed_path = Path(path_url)
        
        # Local-only EPSS feed; TTL doesn't matter
        cache = FeedCache(
            name="EPSS-LOCAL",
            data_path=feed_path,
            ttl_hours=0,
            logger=log.log,
        )
        
        try:
            cache.ensure_feed_checksum(allow_regen=True)
        except Exception as e:
            log.log.print_warning(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} Local EPSS checksum issue: {e}")
        
        cache.print_cache_metadata()
        
        if str(feed_path).endswith(".gz"):
            with gzip.open(feed_path, "rt", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
        else:
            with feed_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
                
        if not epss_data:
            log.log.print_warning(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} Local EPSS file parsed but no data found.")
        log.log.print_success(f"{Fore.BLUE}[Enrich-EPSS]{Style.RESET_ALL} Loaded EPSS data from {Fore.LIGHTYELLOW_EX}{feed_path}{Style.RESET_ALL}")
        return epss_data
    
    # -----------------------------
    # INVALID PATH
    # -----------------------------            
    else:
        raise FileNotFoundError(f"File or URL not found: {path_url}")


def load_kev_from_json(path_url: str, cache_path: str = "./data/kev_cache.json", *, feed_cache: dict, force_refresh: bool) -> Dict[str, bool]:
    '''
    Load CISA KEV data from a JSON file or URL into a dict {cve: True}.
    JSON assumed to have CVE's under a 'cveID' or 'CVE' key in each entry
    '''
    kev_data: Dict[str, bool] = {}
    
    def parse_json(feed_path: Path):
        # Handle .gz and .json
        if str(feed_path).endswith(".gz"):
            with gzip.open(feed_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with feed_path.open("r", encoding="utf-8") as f:
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
        feed_path = Path(cache_path)
        ttl_hours = int(feed_cache.get("kev", 24))
        
        cache = FeedCache(
            name="CISA_KEV",
            data_path=feed_path,
            ttl_hours=ttl_hours,
            logger=log.log,
        )
        
        # ------------------------- Cached Path -------------------------
        if cache.should_use_cached(force_refresh=force_refresh):
            log.log.print_info(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} Using cached CISA KEV feed (TTL still valid).")
            try:
                cache.ensure_feed_checksum(allow_regen=False)
            except RuntimeError as e:
                if force_refresh:
                    log.log.print_warning(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} "
                                          f"Checksum error on cached feed; Re-downloading due to --refresh-cache.")
                else:
                    raise
            else:
                cache.print_cache_metadata()
                parse_json(feed_path)
                log.log.print_success(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} Loaded KEV data from {Fore.LIGHTYELLOW_EX}{feed_path}{Style.RESET_ALL}")
                return kev_data
        
        # ------------------------- Refresh Path -------------------------
        log.log.print_info(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} Downloading CISA KEV feed from {path_url}...")
        try:
            response = requests.get(path_url, allow_redirects=True, timeout=5, headers={
                "User-Agent": "VulnParse-PinV1.0RC"
            })
            response.raise_for_status()
        except requests.RequestException as e:
            log.log.logger.exception(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} Failed to retrieve KEV feed: {e}")
            return {}
        
        feed_path.parent.mkdir(parents=True, exist_ok=True)
        feed_path.write_bytes(response.content)
        log.log.print_success(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} KEV feed cached locally at {feed_path}")
        
        # Save metadata
        cache.save_metadata_file(
            source_url=path_url,
            mode="Online",
            validated=True,
            checksum_src="Remote",
        )
        # Create Checksum — for online mirror fetches/first time.
        cache.create_cs()
        # Ensure checksum + update meta timestamps
        cache.ensure_feed_checksum(allow_regen=True)
        cache.update_cache_meta()
        cache.print_cache_metadata()
        
        # Always parse from cache path (.gz or .json)
        parse_json(feed_path)
        log.log.print_success(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} Loaded KEV data from {Fore.LIGHTYELLOW_EX}{feed_path}{Style.RESET_ALL}")
        return kev_data
    
    # -----------------------------
    # Offline / LOCAL
    # -----------------------------
    if os.path.exists(path_url):
        feed_path = Path(path_url)
        
        # For local-only file, TTL doesn't matter; validate or regen checksum
        cache = FeedCache(
            name="CISA_KEV_LOCAL",
            data_path=feed_path,
            ttl_hours=0,
            logger=log.log,
        )
        
        try:
            cache.ensure_feed_checksum(allow_regen=True)
        except Exception as e:
            log.log.print_warning(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} Local KEV checksum issue: {e}")
            
        cache.print_cache_metadata()
        parse_json(feed_path)
        log.log.print_success(f"{Fore.BLUE}[Enrich-KEV]{Style.RESET_ALL} Loaded KEV data from {Fore.LIGHTYELLOW_EX}{feed_path}{Style.RESET_ALL}")
        return kev_data
    
    # -----------------------------
    # Invalid Path or File Not Found
    # -----------------------------
    else:
        raise FileNotFoundError(f'File or URL not found: {path_url}')
        

def load_config_json(config_name="config.json"):
    """
    Load config from a JSON file.
    """
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", config_name)
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        log.log.print_error(f"Unable to load config file: {e}")
        return {}
    
config = load_config_json()

def calculate_risk_score(cvss_score: float, exploit_available: bool, cisa_kev: bool, epss_score: float, config: dict):
    weights = config["weights"]
    risk_cap = config["risk_cap"]
    
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
        f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} "
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
                log.log.logger.error(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Error parsing CVSS v3 vector '{scanner_vector}': {e}. "
                                    f"Keeping existing score {current_score}")
                log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Using scanner vector without recalculated score: {scanner_vector}")
                return scanner_vector, current_score
            
            if abs(base_score - current_score) > 0.1:
                log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Score mismatch (scanner {base_score} vs stored {current_score}), reconciling...")
                current_score = base_score
            log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Using valid scanner CVSS V3 vector: {scanner_vector}")
            return scanner_vector, current_score
        # v2: Don't feed into CVSS3 Lib - trust scanner score.
        if version == "v2":
            log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} "
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
                log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Using NVD vector for {auth_cve}: {nvd_vector}")
                return nvd_vector, base_score
            
            # Case 3: Score-only fallback
            nvd_score = nvd_record.get("cvss_score")
            if nvd_score is not None:
                log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} No valid vector for {auth_cve}," f"using ScoreOnly sentinel with base score {nvd_score}")
                return f"SENTINEL:ScoreOnly:{nvd_score}", nvd_score
    
    # Case 4: Nothing
    log.log.print_warning(f"[CVSSVector] No CVSS vector available for {auth_cve or 'Unknown'}." " Marking as 'Attempted_NotFound'")
    return "SENTINEL:Attempted_NotFound", current_score

def enrich_scan_results(results: ScanResult, kev_data: Dict[str, bool] = None, epss_data: Dict[str, float] = None, offline_mode: bool = False, nvd_cache: Optional[Any] = None) -> None:
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
    
     #TODO: DEBUG
    
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
                        log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} found in CISA KEV")
                    else:
                        log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No CISA KEV record for {cve}.")
                        miss_logger.log_miss(cve, cisa_kev=False, epss_score=None)
                
                    
                    # EPSS Score Enrichment
                    epss_score = epss_data.get(cve)
                    if epss_score is not None:
                        epss_scores.append(epss_score)
                        log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} EPSS Score: {epss_score}")
                    else:
                        log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No EPSS Score for {cve}")
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
                                log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[NVD_Data]{Style.RESET_ALL} CVSS Vector Found in NVD Cache for {cve} - Mapping vector")
                            elif nvd_record.get("cvss_score") is not None:
                                enrichment_map[cve]["cvss_score"] = nvd_record["cvss_score"]
                                log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[NVD_Data]{Style.RESET_ALL} No vector, but base score found for {cve}: {nvd_record['cvss_score']}")
                        else:
                            log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[NVD_Data]{Style.RESET_ALL} No usable CVSS vector found for {cve} in NVD Cache")
                             
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
                        f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} "
                        f"Authoritative CVE: {authoritative_cve} => "
                        f"EPSS={best['epss_score']} | KEV={best['cisa_kev']} | Exploit={finding.exploit_available}"
                    )
                else:
                    log.log.logger.debug(f"[Enrichment] No authoritative CVE selected for Vuln ID: {finding.vuln_id}")
                
            
            # Stats Vector Tracking
            if finding.cvss_vector:
                if finding.cvss_vector.startswith("SENTINEL:"):
                    log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Skipping validation for sentinel state: "f"{finding.cvss_vector}")
                else:
                    stats.cvss_vectors_assigned += 1
                    stats.cvss_vectors_validated += 1
                    log.log.logger.info(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} "f"Validated vector for {finding.vuln_id}: {finding.cvss_vector}")
                    
                    
                    
            # Calculate Risk_Score
            cvss = finding.cvss_score or 0.0
            epss = finding.epss_score or 0.01 # Prevent zero-risk bias
            
            # Baseline risk adjustment if missing CVSS but has exploit/high+ severity or risk band
            if cvss == 0.0 and (finding.exploit_available or finding.severity in ['Critical', 'High']):
                baseline_risk_count += 1
                baseline_risk = 7
                log.log.logger.warning(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} Missing CVSS for {finding.vuln_id}, setting baseline risk {Fore.LIGHTRED_EX}{baseline_risk}{Style.RESET_ALL} due to exploit/high-critical severity")
                cvss = baseline_risk
            
            # Risk Calculation
            raw_risk_score, risk_score, risk_band = calculate_risk_score(
                cvss_score=cvss,
                exploit_available=finding.exploit_available,
                cisa_kev=finding.cisa_kev,
                epss_score=epss,
                config=config
            )
            if raw_risk_score > 10.0:
                log.log.logger.warning(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} Risk Score for {finding.vuln_id} capped at 10.0 (Raw Score: {Fore.LIGHTRED_EX}{raw_risk_score}{Style.RESET_ALL})")
            else:
                log.log.logger.debug(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} {finding.vuln_id} Raw Risk Score: {Fore.LIGHTRED_EX}{raw_risk_score}{Style.RESET_ALL}")
            log.log.logger.debug(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} {finding.vuln_id} Final Risk Score: {Fore.LIGHTRED_EX}{risk_score}{Style.RESET_ALL} | Triage Priority: {Fore.LIGHTRED_EX}{risk_band}{Style.RESET_ALL} | ")
            
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
                cfg=triagecfg
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
        
    
    print(f"{Fore.LIGHTMAGENTA_EX}==============[Enrichment Summary]=============={Style.RESET_ALL}")
    log.log.print_info(f"   Total CVEs Processed : {stats.total_cves:,}")
    log.log.print_info(f"   Total CISA KEV Hits : {stats.kev_hits:,}")
    log.log.print_info(f"   Total CVSS Vectors Assigned : {stats.cvss_vectors_assigned:,}")
    log.log.print_info(f"   Total CVSS Vectors Validated : {stats.cvss_vectors_validated:,}")
    log.log.print_info(f"   Total EPSS Misses : {stats.epss_misses:,}")
    log.log.print_info(f"   Total Findings Rx Baseline Risk Adjustment: {baseline_risk_count:,}")
    print(f"{Fore.LIGHTMAGENTA_EX}============[Enrichment Summary End]============{Style.RESET_ALL}")
    
    miss_logger.write_log()