from datetime import datetime, timezone
import hashlib
import random
import time
from typing import Dict, List
import gzip
import io
import csv
from bs4 import BeautifulSoup
import requests
import os
import json
import re

from utils.cve_selector import select_authoritative_cve
from .cvss_utils import CVSS3_REGEX_L, is_valid_cvss_vector, parse_cvss_vector
from classes.dataclass import ScanResult, TriageConfig
from utils.triage_priority_helper import determine_triage_priority
from .logger import *
from . import logger_instance as log

triagecfg = TriageConfig()

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
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            meta = json.load(f)
            log.log.print_info(f"{os.path.basename(cache_path)} last updated: {meta['last_updated']}")

def save_metadata_file(cache_path: str, source_url: str):
    meta_path = cache_path + ".meta"
    metadata = {
        "last_updated": datetime.now(timezone.utc).isoformat().replace("00:00", "Z"),
        "source_url": source_url,
        "fetched_by": "vulnparse-pin v1.0"
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



def load_epss_from_csv(path_url: str, cache_path: str = "./data/epss_cache.csv.gz") -> Dict[str, float]:
    '''
    Load EPSS data from a CSV file or URL into a dict {cve: epss_score}.
    CSV assumed to have columns: 'cve', 'epss_score'
    '''
    epss_data = {}
    
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
    if path_url.startswith("http"):
        response = requests.get(path_url, timeout=5, allow_redirects=True)
        response.raise_for_status()
        compressed_data = response.content
        
        # Save downloaded content to local cache
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, 'wb') as f:
            f.write(response.content)
        
        # Save checksum
        save_with_checksum(response.content, cache_path)
        log.log.print_success(f"EPSS feed cached locally at {cache_path}")
        save_metadata_file(cache_path, "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
        
        # Open gzip file from bytes in memory
        with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
            # Read decoded text lines from gzip
            decoded = io.TextIOWrapper(gz, encoding='utf-8')
            reader = csv.DictReader(decoded)
            parse_csv(reader)
                    
    elif os.path.exists(path_url):
        # Local file
        if path_url.endswith('.csv'):
            with open(path_url, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
            
        else:
            # Local gzip file
            with gzip.open(path_url, mode='rt', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
                
    else:
        raise FileNotFoundError(f"File or URL not found: {path_url}")
    
    if epss_data is None:
        log.log.print_error(f"Error loading epss_data. EPSS_Data is empty: {epss_data}")
        
    if not validate_checksum("./data/epss_cache.csv.gz"):
        raise ValueError(f"Corrupted or tampered cache file: {cache_path}")
    
    print_cache_metadata(cache_path)
    
    return epss_data

def load_kev_from_json(path_url: str, cache_path: str = "./data/kev_cache.json.gz") -> Dict[str, bool]:
    '''
    Load CISA KEV data from a JSON file or URL into a dict {cve: True}.
    JSON assumed to have CVE's under a 'cveID' or 'CVE' key in each entry
    '''
    kev_data = {}
    
    def parse_json(data):
        vulns = data.get('vulnerabilities', [])
        for entry in vulns:
            cve = entry.get('cveID') or entry.get('CVE')
            if cve:
                kev_data[cve.upper()] = True
                
    if path_url.startswith('http'):
        response = requests.get(path_url, allow_redirects=True, timeout=5)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')
        
        if 'application/gzip' in content_type or path_url.endswith('.gz'):
            compressed_data = response.content
            
            # Save content to local cache
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, 'wb') as f:
                f.write(response.content)
                
            # Save with checksum
            save_with_checksum(response.content, cache_path)
            log.log.print_success(f"KEV feed cached locally at {cache_path}")
            save_metadata_file(cache_path, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            
            with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
                data = json.load(gz)
                parse_json(data)
        else:
            # Save json data content to local cache
            os.makedirs(os.path.dirname("./data/kev_cache.json"), exist_ok=True)
            with open("./data/kev_cache.json", 'w', encoding='utf-8') as f:
                json.dump(response.json(), f, indent=2)
            # Save with checksum
            save_with_checksum(response.content, "./data/kev_cache.json")
            log.log.print_success(f"KEV JSON feed cached locally at {cache_path}")
            save_metadata_file("./data/kev_cache.json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            
            data = response.json()
            parse_json(data)
            
    elif os.path.exists(path_url):
        if path_url.endswith('.gz'):
            with gzip.open(path_url, 'rt', encoding='utf-8') as f:
                data = json.load(f)
                parse_json(data)
        else:
            with open(path_url, 'r', encoding='utf-8') as f:
                data = json.load(f)
                parse_json(data)
                
    else:
        raise FileNotFoundError(f'File or URL not found: {path_url}')
    
    for path in ["./data/kev_cache.json", "./data/kev_cache.json.gz"]:
        if os.path.exists(path) and validate_checksum(path):
            break
    else:
        raise ValueError(f"Corrupted or tampered cache file: {path}")
        
    for path in ["./data/kev_cache.json", "./data/kev_cache.json.gz"]:
        if os.path.exists(path):
            print_cache_metadata(path)
            break
    
    return kev_data

def load_config(config_name="config.json"):
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
    
config = load_config()

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
    
BASE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_data(cve_id: str, base_url: str = BASE_NVD_URL, cache_dir: str = './nvd_cache', offline_mode: bool = False):
    '''
    Funtion to retrieve CVE data from the NIST NVD database.
    
    Args:
        cve_id (str): CVEID to inquire
        base_url (str): hardcorded NIST NVD BaseURL for API - https://services.nvd.nist.gov/rest/json/cves/2.0
        cache_dir (str): directory to cache dataset. Default './nvd_cache'
        
    Returns:
        CVE JSON data from the NIST NVD API
    '''
    # Create a cache directory if it doesn't exist
    os.makedirs(cache_dir, exist_ok=True)
    
    cache_file = os.path.join(cache_dir, f"{cve_id}.json")
    
    # If cached file exist, use it
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            return json.load(f)
     
    
    # Offline mode prevents outbound requests
    if offline_mode:
        log.log.print_warning(f"[Offline Mode] No cache available for {cve_id}, skipping NVD fallback.")
        with open("logs/missed_nvd_fallbacks.log", 'a') as f:
            f.write(f"{cve_id}\n")
        return None
       
    # Otherwise, fetch the data from NVD
    nvd_url = f"{BASE_NVD_URL}?cveID={cve_id.upper()}"
    response = requests.get(nvd_url, allow_redirects=False, timeout=5)
    if response.status_code == 200:
        cve_data = response.json()
        
        # Cache result
        with open(cache_file, 'w') as f:
            json.dump(cve_data, f)
            
        return cve_data
    else:
        log.log.print_error(f"Failed to fetch data for CVE: {cve_id}")
        return None
    
BASE_CVEDETAILS_URL = "https://www.cvedetails.com/cve"
    # DEPRECATED--------------------------------------------------------
def fetch_cvedetails_data(cve_id: str):
    '''
    Method to fetch CVE data from CVEDetails and parse the data for kev data and other data as secondary source for enrichment intel.
    
    Args:
        cve_id (str): CVE_ID to query for
        
    Returns:
        result (Dict): {cve_id: True/False, "cvss_vector": cvss_vector}
    '''
    url = f"{BASE_CVEDETAILS_URL}/{cve_id}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    # Attempt to retrieve CVE_Details page for CVEID
    try:
        time.sleep(1)
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=5, allow_redirects=False)
        response.raise_for_status()
        
        # Parse HTML content
        soup = BeautifulSoup(response.content, "html.parser")
        
        result = {cve_id: False, "cvss_vector": None}
        # Check for presence of "Known-Exploited" or KEV-related info
        kev_status = soup.find_all(string="Known Exploited")
        if kev_status:
            result[cve_id] = True
            log.log.print_success(f"[CVE_DETAILS] Found CISA KEV Entry for {cve_id}")
        else:
            log.log.print_error(f"[CVE_DETAILS] CISA KEV NOT FOUND for {cve_id}")
            
        
        # Check for presence of CVSS Vector and save to variable.
        cvss_regex = re.compile(CVSS3_REGEX_L)
        cvss_vector = soup.find(string=cvss_regex)
        
        if cvss_vector:
            cvss_vector = cvss_vector.strip()
            result["cvss_vector"] = cvss_vector
            log.log.print_success(f"[CVE_DETAILS] Found CVSS Vector for {cve_id}: {cvss_vector}")
        else:
            log.log.print_error(f"[CVE_DETAILS] CVSS VECTOR NOT FOUND for {cve_id}")
        
        return result
    
    except requests.exceptions.RequestException as e:
        log.log.logger.exception(f"Error fetching CVE details for {cve_id}: {e}")
        log.log.print_error(f"Error fetching CVE Details for {cve_id}")
        return None
    
def update_enrichment_status(finding):
    if finding.exploit_available or finding.epss_score or finding.cisa_kev:
        finding.enriched = True
    else:
        finding.enriched = False

def enrich_scan_results(results: ScanResult, kev_data: Dict[str, bool] = None, epss_data: Dict[str, float] = None, offline_mode: bool = False) -> None:
    '''
    Enrich the findings in a ScanResult object with EPSS Score, CISA KEV status, exploit indicators, and recalculate triage priority.
    
    Args:
        results (ScanResult Obj): The parsed vulnerability scan results.
        kev_data (Dict[str, bool], Optional): Mapping of CVE IDs to CISA KEV status.
        epss_data (Dict[str, float], Optional): Mapping of CVE IDs to EPSS Scores.
    '''
    miss_logger = EnrichmentMissLogger()
    
    baseline_risk_count = 0
    total_cves = 0
    total_kev_hits = 0
    total_epss_misses = 0
    total_cvss_vector_hits = 0
    total_cvss_vector_validated = 0
    
    kev_data = kev_data or {}
    epss_data = epss_data or {}
    
     #TODO: DEBUG
    
    for asset in results.assets:
        for finding in asset.findings:
            sec_cvss_vector = None
            sec_cvss_vectors = []
            cisa_hits = []
            epss_scores = []
            enrichment_attempted = False
            if kev_data is not None and epss_data is not None:
                for cve in finding.cves:
                    total_cves += 1
                    enrichment_attempted = True
                    
                    
                    # CISA KEV Enrichment
                    kev_hit = kev_data.get(cve.upper(), False)
                    cisa_hits.append(kev_hit)
                    
                    
                    if kev_hit:
                        total_kev_hits += 1
                        log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} found in CISA KEV")
                    else:
                        log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No CISA KEV record for {cve}.")
                        miss_logger.log_miss(cve, cisa_kev=False, epss_score=None)
                        
                    # Fetch nvd_data as secondary source
                    nist_nvd_data = fetch_nvd_data(cve, offline_mode=offline_mode)
                    if nist_nvd_data:
                        if "vulnerabilities" in nist_nvd_data and nist_nvd_data["vulnerabilities"]:
                            vulnerability = nist_nvd_data["vulnerabilities"][0]
                            
                            if "metrics" in vulnerability["cve"] and "cvssMetricV31" in vulnerability["cve"]["metrics"]:
                                sec_cvss_metrics = vulnerability["cve"]["metrics"]
                                
                                sec_cvss_vector = "N/A"
                                primary_vector = None
                                secondary_vector = None
                                
                                
                                for metric in sec_cvss_metrics["cvssMetricV31"]:
                                    metric_type = metric.get("type")
                                    vector = metric.get("cvssData", {}).get("vectorString", "").strip()
                                    
                                    if metric_type == "Primary" and is_valid_cvss_vector(vector):
                                        primary_vector = vector
                                        
                                    elif metric_type == "Secondary" and is_valid_cvss_vector(vector):
                                        secondary_vector = vector
                                        
                                if primary_vector:
                                    sec_cvss_vector = primary_vector
                                    log.log.print_info(f"[CVSSVector] Using PRIMARY vector for {cve}")
                                    
                                elif secondary_vector:
                                    sec_cvss_vector = secondary_vector
                                    log.log.print_info(f"[CVSSVector] Using SECONDARY vector for {cve}")
                                    
                                else:
                                    sec_cvss_vector = None
                                    log.log.print_warning(f"[CVSSVector] No usable vector found for {cve}")
                                    
                                if sec_cvss_vector:
                                    sec_cvss_vectors.append(sec_cvss_vector)
                                    log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[NVDData]{Style.RESET_ALL} CVSS Vector Found in NVD Data for {cve}")
                                
                    else:
                        log.log.print_error(f"Could not retrieve cvss_vector from nvd source for {cve}")
                    
                    
                    # EPSS Score Enrichment
                    epss_score = epss_data.get(cve)
                    if epss_score is not None:
                        epss_scores.append(epss_score)
                        log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} EPSS Score: {epss_score}")
                    else:
                        log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No EPSS Score for {cve}")
                        epss_scores.append(0.0)
                        total_epss_misses += 1
                        miss_logger.log_miss(cve, cisa_kev=kev_hit, epss_score=None)
                
                #TODO: Build small dict of enriched cve info
                enrichment_map = {}
                
                for idx, cve in enumerate(finding.cves):
                    enrichment_map[cve] = {
                        "epss_score": epss_data.get(cve, 0.0),
                        "cisa_kev": kev_data.get(cve.upper(), False),
                        "exploit_available": finding.exploit_available if len(finding.cves) > 1 else False,
                        "cvss_score": 0.0,
                        "cvss_vector": None
                    }
                    
                    if idx < len(sec_cvss_vectors):
                        vector = sec_cvss_vectors[idx]
                        if is_valid_cvss_vector(vector):
                            enrichment_map[cve]["cvss_vector"] = vector
                            enrichment_map[cve]["cvss_score"] = parse_cvss_vector(vector)[0]
                            
                authoritative_cve = select_authoritative_cve(list(enrichment_map.keys()), enrichment_map)
                
                if authoritative_cve:
                    best = enrichment_map[authoritative_cve]
                    finding.epss_score = best["epss_score"]
                    finding.cisa_kev = best["cisa_kev"]
                    finding.exploit_available = best["exploit_available"]
                    finding.enrichment_source_cve = authoritative_cve
                    log.log.print_info(
                        f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} "
                        f"Authoritative CVE: {authoritative_cve} => "
                        f"EPSS={best['epss_score']} | KEV={best['cisa_kev']} | Exploit={best['exploit_available']}"
                    )
                else:
                    log.log.print_warning(f"[Enrichment] No authoritative CVE selected for {finding.vuln_id}")

                
            # Get CVSS Vectors w/ Validation / Reconciliation
            if sec_cvss_vectors:
                valid_vectors = [v for v in sec_cvss_vectors if is_valid_cvss_vector(v)]
                if valid_vectors:
                    finding.cvss_vector = valid_vectors[0]
                    log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Assigned CVSS Vector: {finding.cvss_vector}")
                    total_cvss_vector_hits += 1
                else:
                    log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} No valid CVSS vectors found for {finding.cvss_vector}")
                    
            elif finding.cvss_vector in ["N/A", "Unknown", None]:
                finding.cvss_vector = random.choice(sec_cvss_vectors) if sec_cvss_vectors else None
            
            # Now Validate and Reconcile CVSS Vector
            if finding.cvss_vector and is_valid_cvss_vector(str(finding.cvss_vector)):
                cvss_data = parse_cvss_vector(str(finding.cvss_vector))
                log.log.print_info(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Validating and reconciling CVSS Vector for {finding.vuln_id}...")
                total_cvss_vector_validated += 1
                
                if cvss_data:
                    base_score = cvss_data[0]
                    log.log.print_info(f"{finding.vuln_id} Base score from vector: {base_score}")
                    
                    # Auto-Reconcile CVSS base score if it differs by tolerance.
                    if abs(base_score - (finding.cvss_score or 0.0)) > 0.1:
                        log.log.print_warning(f"Score mismatch for {finding.vuln_id}: vector {base_score} vs field: {finding.cvss_score}")
                        log.log.print_success(f"Overwriting cvss score with value from CVSS Vector: {base_score}")
                        finding.cvss_score = base_score
                        
                    else:
                        log.log.print_success(f"CVSS score for {finding.vuln_id} is consistent.")
                    
                        
                else:
                    log.logger.debug(f"Invalid CVSS vector for {finding.vuln_id}")
            else:
                log.log.print_error(f"Invalid CVSS vector format for {finding.vuln_id}: {finding.cvss_vector}")
                    
            # Calculate Risk_Score
            cvss = finding.cvss_score or 0.0
            epss = finding.epss_score or 0.01 # Prevent zero-risk bias
            
            # Baseline risk adjustment if missing CVSS but has exploit/high+ severity or risk band
            if cvss == 0.0 and (finding.exploit_available or finding.severity in ['Critical', 'High']):
                baseline_risk_count += 1
                baseline_risk = 7
                log.log.print_warning(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} Missing CVSS for {finding.vuln_id}, setting baseline risk {Fore.LIGHTRED_EX}{baseline_risk}{Style.RESET_ALL} due to exploit/high-critical severity")
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
                log.log.print_warning(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} Risk Score for {finding.vuln_id} capped at 10.0 (Raw Score: {Fore.LIGHTRED_EX}{raw_risk_score}{Style.RESET_ALL})")
            else:
                log.log.print_info(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} {finding.vuln_id} Raw Risk Score: {Fore.LIGHTRED_EX}{raw_risk_score}{Style.RESET_ALL}")
            log.log.print_info(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} {finding.vuln_id} Final Risk Score: {Fore.LIGHTRED_EX}{risk_score}{Style.RESET_ALL} | Triage Priority: {Fore.LIGHTRED_EX}{risk_band}{Style.RESET_ALL} | ")
            
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
            
        asset.avg_risk_score = round(
            sum(f.risk_score for f in asset.findings) / len(asset.findings), 2
        ) if asset.findings else 0.0
        
    print(f"{Fore.LIGHTMAGENTA_EX}==============[Enrichment Summary]=============={Style.RESET_ALL}")
    log.log.print_info(f"   Total CVEs Processed : {total_cves}")
    log.log.print_info(f"   Total CISA KEV Hits : {total_kev_hits}")
    log.log.print_info(f"   Total CVSS Vectors Assigned : {total_cvss_vector_hits}")
    log.log.print_info(f"   Total CVSS Vectors Validated : {total_cvss_vector_validated}")
    log.log.print_info(f"   Total EPSS Misses : {total_epss_misses}")
    log.log.print_info(f"   Total Findings Rx Baseline Risk Adjustment: {baseline_risk_count}")
    print(f"{Fore.LIGHTMAGENTA_EX}============[Enrichment Summary End]============{Style.RESET_ALL}")
    
    miss_logger.write_log()