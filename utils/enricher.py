from typing import Dict, List
import gzip
import io
import csv
import requests
import os
import json

from classes.dataclass import ScanResult
from utils.triage_priority_helper import determine_triage_priority

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

def load_epss_from_csv(path_url: str) -> Dict[str, float]:
    '''
    Load EPSS data from a CSV file or URL into a dict {cve: epss_score}.
    CSV assumed to have columns: 'cve', 'epss_score'
    '''
    epss_data = {}
    
    def parse_csv(reader):
        for row in reader:
            cve = row.get('cve') or row.get('CVE')
            score_str = row.get('epss_score') or row.get('EPSScore') or row.get('score')
            if cve and score_str:
                try:
                    epss_data[cve.upper()] = float(score_str)
                except ValueError:
                    continue
    
    # Download or open local .gz file
    if path_url.startswith("http"):
        response = requests.get(path_url)
        response.raise_for_status()
        compressed_data = response.content
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
    
    return epss_data

def load_kev_from_json(path_url: str) -> Dict[str, bool]:
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
        response = requests.get(path_url)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')
        
        if 'application/gzip' in content_type or path_url.endswith('.gz'):
            compressed_data = response.content
            with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
                data = json.load(gz)
                parse_json(data)
        else:
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
    
    return kev_data

def enrich_scan_results(results: ScanResult, kev_data: Dict[str, bool] = None, epss_data: Dict[str, float] = None) -> None:
    '''
    Enrich the findings in a ScanResult object with EPSS Score, CISA KEV status, exploit indicators, and recalculate triage priority.
    
    Args:
        results (ScanResult Obj): The parsed vulnerability scan results.
        kev_data (Dict[str, bool], Optional): Mapping of CVE IDs to CISA KEV status.
        epss_data (Dict[str, float], Optional): Mapping of CVE IDs to EPSS Scores.
    '''
    
    kev_data = kev_data or {}
    epss_data = epss_data or {}
    
    for asset in results.assets:
        for finding in asset.findings:
            if finding.cves:
                # Enrich CISA KEV Status
                finding.cisa_kev = any(cve in kev_data for cve in finding.cves)
                # Enrich EPSS Score
                finding.epss_score = max([epss_data.get(cve, 0.0) for cve in finding.cves])
            else:
                finding.epss_score = 0.0
                finding.cisa_kev = False
                
            # Recalculate Triage Priority
            finding.triage_priority = determine_triage_priority(
                finding.severity,
                finding.epss_score or 0.0,
                finding.cisa_kev,
                finding.exploit_available
            )
            
            # Update enrichment flag
            finding.enriched = bool(finding.epss_score or finding.cisa_kev or finding.exploit_available)