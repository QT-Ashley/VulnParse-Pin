
from typing import Any, Dict, List, Optional
import ipaddress
from classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
from utils.normalizer import *
from collections import Counter, defaultdict

def get_key_case_ins(data: Dict[str, Any], possible_keys: List[str], default: Optional[Any] = None) -> Any:
    """
    Retrieve the value from a dictionary using a case-insensitive match against a list of possible keys.

    This utility function iterates through a list of possible key names and returns the value for the
    first key found in the provided dictionary, ignoring key casing. If none of the keys are present,
    it returns a default value.

    Args:
        data (Dict[str, Any]): The dictionary to search for keys in.
        possible_keys (List[str]): A list of possible key names to search for (case-insensitive).
        default (Any, optional): The value to return if none of the keys are found. Defaults to None.

    Returns:
        Any: The value associated with the first matching key, or the default value if no match is found.
    """
    for key in possible_keys:
        for actual_key in data.keys():
            if actual_key.lower() == key.lower():
                return data[actual_key]
    return default

def group_findings_by_asset(flat_list):
    assets = {}
    
    # Use composite key of (hostname, ip) to group findings
    grouped = defaultdict(list)
    
    for item in flat_list:
        host_key = (item.get("hostname") or item.get("host-name") or item.get("host_name"), item.get("ip") or item.get("host_ip") or item.get("host-ip"))
        
        # Extract finding details by removing asset info keys
        finding = {k: v for k, v in item.items() if k not in ["hostname", "host-name", "host_name", "ip", "host-ip", "host_ip", "criticality"]}
        
        grouped[host_key].append(finding)
        
    # Build asset dict with findings list
    for (hostname, ip), findings in grouped.items():
        assets[hostname or ip] = {
            "hostname": hostname,
            "ip": ip,
            "findings": findings
        }
        
    return assets

def transform_flat_list(results_list):
    assets = {}
    
    exploit_indicators = ["exploit", "metasploit", "public exploit", "poc available"]
    
    for result in results_list:
        hostname = result.get("hostname") or result.get("host_name") or result.get("host-name") or result.get("host_ip") or result.get("ip") or result.get("ip_address") or result.get("ip_address") or "Unknown"
        try:
            ip_address = str(ipaddress.ip_address(hostname))
        except ValueError:
            ip_address = None
        if hostname not in assets:
            assets[hostname] = {
                "hostname": hostname,
                "ip_address": hostname if ip_address else None,
                "criticality": "Low",
                "findings": [],
                "shodan_data": None
            }
            
        finding = {
            "vuln_id": str(result.get("plugin_id", "")),
            "title": result.get("plugin_name", ""),
            "description": result.get("description", ""),
            "severity": result.get("severity", "Unknown"),
            "affected_port": result.get("port"),
            "protocol": result.get("protocol"),
            "cves": result.get("cve", []),
            "solution": result.get("solution"),
            "plugin_output": result.get("plugin_output"),
            "risk": get_key_case_ins(result, ["risk_factor"], default="Unknown"),
            "exploit_available": any(indicator in str(result.get("plugin_output", "").lower()) for indicator in exploit_indicators or "Unknown")
        }
        assets[hostname]["findings"].append(finding)
        
    return {
        "scan_metadata": {
            "source": "Unknown",
            "scan_date": None,
            "asset_count": len(assets),
            "vulnerability_count": sum(len(a["findings"]) for a in assets.values())
        },
        "assets": list(assets.values())
    }

def detect_and_transform_flat_json(some_json):
    '''
    Detects the structure of flat JSON file and transform into proper structured format.
    '''
    if isinstance(some_json, list):
        print("[*] Detected flat list JSON format.")
        return transform_flat_list(some_json)
    
    elif isinstance(some_json, dict):
        if "results" in some_json and isinstance(some_json["results"], list):
            print("[*] Detected 'results' key with flat list.")
            return transform_flat_list(some_json["results"])
        
        elif "assets" in some_json:
            print("[*] Detected already normalized scheme.")
            return some_json
        
        else:
            # Fallback: Unknown dict format - TODO: Log or throw
            print("[!] Unknown dict formation - returning as-is.")
            return some_json
    
    else:
        # Not a list or dict - invalid JSON
        print("[!] Unrecognized JSON structured - returning as-is.")
        return some_json

def normalize_structure(data):
    '''
    Detects the JSON structure type and normalizes it to a consistent format.
    
    Returns:
        metadata (dict): standardized scan metadata
        report_data (dict): standardized list of asset findings
    '''
    # Defensive Check
    if isinstance(data, list):
        if len(data) > 0:
            data = data[0]
        else:
            raise ValueError("Empty list provided - no data to normalize.")
        
    # Nessus native with 'scan_metadata'
    if is_nessus_scan_metadata(data):
        return normalize_nessus_scan_metadata(data)
    
    # Simplified Nessus with 'source' + 'scan_date' + 'report'
    elif is_nessus_source_scan_date(data):
        return normalize_nessus_source_scan_date(data)
    
    # Qualys style
    elif is_qualys_style(data):
        return normalize_qualys_style(data)
    
    # "Assets"-Based JSON
    elif is_assets_based(data):
        return normalize_assets_based(data)
    
    # "Hosts"-Based JSON
    elif is_hosts_based(data):
        return normalize_hosts_based(data)
    
    # "Results"-Based JSON
    elif is_results_based(data):
        return normalize_results_based(data)
    
    # Extensible for future support
    

    else:
        print(f"[!] Unknown JSON structure: top-level keys: {list(data.keys())}")
        return {
            "source": "Unknown",
            "scan_date": None
        }, data.get("report", [])
        
# ====Schema Detectors====

def is_nessus_scan_metadata(data):
    return isinstance(data, dict) and "scan_metadata" in data and "report" in data

def is_nessus_source_scan_date(data):
    return isinstance(data, dict) and all(k in data for k in ["source", "scan_date", "report"])

def is_qualys_style(data):
    return isinstance(data, dict) and "scan_date" in data and "vulnerabilities" in data

def is_assets_based(data):
    return isinstance(data, dict) and "assets" in data

def is_hosts_based(data):
    return isinstance(data, dict) and "hosts" in data

def is_results_based(data):
    return isinstance(data, dict) and "results" in data

# ====Normalizers====

def normalize_nessus_scan_metadata(data):
    metadata = data.get("scan_metadata", {})
    report_data = data.get("report", [])
    return metadata, report_data

def normalize_nessus_source_scan_date(data):
    metadata = {
        "source": data.get("source", "Nessus"),
        "scan_date": data.get("scan_date")
    }
    report_data = data.get("report", [])
    return metadata, report_data

def normalize_qualys_style(data):
    metadata = {
        "source": "Qualys",
        "scan_date": data.get("scan_date")
    }
    report_data = data.get("vulnerabilities", [])
    return metadata, report_data

def normalize_assets_based(data):
    metadata = {
        "source": data.get("source", "Unknown"),
        "scan_date": data.get("scan_date")
    }
    report_data = data.get("assets", [])
    return metadata, report_data

def normalize_hosts_based(data):
    metadata = {
        "source": data.get("source", "Unknown"),
        "scan_date": data.get("scan_date")
    }
    report_data = data.get("hosts", [])
    return metadata, report_data

def normalize_results_based(data):
    metadata = data.get("metadata", {})
    report_data = data.get("results", [])
    return metadata, report_data

def determine_asset_criticality(severity_counter: Counter) -> str:
    crit_count = severity_counter["Critical"]
    high_count = severity_counter["High"]
    
    
    if crit_count >= 3:
        return "Extreme"
    elif crit_count >= 1 or high_count >= 2:
        return "High"
    elif high_count == 1:
        return "Medium"
    else:
        return "Low"
    
# =========END Helpers===========#

def parse_json(nessus_json: Dict[str, Any]) -> ScanResult:
    """
    Parse a Nessus JSON vulnerability scan report into structured Python objects.

    This function processes a Nessus scan report, extracts relevant host and vulnerability 
    details, enriches findings with EPSS scores, CISA KEV status, and exploit availability,
    and structures them into a ScanResult object containing assets and findings.

    Args:
        nessus_json (Dict[str, Any]): The parsed Nessus JSON report data.
        epss_data (Dict[str, float]): A dictionary mapping CVEs to their EPSS scores.
        kev_data (Dict[str, bool]): A dictionary indicating whether a CVE is on the CISA KEV list.

    Returns:
        ScanResult: An object containing structured scan metadata, assets, and vulnerability findings.
    """
    nessus_json = detect_and_transform_flat_json(nessus_json)
    
    metadata, report_data = normalize_structure(nessus_json)
    
    assets: Dict[str, Asset] = {}
    
    source = coerce_str(metadata.get("source"), default="Unknown")
    
    scan_date = coerce_date(metadata.get("scan_date"), default=None)
    
    if isinstance(report_data, list) and report_data and ("finding" or "results") in report_data[0]:
        grouped_assets = group_findings_by_asset(report_data)
        report_data = list(grouped_assets.values())
    
    
    
    
    for report_host in report_data:
        hostname = coerce_str(get_key_case_ins(report_host, ["host-name", "hostname", "host_name"], default="unknown"))
        ip_address = coerce_ip(get_key_case_ins(report_host, ["host-ip", "ip", "ip-address", "ip_address", "host_ip"], default="Unknown"))
        asset_id_raw = hostname or ip_address or "unknown"
        asset_id = coerce_str(asset_id_raw, default="Unknown")
        
        if asset_id not in assets:
            assets[asset_id] = Asset(
                hostname=hostname,
                ip_address=ip_address or "Unknown",
                criticality=None,
                findings=[],
                shodan_data=None #TODO: Build this out.
            )
            
        severity_counter = Counter()
            
        for item in report_host.get("findings", []):
            vuln_id = coerce_str(get_key_case_ins(item, ["plugin_id", "vuln_id", "id"], default="unknown"))
            title = coerce_str(get_key_case_ins(item, ["plugin_name", "title", "vuln_title"], default="No Title"))
            description = coerce_str(get_key_case_ins(item, ["description"], default="Description Not Available"))
            solution = coerce_str(get_key_case_ins(item, ["solution"], default="Solution Not Available"))
            plugin_output = coerce_str(get_key_case_ins(item, ["plugin_output"], default="Unavailable"))
            risk = coerce_str(get_key_case_ins(item, ["risk_factor"], default="Unknown"))
            severity = risk.capitalize() if risk else coerce_severity(get_key_case_ins(item, ["severity"], default="Low"), default="Low")
            cves = coerce_list(get_key_case_ins(item, ["cves", "cve_list", "cve"], default=[]))
            references = coerce_list(get_key_case_ins(item, ["see also", "references"], default=[]))
            
            
            exploit_indicators = ["exploit", "metasploit", "public exploit", "poc available"]
            exploit_available = any(indicator in str(plugin_output).lower() for indicator in exploit_indicators)
            cvss_score = coerce_float(get_key_case_ins(item, ["cvss3_base_score", "cvss_base_score"], default=0.0))
            affected_port = coerce_int(get_key_case_ins(item, ["port", "affected_port"], default=0), default=0)
            protocol = coerce_protocol(get_key_case_ins(item, ["protocol"], default="Unavailable"), default="Unavailable").lower()
            
            severity_counter[severity] += 1
            
            finding = Finding(
                vuln_id=vuln_id,
                title=title,
                severity=severity,
                description=description,
                solution=solution,
                plugin_output=plugin_output,
                cves=cves,
                cvss_score=cvss_score,
                epss_score=0.0,
                cisa_kev=False,
                exploit_available=exploit_available,
                triage_priority=None,
                enriched=False,
                affected_port=affected_port,
                protocol=protocol,
                references=references,
                remediation=solution, #TODO: Find alternative remediation outside of solution
                detection_plugin=title,
                assetid=asset_id
            )
            
            assets[asset_id].findings.append(finding)
            
        # Determine criticality
        assets[asset_id].criticality = determine_asset_criticality(severity_counter)
            
    asset_count = len(assets)
    vuln_count = sum(len(asset.findings) for asset in assets.values())
    
    metadata = ScanMetaData(
        source=source,
        scan_date=scan_date,
        asset_count=asset_count,
        vulnerability_count=vuln_count
    )
            
    result = ScanResult(
        scan_metadata=metadata,
        assets=list(assets.values())
    )
    return result