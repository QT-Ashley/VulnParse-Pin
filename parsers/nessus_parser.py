
from datetime import timezone
from operator import itemgetter
from typing import Any, Dict, List, Optional
import ipaddress
from classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
from json_parser import get_key_case_ins
from parsers.base_parser import BaseParser
from utils.normalizer import *
from collections import Counter, defaultdict
import utils.logger_instance as log


class NessusParser(BaseParser):
        
    def detect(self, data: dict) -> bool:
        # Logic that detects if the JSON data looks like a Nessus report.
        # Example: check for a key or structure unique for Nessus
        detection_patterns = [
            # Pattern 1: Check for current Nessus-like structure
            lambda d: "scan" in d and isinstance(d["scan"].get("hosts"), list) and any("vulnerabilities" in h for h in d["scan"]["hosts"]),
            
            # Pattern 2: Generic 'results' list
            lambda d: "results" in d and any(
                isinstance(item, dict) and (
                    "plugin_name" in item or
                    "plugin_id" in item
                    ) for item in d.get("results", [])
                ),
            
            # Pattern 3: Check for top-level 'assets'
            lambda d: "assets" in d and isinstance(d["assets"], list),
            
            # Pattern 4: Flat list structure (some custom JSONs)
            lambda d: isinstance(d, list) and any(
                isinstance(item, dict) and (
                    "plugin_id" in item or
                    "plugin_name" in item
                ) for item in d
            )
        ]
        
        for pattern in detection_patterns:
            try:
                if pattern(data):
                    return True
            except Exception as e:
                log.log.print_error(f"Pattern check failed: {e}")
                continue
        
        return False
        
    

    def parse(self, nessus_json: Dict[str, Any]) -> ScanResult:
        """
        Parse a Nessus JSON vulnerability scan report into structured Python objects.

        This function processes a Nessus scan report, extracts relevant host and vulnerability 
        details,
        and structures them into a ScanResult object containing assets and findings.

        Args:
            nessus_json (Dict[str, Any]): The parsed Nessus JSON report data.

        Returns:
            ScanResult: An object containing structured scan metadata, assets, and vulnerability findings.
        """
        nessus_json = self.detect_and_transform_flat_json(nessus_json)
        if "scan_metadata" in nessus_json and "scan_date" in nessus_json["scan_metadata"]:
            scan_date = nessus_json["scan_metadata"].get("scan_date")
        
        metadata, report_data = self.normalize_structure(nessus_json)
        
        assets: Dict[str, Asset] = {}
        
        
        
        
        if isinstance(report_data, list) and report_data and any(k in report_data[0] for k in ["finding", "results"]):
            grouped_assets = self.group_findings_by_asset(report_data)
            report_data = list(grouped_assets.values())
        
        
        
        
        for report_host in report_data:
            hostname = coerce_str(self.get_key_case_ins(report_host, ["host-name", "hostname", "host_name"], default="unknown"))
            ip_address = coerce_ip(self.get_key_case_ins(report_host, ["host-ip", "ip", "ip-address", "ip_address", "host_ip"], default="Unknown"))
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
                vuln_id = coerce_str(self.get_key_case_ins(item, ["plugin_id", "vuln_id", "id"], default="unknown"))
                title = coerce_str(self.get_key_case_ins(item, ["plugin_name", "title", "vuln_title"], default="No Title"))
                description = coerce_str(self.get_key_case_ins(item, ["description"], default="Not Available"))
                solution = coerce_str(self.get_key_case_ins(item, ["solution"], default="Not Available"))
                plugin_output = coerce_str(self.get_key_case_ins(item, ["plugin_output"], default="Unavailable"))
                risk = coerce_str(self.get_key_case_ins(item, ["risk_factor", "risk"], default="Unknown"))
                severity = risk.capitalize() if risk != "Unknown" else coerce_severity(self.get_key_case_ins(item, ["severity"], default="Low"), default="Low")
                cves = coerce_list_of_strs(self.get_key_case_ins(item, ["cves", "cve_list", "cve"], default=[]))
                references = coerce_list(self.get_key_case_ins(item, ["see also", "references"], default=[]))
                if isinstance(cves, str):
                    cves = [c.strip() for c in cves.split(",") if c.strip()]
                if not risk:
                    risk = severity
                
                
                exploit_indicators = ["exploit", "metasploit", "public exploit", "poc available"]
                exploit_available = any(indicator in str(plugin_output).lower() for indicator in exploit_indicators)
                cvss_score = coerce_float(self.get_key_case_ins(item, ["cvss3_base_score", "cvss_base_score"], default=0.0))
                affected_port = coerce_int(self.get_key_case_ins(item, ["port", "affected_port"], default=0), default=0)
                protocol = coerce_protocol(self.get_key_case_ins(item, ["protocol"], default="Unavailable"), default="Unavailable").lower()
                
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
                    cvss_vector=None,
                    epss_score=0.0,
                    cisa_kev=False,
                    exploit_available=exploit_available,
                    risk=risk,
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
            assets[asset_id].criticality = self.determine_asset_criticality(severity_counter)
                
        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())
        
        metadata = ScanMetaData(
            source="Nessus",
            scan_date=scan_date,
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        )
                
        result = ScanResult(
            scan_metadata=metadata,
            assets=list(assets.values())
        )
        return result
    
    
    def get_key_case_ins(self, data: Dict[str, Any], possible_keys: List[str], default: Optional[Any] = None) -> Any:
        for key in possible_keys:
            for actual_key in data.keys():
                if actual_key.lower() == key.lower():
                    return data[actual_key]
        return default

    def group_findings_by_asset(self, flat_list):
        assets = {}
        grouped = defaultdict(list)

        for item in flat_list:
            host_key = (item.get("hostname") or item.get("host-name") or item.get("host_name"),
                        item.get("ip") or item.get("host_ip") or item.get("host-ip"))
            finding = {k: v for k, v in item.items() if k not in ["hostname", "host-name", "host_name", "ip", "host-ip", "host_ip", "criticality"]}
            grouped[host_key].append(finding)

        for (hostname, ip), findings in grouped.items():
            assets[hostname or ip] = {
                "hostname": hostname,
                "ip": ip,
                "findings": findings
            }
        return assets

    def transform_flat_list(self, results_list):
        assets = {}
        exploit_indicators = ["exploit", "metasploit", "public exploit", "poc available"]

        for result in results_list:
            hostname = result.get("hostname") or result.get("host_name") or result.get("host-name") or result.get("host_ip") or result.get("ip") or "Unknown"
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
                "risk": self.get_key_case_ins(result, ["risk_factor"], default="Unknown"),
                "exploit_available": any(indicator in str(result.get("plugin_output", "").lower()) for indicator in exploit_indicators)
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

    def detect_and_transform_flat_json(self, some_json):
        if isinstance(some_json, list):
            log.log.print_info("Detected flat list JSON format.")
            return self.transform_flat_list(some_json)

        elif isinstance(some_json, dict):
            if "results" in some_json and isinstance(some_json["results"], list):
                log.log.print_info("Detected 'results' key with flat list.")
                return self.transform_flat_list(some_json["results"])

            elif "assets" in some_json:
                log.log.print_info("Detected already normalized schema.")
                return some_json
            
            elif "scan" in some_json and "hosts" in some_json["scan"]:
                log.log.print_info("Detected 'scan' top-level key with 'hosts'. Extracting hosts list.")
                # Return a normalized dict with "assets" key, mapping hosts to assets for parser.
                hosts = some_json["scan"]["hosts"]
                assets_list = []
                for host in hosts:
                    asset = {
                        "hostname": self.get_key_case_ins(host, ["hostname", "host-name", "host_name"], default="Unknown"),
                        "ip_address": self.get_key_case_ins(host, ["ip", "ip-address", "ip_address", "host-ip", "host_ip"], default="Unknown"),
                        "criticality": host.get("criticality", None),
                        "findings": host.get("vulnerabilities", [])
                    }
                    assets_list.append(asset)
                    
                scan_metadata = some_json["scan"]["info"]
                    
                return {
                    "scan_metadata": {
                        "source": scan_metadata.get("name", "Unknown"),
                        "scan_date": scan_metadata.get("start_time", "Unavailable"),
                        "asset_count": len(assets_list),
                        "vulnerability_count": sum(len(a["findings"]) for a in assets_list),
                        "parsed_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                    },
                    "assets": assets_list
                }

            else:
                log.log.print_warning("Unknown dict formation - returning as-is.")
                return some_json

        else:
            log.log.print_warning("Unrecognized JSON structure - returning as-is.")
            return some_json
        
    # ==========Schema detectors and normalizers=========

    def normalize_structure(self, data):
        if isinstance(data, list):
            if len(data) > 0:
                data = data[0]
            else:
                raise ValueError("Empty list provided - no data to normalize.")

        if self.is_nessus_scan_metadata(data):
            log.log.print_info("Nessus 'scan_metadata' key detected.")
            return self.normalize_nessus_scan_metadata(data)
        elif self.is_nessus_source_scan_date(data):
            return self.normalize_nessus_source_scan_date(data)
        elif self.is_qualys_style(data):
            return self.normalize_qualys_style(data)
        elif self.is_assets_based(data):
            return self.normalize_assets_based(data)
        elif self.is_hosts_based(data):
            return self.normalize_hosts_based(data)
        elif self.is_results_based(data):
            return self.normalize_results_based(data)
        else:
            log.log.print_warning(f"Unknown JSON structure: top-level keys: {list(data.keys())}")
            return {
                "source": "Unknown",
                "scan_date": None
            }, data.get("report", [])


    def is_nessus_scan_metadata(self, data):
        return isinstance(data, dict) and "scan_metadata" in data and "report" in data

    def is_nessus_source_scan_date(self, data):
        return isinstance(data, dict) and all(k in data for k in ["source", "scan_date", "report"])

    def is_qualys_style(self, data):
        return isinstance(data, dict) and "scan_date" in data and "vulnerabilities" in data

    def is_assets_based(self, data):
        return isinstance(data, dict) and "assets" in data

    def is_hosts_based(self, data):
        return isinstance(data, dict) and "hosts" in data

    def is_results_based(self, data):
        return isinstance(data, dict) and "results" in data

    def normalize_nessus_scan_metadata(self, data):
        metadata = data.get("scan_metadata", {})
        report_data = data.get("report", [])
        return metadata, report_data

    def normalize_nessus_source_scan_date(self, data):
        metadata = {
            "source": data.get("source", "Nessus"),
            "scan_date": data.get("scan_date")
        }
        report_data = data.get("report", [])
        return metadata, report_data

    def normalize_qualys_style(self, data):
        metadata = {
            "source": "Qualys",
            "scan_date": data.get("scan_date")
        }
        report_data = data.get("vulnerabilities", [])
        return metadata, report_data

    def normalize_assets_based(self, data):
        metadata = {
            "source": data.get("source", "Unknown"),
            "scan_date": data.get("scan_date")
        }
        report_data = data.get("assets", [])
        return metadata, report_data

    def normalize_hosts_based(self, data):
        metadata = {
            "source": data.get("source", "Unknown"),
            "scan_date": data.get("scan_date")
        }
        report_data = data.get("hosts", [])
        return metadata, report_data

    def normalize_results_based(self, data):
        metadata = data.get("metadata", {})
        report_data = data.get("results", [])
        return metadata, report_data
    
    #========== End Schema detectors and normalizers=========

    def determine_asset_criticality(self, severity_counter: Counter) -> str:
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