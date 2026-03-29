# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

# THIS MODULE IS EXPERIMENTAL AND INCOMPLETE AT THIS TIME.
# PENDING REAL-WORLD JSON DATA SAMPLES, THIS MODULE WILL NOT BE FURTHER DEVELOPED.
# THERE ARE NO GUARANTEES THIS MODULE WILL WORK.
# NOT SUPPORTED IN V1.0-RC; EXCLUDED FROM SCHEMADETECTOR BY DEFAULT.
# IF YOU WISH TO TEST, UNCOMMENT ALL BELOW THIS LINE.
from __future__ import annotations

EXPERIMENTAL = True
EXPERIMENTAL_REASON = "Pending real-world JSON samples; parser not validated."

from typing import TYPE_CHECKING
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import ipaddress
from collections import Counter, defaultdict
from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
from vulnparse_pin.core.id import make_asset_id
from vulnparse_pin.parsers.base_parser import BaseParser
from vulnparse_pin.utils.normalizer import coerce_float, coerce_int, coerce_ip, coerce_list, coerce_list_of_strs, coerce_protocol, coerce_severity, coerce_str


if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


class NessusParser(BaseParser):
    def __init__(self, ctx: "RunContext", filepath: str | None = None) -> None:
        super().__init__(ctx = ctx, filepath=filepath)

    @classmethod
    def detect_file(cls, filepath):
        """Lightweight file-level detection for Nessus JSON."""
        return False
    #    if filepath.suffix == ".json":
    #        try:
    #            with open(filepath, "r", encoding="utf-8") as f:
    #                head = f.read(900)
    #                return '"plugin_id"' in head or '"plugin_name"' in head
    #        except Exception:
    #            return False
    #    else:
    #        return False

    def detect(self, data: dict) -> bool:
        # Logic that detects if the JSON data looks like a Nessus report.
        # Example: check for a key or structure unique for Nessus
        return False
    #    detection_patterns = [
    #        # Pattern 1: Check for current Nessus-like structure
    #        lambda d: "scan" in d and isinstance(d["scan"].get("hosts"), list) and any("vulnerabilities" in h for h in d["scan"]["hosts"]),

    #        # Pattern 2: Generic 'results' list
    #        lambda d: "results" in d and any(
    #            isinstance(item, dict) and (
    #                "plugin_name" in item or
    #                "plugin_id" in item
    #                ) for item in d.get("results", [])
    #            ),

    #        # Pattern 3: Check for top-level 'assets'
    #        lambda d: "assets" in d and isinstance(d["assets"], list),

    #        # Pattern 4: Flat list structure (some custom JSONs)
    #        lambda d: isinstance(d, list) and any(
    #            isinstance(item, dict) and (
    #                "plugin_id" in item or
    #                "plugin_name" in item
    #            ) for item in d
    #        )
    #    ]

    #    for pattern in detection_patterns:
    #        try:
    #            if pattern(data):
    #                return True
    #        except Exception as e:
    #            self.ctx.logger.print_error(f"Pattern check failed: {e}")
    #            continue

    #    return False

    def parse(self, nessus_json: dict = None) -> ScanResult:
        raise RuntimeError(
            f"{self.__class__.__name__} is experimental/disabled in this release: {EXPERIMENTAL_REASON}"
        )
    #    if nessus_json is None:
    #        with open(self.filepath, "r", encoding="utf-8") as f:
    #            nessus_json = json.load(f)
    #        return self._parse_json(nessus_json)

    def _parse_json(self, nessus_json: Dict[str, Any]) -> ScanResult:
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
        depth = self.get_json_depth(nessus_json)
        if depth <= 1:
            nessus_json = self.detect_and_transform_flat_json(nessus_json)
        if "scan_metadata" in nessus_json and "scan_date" in nessus_json["scan_metadata"]:
            scan_date = nessus_json["scan_metadata"].get("scan_date")

        metadata, report_data = self.normalize_structure(nessus_json)
        scan_date = metadata.get("scan_date")
        assets: Dict[str, Asset] = {}


        if isinstance(report_data, list) and report_data and any(k in report_data[0] for k in ["finding", "results"]):
            grouped_assets = self.group_findings_by_asset(report_data)
            report_data = list(grouped_assets.values())




        for report_host in report_data:
            hostname = coerce_str(self.get_key_case_ins(report_host, ["host-name", "hostname", "host_name", "host"], default="Unknown"))
            ip_address = coerce_ip(self.get_key_case_ins(report_host, ["host-ip", "ip", "ip-address", "ip_address", "host_ip", "host"], default="Unknown"))
            canonical_asset_id = make_asset_id(ip_address or "Unknown", hostname or "Unknown")

            if canonical_asset_id not in assets:
                assets[canonical_asset_id] = Asset(
                    hostname=hostname,
                    ip_address=ip_address or "Unknown",
                    criticality=None,
                    findings=[],
                    shodan_data=None, #TODO: Build this out.
                    asset_id=canonical_asset_id,
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

                # Create Finding ID
                finding_id = ""
                finding_asset_id = assets[canonical_asset_id].asset_id or canonical_asset_id

                finding = Finding(
                    finding_id=finding_id,
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
                    triage_priority=None,
                    enriched=False,
                    affected_port=affected_port,
                    protocol=protocol,
                    references=references,
                    detection_plugin=title,
                    asset_id=finding_asset_id
                )

                assets[canonical_asset_id].findings.append(finding)

            # Asset criticality is derived later in Scoring pass.

        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())
        parsed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        normalized_scan_date = scan_date
        if not normalized_scan_date or str(normalized_scan_date).startswith("SENTINEL:"):
            normalized_scan_date = parsed_at

        metadata = ScanMetaData(
            source="Nessus",
            scan_date=normalized_scan_date,
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=parsed_at
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
            self.ctx.logger.print_info("Detected flat list JSON format.")
            return self.transform_flat_list(some_json)

        elif isinstance(some_json, dict):
            if "results" in some_json and isinstance(some_json["results"], list):
                self.ctx.logger.print_info("Detected 'results' key with flat list.")
                return self.transform_flat_list(some_json["results"])

            elif "assets" in some_json:
                self.ctx.logger.print_info("Detected already normalized schema.")
                return some_json

            elif "scan" in some_json and "hosts" in some_json["scan"]:
                self.ctx.logger.print_info("Detected 'scan' top-level key with 'hosts'. Extracting hosts list.")
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
                self.ctx.logger.print_warning("Unknown dict formation - returning as-is.")
                return some_json

        else:
            self.ctx.logger.print_warning("Unrecognized JSON structure - returning as-is.")
            return some_json

    # ==========Schema detectors and normalizers=========

    def normalize_structure(self, data):
        if isinstance(data, list):
            if len(data) > 0:
                data = data[0]
            else:
                raise ValueError("Empty list provided - no data to normalize.")

        if self.is_nessus_scan_metadata(data):
            self.ctx.logger.print_info("Nessus 'scan_metadata' key detected.")
            return self.normalize_nessus_scan_metadata(data)
        elif self.is_nessus_source_scan_date(data):
            return self.normalize_nessus_source_scan_date(data)
        elif self.is_top_level_scan(data):
            return self.normalize_top_level_scan(data)
        elif self.is_assets_based(data):
            return self.normalize_assets_based(data)
        elif self.is_hosts_based(data):
            return self.normalize_hosts_based(data)
        elif self.is_results_based(data):
            return self.normalize_results_based(data)
        else:
            self.ctx.logger.print_warning(f"Unknown JSON structure: top-level keys: {list(data.keys())}")
            return {
                "source": "Unknown",
                "scan_date": None
            }, data.get("report", [])


    def is_nessus_scan_metadata(self, data):
        return isinstance(data, dict) and "scan_metadata" in data and "report" in data

    def is_nessus_source_scan_date(self, data):
        return isinstance(data, dict) and all(k in data for k in ["source", "scan_date", "report"])

    def is_top_level_scan(self, data):
        self.ctx.logger.print_info("top-levle-scan detected")
        return isinstance(data, dict) and "scan" in data and isinstance(data.get("scan", {}), dict) and "results" in data.get("scan")

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

    def normalize_top_level_scan(self, data):
        """
        Normalize Nessus JSON into a consistent format that the parse expects.
        """

        # Case - Top-Level 'scan' wrapper
        if "scan" in data:
            scan = data["scan"]
            metadata = {
                "source": "Nessus",
                "scan_date": scan.get("scan_data") or "SENTINEL:Orig_Date_NotFound",
            }
            results = scan.get("results", [])


            report_data = results
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

    def get_json_depth(self, obj, level=1):
        """Return the depth of a JSON-like structure (dict/list)."""
        if isinstance(obj, dict):
            if not obj:
                return level
            return max(self.get_json_depth(v, level + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return level
            return max(self.get_json_depth(v, level + 1) for v in obj)
        else:
            return level