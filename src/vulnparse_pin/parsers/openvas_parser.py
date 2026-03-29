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

EXPERIMENTAL = True
EXPERIMENTAL_REASON = "Pending real-world JSON samples; parser not validated."

import re
import json
from datetime import datetime, timezone
import hashlib
from vulnparse_pin.utils.cvss_utils import is_valid_cvss_vector

from typing import Any, Counter, Dict, List, Optional, Union
from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding
from vulnparse_pin.core.id import make_asset_id
from vulnparse_pin.parsers.base_parser import BaseParser
from vulnparse_pin.utils.normalizer import coerce_float, coerce_int, coerce_list, coerce_severity, coerce_str


class OpenVASParser(BaseParser):
   def __init__(self, data: dict | None = None, filepath: str | None = None):
       super().__init__(filepath=filepath)
       self.data = data or {}

   @classmethod
   def detect_file(cls, filepath):
       """Lightweight file-level detection for OpenVAS JSON."""
       return False
    #    if filepath.suffix == ".json":
    #        try:
    #            with open(filepath, "r", encoding='utf-8') as f:
    #                head = f.read(5000)

    #            # Candidate fields
    #            possible_fields = [
    #                '"results"',
    #                '"scan_start"',
    #                '"scan_end"',
    #                '"host"',
    #                '"port"',
    #                '"severity"',
    #                '"name"',
    #                '"nvt"',
    #                '"oid"',
    #            ]

    #            # Count Matches
    #            matches = sum(1 for field in possible_fields if field in head)

    #            # Require at least 3 hit to be confident
    #            return matches >=3

    #        except Exception:
    #            return False
    #    else:
    #        return False


   def detect(self, data):
       return False
    #    detection_patterns = [
    #        # Pattern 1: Check for top-level 'report' key with 'results' list with nested dictionaries
    #        lambda d: "report" in d and isinstance(d["report"].get("results"), list),

    #        # Pattern 2: Check for flat openvas schema. 'scan_id' and 'vulns'[] key
    #        lambda d: isinstance(d, dict) and self.get_key_cins(d, ["scan_id", "vulns"]),

    #        # Pattern 3: Check for flat 'results' key with list of findings.
    #        lambda d: "results" in d and any(
    #            isinstance(item, dict) and (
    #                "cvss_base_vector" in item or
    #                "oid" in item or
    #                "affected_hosts" in item
    #            ) for item in d.get("results", [])
    #        ),

    #        # Pattern 4: Check for Report object with all data in a "results" dictionary nested in a "result" list of dictionaries. GVM CLI Export format
    #        lambda d: "report" in d and isinstance(d["report"].get("results", {}).get("result", []), list),

    #        # Pattern 5: Check for flat list of data with 'nvt' key.
    #        lambda d: isinstance(d, list) and "nvt" in d[0],

    #        # Pattern 6: GSA Web UI Export format
    #        lambda d: "results" in d and "nvt" in d["results"][0],

    #        # Pattern 7: OMP API Export format
    #        lambda d: "scan" in d and ("results" in d["scan"] and isinstance(d["scan"]["results"], list))
    #    ]

    #    for pattern in detection_patterns:
    #        try:
    #            if pattern(data):
    #                return True
    #        except Exception as e:
    #            self.ctx.logger.print_error(f"Pattern check failed: {e}")
    #            continue

    #    return False

   def parse(self, openvasdata: Dict = None) -> ScanResult:
       raise RuntimeError(
           f"{self.__name__} is experimental/disabled in this release: {EXPERIMENTAL_REASON}"
       )
    #    if openvasdata is None:
    #        with open(self.filepath, 'r', encoding='utf-8') as f:
    #            openvasdata = json.load(f)
    #        return self._parse_json(openvasdata)


   def _parse_json(self, openvasdata: Dict[str, Any]) -> ScanResult:
       '''
       Parse a OpenVAS JSON vulnerability scan report into structured Python objects.

       Args:
           data (Dict[str, Any]): The JSON OpenVAS scan report.

       Returns:
           ScanResult: An object containing structured scan metadata, assets, and vulnerability findings.
       '''
       # Check if it's flat json. if not, continue.
       metadata, report_data = self.normalize_structure(openvasdata)

       metadata_time = metadata

       assets: Dict[str, Asset] = {}


       for item in report_data["results"]:
           hostname = coerce_str(self.get_key_cins(item, ["host", "hostname", "host-name", "host_name"]), default="unknown_host")
           ip_address = coerce_str(self.get_key_cins(item, ["ip", "host-ip", "ip-address", "ip_address", "host_ip"], default="N/A"))
           canonical_asset_id = make_asset_id(ip_address or "N/A", hostname or "unknown_host")

           if canonical_asset_id not in assets:
               assets[canonical_asset_id] = Asset(
                   hostname=hostname,
                   ip_address=ip_address,
                   criticality=None,
                   findings=[],
                   shodan_data=None,
                   asset_id=canonical_asset_id,
               )


           tags = self.get_key_cins(item.get("nvt", {}), ["tags"], default="Not Available")


           vuln_id = self.get_vuln_id(item)

           title = coerce_str(self.get_key_cins(item.get("nvt", {}), ["name", "title"]) or self.get_key_cins(item, ["name", "title"]), default="N/A")
           description = coerce_str(self.get_key_cins(item, ["description"]) or self.get_key_cins(item.get("nvt", {}), ["description"]))
           if description in ["null", "", "N/A"] or None:
               description = "No description available"
           severity = coerce_severity(self.get_key_cins(item, ["threat", "severity"], default="unknown"))
           cves_raw = self.convert_cves_str_list(self.get_key_cins(item.get("nvt", {}), ["cve", "cves"]) or self.get_key_cins(item, ["cve", "cves"], default=[]))
           cves_raw = list(set(cves_raw))

           cvss_score = None # Initialize cvss_score

           if tags:
               cvss_score = self.parse_cvss_score(tags)

           if not isinstance(cvss_score, (int, float)) or cvss_score == 0.0:
               fallback_cvss = self.get_key_cins(item.get("nvt", {}), ["cvss_base", "cvss", "cvss_score", "cvss_base_score"], default=0.0)
               cvss_score = coerce_float(fallback_cvss, default=0.0)

           cvss_vector = coerce_str(self.get_key_cins(item.get("nvt", {}), ["cvss_base_vector", "cvss_vector"], default="N/A"))
           if not is_valid_cvss_vector(cvss_vector):
               cvss_vector = "Unknown"
           references_raw = coerce_str(self.get_key_cins(item.get("nvt", {}), ["tags", "references"], default=""))
           references_list = coerce_list([ref.strip() for ref in references_raw.split(";")] if references_raw else [])
           affected_port_raw = coerce_str(self.get_key_cins(item, ["port"], default="unknown_port"))
           affected_port = affected_port_raw
           if affected_port != "unknown_port":
               affected_port = coerce_int(affected_port_raw.split("/")[0])
           solution = coerce_str(self.get_key_cins(item, ["solution"], default="N/A"))
           protocol = coerce_str(self.get_key_cins(item, ["port"], default="unknown"))
           if protocol != "unknown" and protocol is not isinstance(protocol, int):
               parts = protocol.split("/")
               if len(parts) > 1:
                   protocol = parts[1]
               else:
                   protocol = "unknown"

           exploit_indicators = ["exploit", "metasploit", "public exploit", "poc available", "poc"]
           search_text = f"{solution or ''} {description or ''}".lower()
           exploit_available = any(indicator in search_text for indicator in exploit_indicators)

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
               cves=cves_raw,
               cvss_score=cvss_score or 0.0,
               cvss_vector=cvss_vector,
               epss_score=0.0,
               cisa_kev=False,
               exploit_available=exploit_available,
               triage_priority=None,
               enriched=False,
               affected_port=affected_port,
               protocol=protocol,
               references=references_list,
               detection_plugin=title,
               asset_id=finding_asset_id
           )

           assets[canonical_asset_id].findings.append(finding)

       # Asset criticality is derived later in Scoring pass.

       asset_count = len(assets)
       vuln_count = sum(len(asset.findings) for asset in assets.values())
       parsed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
       normalized_scan_date = metadata_time
       if not normalized_scan_date or str(normalized_scan_date).startswith("SENTINEL:"):
           normalized_scan_date = parsed_at

       metadata_final = ScanMetaData(
           source="OpenVAS",
           scan_date=normalized_scan_date,
           asset_count=asset_count,
           vulnerability_count=vuln_count,
           parsed_at=parsed_at
       )

       result = ScanResult(
           scan_metadata=metadata_final,
           assets=list(assets.values())
       )
       return result

   def get_key_cins(self, data: Dict[str, Any], possible_keys: List[str], default: Optional[Any] = None) -> Any:
       for key in possible_keys:
           for actual_key in data.keys():
               if actual_key.lower() == key.lower():
                   return data[actual_key]
       return default

   def detect_and_transform_flat_json(self, data: Dict[str, Any]):
       if isinstance(data, dict) and self.get_key_cins(data, ["scan_id", "vulns"]):
           self.ctx.logger.print_info("Detected OpenVas flat JSON format w/ 'vulns' list of hosts")
           # Transform flat JSON into standard structure.
           results = []
           hosts = data.get("vulns")
           if hosts:
               for host in hosts:
                   # Normalize some fields first before building assets and findings.
                   severity = host.get("severity", "N/A")
                   if str(severity).isdigit():
                       severity = self.convert_sev_num(severity)
                   cves = self.get_key_cins(host, ["cves", "cve"], default="")
                   if cves:
                       cves = self.convert_cves_str_list(cves)
                   port = host.get("port", "N/A")

                   result_item = {
                       "host": self.get_key_cins(host, ["host", "hostname", "host-id", "host_name", "host-name"], default="N/A"),
                       "ip": self.get_key_cins(host, ["ip", "ip_address", "host-ip", "ip-address", "host"], default="N/A"),
                       "port": port,
                       "description": self.get_key_cins(host, ["description"], default="N/A"),
                       "severity": severity,
                       "threat": self.get_key_cins(host, ["threat", "severity"], default="N/A"),
                       "solution": self.get_key_cins(host, ["solution"], default="N/A"),
                       "nvt": {
                           "cve": cves,
                           "cvss_base_vector": self.get_key_cins(host, ["cvss_base_vector"], default=""),
                           "name": self.get_key_cins(host, ["name"], default="N/A"),
                           "cvss_base": self.get_key_cins(host, ["cvss_base", "cvss_base_score", "cvss"], default="N/A"),
                           "tags": self.get_key_cins(host, ["tags", "references"], default="N/A")
                       }
                   }
                   results.append(result_item)

               if not isinstance(results, list):
                   raise ValueError("[FlatJSONTransform] Transformation failed, var: 'results' is not a list.")
               return {
                   "report": {
                       "scan_start": data.get("scan_start", "N/A"),
                       "scan_end": data.get("scan_end", "N/A"),
                       "results": results
                   }
               }
           else:
               self.ctx.logger.print_error("vulns list is empty. Unable to transform schema.")

       elif (
           isinstance(data, dict)
           and "results" in data
           and isinstance(data["results"], list)
           and all(
               isinstance(entry, dict)
               and not isinstance(entry.get("nvt"), dict)
               and "host" in entry
               and "port" in entry
               and "plugin_name" in entry
               for entry in data["results"][:5]
           )
       ):
           self.ctx.logger.print_info(f"Detected OpenVAS JSON with flat results list")

           results = []
           hosts = data.get("results", [])

           if hosts:
               for host in hosts:
                   # Normalize what's possible with info given.
                   severity = host.get("severity", "N/A")
                   if str(severity).isdigit():
                       severity = self.convert_sev_num(severity)
                   cves = self.get_key_cins(host, ["cves", "cve"], default=[])
                   if not cves:
                       nested_cve = self.detect_nested_key(host, "cve")
                       if nested_cve:
                           try:
                               cves = nested_cve.get("cve", [])
                           except Exception as e:
                               self.ctx.logger.exception(f"Exception: {e}")
                   if cves is not None and cves != "":
                       cves = self.convert_cves_str_list(cves)
                   else:
                       cves = []
                   port = host.get("port", "N/A")
                   # Building finding_item

                   result_item = {
                       "host": self.get_key_cins(host, ["host", "hostname", "host-id", "host_name", "host-name"], default="N/A"),
                       "ip": self.get_key_cins(host, ["ip", "ip_address", "host-ip", "ip-address", "host"], default="N/A"),
                       "port": port,
                       "description": self.get_key_cins(host, ["description"], default="N/A"),
                       "severity": severity,
                       "threat": self.get_key_cins(host, ["threat", "severity"], default="N/A"),
                       "solution": self.get_key_cins(host, ["solution"], default="N/A"),
                       "nvt": {
                           "cve": cves,
                           "cvss_base_vector": self.get_key_cins(host, ["cvss_base_vector"], default=""),
                           "name": self.get_key_cins(host, ["name"], default="N/A"),
                           "cvss_base": self.get_key_cins(host, ["cvss_base", "cvss_base_score", "cvss"], default="N/A"),
                           "tags": self.get_key_cins(host, ["tags", "references"], default="N/A")
                       }
                   }
                   results.append(result_item)

               if not isinstance(results, list):
                   raise ValueError("[FlatJSONTransform] Transformation failed, var: 'results' is not a list.")
               return {
                   "report": {
                       "scan_start": data.get("scan_start", "N/A"),
                       "scan_end": data.get("scan_end", "N/A"),
                       "results": results
                   }
               }
       # If Flat list with nvt key
       elif isinstance(data, list) and "nvt" in data[0]:
           self.ctx.logger.print_info(f"Detected flat list with 'nvt' key.")

           results = []

           for host in data:
               if not isinstance(host, dict):
                   continue
               # Loop through each 'finding' entry in the flat list

               severity = host.get("severity", "N/A")
               if str(severity).isdigit():
                   severity = self.convert_sev_num(severity)

               result_item = {
                   "host": self.get_key_cins(host, ["host", "hostname", "host-id", "host_name", "host-name"], default="N/A"),
                   "ip": self.get_key_cins(host, ["ip", "ip_address", "host-ip", "ip-address"], default="N/A"),
                   "port": host.get("port", "N/A"),
                   "description": self.get_key_cins(host, ["description"], default="N/A"),
                   "severity": severity,
                   "nvt": self.parse_nvt(host.get("nvt", {}))
               }
               results.append(result_item)

           if not isinstance(results, list):
               raise ValueError("[FlatJSONTransform] Transformation failed, var: 'results' is not a list.")
           return {
               "report": {
                   "scan_start": data[0].get("scan_start", "N/A") if isinstance(data[0], dict) else "N/A",
                   "scan_end": data[0].get("scan_end", "N/A") if isinstance(data[0], dict) else "N/A",
                   "results": results,
                   "schema_version": "native_flat_list"
               }
           }

       elif (isinstance(data, dict)
             and "results" in data
             and isinstance(data["results"], list)
             and all (
                 isinstance(entry, dict)
                 and any(k in entry for k in ("name", "description", "cve", "cvss_base_vector")) for entry in data["results"][:5]
             )
       ):
           self.ctx.logger.print_info("Detected simplified OpenVAS flat JSON (name/desc/cve/cvss format).")

           results = []
           for entry in data["results"]:
               cves = self.get_key_cins(entry, ["cves", "cve"], default=[])
               if not cves:
                   nested_cve = self.detect_nested_key(entry, "cve")
                   if nested_cve:
                       try:
                           cves = nested_cve.get("cve", [])
                       except Exception as e:
                           self.ctx.logger.exception(f"Exception while extraction nested CVE: {e}")
               cves = self.convert_cves_str_list(cves) if cves else []

               result_item = {
                   "host": self.get_key_cins(entry, ["host", "hostname", "ip"], default="N/A"),
                   "ip": self.get_key_cins(entry, ["ip", "ip_address"], default="N/A"),
                   "port": self.get_key_cins(entry, ["port"], default="N/A"),
                   "description": self.get_key_cins(entry, ["description"], default="N/A"),
                   "severity": entry.get("severity", "N/A"),
                   "nvt": {
                       "cve": cves,
                       "cvss_base_vector": self.get_key_cins(entry, ["cvss_base_vector"], default=""),
                       "name": self.get_key_cins(entry, ["name"], default="N/A"),
                       "cvss_base": self.get_key_cins(entry, ["cvss_base", "cvss_base_score"], default="N/A"),
                       "tags": self.get_key_cins(entry, ["tags", "references"], default="N/A")
                   }
               }
               results.append(result_item)

           return {
               "report": {
               "scan_start": data.get("scan_start", "N/A"),
               "scan_end": data.get("scan_end", "N/A"),
               "results": results,
               "schema_version": "simplified_flat"
               }
           }


       else:
           self.ctx.logger.print_warning("Unknown dict formation - returning as-is.")
           return data

   # Big Normalizer

   def normalize_structure(self, data):
       if isinstance(data, list):
           if len(data) > 0:
               data = data[0]
           else:
               raise ValueError("Empty list provided - no data to normalize")

       elif self.is_openvas_standard(data):
           return self.normalize_openvas_standard(data)

       elif self.is_flat_openvas(data):
           # For already transformed flat JSON by detect_and_transform_flat_json
           transformed = self.detect_and_transform_flat_json(data)
           return self.normalize_openvas_standard(transformed)

       elif self.is_flat_results_openvas(data):
           transformed = self.detect_and_transform_flat_json(data)
           return self.normalize_openvas_standard(transformed)

       elif self.is_gvm_cli_format(data):
           return self.normalize_gvm_cli_format(data)

       elif self.is_flat_list_nvt(data):
           transformed = detect_and_transform_flat_json(data)
           return self.normalize_openvas_standard(transformed)

       elif self.is_gsa_web_ui_format(data):
           transformed = self.normalize_gsa_web_ui_format(data)
           return self.normalize_openvas_standard(transformed)

       elif self.is_omp_api_format(data):
           transformed = self.normalize_omp_api_format(data)
           return self.normalize_openvas_standard(transformed)

       else:
           raise ValueError("Unknown or unsupported OpenVAS data structure for normalization.")

   # -----------------------------------------------------------------------------------

   # Schema Detectors
   def is_openvas_standard(self, data) -> bool:
       return isinstance(data, dict) and "report" in data and isinstance(data["report"].get("results"), list)

   def is_flat_openvas(self, data) -> bool:
       """
       Detects a CLI-style flat OpenVAS structure where 'scan_id' and 'vulns' are present, and there are no nested result structures (e.g., no 'nvt' dicts)
       """
       return (
           isinstance(data, dict)
           and "scan_id" in data
           and "vulns" in data
           and isinstance(data["vulns"], list)
           and all(
               isinstance(v, dict)
               and (
                   "plugin_name" in v
                   or "name" in v
                   )
               and not isinstance(v.get("nvt"), dict)
               for v in data["vulns"][:5]
           )
       )

   def is_flat_results_openvas(self, data) -> bool:
       if not (isinstance(data, dict) and "results" in data and isinstance(data["results"], list)):
           return False

       sample_entries = data["results"][:5]
       if not sample_entries:
           return False

       # Case 1: Traditional flat structure with host/port/plugin_name
       flat_with_host = all(
           isinstance(entry, dict)
           and "host" in entry
           and "port" in entry
           and "plugin_name" in entry
           for entry in sample_entries
       )
       if flat_with_host:
           return True

       # Case 2: simplified flat structure (has at least name/description or cve/cvss)
       flat_simplified = all(
           isinstance(entry, dict)
           and any(k in entry for k in ("name", "description", "cve", "cvss_base_vector")) for entry in sample_entries
       )
       if flat_simplified:
           return True

       return False

   def is_gvm_cli_format(self, data) -> bool:
       return "report" in data and isinstance(data["report"].get("results", {}).get("result", []), list)

   def is_flat_list_nvt(self, data) -> bool:
       return isinstance(data, list) and "nvt" in data[0]

   def is_gsa_web_ui_format(self, data) -> bool:
       if not isinstance(data, dict):
           return False

       if "results" in data and isinstance(data["results"], list):
           for result in data["results"]:
               if isinstance(result, dict):
                   if "nvt" in result and isinstance(result["nvt"], dict):
                       if "tags" in result["nvt"] and "name" in result["nvt"]:
                           print("gsa DETECTED")
                           return True

       return False

   def is_omp_api_format(self, data) -> bool:
       return "scan" in data and ("results" in data["scan"] and isinstance(data["scan"]["results"], list))

   # -------------------------------------------------------------------------------

   # Normalizers
   def normalize_openvas_standard(self, data):
       report = data["report"]
       scan_start = data["report"].get("scan_start", "N/A")
       scan_end = data["report"].get("scan_end", "N/A")
       metadata = (scan_start, scan_end)

       return metadata[0], report

   def normalize_gvm_cli_format(self, data):
       report = data["report"]
       scan_start = data["report"].get("scan_start", "N/A")
       scan_end = data["report"].get("scan_end", "N/A")
       metadata = (scan_start, scan_end)

       return metadata[0], report

   def normalize_gsa_web_ui_format(self, data):
       results = []

       scan_start = "N/A"
       scan_end = "N/A"

       metadata = (scan_start, scan_end)

       hosts = data.get("results", [])

       for host in hosts:
           if not isinstance(host, dict):
               self.ctx.logger.warning(f"[Normalizer_GSA_WEB_UI] Host entry is not a dictionary... Skipping")
               continue

           severity = host.get("severity", "N/A")
           if str(severity).isdigit():
               severity = self.convert_sev_num(severity)

           result_item = {
               "host": self.get_key_cins(host, ["host", "hostname", "host-id", "host_name", "host-name"], default="N/A"),
               "ip": self.get_key_cins(host, ["ip", "ip_address", "host-ip", "ip-address"], default="N/A"),
               "port": host.get("port", "N/A"),
               "description": self.get_key_cins(host, ["description"], default="N/A"),
               "severity": severity,
               "nvt": self.parse_nvt(host.get("nvt", {}))
           }
           results.append(result_item)

       report = {
           "report": {
               "scan_start": scan_start,
               "scan_end": scan_end,
               "results": results,
               "schema_version": "gsa_web_ui"
           }
       }

       return report


   def normalize_omp_api_format(self, data):
       scan_start = data.get("scan", {}).get("info", {}).get("start_time", "N/A")
       scan_end = data.get("scan", {}).get("info", {}).get("end_time", "N/A")

       results = []

       hosts = data.get("scan", {}).get("results", [])

       if isinstance(hosts, dict):
           hosts = [hosts]

       elif not isinstance(hosts, list):
           self.ctx.logger.warning("[OMPNormalizer] Malformed results structure. Skipping...")
           return {
               "report": {
                   "scan_start": scan_start,
                   "scan_end": scan_end,
                   "results": [],
                   "schema_version": "omp_api"
               }
           }

       for host in hosts:
           severity = host.get("severity", "N/A")
           if str(severity).isdigit():
               severity = self.convert_sev_num(severity)

           result_item = {
               "host": self.get_key_cins(host, ["host", "hostname", "host-id", "host_name", "host-name"], default="N/A"),
               "ip": self.get_key_cins(host, ["ip", "ip_address", "host-ip", "ip-address"], default="N/A"),
               "port": host.get("port", "N/A"),
               "description": self.get_key_cins(host, ["description"], default="N/A"),
               "severity": severity,
               "nvt": self.parse_nvt(host.get("nvt", {}))
           }
           results.append(result_item)

       report = {
           "report": {
               "scan_start": scan_start,
               "scan_end": scan_end,
               "results": results,
               "schema_version": "omp"
           }
       }

       return report



   # -------------------------------------------------------------------------------------

   # Helper Functions

   def determine_asset_criticality(self, severity_counter: Counter) -> str:
       crit_count: int = severity_counter["Critical"]
       high_count: int = severity_counter["High"]

       if crit_count >= 3:
           return "Extreme"
       elif crit_count >= 1 or high_count >= 2:
           return "High"
       elif high_count == 1:
           return "Medium"
       else:
           return "Low"

   def parse_cvss_score(self, tags: Union[str, List[str], None]) -> float:
       '''
       Parses cvss_base_score from OpenVAS tags.

       Args:
           tags: Either a semicolon-delimited string, list of strings, or none.

       Returns:
           CVSS Base score as a float. Defaults to 0.0 if parsing fails or not found.
       '''
       if not tags:
           return 0.0

       # If it's a string, split into a list by semicolon.
       if isinstance(tags, str):
           pairs = tags.split(";")
       elif isinstance(tags, list):
           pairs = tags
       else:
           self.ctx.logger.print_warning(f"[parse_cvss_score] Unexpected type for tags: {type(tags)}")
           return 0.0


       for pair in pairs:
           if not isinstance(pair, str):
               continue


           if pair.startswith("cvss_base_score="):
               _, val = pair.split('=', 1)
               try:
                   return float(val)
               except ValueError:
                   self.ctx.logger.print_error(f"[parse_cvss_score] Value Error occured while converting {val}")
                   self.ctx.logger.exception("ValueError Exception")
                   return 0.0

       return 0.0

   def convert_sev_num(self, value):
       value = float(value)

       if value >= 8.5:
           return "Critical"
       elif value >= 6.5:
           return "High"
       elif value >= 5.0:
           return "Medium"
       else:
           return "Low"

   def convert_cves_str_list(self, cvestype):
       if isinstance(cvestype, str):
           cvestype = coerce_list([c.strip() for c in re.split(r'[;|,]', cvestype) if cvestype.strip()])
           return cvestype
       elif isinstance(cvestype, list):
           return list(cvestype)
       else:
           return []

   def get_vuln_id(self, item):
       nvt_key = item.get("nvt", {})

       try:
           vuln_id = nvt_key.get("cve") or nvt_key.get("oid") or item.get("cve") or item.get("cves")
           if isinstance(vuln_id, list):
               return vuln_id[0]
           elif isinstance(vuln_id, str) and vuln_id.strip():
               return [c.strip() for c in vuln_id.split(",") if c.strip()][0]
       except (ValueError, IndexError, KeyError, TypeError) as e:
           self.ctx.logger.print_error(f"Error when retrieving vuln_id: {e}.")

       host = item.get("host", "unknown_host")
       port = item.get("port", "unknown_port")
       title = nvt_key.get("name", "unknown_title")

       data_to_hash = f"{host}:{port}:{title}"

       self.ctx.logger.print_info(f"No vuln_id found - generating fallback hash for {host}:{port}:{title}")

       hashed_fb = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()[:12]

       return f"unknown_{hashed_fb}"

   def detect_nested_key(self, data: Any, target_key: str) -> Any:
       '''
       Recursively check if a nested key exists anywhere in dictionary.

       Args:
           data: The dict to search
           target_key: The key to look for.

       Returns:
           Value associated with the target_key if found, else None.
       '''
       if isinstance(data, dict):

           for key, value in data.items():
               if key == target_key:
                   self.ctx.logger.debug(f"[detect_nested_key]Nested Key: {target_key} Found")
                   return data
               result = self.detect_nested_key(value, target_key)
               if result:
                   return result

       elif isinstance(data, list):
           for item in data:
               result = self.detect_nested_key(item, target_key)
               if result:
                   return result

       return None

   def parse_nvt(self, nvt_dict: dict) -> dict:

       cve_raw = self.get_key_cins(nvt_dict, ["cve", "cves"], default=None)
       cvss_vector = self.get_key_cins(nvt_dict, ["cvss_base_vector", "cvss_vector"], default=None)
       cvss_base = self.get_key_cins(nvt_dict, ["cvss_base", "cvss_base_score", "cvss_score"], default="N/A")
       tags = self.get_key_cins(nvt_dict, ["tags", "tag"], default="N/A")
       name = self.get_key_cins(nvt_dict, ["title", "name"], default="N/A")

       # Parse
       if (not cve_raw or cve_raw in ["N/A", ""]):
           cve_raw = self.extract_tag_value(tags, "cve")

       if (not cvss_vector or cvss_vector in ["N/A", ""]):
           cvss_vector = self.extract_tag_value(tags, f"cvss_base_vector")

       return {
       "name": name,
       "cvss_base": cvss_base,
       "cvss_vector": cvss_vector,
       "cve": cve_raw,
       "tags": tags
       }

   def extract_tag_value(self, tag_string: str, key: str) -> str:
       if not tag_string:
           return "N/A"

       for tag in tag_string.split(';'):
           if "=" in tag:
               k, v = tag.strip().split("=", 1)
               if k.strip().lower() == key.lower():
                   return v.strip()
       return "N/A"
