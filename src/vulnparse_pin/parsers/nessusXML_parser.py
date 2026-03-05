# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
#  any later version.
# See the LICENSE file for full terms.

from datetime import datetime, timezone
from pathlib import Path
import os
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from defusedxml.ElementTree import fromstring
from iniconfig import ParseError
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id
from vulnparse_pin.parsers.base_parser import BaseParser
from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult, Asset, Finding

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

class NessusXMLParser(BaseParser):
    def __init__(self, ctx: "RunContext", filepath: str | None = None):
        super().__init__(ctx = ctx, filepath=filepath)

    @classmethod
    def detect_file(cls, filepath):
        """Detect if the file is a Nessus XML export (.nessus)"""
        if filepath.suffix in [".nessus", ".xml"]:
            try:
                # Size guardrail (Lets do >500MB)
                if os.path.getsize(filepath) > 500 * 1024 * 1024:
                    cls.ctx.logger.print_error(f"File supplied exceeds 500MB. This is a mechanism to protect against DOS. File: {filepath}")
                    return False

                # Setup Parser
                raw = Path(filepath).read_bytes()
                root = fromstring(raw)

                # Valid Nessus report must have root and at least one ReportItem to look for.
                if root.tag == "NessusClientData_v2" or root.find(".//NessusClientData_v2") is not None:
                    # Look for at least one ReportHost/ReportItem
                    has_hosts = root.find(".//ReportHost") is not None
                    has_items = root.find(".//ReportItem") is not None
                    return has_hosts and has_items
                return False
            except (OSError, ParseError):
                return False
        return False


    def parse(self) -> ScanResult:
        """Parse Nessus XML (.nessus) into a ScanResult with Assets + Findings."""
        if not self.filepath:
            raise ValueError("NessusXMLParser requires an accessible filepath.")

        # Guard
        try:
            size = os.path.getsize(self.filepath)
            if size > 500 * 1024 * 1024:
                raise ValueError(f"Refusing to parse files largers than 500MB: {self.filepath}")
        except OSError as e:
            raise ValueError(f"Failed to stat file {self.filepath}: {e}") from e

        # Safe parse xml
        raw = Path(self.filepath).read_bytes()
        try:
            root = fromstring(raw)
        except (OSError, ParseError) as e:
            raise ValueError(f"Failed to parse XML: {e}") from e

        report = root.find("Report")
        if report is None:
            report = root.find(".//Report")
        if report is None:
            raise ValueError("Nessus XML missing <Report> node.")

        scan_name = report.get("name") or "SENTINEL:ScanName_Unavailable"

        # Init
        assets: Dict[str, Asset] = {}

        # Loop through each host in the report
        for rh in report.findall("ReportHost"):
            # Gather hostname and host metadata.
            host_name = rh.get("name") or "SENTINEL:HostName_Unavailable"
            host_props = self._host_properties_map(rh.find("HostProperties"))

            ip = host_props.get("host-ip") or host_name
            os_name = self._extract_os(host_props)
            scan_date = None

            # Use HOST_END for scan_date
            if not scan_date:
                scan_date = host_props.get("HOST_END") or host_props.get("HOST_START")

            asset_key = ip or host_name
            if asset_key not in assets:
                assets[asset_key] = Asset(
                    hostname=asset_key,
                    ip_address=ip,
                    criticality=None,
                    os=os_name,
                    findings=[],
                    shodan_data=None,
                )

            # Iterate ReportItem nodes
            for item in rh.findall("ReportItem"):

                plugin_id = item.get("pluginID") or "SENTINEL:No_PluginID"
                title = (
                    item.findtext("plugin_name")
                    or item.get("pluginName")
                    or "SENTINEL:No_Title"
                ).strip()

                description = (
                    item.findtext("description")
                    or item.findtext("synopsis")
                    or "SENTINEL:No_Description"
                ).strip()
                if len(description) > 250:
                    description = description[:250] + "..."

                solution = (item.findtext("solution") or "").strip() or "SENTINEL:No_Solution"
                if len(solution) > 250:
                    solution = solution[:250] + "..."
                plugin_output = (item.findtext("plugin_output") or "").strip()

                # Summarize plugin output -> evidence
                summary, evidence = self._summarize_plugin_output(plugin_output)
                plugin_output_final = plugin_output or "SENTINEL:No_Plugin_Output"
                if len(plugin_output_final) > 250:
                    plugin_output_final = plugin_output_final[:250] + "..."
                plugin_evidence = evidence or ["SENTINEL:No_Evidence"]

                # Port/Proto
                port = self._parse_port(item.get("port"))
                protocol = item.get("protocol") or item.get("svc_name") or None

                # Severity
                severity_code = item.get("severity") or "0"
                risk_factor = (item.findtext("risk_factor") or "").strip()
                severity = self._map_severity(severity_code, risk_factor)

                # CVEs
                cves = self._extract_cves(item)

                # CVSS score + vector (v3 preferred, else v2)
                cvss_score, cvss_vector = self._extract_cvss(item)

                # Refs
                references = [
                    r.text.strip()
                    for r in item.findall("see_also")
                    if r is not None and r.text
                ]
                scanner_sig = "nessus:" + plugin_id
                kind = title
                asset_id = make_asset_id(assets[asset_key].ip_address, assets[asset_key].hostname)
                canon_fid = make_finding_base_canon(
                    asset_id=asset_id,
                    scanner_sig=scanner_sig,
                    proto=protocol,
                    port=port,
                    kind=kind
                )
                finding_id = make_finding_id(canon_fid)

                finding = Finding(
                    finding_id=finding_id,
                    vuln_id=plugin_id,
                    title=title,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector or "N/A",
                    cves=cves,
                    epss_score=None,
                    affected_port=port,
                    protocol=protocol,
                    plugin_output=plugin_output_final,
                    plugin_evidence=plugin_evidence,
                    solution=solution,
                    detection_plugin=title,
                    asset_id=asset_id,
                    references=references,
                )

                assets[asset_key].findings.append(finding)

        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())

        metadata = ScanMetaData(
        source="Nessus",
        scan_name=scan_name,
        scan_date=scan_date if scan_date else "SENTINEL:Date_Unavailable",
        source_file=str(self.filepath),
        asset_count=asset_count,
        vulnerability_count=vuln_count,
        parsed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        )

        return ScanResult(scan_metadata=metadata, assets=list(assets.values()))

    # ------------------------- Helpers ------------------------

    @staticmethod
    def _host_properties_map(host_props_elem) -> Dict[str, str]:
        """
        Flatten <HostProperties><tag name="...">value</tag> into a dict.
        Keys are kept as-is (Nessus uses mixed-case like 'HOST_END', 'host-ip').
        """
        props: Dict[str, str] = {}

        if host_props_elem is None:
            return props

        for tag in host_props_elem.findall("tag"):
            name = tag.get("name")
            if not name:
                continue
            text = (tag.text or "").strip()
            props[name] = text
        return props

    @staticmethod
    def _extract_os(props: Dict[str, str]) -> Optional[str]:
        """
        Try to derive a human-readabnle OS string from HostProperties
        Preference:
        1. cpe-0 -> "... -> Huamn OS name"
        2. operating-system
        3. os
        """

        candidates = ["cpe-0", "operating-system", "os"]
        for key in candidates:
            val = props.get(key)
            if not val:
                continue
            # Handle "cpe:/o:microsoft:windows_10 -> Microsoft Windows 10"
            if "->" in val:
                val = val.split("->", 1)[1]
            val = val.strip()
            if val:
                return val
        return None

    @staticmethod
    def _parse_port(port_str: Optional[str]) -> Optional[int]:
        if not port_str:
            return None
        try:
            return int(port_str)
        except ValueError:
            return None

    @staticmethod
    def _map_severity(severity_code: str, risk_factor: str) -> str:
        """
        Map Nessus Severity Codes (0-4) plus risk_factor into something readable.
        Prefer risk_factor text if present.
        """
        rf = (risk_factor or "").strip()
        if rf:
            return rf # 'Informational', 'Low', 'Medium', 'High', 'Critical'

        mapping = {
            "0": "Informational",
            "1": "Low",
            "2": "Medium",
            "3": "High",
            "4": "Critical",
        }
        return mapping.get(severity_code, "SENTINEL:Unknown_Severity")

    @staticmethod
    def _extract_cves(item) -> List[str]:
        cves: List[str] = [
            c.text.strip()
            for c in item.findall("cve")
            if c is not None and c.text
        ]
        return cves or ["SENTINEL:No_CVE_Listed"]

    def _extract_cvss(self, item) -> Tuple[Optional[float], Optional[str]]:
        """
        Prefer CVSS v3 if present, else fall back to v2.
        Normalize Nessus v2 vectors.
        """
        #Score candidates (v3 first)
        score: Optional[float] = None

        v3_score_text = item.findtext("cvss3_base_score") or item.findtext("cvssV3_base_score")
        v2_score_text = item.findtext("cvss_base_score")

        if v3_score_text:
            score = self._safe_float(v3_score_text)
        elif v2_score_text:
            score = self._safe_float(v2_score_text)


        # Vector candidates
        vector: Optional[str] = None
        v3_vector = (item.findtext("cvss3_vector") or "").strip()
        v2_vector_raw = (item.findtext("cvss_vector") or "").strip()

        if v3_vector:
            vector = v3_vector
        elif v2_vector_raw:
            # Strip Nessus prefix
            v2_vector_raw = v2_vector_raw.split("#", 1)[1]
            vector = v2_vector_raw

        if vector:
            vector = vector.strip()
        else:
            vector = "SENTINEL:Vector_Unavailable"

        return score, vector
