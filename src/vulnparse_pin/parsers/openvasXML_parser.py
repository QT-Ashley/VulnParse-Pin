# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations
from pathlib import Path

from datetime import datetime, timezone
import os
import re
from typing import Dict, Optional, TYPE_CHECKING
from defusedxml.ElementTree import fromstring
from vulnparse_pin.parsers.base_parser import BaseParser
from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id
if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

class OpenVASXMLParser(BaseParser):
    NAME = "openvas-xml"

    def __init__(self, ctx: "RunContext", filepath: str | None = None):
        super().__init__(ctx = ctx, filepath=filepath)

    @classmethod
    def detect_file(cls, filepath) -> tuple[float, list[tuple[str, str]]]:
        """
        Detect if the file is an OpenVAS/GVM XML export.

        Returns (confidence, evidence_pairs) where confidence is in [0.0, 1.0].
        Signals are additive; sum is capped at 1.0.
        Hard negative gate: any NessusClientData_v2 presence → 0.0.
        Signals:
          known GVM root tag               :  +0.20
          results//result structure        :  +0.30
          nvt element present              :  +0.25
          OID attribute on first nvt       :  +0.10  (dotted-numeric GVM OID)
          creation_time element present    :  +0.05
          host elements present            :  +0.05
        """
        evidence: list[tuple[str, str]] = []

        if filepath.suffix != ".xml":
            return 0.0, [("extension", f"rejected:{filepath.suffix}")]

        try:
            if os.path.getsize(filepath) > 500 * 1024 * 1024:
                return 0.0, [("size", "exceeds_500MB")]
            raw = Path(filepath).read_bytes()
            root = fromstring(raw)
        except (OSError, ValueError, Exception):
            return 0.0, [("parse", "failed")]

        # Hard negative: reject any Nessus file immediately
        if root.tag == "NessusClientData_v2" or root.find(".//NessusClientData_v2") is not None:
            return 0.0, [("rejected", "NessusClientData_v2_found")]

        score = 0.0

        # Root tag signal — known GVM/OpenVAS root element names
        _GVM_ROOT_TAGS = frozenset({"report", "get_reports_response", "omp", "get_results_response"})
        if root.tag in _GVM_ROOT_TAGS:
            score += 0.20
            evidence.append(("root_tag", root.tag))

        # Core structural signal: result nodes under results hierarchy
        result_node = root.find(".//report//results//result") or root.find(".//results//result")
        if result_node is not None:
            score += 0.30
            evidence.append(("structure", "results//result"))

        # NVT presence — GVM-specific concept, not present in other scanners
        first_nvt = root.find(".//nvt")
        if first_nvt is not None:
            score += 0.25
            evidence.append(("structure", "nvt"))

            # OID attribute on nvt element: dotted-numeric GVM plugin identifier
            oid = first_nvt.get("oid", "")
            if oid and re.match(r'^\d+(\.\d+)+$', oid):
                score += 0.10
                evidence.append(("nvt_oid", oid[:40]))

        # creation_time is present on all well-formed GVM reports
        if root.findtext(".//creation_time"):
            score += 0.05
            evidence.append(("meta", "creation_time"))

        # host elements confirm actual scan result data is present
        host_count = len(root.findall(".//host"))
        if host_count > 0:
            score += 0.05
            evidence.append(("structure", f"host_count={host_count}"))

        return min(score, 1.0), evidence

    def parse(self) -> ScanResult:
        """Parse OpenVAS XML into ScanResult object with Assets + Findings."""
        if not self.filepath:
            raise ValueError("OpenVASXMLParser requires an accessible filepath.")

        # Guard
        try:
            size = os.path.getsize(self.filepath)
            if size > 500 * 1024 * 1024:
                raise ValueError(f"Refusing to parse files largers than 500MB: {self.filepath}")
        except OSError as e:
            raise ValueError(f"Failed to stat file {self.filepath}: {e}") from e

        # Parse XML securely.
        raw = Path(self.filepath).read_bytes()
        try:
            root = fromstring(raw)
        except (OSError, ValueError) as e:
            raise ValueError(f"Failed to parse XML: {e}") from e


        assets: Dict[str, Asset] = {}
        dropped = 0

        scan_date = root.findtext(".//creation_time") or "SENTINEL:Date_Unavailable"
        scan_name = root.attrib.get("id") or "SENTINEL:Not_Found"

        # Start Parsing
        for result in root.findall(".//result"):
            raw_host = result.findtext("host")
            if not raw_host or not raw_host.strip():
                self.ctx.logger.warning("Dropping Openvas result with no host entry — malformed or incomplete XML <result> block.")
                dropped += 1
                continue
            host = raw_host.strip()
            port = self._safe_int(self._parse_port(result.findtext("port")))
            protocol = self._safe_text(self._parse_protocol(result.findtext("port")))
            description = self._safe_text(result.findtext("description")) or "SENTINEL:No_Description"
            severity = self._safe_text(result.findtext("threat"))

            # Collect NVT Field
            nvt_field = result.find("nvt")
            cvss_score = None
            cvss_vector = None
            cves = []
            if nvt_field is not None:
                tags = nvt_field.findtext("tags") or ""
                if tags is None:
                    self.ctx.logger.debug("[OpenVASXML] Tags field is empty. %s", tags)
                title = nvt_field.findtext("name")
                cvss_score, cvss_vector = self._extract_cvss(nvt_field, result)
                if not cvss_vector:
                    cvss_vector = "SENTINEL:Vector_Unavailable"
                solution = self._safe_text(nvt_field.findtext("solution"))
                # Plugin_Output
                plugin_output = self._extract_from_tags(tags, "summary=")
                # Grab CVEs
                cves = self._extract_cves(nvt_field, result)
            else:
                tags = ""
                title = "SENTINEL:No_Title_Found"
                cvss_vector = "SENTINEL:Vector_Unavailable"
                cvss_score = 0.0
                solution = "SENTINEL:No_Solution_Found"
                plugin_output = "SENINTEL:No_Plugin_Output_Found"
                cves = ["SENTINEL:No_CVE_Listed"]

            # Build out evidence values and other potentially valuable information
            detection = result.find("detection")

            evidence = []
            if detection is not None:
                for detail in detection.findall(".//detail"):
                    name = detail.findtext("name") or "Unknown"
                    value = detail.findtext("value") or "N/A"
                    evidence.append(f"{name}: {value}")

            _, summarized_evidence = self._summarize_plugin_output(plugin_output)
            if not evidence:
                evidence = summarized_evidence

            # Now time for Asset Creation
            if host not in assets:
                generated_asset_id = make_asset_id(host, host)
                assets[host] = Asset(
                    hostname=host,
                    ip_address=host,
                    criticality=None,
                    os=None,
                    findings=[],
                    shodan_data=None,
                    asset_id=generated_asset_id,
                )

            # Create Unique Finding_ID
            scanner_sig = "openvas:" + nvt_field.attrib.get("oid") if nvt_field is not None else "No_SigID"
            kind = title
            asset_obj = assets[host]
            asset_id = asset_obj.asset_id or make_asset_id(asset_obj.ip_address, asset_obj.hostname)
            canon_fid = make_finding_base_canon(
                asset_id=asset_id,
                scanner_sig=scanner_sig,
                proto=protocol,
                port=port,
                kind=kind
            )
            finding_id = make_finding_id(canon_fid)

            # Build Finding
            finding = Finding(
                finding_id=finding_id,
                vuln_id=nvt_field.attrib.get("oid") if nvt_field is not None else "SENTINEL:No_OID",
                title=title or "SENTINEL:No_Title",
                description=description,
                severity=severity,
                cves=cves,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                epss_score=None,
                affected_port=port,
                protocol=protocol,
                plugin_output=plugin_output or "SENTINEL:No_Plugin_Output",
                plugin_evidence=summarized_evidence or evidence or "SENTINEL:No_Evidence",
                solution=solution or "SENTINEL:No_Solution",
                detection_plugin=title or "SENTINEL:No_Detection_Plugin",
                asset_id=asset_id,
            )
            assets[host].findings.append(finding)

        # Check Droppped findings and log.
        if dropped:
            self.ctx.logger.debug("Dropped '%s' malformed OpenVAS result(s) with no host.", dropped)

        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())
        parsed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        normalized_scan_date = scan_date
        if not normalized_scan_date or str(normalized_scan_date).startswith("SENTINEL:"):
            normalized_scan_date = parsed_at

        # Build Metadata
        metadata = ScanMetaData(
            source="OpenVAS",
            scan_name=scan_name,
            scan_date=normalized_scan_date,
            source_file=str(self.filepath),
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=parsed_at,
        )

        return ScanResult(scan_metadata=metadata, assets=list(assets.values()))

    def _extract_cves(self, nvt_elem, result_elem):
        cves = []

        # Primary Method
        if nvt_elem is not None:
            for ref in nvt_elem.findall(".//refs/ref[@type='cve']"):
                raw = (ref.get("id") or (ref.text or "")).strip()
                if raw:
                    cves.append(raw)

        # CVEs in tags/reference fallback
        tags_text = []

        if nvt_elem is not None:
            tags_text.append(self._safe_text(nvt_elem.findtext("tags")))
            tags_text.append(self._safe_text(nvt_elem.findtext("description")))

        # Catch all for diff schemas
        tags_text.append(self._safe_text(result_elem.findtext("tags")))
        tags_text.append(self._safe_text(result_elem.findtext("description")))

        joined = " ".join(t for t in tags_text if t)
        if joined:
            for match in re.findall(rf"CVE-\d{4}-\d{4,7}", joined):
                cves.append(match)

        # Dedup & keep order
        seen = set(); out = []
        for cv in cves:
            if cv and cv not in seen:
                seen.add(cv); out.append(cv)
        return out or ["SENTINEL:No_CVE_Listed"]

    def _extract_cvss(self, nvt_elem, result_elem):
        """
        Prefer CVSS v3 if present, else fall back to v2.
        Accept score/vector from either <nvt> or <result>.
        """
        # Score Candidates
        score_candidates = [
            nvt_elem.findtext("cvss3_base") if nvt_elem is not None else None,
            nvt_elem.findtext("cvss_base") if nvt_elem is not None else None,
            result_elem.findtext("cvss3_base"),
            result_elem.findtext("cvss_base"),
            nvt_elem.findtext("cvss_base_score") if nvt_elem is not None else None,
            result_elem.findtext("cvss_base_score"),
        ]
        score = next((self._safe_float(s) for s in score_candidates if s), None)

        # Vector Candidates
        vector_candidates = [
            nvt_elem.findtext("cvss3_vector") if nvt_elem is not None else None,
            nvt_elem.findtext("cvss_base_vector") if nvt_elem is not None else None,
            nvt_elem.findtext("cvss_vector") if nvt_elem is not None else None,
            result_elem.findtext("cvss3_vector"),
            result_elem.findtext("cvss_vector"),
        ]

        # Pull from tags key/value strings
        tag_texts = []
        if nvt_elem is not None:
            tag_texts.append(self._safe_text(nvt_elem.findtext("tags")))
        tag_texts.append(self._safe_text(result_elem.findtext("tags")))

        for tags in tag_texts:
            if not tags:
                continue

            vec = (
                self._extract_from_tags(tags, "cvss3_vector=")
                or self._extract_from_tags(tags, "cvss_base_vector=")
            )
            if vec:
                vector_candidates.append(vec)

        vector = next((self._safe_text(v) for v in vector_candidates if v), None)

        # Return score and vector
        return score, vector

    @staticmethod
    def _extract_nvd_oid(result_elem) -> Optional[str]:
        """Extract the NVT OID"""
        nvt = result_elem.find("nvt")
        if nvt is not None:
            return nvt.get("oid")
        return None

    @staticmethod
    def _parse_port(port_field: Optional[str]) -> Optional[str]:
        """Convert ##/tcp to ##"""
        if not port_field:
            return None
        try:
            return int(port_field.split("/")[0])
        except ValueError:
            return None

    @staticmethod
    def _parse_protocol(port_field: Optional[str]) -> Optional[str]:
        """Extract protocol from port field"""
        if not port_field or "/" not in port_field:
            return "SENTINEL:Protocol_Unknown"
        return port_field.split("/")[1]

    @staticmethod
    def _extract_from_tags(tags_text: str, key: str) -> Optional[str]:
        if not tags_text or key not in tags_text:
            return None
        for item in tags_text.split('|'):
            if item.strip().startswith(key):
                return item.split('=', 1)[1].strip()
        return None
