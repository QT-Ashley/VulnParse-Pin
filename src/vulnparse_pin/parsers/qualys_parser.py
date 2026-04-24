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

import os
import re
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional, TYPE_CHECKING
from xml.etree.ElementTree import ParseError
from defusedxml.ElementTree import fromstring

from vulnparse_pin.parsers.base_parser import BaseParser
from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MAX_XML_BYTES = 500 * 1024 * 1024


def _local_name(tag: str) -> str:
    if not tag:
        return ""
    return str(tag).split("}")[-1].strip().upper()


def _iter_by_local(root, names: Iterable[str]):
    wanted = {str(n).strip().upper() for n in names}
    for elem in root.iter():
        if _local_name(elem.tag) in wanted:
            yield elem


def _first_text_by_local(root, names: Iterable[str]) -> Optional[str]:
    for elem in _iter_by_local(root, names):
        text = (elem.text or "").strip()
        if text:
            return text
    return None


class QualysXMLParser(BaseParser):
    """
    Qualys XML report parser for vulnerability findings.
    
    Supports standard Qualys SCAN XML export format with ASSET and VULN elements.
    Normalizes data into VulnParse-Pin canonical format.
    """
    
    NAME = "qualys-xml"

    def __init__(self, ctx: "RunContext", filepath: str | None = None):
        super().__init__(ctx=ctx, filepath=filepath)

    @classmethod
    def detect_file(cls, filepath) -> tuple[float, list[tuple[str, str]]]:
        """
        Detect if the file is a Qualys XML export.

        Returns (confidence, evidence_pairs) where confidence is in [0.0, 1.0].
        Signals are additive; sum is capped at 1.0.

        Detection signals:
          - Root tag "SCAN"                         :  +0.30
          - ASSET element present                  :  +0.25
          - VULN elements under ASSET              :  +0.25
          - QID attributes (Qualys plugin IDs)     :  +0.10
          - CVSS_BASE or CVSS_VECTOR present       :  +0.05
          - IP or FQDN element in ASSET            :  +0.05
        """
        evidence: list[tuple[str, str]] = []

        path = Path(filepath)
        if path.suffix.lower() != ".xml":
            return 0.0, [("extension", f"rejected:{filepath.suffix}")]

        try:
            if os.path.getsize(filepath) > _MAX_XML_BYTES:
                return 0.0, [("size", "exceeds_500MB")]
            raw = path.read_bytes()
            root = fromstring(raw)
        except (OSError, ValueError, ParseError):
            return 0.0, [("parse", "failed")]

        score = 0.0

        # Root tag signal — SCAN is the canonical Qualys root element
        root_name = _local_name(root.tag)
        if root_name in {"SCAN", "SCAN_REPORT"}:
            score += 0.30
            evidence.append(("root_tag", root_name))
        else:
            # Hard reject if root is not SCAN-like
            return 0.0, [("root_tag", f"rejected:{root_name or root.tag}")]

        # ASSET elements — primary organizational unit in Qualys
        assets = list(_iter_by_local(root, {"ASSET", "HOST"}))
        if len(assets) > 0:
            score += 0.25
            evidence.append(("structure", f"asset_count={len(assets)}"))

        # VULN elements — specific vulnerability findings
        vulns = list(_iter_by_local(root, {"VULN", "VULNERABILITY"}))
        if len(vulns) > 0:
            score += 0.25
            evidence.append(("structure", f"vuln_count={len(vulns)}"))

        # QID heuristic — Qualys-specific numeric plugin identifier
        first_vuln = next(iter(vulns), None)
        if first_vuln is not None:
            qid = _first_text_by_local(first_vuln, {"QID", "QID_ID", "VULN_ID"})
            if qid and re.match(r'^\d+$', qid.strip()):
                score += 0.10
                evidence.append(("qid", f"numeric:{qid[:10]}"))

        # CVSS presence — either BASE score or VECTOR
        first_cvss = (
            _first_text_by_local(root, {"CVSS_BASE", "CVSS3_BASE", "CVSS_SCORE"})
            or _first_text_by_local(root, {"CVSS_VECTOR", "CVSS3_VECTOR"})
        )
        if first_cvss:
            score += 0.05
            evidence.append(("meta", "cvss_present"))

        # IP or FQDN signal — network identifier for asset
        first_ip = _first_text_by_local(root, {"IP", "IP_ADDRESS", "FQDN", "HOSTNAME", "DNS"})
        if first_ip:
            score += 0.05
            evidence.append(("asset_id", "ip_or_fqdn"))

        return min(score, 1.0), evidence

    def parse(self) -> ScanResult:
        """Parse Qualys XML into ScanResult object with Assets + Findings."""
        if not self.filepath:
            raise ValueError("QualysXMLParser requires an accessible filepath.")

        # Guard: file size check
        try:
            size = os.path.getsize(self.filepath)
            if size > _MAX_XML_BYTES:
                raise ValueError(f"Refusing to parse files larger than 500MB: {self.filepath}")
        except OSError as e:
            raise ValueError(f"Failed to stat file {self.filepath}: {e}") from e

        # Parse XML securely
        raw = Path(self.filepath).read_bytes()
        try:
            root = fromstring(raw)
        except (OSError, ValueError, ParseError) as e:
            raise ValueError(f"Failed to parse XML: {e}") from e

        root_name = _local_name(root.tag)
        if root_name not in {"SCAN", "SCAN_REPORT"}:
            raise ValueError(f"Qualys XML missing expected root tag. got={root_name or root.tag}")

        assets: Dict[str, Asset] = {}
        dropped = 0

        # Extract scan metadata
        parsed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        scan_date = (
            _first_text_by_local(root, {"SCAN_DATETIME", "SCAN_DATE", "DATETIME", "CREATED"})
            or parsed_at
        )
        scan_name = (
            _first_text_by_local(root, {"TITLE", "SCAN_TITLE", "NAME"})
            or root.attrib.get("id")
            or Path(self.filepath).stem
        )

        # Parse all assets and their vulnerabilities
        for asset in _iter_by_local(root, {"ASSET", "HOST"}):
            # Primary asset identifier (prefer IP over FQDN)
            raw_ip = _first_text_by_local(asset, {"IP", "IP_ADDRESS", "HOST_IP"})
            raw_fqdn = _first_text_by_local(asset, {"FQDN", "HOSTNAME", "DNS"})
            host = None

            if raw_ip and raw_ip.strip():
                host = raw_ip.strip()
            elif raw_fqdn and raw_fqdn.strip():
                host = raw_fqdn.strip()

            if not host:
                self.ctx.logger.warning(
                    "Dropping Qualys ASSET with no IP or FQDN entry — malformed or incomplete XML."
                )
                dropped += 1
                continue

            asset_id = make_asset_id(ip=host, hostname=host)

            # Ensure asset entry exists
            if asset_id not in assets:
                assets[asset_id] = Asset(
                    asset_id=asset_id,
                    hostname=host,
                    ip_address=host,
                    findings=[],
                )

            # Parse vulnerabilities for this asset
            for vuln in _iter_by_local(asset, {"VULN", "VULNERABILITY"}):
                qid = self._safe_text(_first_text_by_local(vuln, {"QID", "QID_ID", "VULN_ID"}))
                title = self._safe_text(_first_text_by_local(vuln, {"TITLE", "NAME", "VULN_TITLE"})) or "SENTINEL:No_Title"
                description = self._safe_text(_first_text_by_local(vuln, {"DESCRIPTION", "DIAGNOSIS", "DETAILS"})) or "SENTINEL:No_Description"
                
                # Extract port and protocol if available
                port = None
                protocol = None
                port_text = _first_text_by_local(vuln, {"PORT", "SERVICE_PORT", "AFFECTED_PORT"})
                if port_text:
                    parts = [p.strip().lower() for p in str(port_text).split("/") if p.strip()]
                    if len(parts) == 2 and parts[0].isdigit():
                        port = self._safe_int(parts[0])
                        protocol = parts[1]
                    elif len(parts) == 2 and parts[1].isdigit():
                        protocol = parts[0]
                        port = self._safe_int(parts[1])
                    else:
                        port = self._safe_int(parts[0] if parts else port_text)
                
                # Normalize protocol
                protocol = protocol or "tcp"
                protocol_str = protocol if isinstance(protocol, str) else str(protocol).lower()
                if protocol_str not in {"tcp", "udp", "icmp"}:
                    protocol_str = "tcp"
                if port is not None and not (0 <= int(port) <= 65535):
                    port = None
                
                # CVSS scoring
                cvss_score = None
                cvss_vector = None
                
                cvss_base = _first_text_by_local(vuln, {"CVSS_BASE", "CVSS3_BASE", "CVSS_SCORE"})
                if cvss_base:
                    cvss_score = self._safe_float(cvss_base)
                    if cvss_score is not None and not (0.0 <= cvss_score <= 10.0):
                        cvss_score = None
                
                cvss_vector_node = _first_text_by_local(vuln, {"CVSS_VECTOR", "CVSS3_VECTOR"})
                if cvss_vector_node:
                    cvss_vector = self._safe_text(cvss_vector_node)

                # CVE extraction
                cves = []
                cve_text = _first_text_by_local(vuln, {"CVE_ID", "CVE", "CVES"})
                if cve_text:
                    # CVE_ID may be comma-separated; extract all CVE-YYYY-NNNNN identifiers
                    cve_matches = _CVE_RE.findall(cve_text)
                    cves.extend(sorted({m.upper() for m in cve_matches}))

                solution = self._safe_text(_first_text_by_local(vuln, {"SOLUTION", "FIX", "REMEDIATION"})) or "SENTINEL:No_Solution"
                plugin_output = self._safe_text(_first_text_by_local(vuln, {"RESULT", "EVIDENCE", "DIAGNOSIS"})) or "SENTINEL:No_Plugin_Output"

                missing_fields = []
                if not cves:
                    missing_fields.append("cves")
                if not cvss_vector:
                    missing_fields.append("cvss_vector")
                if plugin_output == "SENTINEL:No_Plugin_Output":
                    missing_fields.append("plugin_output")
                if port is None:
                    missing_fields.append("affected_port")

                if not missing_fields:
                    fidelity_tier = "full"
                    ingestion_confidence = 0.95
                    confidence_reasons = ["base:full=0.95"]
                elif len(missing_fields) <= 2:
                    fidelity_tier = "partial"
                    ingestion_confidence = 0.70
                    confidence_reasons = ["base:partial=0.70"]
                else:
                    fidelity_tier = "minimal"
                    ingestion_confidence = 0.45
                    confidence_reasons = ["base:minimal=0.45"]
                degraded_input = fidelity_tier != "full"

                # Build canonical finding using the proper signature
                scanner_sig = f"qualys:{qid}" if qid else "qualys:unknown"
                port_str = str(port) if port is not None else "0"
                finding_base = make_finding_base_canon(
                    asset_id=asset_id,
                    scanner_sig=scanner_sig,
                    proto=protocol_str,
                    port=port_str,
                    kind=title,
                )
                finding_id = make_finding_id(canon=finding_base)

                # Create finding with all required fields
                finding = Finding(
                    finding_id=finding_id,
                    vuln_id=qid or "SENTINEL:No_QID",
                    title=title,
                    description=description,
                    severity=self._map_qualys_severity(_first_text_by_local(vuln, {"SEVERITY", "THREAT", "RISK"})),
                    cves=list(cves),
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    affected_port=port,
                    protocol=protocol_str,
                    detection_plugin=f"Qualys:{qid}" if qid else "Qualys:unknown",
                    plugin_output=plugin_output,
                    plugin_evidence=[plugin_output] if plugin_output != "SENTINEL:No_Plugin_Output" else ["SENTINEL:No_Evidence"],
                    solution=solution,
                    asset_id=asset_id,
                    source_format="qualys-xml",
                    fidelity_tier=fidelity_tier,
                    missing_fields=missing_fields,
                    degraded_input=degraded_input,
                    ingestion_confidence=ingestion_confidence,
                    confidence_reasons=confidence_reasons,
                )

                assets[asset_id].findings.append(finding)

        if dropped > 0:
            self.ctx.logger.warning(f"Dropped {dropped} malformed ASSET entries during parsing.")

        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())

        # Build scan metadata
        scan_metadata = ScanMetaData(
            source="Qualys",
            scan_name=scan_name,
            scan_date=scan_date,
            source_file=str(self.filepath),
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=parsed_at,
        )

        return ScanResult(
            scan_metadata=scan_metadata,
            assets=list(assets.values()),
        )

    @staticmethod
    def _map_qualys_severity(raw: Optional[str]) -> str:
        val = str(raw or "").strip().lower()
        mapping = {
            "5": "Critical",
            "4": "High",
            "3": "Medium",
            "2": "Low",
            "1": "Informational",
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
            "informational": "Informational",
        }
        return mapping.get(val, "Unknown")
