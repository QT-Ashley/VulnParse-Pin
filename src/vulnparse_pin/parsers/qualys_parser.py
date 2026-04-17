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
from typing import Dict, Optional, TYPE_CHECKING
from defusedxml.ElementTree import fromstring

from vulnparse_pin.parsers.base_parser import BaseParser
from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


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

        if filepath.suffix != ".xml":
            return 0.0, [("extension", f"rejected:{filepath.suffix}")]

        try:
            if os.path.getsize(filepath) > 500 * 1024 * 1024:
                return 0.0, [("size", "exceeds_500MB")]
            raw = Path(filepath).read_bytes()
            root = fromstring(raw)
        except (OSError, ValueError, Exception):
            return 0.0, [("parse", "failed")]

        score = 0.0

        # Root tag signal — SCAN is the canonical Qualys root element
        if root.tag == "SCAN":
            score += 0.30
            evidence.append(("root_tag", "SCAN"))
        elif root.tag != "SCAN":
            # Hard reject if root is not SCAN-like
            return 0.0, [("root_tag", f"rejected:{root.tag}")]

        # ASSET elements — primary organizational unit in Qualys
        assets = root.findall(".//ASSET")
        if len(assets) > 0:
            score += 0.25
            evidence.append(("structure", f"asset_count={len(assets)}"))

        # VULN elements — specific vulnerability findings
        vulns = root.findall(".//VULN")
        if len(vulns) > 0:
            score += 0.25
            evidence.append(("structure", f"vuln_count={len(vulns)}"))

        # QID heuristic — Qualys-specific numeric plugin identifier
        first_vuln = root.find(".//VULN")
        if first_vuln is not None:
            qid = first_vuln.findtext("QID")
            if qid and re.match(r'^\d+$', qid.strip()):
                score += 0.10
                evidence.append(("qid", f"numeric:{qid[:10]}"))

        # CVSS presence — either BASE score or VECTOR
        first_cvss = (root.findtext(".//CVSS_BASE") or
                      root.findtext(".//CVSS_VECTOR"))
        if first_cvss:
            score += 0.05
            evidence.append(("meta", "cvss_present"))

        # IP or FQDN signal — network identifier for asset
        first_ip = root.findtext(".//IP") or root.findtext(".//FQDN")
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
            if size > 500 * 1024 * 1024:
                raise ValueError(f"Refusing to parse files larger than 500MB: {self.filepath}")
        except OSError as e:
            raise ValueError(f"Failed to stat file {self.filepath}: {e}") from e

        # Parse XML securely
        raw = Path(self.filepath).read_bytes()
        try:
            root = fromstring(raw)
        except (OSError, ValueError) as e:
            raise ValueError(f"Failed to parse XML: {e}") from e

        assets: Dict[str, Asset] = {}
        dropped = 0

        # Extract scan metadata
        scan_date = root.findtext("SCAN_DATETIME") or "SENTINEL:Date_Unavailable"
        scan_name = root.findtext("TITLE") or root.attrib.get("id") or "SENTINEL:Not_Found"

        # Parse all assets and their vulnerabilities
        for asset in root.findall(".//ASSET"):
            # Primary asset identifier (prefer IP over FQDN)
            raw_ip = asset.findtext("IP")
            raw_fqdn = asset.findtext("FQDN")
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
            for vuln in asset.findall(".//VULN"):
                qid = self._safe_text(vuln.findtext("QID"))
                title = self._safe_text(vuln.findtext("TITLE")) or "SENTINEL:No_Title"
                description = self._safe_text(vuln.findtext("DESCRIPTION")) or "SENTINEL:No_Description"
                
                # Extract port and protocol if available
                port = None
                protocol = None
                port_text = vuln.findtext("PORT")
                if port_text:
                    port = self._safe_int(port_text.split("/")[0]) if "/" in port_text else self._safe_int(port_text)
                    if port_text and "/" in port_text:
                        # "443/tcp" format
                        protocol = port_text.split("/")[1].lower()
                
                # Normalize protocol
                protocol = protocol or "tcp"
                protocol_str = protocol if isinstance(protocol, str) else str(protocol).lower()
                
                # CVSS scoring
                cvss_score = None
                cvss_vector = None
                
                cvss_base = vuln.findtext("CVSS_BASE")
                if cvss_base:
                    cvss_score = self._safe_float(cvss_base)
                
                cvss_vector_node = vuln.findtext("CVSS_VECTOR")
                if cvss_vector_node:
                    cvss_vector = self._safe_text(cvss_vector_node)

                # CVE extraction
                cves = []
                cve_text = vuln.findtext("CVE_ID")
                if cve_text:
                    # CVE_ID may be comma-separated; extract all CVE-YYYY-NNNNN identifiers
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', cve_text, re.IGNORECASE)
                    cves.extend(cve_matches)

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
                    severity="Unknown",  # Qualys severity mapped separately if needed
                    cves=tuple(cves),
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    affected_port=port,
                    protocol=protocol_str,
                    detection_plugin=f"Qualys:{qid}" if qid else "Qualys:unknown",
                    plugin_output="SENTINEL:No_Plugin_Output",
                    asset_id=asset_id,
                )

                assets[asset_id].findings.append(finding)

        if dropped > 0:
            self.ctx.logger.warning(f"Dropped {dropped} malformed ASSET entries during parsing.")

        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())
        parsed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        # Build scan metadata
        scan_metadata = ScanMetaData(
            source="Qualys",
            scan_name=scan_name,
            scan_date=scan_date,
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=parsed_at,
        )

        return ScanResult(
            scan_metadata=scan_metadata,
            assets=list(assets.values()),
        )
