# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

"""
Nmap XML parser scaffold for VulnParse-Pin.

This module provides baseline support for Nmap XML output format.
Status: Scaffold only - parsing logic deferred to v1.2.1

Nmap is widely used for network discovery and port scanning. Output includes:
- Host enumeration with IP/hostname
- Port status (open, closed, filtered)
- Service detection via version probing
- OS detection fingerprints
- Script output (NSE scripts)

This parser normalizes Nmap scan outputs into VulnParse-Pin's canonical format.
Note: Nmap generates port/service inventory, not vulnerability assessments directly.
VulnParse-Pin bridges this by treating open ports as baseline "findings" that can be
enriched with vulnerability intelligence from KEV, EPSS, Exploit-DB, etc.
"""

from __future__ import annotations
from pathlib import Path

import os
from typing import Dict, Optional, TYPE_CHECKING

from vulnparse_pin.parsers.base_parser import BaseParser
from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


class NmapXMLParser(BaseParser):
    """
    Nmap XML report parser for network reconnaissance findings.
    
    Transforms Nmap port scan outputs into VulnParse-Pin canonical format.
    Each open/filtered port is represented as a "finding" for further enrichment.
    """
    
    NAME = "nmap-xml"

    def __init__(self, ctx: "RunContext", filepath: str | None = None):
        super().__init__(ctx=ctx, filepath=filepath)

    @classmethod
    def detect_file(cls, filepath) -> tuple[float, list[tuple[str, str]]]:
        """
        Detect if the file is an Nmap XML export.

        Returns (confidence, evidence_pairs) where confidence is in [0.0, 1.0].

        Detection signals:
          - Root tag "nmaprun"                      :  +0.40
          - host elements within <nmaprun>          :  +0.20
          - port elements with state                :  +0.20
          - version/osclass detection               :  +0.10
          - start/end timestamp attributes          :  +0.10
        """
        evidence: list[tuple[str, str]] = []

        if filepath.suffix != ".xml":
            return 0.0, [("extension", f"rejected:{filepath.suffix}")]

        try:
            if os.path.getsize(filepath) > 500 * 1024 * 1024:
                return 0.0, [("size", "exceeds_500MB")]
            
            # Lightweight detection via sniffing first few lines
            with open(filepath, 'rb') as f:
                header = f.read(1024)
            
            header_text = header.decode('utf-8', errors='ignore').lower()
            
        except (OSError, ValueError, Exception):
            return 0.0, [("parse", "failed")]

        score = 0.0

        # Root tag signal
        if "<nmaprun" in header_text:
            score += 0.40
            evidence.append(("root_tag", "nmaprun"))
        else:
            return 0.0, [("root_tag", "rejected:not_nmap")]

        # Host element signal
        if "<host " in header_text or "<host>" in header_text:
            score += 0.20
            evidence.append(("structure", "host"))

        # Port element signal
        if "<port " in header_text or "<port>" in header_text:
            score += 0.20
            evidence.append(("structure", "port"))

        # Version detection
        if "<version" in header_text or "version=" in header_text:
            score += 0.10
            evidence.append(("detection", "version_probing"))

        # Timing metadata
        if "start=" in header_text or "end=" in header_text:
            score += 0.10
            evidence.append(("meta", "timestamps"))

        return min(score, 1.0), evidence

    def parse(self) -> ScanResult:
        """
        Parse Nmap XML into ScanResult object with Assets + Findings.
        
        Status: Scaffold only - full implementation deferred to v1.2.1
        """
        if not self.filepath:
            raise ValueError("NmapXMLParser requires an accessible filepath.")

        # Guard: file size check
        try:
            size = os.path.getsize(self.filepath)
            if size > 500 * 1024 * 1024:
                raise ValueError(f"Refusing to parse files larger than 500MB: {self.filepath}")
        except OSError as e:
            raise ValueError(f"Failed to stat file {self.filepath}: {e}") from e

        # Return minimal valid ScanResult
        # Full parsing logic to be implemented in v1.2.1+
        self.ctx.logger.warning(
            "Nmap XML parser is scaffolded for v1.2.1. "
            "Full port enumeration and service detection pending."
        )

        scan_metadata = ScanMetaData(
            source="Nmap",
            scan_date="SENTINEL:Date_Unavailable",
            asset_count=0,
            vulnerability_count=0,
        )

        return ScanResult(
            scan_metadata=scan_metadata,
            assets=[],
        )
