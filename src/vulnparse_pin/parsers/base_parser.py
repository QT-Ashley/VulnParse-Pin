# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
#  any later version.
# See the LICENSE file for full terms.
from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC, abstractmethod
from pathlib import Path
import re
from typing import List, Optional, Tuple
from vulnparse_pin.core.classes.dataclass import ScanResult

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

class BaseParser(ABC):
    ctx: "RunContext"

    def __init__(self, ctx: "RunContext", filepath: str | Path):
        self.ctx = ctx
        self.filepath = filepath
    
    @classmethod
    def detect(cls, data: dict) -> bool:
        """Return True if this parser can handle the given data"""
        pass
    
    @classmethod
    def detect_file(cls, filepath: str | Path) -> bool:
        """Detect based on file-level sniffing (XML, CSV, JSON header)."""

    @abstractmethod
    def parse(self) -> ScanResult:
        """Parse the data and return normalized VulnParse-Pin format"""
        pass
    
    @staticmethod
    def _safe_float(value: str):
        try: 
            return float(value)
        except (TypeError, ValueError):
            return None
    
    @staticmethod    
    def _safe_int(value:str):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
        
    @staticmethod
    def _safe_text(elem_text: Optional[str]) -> Optional[str]:
        """Normalize text from xml by stripping leading/trailing whitespace and collapsing newlines"""
        if not elem_text:
            return None
        return " ".join(elem_text.split())
    
    _KEY_PATTERNS = [
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    re.compile(r"\bversion\s*[:=]?\s*[v]?\d+(\.\d+){0,4}\b", re.IGNORECASE),
    re.compile(r"\b(cvss[:=]?\s*\d+(\.\d+)?)\b", re.IGNORECASE),
    re.compile(r"\b(epss|epS S)\b", re.IGNORECASE),  # liberal
    re.compile(r"\b(?:port|tcp|udp)\s*[:=]?\s*\d{1,5}\b", re.IGNORECASE),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),  # IPv4
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # UUID
    re.compile(r"\b(error|failed|denied|not found|timeout|exception)\b", re.IGNORECASE),
    re.compile(r"\b(Registry|HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\b", re.IGNORECASE),
    re.compile(r"\b(Microsoft-IIS|nginx|apache|OpenSSH|OpenSSL|IIS|Tomcat)\b", re.IGNORECASE),
    re.compile(r"\b(Named pipe|\\PIPE\\|\\\\[A-Z0-9-_]+)"),  # windows pipes / shares
    re.compile(r"\b(Scan Start Date|Scan Start|Scan duration|Scanner IP)\b", re.IGNORECASE),
    ]

    _SPLIT_DELIMS_RE = re.compile(
        r"(?:\r\n|\n)|"            # real newlines
        r"\.\s+|"            # sentence boundaries after period
        r"\?\s+|"
        r"!\s+|"
        r"\s;+\s|"                # semicolons
        r"\s\|\s|"                # pipes
        r"\s-\s|"                 # spaced hyphen bullets
        r"\s:\s(?!\d)"                  # well-formed 'key : value' pairs
        , re.VERBOSE)
    
    @classmethod
    def _smart_chunk_lines(cls, raw: str, max_chunk_len: int = 350) -> List[str]:
        """
        Turn raw plugin_output into a list of chunks to evaluate. Handles both natural multiline text and very long single-line blobs.
        """
        if not raw:
            return []
        lines = BaseParser._SPLIT_DELIMS_RE.split(raw)
        chunks, buf = [], ""
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if len(buf) + len(line) < max_chunk_len:
                buf += ((" " if buf else "") + line)
            else:
                chunks.append(buf.strip())
                buf = line
        if buf:
            chunks.append(buf.strip())
        return chunks
    
    @staticmethod
    def _summarize_plugin_output(output: Optional[str], max_lines: int = 5) -> Tuple[str, List[str]]:
        '''
        Summarize plugin_output field from scanners.
        
        - Keeps first "max_lines" lines
        - Extracts key info (versions, errors, registry keys, banners))
        - Appends a truncation notice if cut
        
        Args:
            output: Raw plugin_output string
            max_lines: Max number of lines to keep before truncating
            
        Returns:
            (summary_text, key_info_list)
            - summary_text is a short human-readable string (multiline).
            - key_info_list is a list of extracted key lines (may be empty).
        '''
        if not output:
            return ("SENTINEL:No_Plugin_Output", ["SENTINEL:No_Plugin_Output_Src"])
        
        chunks = BaseParser._smart_chunk_lines(output)
        if not chunks:
            cleaned = output.strip()
            return cleaned, [cleaned]
        
        # Always keep first chunk as summary
        summary = chunks[0]
        
        # Always do at least one evidence line.
        evidence = chunks[:max_lines] if chunks else [summary]
        
        # Add truncation marker if there exists more content
        if len(chunks) > max_lines:
            evidence.append(f"...truncated (~{len(chunks) - max_lines} more lines)")
            
        # Dedup if evidence is only one line and equals summmary.
        if len(evidence) == 1 and evidence[0] == summary:
            evidence = ["SENTINEL:Deduped_From_Output"]
        
        return summary, evidence
    