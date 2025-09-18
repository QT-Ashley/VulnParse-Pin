from multiprocessing import Value
from unittest import result
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, List, Optional
from .base_parser import BaseParser
from classes.dataclass import ScanResult, Asset, Finding

class OpenVASXMLParser(BaseParser):
    @classmethod
    def detect_file(cls, filepath):
        """Detect if the file is an OpenVAS XML file."""
        if filepath.lower().endswith(".xml"):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    head = f.read(1000)
                    # Look for common OpenVAS XML markers
                    return "<report" in head and "<result" in head
            except Exception:
                return False
        return False
    
    def parse(self) -> ScanResult:
        """Parse OpenVAS XML into ScanResult object with Assets + Findings."""
        path = Path(self.filepath)
        tree = ET.parse(path)
        root = tree.getroot()
        assets: List[Asset] = []
        
        metadata = {
            "source": "OpenVASXML",
            "source_file": str(path),
        }
        
        # Gather host elements
        for host_elem in root.findall(".//host"):
            ip_or_host = host_elem.text.strip() if host_elem.text else None
            asset = Asset(hostname=ip_or_host,
                          ip_address=ip_or_host,
                          findings=[])
            
            
            # Collect results tied to host
            for result in root.findall(".//result"):
                
                # Get Fields
                nvt = result.find("nvt")
                
                cve_ids = self._extract_cves(nvt, result)
                cvss_score, cvss_vector = self._extract_cvss(nvt, result)
                
                finding = Finding(
                    vuln_id=self._extract_nvd_oid(result),
                    title=self._safe_text(result.findtext("name")),
                    description=self._safe_text(result.findtext("description")),
                    severity=self._safe_text(result.findtext("severity")) or self._safe_text(result.findtext("threat")),
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cves=cve_ids,
                    affected_port=self._parse_port(result.findtext("port")),
                    protocol=self._parse_protocol(result.findtext("port")),
                    solution=self._safe_text(result.findtext("solution")),
                )
                asset.findings.append(finding)
                
            assets.append(asset)
            
        return ScanResult(scan_metadata=metadata, assets=assets)
                
    def _extract_cves(self, nvt_elem, result_elem):
        cves = []
        if nvt_elem is not None:
            cves.extend(self._safe_text(c.text) for c in nvt_elem.findall("cve") if c is not None and c.text)
        # CVEs in tags/reference fallback
        tags_text = self._safe_text(result_elem.findtext("tags")) or self._safe_text(result_elem.findtext("references"))
        if tags_text:
            import re
            cves.extend(re.findall(rf"CVE-\d{4}-\d{4,7}", tags_text))
        
        # Dedup & keep order
        seen = set(); out = []
        for cv in cves:
            if cv and cv not in seen:
                seen.add(cv); out.append(cv)
        return out
    
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
            result_elem.findtext("cvss3_vector"),
            result_elem.findtext("cvss_vector"),
        ]
        vector = next((self._safe_text(v) for v in vector_candidates if v), None)
        
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
            return None
        return port_field.split("/")[1]