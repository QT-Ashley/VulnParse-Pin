from pathlib import Path
from defusedxml.ElementTree import fromstring
from datetime import datetime, timezone
import os
from iniconfig import ParseError
import utils.logger_instance as log
from typing import Dict, Optional
from .base_parser import BaseParser
from classes.dataclass import ScanMetaData, ScanResult, Asset, Finding

class OpenVASXMLParser(BaseParser):
    NAME = "openvas-xml"
    
    def __init__(self, filepath: str | None = None):
        super().__init__(filepath=filepath)
        
    @classmethod
    def detect_file(cls, filepath) -> bool:
        """Detect if the file is an OpenVAS XML file by structure"""
        
        if not filepath.lower().endswith(".xml"):
            return False
        
        try:
            size = os.path.getsize(filepath)
            if size > 500 * 1024 * 1024:
                log.log.print_error(f"File supplied exceeds 500MB. "
                                    f"This is a mechanism to protect against DOS. File: {filepath}")
                return False
        except OSError as e:
            log.log.logger.error(f"Failed to stat file for detection: {e}")
            return False

        
        try:
            raw = Path(filepath).read_bytes()
            root = fromstring(raw)
        except (OSError, ParseError) as e:
            log.log.logger.error(f"Error detecting file: {e}")
            return False
        
        if (
            root.tag == "NessusClientData_v2"
            or root.find(".//NessusClientData_v2") is not None
        ):
            return False
        
        result_nodes = root.find(".//report//results//result") or root.find(".//results//result")
        has_nvt = root.find(".//nvt") is not None
        
        # Confirm GVM structure
        return bool(result_nodes) and has_nvt
    
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
        except (OSError, ParseError) as e:
            raise ValueError(f"Failed to parse XML: {e}") from e
        
        
        assets: Dict[str, Asset] = {}
        dropped = 0
        
        scan_date = root.findtext(".//creation_time") or "SENTINEL:Date_Unavailable"
        scan_name = root.attrib.get("id") or "SENTINEL:Not_Found"
        
        # Start Parsing
        for result in root.findall(".//result"):
            raw_host = result.findtext("host")
            if not raw_host or not raw_host.strip():
                log.log.logger.warning("Dropping Openvas result with no host entry — malformed or incomplete XML <result> block.")
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
                    print(f"[DEBUG] YO TAGS IS NULL FAM")
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
                title = None
                cvss_vector = "SENTINEL:Vector_Unavailable"
                cvss_score = 0.0
                solution = None
                plugin_output = None
                cves = ["SENTINEL:No_CVE_Listed"]
                
            # Build out evidence values and other potentially valuable information
            detection = result.find("detection")
            
            evidence = []
            if detection is not None:
                for detail in detection.findall(".//detail"):
                    name = detail.findtext("name") or "Unknown"
                    value = detail.findtext("value") or "N/A"
                    evidence.append(f"{name}: {value}")
                    
            summary, summarized_evidence = self._summarize_plugin_output(plugin_output)
            if not evidence:
                evidence = summarized_evidence
            
            # Now time for Asset Creation
            if host not in assets:
                assets[host] = Asset(
                    hostname=host,
                    ip_address=host,
                    criticality=None,
                    os=None,
                    findings=[],
                    shodan_data=None,
                )
            
            # Build Finding
            finding = Finding(
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
                assetid=host,
            )
            assets[host].findings.append(finding)
        
        # Check Droppped findings and log.
        if dropped:
            log.log.logger.info(f"Dropped {dropped} malformed OpenVAS result(s) with no host.")
            
        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())
        
        # Build Metadata
        metadata = ScanMetaData(
            source="OpenVAS",
            scan_name=scan_name,
            scan_date=scan_date,
            source_file=str(self.filepath),
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
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
            import re
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