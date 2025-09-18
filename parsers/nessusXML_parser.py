import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional
from .base_parser import BaseParser
from classes.dataclass import ScanResult, Asset, Finding

class NessusXMLParser(BaseParser):
    @classmethod
    def detect_file(cls, filepath):
        """Detect if the file is a Nessus XML export (.nessus)"""
        if filepath.lower().endswith((".nessus", ".xml")):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    head = f.read(300)
                    return "<NessusClientData_v2" in head
            except Exception:
                return False
        return False
    
    def parse(self) -> ScanResult:
        """Parse Nessus XML (.nessus) into a ScanResult with Assets + Findings."""
        path = Path(self.filepath)
        tree = ET.parse(path)
        root = tree.getroot()
        assets: List[Asset] = []
        
        metadata = {
            "scanner": "Nessus",
            "source_file": str(path),
        }
        
        # Loop through each host in the report
        for host in root.findall(".//ReportHost"):
            ip_or_host = host.get("name")
            os_name: Optional[str] = None
            
            # Extract host OS if it is present
            for tag in host.findall("HostProperties/tag"):
                if tag.get("name") == "operating-system":
                    os_name = tag.text
                    
            
            asset = Asset(
                hostname=ip_or_host,
                ip_address=ip_or_host,
                os=os_name,
                findings=[]
            )
            
            # Each ReportItem = vuln finding
            for report_item in host.findall("ReportItem"):
                finding = Finding(
                    vuln_id=report_item.get("pluginID"),
                    title=report_item.get("plugin_name"),
                    description=report_item.get("description"),
                    severity=report_item.get("risk_factor"),
                    cvss_score=report_item.get("cvss_base_score"),
                    cvss_vector=report_item.get("cvss_vector"),
                    cves=[cve.text for cve in report_item.findall("cve")],
                    affected_port=self._safe_int(report_item.get("port")),
                    protocol=report_item.get("protocol"),
                    solution=report_item.get("solution"),
                )
                asset.findings.append(finding)
            
            assets.append(asset)
            
        return ScanResult(scan_metadata=metadata, assets=assets)