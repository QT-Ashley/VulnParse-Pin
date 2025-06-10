from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class Finding:
    vuln_id: str
    title: str
    description: str
    severity: str
    cves: List[str]
    cvss_score: Optional[float] = field(default_factory=float)
    epss_score: Optional[float] = None
    cisa_kev: Optional[bool] = None
    cvss_vector: Optional[str] = None
    exploit_available: Optional[bool] = None
    risk: Optional[str] = None
    affected_port: Optional[int] = None
    protocol: Optional[str] = None
    detection_plugin: Optional[str] = None
    plugin_output: Optional[str] = None
    solution: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = field(default_factory=list)
    triage_priority: Optional[str] = None
    enriched: Optional[bool] = None
    assetid: Optional[str] = None
    
@dataclass
class Asset:
    hostname: str
    ip_address: str
    criticality: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    shodan_data: Optional[dict] = None
    
    
@dataclass
class ScanMetaData:
    source: str
    scan_date: datetime
    asset_count: int
    vulnerability_count: int
    
@dataclass
class ScanResult:
    scan_metadata: ScanMetaData
    assets: List[Asset] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "metadata": self.metadata.__dict__,
            "assets": {k: v.__dict__ for k, v in self.assets.items()}
        }