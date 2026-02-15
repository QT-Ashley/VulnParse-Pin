# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.pass_classes import DerivedContext
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.feed_cache import FeedCacheManager
from vulnparse_pin.utils.nvdcacher import NVDFeedCache

@dataclass
class Finding:
    """
    Finding class for VPP's result objects.
    """
    finding_id: str
    vuln_id: str
    title: str
    description: str
    severity: str
    cves: List[str]
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    cisa_kev: Optional[bool] = False
    cvss_vector: Optional[str] = None
    exploit_available: Optional[bool] = False
    exploit_references: Optional[List[Dict]] = None
    raw_risk_score: Optional[float] = None
    risk_score: Optional[float] = None
    risk_band: Optional[str] = None
    affected_port: Optional[int] = None
    protocol: Optional[str] = None
    detection_plugin: Optional[str] = None
    plugin_output: Optional[str] = None
    plugin_evidence: Optional[List[str]] = None
    solution: Optional[str] = None
    references: Optional[List[str]] = field(default_factory=list)
    triage_priority: Optional[str] = None
    enriched: Optional[bool] = False
    enrichment_source_cve: Optional[str] = None
    asset_id: Optional[str] = None

@dataclass
class Asset:
    """
    Asset class for VPP's result objects.
    """
    # Wire up Asset_ID
    hostname: str
    ip_address: str
    criticality: Optional[str] = None
    avg_risk_score: Optional[float] = None
    os: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    shodan_data: Optional[dict] = None


@dataclass
class ScanMetaData:
    """
    Encompasses Scan Metadata for VPP's result objects.
    """
    source: str
    scan_date: datetime
    asset_count: int
    vulnerability_count: int
    parsed_at: Optional[str] = None
    source_file: Optional[str] = None
    scan_name: Optional[str] = None


@dataclass
class ScanResult:
    """
    Complete ScanResult object encompassing Metadata and Scan Data.
    """
    scan_metadata: ScanMetaData
    assets: List[Asset] = field(default_factory=list)
    derived: DerivedContext = field(default_factory=DerivedContext)


@dataclass
class TriageConfig:
    """
    Config class object that holds values that define thresholds for High or Critical ratings.
    """
    critical_score: float = 9.0 # CVSS >= this -> crit
    high_epss_score: float = 0.7 # EPSS >= this + High sev -> crit
    exploit_floor_score: float = 7.5 # Min raw score if exploit w/o CVSS
    balanced: bool = True # Prof togg


@dataclass(frozen = True)
class Services:
    """
    Services container for RunContext
    """
    feed_cache: Optional["FeedCacheManager"] = None
    nvd_cache: Optional["NVDFeedCache"] = None

@dataclass(frozen = True)
class RunContext:
    """
    Centralized runtime context object.
    """
    paths: AppPaths
    pfh: PermFileHandler
    logger: Any
    services: Optional[Services] = None

@dataclass(frozen = True)
class FeedSpec:
    """
    Manages feed specifications.
    """
    key: str
    filename: str
    label: str
    sha256_suffix: str = ".sha256"
    meta_suffix: str = ".meta.json"
    ttl_seconds: int | None = None
    ttl_hours_value: float | None = None

    @property
    def ttl_hours(self) -> float:
        """
        Backwards-Compatible TTL accessor used by FeedCacheManager.
        Returns a float hour value.

        :return: Hours value
        :rtype: float
        """
        if hasattr(self, "ttl_hours_value") and self.ttl_hours_value is not None:
            return float(self.ttl_hours_value)
        if hasattr(self, "ttl_hours") and self.ttl_seconds is not None:
            return float(self.ttl_seconds) / 3600
        # Default TTL if not configured
        return 24.0

@dataclass(frozen = True)
class FeedCachePolicy:
    """
    Holds policy config info for Feeds.
    """
    default_ttl_hours: int
    ttl_hours: Dict[str, int]

    def ttl_for(self, key: str) -> int:
        return int(self.ttl_hours.get(key, self.default_ttl_hours))
