# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
from datetime import datetime

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.pass_classes import DerivedContext
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.feed_cache import FeedCacheManager
from vulnparse_pin.utils.nvdcacher import NVDFeedCache

if TYPE_CHECKING:
    from vulnparse_pin.core.passes.TopN.TN_triage_config import TriageConfigLoadResult
    from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
    from vulnparse_pin.core.classes.execution_manifest import LedgerService

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
    score_trace: Dict[str, Any] = field(default_factory=dict)
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
    cve_analysis: List[Dict[str, Any]] = field(default_factory=list)
    enrichment_sources: List[str] = field(default_factory=list)
    confidence: int = 0
    confidence_evidence: Dict[str, int] = field(default_factory=dict)
    source_format: Optional[str] = None
    fidelity_tier: Optional[str] = None
    missing_fields: List[str] = field(default_factory=list)
    degraded_input: bool = False
    ingestion_confidence: Optional[float] = None
    confidence_reasons: List[str] = field(default_factory=list)
    asset_id: Optional[str] = None

@dataclass
class Asset:
    """
    Asset class for VPP's result objects.
    """
    hostname: str
    ip_address: str
    criticality: Optional[str] = None
    avg_risk_score: Optional[float] = None
    os: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    shodan_data: Optional[dict] = None
    asset_id: Optional[str] = None


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


@dataclass(frozen=True)
class AssetObservation:
    """
    Observation view of an Asset for TopN pass processing.
    Extracted to dataclass.py for indexing without circular imports.
    """
    asset_id: str
    ip: Optional[str]
    hostname: Optional[str]
    criticality: Optional[str] = None
    open_ports: Tuple[int, ...] = field(default_factory=tuple)
    finding_text_blob: str = ""
    finding_title_blob: str = ""
    finding_description_blob: str = ""
    finding_plugin_output_blob: str = ""


@dataclass(frozen=True)
class PostEnrichmentIndex:
    """
    Immutable post-enrichment index built once after enrichment pipeline completes.
    Provides O(1) lookups for pass phases to avoid repeated ScanResult traversals.
    
    Built after enrichment, before pass runner execution.
    Read-only for all downstream passes.
    Rebuilt on each run (not cached across invocations).
    """
    # Core indices
    finding_by_id: Dict[str, Finding] = field(default_factory=dict)
    findings_by_asset_id: Dict[str, List[Finding]] = field(default_factory=dict)
    asset_observations: Dict[str, AssetObservation] = field(default_factory=dict)
    
    # Precomputed attributes for frequent access patterns
    finding_attributes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Optional secondary indices
    findings_by_severity: Dict[str, List[Finding]] = field(default_factory=dict)
    findings_by_cve: Dict[str, List[Finding]] = field(default_factory=dict)

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """O(1) lookup for finding by ID."""
        return self.finding_by_id.get(finding_id)

    def get_findings_for_asset(self, asset_id: str) -> List[Finding]:
        """Get all findings for a specific asset."""
        return self.findings_by_asset_id.get(asset_id, [])

    def get_asset_observation(self, asset_id: str) -> Optional[AssetObservation]:
        """Get precomputed asset observation."""
        return self.asset_observations.get(asset_id)


@dataclass(frozen = True)
class Services:
    """
    Services container for RunContext
    """
    feed_cache: Optional["FeedCacheManager"] = None
    nvd_cache: Optional["NVDFeedCache"] = None
    scoring_config: Optional["ScoringPolicyV1"] = None
    topn_config: Optional["TriageConfigLoadResult"] = None
    post_enrichment_index: Optional[PostEnrichmentIndex] = None
    ledger: Optional["LedgerService"] = None
    runmanifest_mode: str = "compact"
    nmap_ctx_config: Optional[dict] = None
    webhook_config: Optional["WebhookRuntimeConfig"] = None


@dataclass(frozen=True)
class WebhookEndpointConfig:
    url: str
    enabled: bool = True
    oal_filter: str = "all"
    format: str = "generic"


@dataclass(frozen=True)
class WebhookRuntimeConfig:
    enabled: bool = False
    signing_key_env: str = "VP_WEBHOOK_HMAC_KEY"
    key_id: str = "primary"
    timeout_seconds: int = 5
    connect_timeout_seconds: int = 3
    read_timeout_seconds: int = 5
    max_retries: int = 2
    max_payload_bytes: int = 262144
    replay_window_seconds: int = 300
    allow_spool: bool = True
    spool_subdir: str = "webhook_spool"
    endpoints: Tuple[WebhookEndpointConfig, ...] = field(default_factory=tuple)

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
