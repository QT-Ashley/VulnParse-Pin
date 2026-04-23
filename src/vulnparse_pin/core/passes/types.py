# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.pass_classes import DerivedPassResult
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult

# -------------------------------------------
# Scoring Pass
# -------------------------------------------

@dataclass(frozen=True)
class ScoredFinding:
    finding_id: str
    asset_id: str
    raw_score: float
    operational_score: float
    risk_band: str
    reason: str = ""
    score_trace: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class ScoreCoverage:
    total_findings: int
    scored_findings: int
    coverage_ratio: float

@dataclass(frozen=True)
class ScoringPassOutput:
    scored_findings: Dict[str, ScoredFinding] = field(default_factory=dict)
    asset_scores: Dict[str, float] = field(default_factory=dict)
    asset_criticality: Dict[str, str] = field(default_factory=dict)
    asset_band_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    asset_criticality_thresholds: Dict[str, int] = field(default_factory=dict)
    coverage: ScoreCoverage = field(default_factory=lambda: ScoreCoverage(0, 0, 0.0))
    highest_risk_asset: Optional[str] = None
    highest_risk_asset_score: Optional[float] = None
    avg_scored_risk: Optional[float] = None
    avg_operational_risk: Optional[float] = None


# -------------------------------------------
# TopN Pass
# -------------------------------------------

@dataclass(frozen=True)
class ExposureInference:
    exposure_score: int
    confidence: str
    externally_facing_inferred: bool
    public_service_ports_inferred: bool
    evidence: Tuple[str, ...]
    evidence_rule_ids: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RankedFindingRef:
    finding_id: str
    asset_id: str
    rank: int
    score_basis: str
    score: float
    risk_band: str
    reasons: Tuple[str, ...]
    port: Optional[int] = None
    proto: Optional[str] = None
    plugin_id: Optional[str] = None


@dataclass(frozen=True)
class RankedAssetRef:
    asset_id: str
    rank: int
    score_basis: str
    score: float
    top_scores: Tuple[float, ...]
    scored_findings: int
    inference: Optional[ExposureInference] = None


@dataclass(frozen=True)
class TopNPassOutput:
    """
    Derived artifact
    """
    rank_basis: str
    k: int
    decay: Tuple[float, ...]

    assets: Tuple[RankedAssetRef, ...]
    findings_by_asset: Dict[str, Tuple[RankedFindingRef, ...]]

    global_top_findings: Tuple[RankedFindingRef, ...] = ()


# -------------------------------------------
# Attack Capability Inference (ACI) Pass
# -------------------------------------------

@dataclass(frozen=True)
class ACIFindingSemantic:
    finding_id: str
    asset_id: str
    confidence: float
    confidence_factors: Tuple[str, ...] = ()
    capabilities: Tuple[str, ...] = ()
    chain_candidates: Tuple[str, ...] = ()
    cwe_ids: Tuple[str, ...] = ()
    evidence: Tuple[str, ...] = ()
    exploit_boost_applied: float = 0.0
    rank_uplift: float = 0.0


@dataclass(frozen=True)
class ACIAssetSemantic:
    asset_id: str
    weighted_confidence: float
    max_confidence: float
    capability_count: int
    chain_candidate_count: int
    ranked_finding_count: int
    rank_uplift: float = 0.0


@dataclass(frozen=True)
class ACIPassMetrics:
    total_findings: int
    inferred_findings: int
    coverage_ratio: float
    capabilities_detected: Dict[str, int] = field(default_factory=dict)
    chain_candidates_detected: Dict[str, int] = field(default_factory=dict)
    confidence_buckets: Dict[str, int] = field(default_factory=dict)
    uplifted_findings: int = 0


@dataclass(frozen=True)
class ACIPassOutput:
    finding_semantics: Dict[str, ACIFindingSemantic] = field(default_factory=dict)
    asset_semantics: Dict[str, ACIAssetSemantic] = field(default_factory=dict)
    metrics: ACIPassMetrics = field(default_factory=lambda: ACIPassMetrics(0, 0, 0.0))


# -------------------------------------------
# Nmap Adapter Pass
# -------------------------------------------

@dataclass(frozen=True)
class NmapAdapterPassOutput:
    """
    Derived Nmap adapter snapshot used by downstream scoring/TopN phases.
    """
    status: str
    source_file: Optional[str]
    host_count: int
    matched_asset_count: int
    unmatched_asset_ids: Tuple[str, ...] = ()
    asset_open_ports: Dict[str, Tuple[int, ...]] = field(default_factory=dict)
    nse_cves_by_asset: Dict[str, Tuple[str, ...]] = field(default_factory=dict)


# -------------------------------------------
# Summary Pass
# -------------------------------------------

@dataclass(frozen=True)
class SummaryPassOutput:
    """
    Aggregated summary statistics for reporting.
    """
    overview: Dict[str, Any]
    asset_summary: Dict[str, Any]
    finding_summary: Dict[str, Any]
    risk_distribution: Dict[str, Any]
    top_risks: Tuple[Dict[str, Any], ...]
    enrichment_metrics: Dict[str, Any]
    remediation_priorities: Dict[str, Any]
    decision_trace_summary: Dict[str, Any] = field(default_factory=dict)