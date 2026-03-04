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

@dataclass(frozen=True)
class ScoreCoverage:
    total_findings: int
    scored_findings: int
    coverage_ratio: float

@dataclass(frozen=True)
class ScoringPassOutput:
    scored_findings: Dict[str, ScoredFinding] = field(default_factory=dict)
    asset_scores: Dict[str, float] = field(default_factory=dict)
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