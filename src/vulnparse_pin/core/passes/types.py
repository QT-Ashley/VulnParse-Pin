from dataclasses import dataclass, field
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.pass_classes import DerivedPassResult
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult

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
