# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Pass pipeline exports and v2 DuckDB orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassRunner
from vulnparse_pin.core.config_projector import ConfigProjector, RuntimeConfigBundle
from vulnparse_pin.core.passes.ACI.aci_pass import ACIV2Pass, AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Nmap.nmap_adapter_pass import NmapAdapterPass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass, ScoringV3Pass
from vulnparse_pin.core.passes.Summary.summary_pass import SummaryConfig, SummaryPass, SummaryV2Pass
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass, TopNV2Pass
from vulnparse_pin.core.passes.Triage.triage_pass import TriageDecisionPass, TriagePass

if TYPE_CHECKING:
    from vulnparse_pin.core.assets_context import DecisionsRegistry
    from vulnparse_pin.core.classes.dataclass import RunContext


def run_v2_duckdb_pipeline(
    ctx: "RunContext",
    *,
    bundle: Optional[RuntimeConfigBundle] = None,
    profile: Optional[str] = None,
    nmap_path: Optional[str] = None,
    decisions_registry: Optional["DecisionsRegistry"] = None,
    now_utc: Optional[Any] = None,
    scan: Optional[ScanResult] = None,
) -> Dict[str, DerivedPassResult]:
    """
    Execute the canonical v2 DuckDB pass DAG via PassRunner:
      [NmapAdapter@1.0] -> ACI@2.0 -> Scoring@3.0 -> Triage@2.0 -> TopN@2.0 -> Summary@2.0
    """
    from pathlib import Path
    cfg_bundle = bundle or ConfigProjector.load_packaged_default_bundle()
    passes: List[Pass] = []
    if nmap_path:
        passes.append(NmapAdapterPass(nmap_source=Path(nmap_path)))
    passes.extend(
        [
            ACIV2Pass(cfg_bundle.topn_config),
            ScoringV3Pass(cfg_bundle.scoring_policy),
            TriageDecisionPass(
                cfg_bundle.triage_policy,
                profile=profile,
                decisions_registry=decisions_registry,
                now_utc=now_utc,
            ),
            TopNV2Pass(k=int(cfg_bundle.v2_config.summary_top_n)),
            SummaryV2Pass(SummaryConfig(include_top_risks=int(cfg_bundle.v2_config.summary_top_n))),
        ]
    )

    container = scan or ScanResult(
        scan_metadata=ScanMetaData(
            source="duckdb-v2",
            scan_date=datetime.now(timezone.utc),
            asset_count=0,
            vulnerability_count=0,
        ),
        assets=[],
    )
    runner = PassRunner(passes=passes)
    result_scan = runner.run_all(ctx, container)
    return dict(result_scan.derived.passes)


__all__ = [
    "ACIV2Pass",
    "AttackCapabilityInferencePass",
    "NmapAdapterPass",
    "ScoringPass",
    "ScoringV3Pass",
    "TriageDecisionPass",
    "TriagePass",
    "TopNPass",
    "TopNV2Pass",
    "SummaryPass",
    "SummaryV2Pass",
    "SummaryConfig",
    "run_v2_duckdb_pipeline",
]
