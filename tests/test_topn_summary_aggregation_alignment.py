from datetime import datetime

from vulnparse_pin.core.classes.dataclass import (
    AppPaths,
    Asset,
    Finding,
    RunContext,
    ScanMetaData,
    ScanResult,
)
from vulnparse_pin.core.classes.pass_classes import DerivedContext, DerivedPassResult, PassMeta
from vulnparse_pin.core.passes.Summary.summary_pass import SummaryPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.logger import LoggerWrapper


def _make_ctx(tmp_path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "topn-summary-alignment.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


def _finding(finding_id: str, asset_id: str) -> Finding:
    return Finding(
        finding_id=finding_id,
        vuln_id=f"V-{finding_id}",
        title=f"Finding {finding_id}",
        description="test",
        severity="High",
        cves=["CVE-2026-1000"],
        cvss_score=8.0,
        asset_id=asset_id,
        affected_port=443,
        protocol="tcp",
    )


def _scan_with_assets(*assets: Asset) -> ScanResult:
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="unit-test",
            scan_date=datetime.now(),
            asset_count=len(assets),
            vulnerability_count=sum(len(a.findings) for a in assets),
        ),
        assets=list(assets),
    )


def _derived_scoring(scored_findings: dict) -> DerivedPassResult:
    return DerivedPassResult(
        meta=PassMeta(
            name="Scoring",
            version="2.0",
            created_at_utc="2026-04-17T00:00:00Z",
            notes="test",
        ),
        data={
            "scored_findings": scored_findings,
            "asset_scores": {},
            "coverage": {"total_findings": len(scored_findings), "scored_findings": len(scored_findings), "coverage_ratio": 1.0},
        },
    )


def _derived_aci() -> DerivedPassResult:
    return DerivedPassResult(
        meta=PassMeta(
            name="ACI",
            version="1.0",
            created_at_utc="2026-04-17T00:00:00Z",
            notes="test",
        ),
        data={
            "finding_semantics": {},
            "asset_semantics": {},
            "metrics": {
                "total_findings": 0,
                "inferred_findings": 0,
                "coverage_ratio": 0.0,
                "capabilities_detected": {},
                "chain_candidates_detected": {},
                "confidence_buckets": {"low": 0, "medium": 0, "high": 0},
                "uplifted_findings": 0,
            },
        },
    )


def test_topn_finding_tiebreak_prefers_exploit_breadth(tmp_path):
    ctx = _make_ctx(tmp_path)

    asset = Asset(hostname="a1", ip_address="10.0.0.1", findings=[_finding("F-1", "A1"), _finding("F-2", "A1")])
    asset.asset_id = "A1"

    scan = _scan_with_assets(asset)
    scan.derived = DerivedContext(
        passes={
            "Scoring@2.0": _derived_scoring(
                {
                    "F-1": {
                        "raw_score": 9.0,
                        "operational_score": 9.0,
                        "risk_band": "Critical",
                        "reason": "Whole-of-CVEs Aggregated",
                        "score_trace": {
                            "cve_count": 1,
                            "union_flags": {"exploit": False, "kev": False},
                            "contributors": [{"cve_id": "CVE-2026-1000", "exploit_available": False, "cisa_kev": False}],
                        },
                    },
                    "F-2": {
                        "raw_score": 9.0,
                        "operational_score": 9.0,
                        "risk_band": "Critical",
                        "reason": "Whole-of-CVEs Aggregated",
                        "score_trace": {
                            "cve_count": 3,
                            "union_flags": {"exploit": True, "kev": False},
                            "contributors": [
                                {"cve_id": "CVE-2026-2000", "exploit_available": True, "cisa_kev": False},
                                {"cve_id": "CVE-2026-2001", "exploit_available": True, "cisa_kev": False},
                                {"cve_id": "CVE-2026-2002", "exploit_available": False, "cisa_kev": False},
                            ],
                        },
                    },
                }
            ),
            "ACI@1.0": _derived_aci(),
        }
    )

    topn = TopNPass(_safe_fallback_config(), process_pool_threshold=50_000)
    out = topn.run(ctx, scan)

    ranked = out.data["findings_by_asset"]["A1"]
    assert ranked[0]["finding_id"] == "F-2"


def test_topn_asset_tiebreak_prefers_combined_cve_depth(tmp_path):
    ctx = _make_ctx(tmp_path)

    asset_a = Asset(hostname="a", ip_address="10.0.0.1", findings=[_finding("FA", "A")])
    asset_a.asset_id = "A"
    asset_b = Asset(hostname="b", ip_address="10.0.0.2", findings=[_finding("FB", "B")])
    asset_b.asset_id = "B"

    scan = _scan_with_assets(asset_a, asset_b)
    scan.derived = DerivedContext(
        passes={
            "Scoring@2.0": _derived_scoring(
                {
                    "FA": {
                        "raw_score": 8.0,
                        "operational_score": 8.0,
                        "risk_band": "High",
                        "reason": "Whole-of-CVEs Aggregated",
                        "score_trace": {
                            "cve_count": 4,
                            "union_flags": {"exploit": True, "kev": True},
                            "contributors": [
                                {"cve_id": "CVE-2026-3000", "exploit_available": True, "cisa_kev": True},
                                {"cve_id": "CVE-2026-3001", "exploit_available": True, "cisa_kev": False},
                            ],
                        },
                    },
                    "FB": {
                        "raw_score": 8.0,
                        "operational_score": 8.0,
                        "risk_band": "High",
                        "reason": "Whole-of-CVEs Aggregated",
                        "score_trace": {
                            "cve_count": 1,
                            "union_flags": {"exploit": False, "kev": False},
                            "contributors": [{"cve_id": "CVE-2026-4000", "exploit_available": False, "cisa_kev": False}],
                        },
                    },
                }
            ),
            "ACI@1.0": _derived_aci(),
        }
    )

    topn = TopNPass(_safe_fallback_config(), process_pool_threshold=50_000)
    out = topn.run(ctx, scan)

    ranked_assets = out.data["assets"]
    assert ranked_assets[0]["asset_id"] == "A"


def test_summary_uses_union_flags_for_immediate_action(tmp_path):
    ctx = _make_ctx(tmp_path)

    finding = _finding("F-SUM", "A1")
    finding.cisa_kev = False
    finding.exploit_available = False

    asset = Asset(hostname="sum-host", ip_address="10.0.0.10", findings=[finding])
    asset.asset_id = "A1"

    scan = _scan_with_assets(asset)
    scan.derived = DerivedContext(
        passes={
            "Scoring@2.0": _derived_scoring(
                {
                    "F-SUM": {
                        "raw_score": 9.5,
                        "operational_score": 9.5,
                        "risk_band": "Critical",
                        "reason": "Whole-of-CVEs Aggregated",
                        "score_trace": {
                            "display_cve": "CVE-2026-5555",
                            "cve_count": 2,
                            "union_flags": {"exploit": True, "kev": False},
                            "contributors": [
                                {"cve_id": "CVE-2026-5555", "exploit_available": True, "cisa_kev": False},
                                {"cve_id": "CVE-2026-5556", "exploit_available": False, "cisa_kev": False},
                            ],
                        },
                    }
                }
            )
        }
    )

    summary = SummaryPass().run(ctx, scan).data

    remediation = summary.remediation_priorities
    assert remediation["immediate_action"] == 1
    assert "CVE-2026-5555" in remediation["immediate_cves"]

    top_risks = list(summary.top_risks)
    assert top_risks[0]["aggregated_cve_count"] == 2
    assert top_risks[0]["aggregated_exploitable_cve_count"] == 1


def test_summary_emits_decision_trace_summary(tmp_path):
    ctx = _make_ctx(tmp_path)

    finding = _finding("F-TRACE", "A1")
    finding.exploit_available = False
    finding.cisa_kev = False
    asset = Asset(hostname="trace-host", ip_address="10.0.0.20", findings=[finding])
    asset.asset_id = "A1"

    scan = _scan_with_assets(asset)
    scan.derived = DerivedContext(
        passes={
            "Scoring@2.0": _derived_scoring(
                {
                    "F-TRACE": {
                        "raw_score": 8.2,
                        "operational_score": 8.2,
                        "risk_band": "High",
                        "reason": "Whole-of-CVEs Aggregated",
                        "score_trace": {
                            "display_cve": "CVE-2026-7777",
                            "cve_count": 1,
                            "union_flags": {"exploit": False, "kev": False},
                            "contributors": [
                                {"cve_id": "CVE-2026-7777", "exploit_available": False, "cisa_kev": False},
                            ],
                        },
                    }
                }
            ),
            "TopN@1.0": DerivedPassResult(
                meta=PassMeta(
                    name="TopN",
                    version="1.0",
                    created_at_utc="2026-04-22T00:00:00Z",
                    notes="test",
                ),
                data={
                    "assets": [
                        {
                            "asset_id": "A1",
                            "inference": {
                                "confidence": "medium",
                                "evidence_rule_ids": ["public_ip", "finding_text_exposure_hint"],
                            },
                        }
                    ],
                    "findings_by_asset": {
                        "A1": [
                            {"finding_id": "F-TRACE", "asset_id": "A1", "rank": 1, "risk_band": "high"},
                            {"finding_id": "F-TRACE2", "asset_id": "A1", "rank": 2, "risk_band": "critical"},
                        ]
                    },
                },
            ),
            "ACI@1.0": DerivedPassResult(
                meta=PassMeta(
                    name="ACI",
                    version="1.0",
                    created_at_utc="2026-04-22T00:00:00Z",
                    notes="test",
                ),
                data={
                    "metrics": {
                        "inferred_findings": 3,
                        "chain_candidates_detected": {"chain_initial_to_credential": 2},
                    }
                },
            ),
        }
    )

    summary = SummaryPass().run(ctx, scan).data
    trace = summary.decision_trace_summary

    assert trace["assets_with_exposure_inference"] == 1
    assert trace["exposure_confidence_counts"]["medium"] == 1
    assert trace["exposure_rule_hit_counts"]["public_ip"] == 1
    assert trace["aci_inferred_findings"] == 3
    assert trace["aci_chain_candidates_detected"]["chain_initial_to_credential"] == 2
    assert trace["findings_by_risk_band"]["high"] == 1
    assert trace["findings_by_risk_band"]["critical"] == 1
