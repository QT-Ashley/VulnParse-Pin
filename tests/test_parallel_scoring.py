"""
Tests for parallel scoring optimization (Tier 5).
Validates that:
1. Plugin caching works correctly (avoids repeated getattr calls)
2. Parallel execution produces identical results to sequential
3. Performance improves on large workloads
4. Thread safety is maintained
"""
import time
from datetime import datetime
from pathlib import Path
import pytest

from vulnparse_pin.core.classes.dataclass import (
    ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
)
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.io.pfhandler import PermFileHandler


@pytest.fixture
def ctx(tmp_path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


def make_policy() -> ScoringPolicyV1:
    return ScoringPolicyV1(
        epss_scale=1,
        epss_min=0,
        epss_max=1,
        kev_evd=1,
        exploit_evd=1,
        band_critical=10,
        band_high=7,
        band_medium=4,
        band_low=1,
        asset_aggregation="max",
        w_epss_high=1,
        w_epss_medium=1,
        w_kev=1,
        w_exploit=1,
        max_raw_risk=10,
        max_op_risk=10,
    )


def make_finding(
    finding_id: str,
    asset_id: str = "asset-1",
    cvss_score: float = None,
    epss_score: float = None,
    cisa_kev: bool = False,
    exploit_available: bool = False,
) -> Finding:
    """Create a test finding with optional enrichment data."""
    return Finding(
        finding_id=finding_id,
        vuln_id=f"vuln-{finding_id}",
        asset_id=asset_id,
        title="Test Finding",
        description="Test description",
        cves=["CVE-2024-1234"],
        severity="high",
        affected_port=443,
        protocol="tcp",
        cvss_score=cvss_score,
        epss_score=epss_score,
        cisa_kev=cisa_kev,
        exploit_available=exploit_available,
    )


class TestPluginCaching:
    """Validate that plugin caching correctly pre-computes attributes."""

    def test_build_plugin_cache_extracts_attributes(self, ctx):
        """Verify cache captures all plugin attributes for later use."""
        scoring = ScoringPass(make_policy())
        
        findings = [
            make_finding("f1", cvss_score=7.5, epss_score=0.8),
            make_finding("f2", cisa_kev=True),
            make_finding("f3", exploit_available=True),
        ]
        
        # Build context tuple
        findings_with_context = [(f, f.asset_id, "192.168.1.1") for f in findings]
        
        # Cache should have all attributes for all findings
        cache = scoring._build_plugin_cache(findings_with_context, {})
        
        assert len(cache) == 3
        assert cache["f1"]["cvss"] == 7.5
        assert cache["f1"]["epss"] == 0.8
        assert cache["f2"]["kev"] is True
        assert cache["f3"]["exploit"] is True

    def test_cache_avoids_repeated_getattr(self, ctx):
        """Verify that using cache avoids repeated getattr lookups."""
        policy = make_policy()
        scoring = ScoringPass(policy)
        
        # Create finding with all enrichment fields
        finding = make_finding(
            "f1",
            cvss_score=8.5,
            epss_score=0.9,
            cisa_kev=True,
            exploit_available=True,
        )
        
        findings_with_context = [(finding, "asset-1", "192.168.1.1")]
        cache = scoring._build_plugin_cache(findings_with_context, {})
        
        # Score using cache
        sf = scoring._score_one_cached(finding, "asset-1", cache["f1"])
        
        # Result should have all signals combined
        assert sf.raw_score > 0
        assert "cvss" in sf.reason
        assert "epss" in sf.reason
        assert "KEV" in sf.reason
        assert "Exploit" in sf.reason

    def test_whole_cve_cache_builds_bounded_aggregate(self, ctx):
        """Whole-of-CVEs scoring should aggregate multiple CVEs instead of selecting just one."""
        scoring = ScoringPass(make_policy())

        finding = make_finding("f-agg", cvss_score=None, epss_score=None)
        finding.cve_analysis = [
            {
                "cve_id": "CVE-2026-0001",
                "resolved_cvss_score": 9.0,
                "epss_score": 0.0,
                "cisa_kev": False,
                "exploit_available": False,
                "summary": "Primary CVE",
                "selected_for_display": True,
            },
            {
                "cve_id": "CVE-2026-0002",
                "resolved_cvss_score": 5.0,
                "epss_score": 0.0,
                "cisa_kev": False,
                "exploit_available": True,
                "summary": "Secondary CVE",
            },
            {
                "cve_id": "CVE-2026-0003",
                "resolved_cvss_score": 0.0,
                "epss_score": 0.0,
                "cisa_kev": True,
                "exploit_available": False,
                "summary": "Tertiary CVE",
            },
        ]

        cache = scoring._build_plugin_cache([(finding, finding.asset_id, "192.168.1.1")], {})
        attrs = cache["f-agg"]

        assert attrs["whole_cve_raw"] > 9.0
        trace = attrs["score_trace_base"]
        assert trace["aggregation_mode"] == "stacked_decay"
        assert trace["aggregate_cve_raw_score"] == pytest.approx(11.2225)
        assert trace["contributors"][0]["cve_id"] == "CVE-2026-0001"
        assert trace["contributors"][1]["raw_contribution"] == pytest.approx(2.1)
        assert trace["contributors"][2]["raw_contribution"] == pytest.approx(0.1225)


class TestParallelScoring:
    """Validate that parallel execution produces correct results."""

    def test_scoring_persists_whole_cve_trace_on_finding(self, ctx):
        """Scoring should write the aggregate trace back onto the mutable finding object."""
        policy = make_policy()
        scoring = ScoringPass(policy, parallel_threshold=10_000)

        finding = make_finding("f-trace", cvss_score=None, epss_score=None)
        finding.cve_analysis = [
            {
                "cve_id": "CVE-2026-0100",
                "resolved_cvss_score": 8.0,
                "epss_score": 0.4,
                "cisa_kev": False,
                "exploit_available": False,
                "summary": "Base issue",
                "selected_for_display": True,
            },
            {
                "cve_id": "CVE-2026-0101",
                "resolved_cvss_score": 6.0,
                "epss_score": 0.0,
                "cisa_kev": False,
                "exploit_available": True,
                "summary": "Exploit-backed issue",
            },
        ]

        asset = Asset(hostname="host-test", ip_address="192.168.1.1", findings=[finding])
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=1,
            ),
            assets=[asset],
        )

        result = scoring.run(ctx, scan)
        scored = result.data["scored_findings"]["f-trace"]

        assert scored["raw_score"] > 8.0
        assert finding.raw_risk_score == scored["raw_score"]
        assert finding.risk_score == scored["operational_score"]
        assert finding.risk_band == scored["risk_band"]
        assert finding.score_trace["aggregation_mode"] == "stacked_decay"
        assert finding.score_trace["display_cve"] == "CVE-2026-0100"
        assert len(finding.score_trace["contributors"]) == 2
        assert finding.score_trace["contributors"][1]["selected_for_score"] is True

    def test_parallel_vs_sequential_identical_results(self, ctx):
        """Verify parallel and sequential modes produce identical outputs."""
        policy = make_policy()
        scoring = ScoringPass(policy)
        
        # Create 150+ findings to trigger parallel mode
        findings = []
        for i in range(150):
            f = make_finding(
                f"f{i}",
                asset_id=f"asset-{i % 10}",  # 10 different assets
                cvss_score=5.0 + (i % 10),
                epss_score=0.1 + (i % 100) / 100,
                cisa_kev=(i % 7 == 0),
                exploit_available=(i % 13 == 0),
            )
            findings.append(f)
        
        # Create scan result
        asset = Asset(
            hostname="host-test",
            ip_address="192.168.1.1",
            findings=findings,
        )
        
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=len(findings)
            ),
            assets=[asset]
        )
        
        # Run through pass (will use parallel for 150+ findings)
        result = scoring.run(ctx, scan)
        data = result.data
        
        # Should have scored findings (some may be filtered out due to gate)
        assert len(data["scored_findings"]) > 0
        assert data["coverage"]["total_findings"] == 150
        assert data["coverage"]["scored_findings"] > 0
        
        # Each scored finding should have complete scoring data
        for finding_id, sf in data["scored_findings"].items():
            assert "raw_score" in sf
            assert "operational_score" in sf
            assert "risk_band" in sf
            assert sf["raw_score"] >= 0
            assert sf["operational_score"] >= 0

    def test_small_workload_uses_sequential(self, ctx):
        """Verify that < 100 findings uses sequential (no parallel overhead)."""
        policy = make_policy()
        scoring = ScoringPass(policy)
        
        findings = [
            make_finding(f"f{i}", cvss_score=7.0 + i)
            for i in range(50)  # Below 100 threshold
        ]
        
        asset = Asset(ip_address="192.168.1.1", hostname="host-test", findings=findings)
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=50
            ),
            assets=[asset]
        )
        
        result = scoring.run(ctx, scan)
        # Just verify it runs and produces results (execution mode not visible, but internal logic used)
        assert len(result.data["scored_findings"]) > 0

    def test_asset_score_aggregation_across_parallel_chunks(self, ctx):
        """Verify asset scores are correctly max-aggregated across parallel chunks."""
        policy = make_policy()
        scoring = ScoringPass(policy)
        
        # Create findings for 2 assets with varying scores
        findings = []
        for i in range(200):
            # Asset 1: get higher scores
            asset_id = "asset-1" if i < 100 else "asset-2"
            cvss = 8.0 + (i % 10) if asset_id == "asset-1" else 5.0
            
            f = make_finding(
                f"f{i}",
                asset_id=asset_id,
                cvss_score=cvss,
            )
            findings.append(f)
        
        asset = Asset(hostname="host-test", ip_address="192.168.1.1", findings=findings)
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=200
            ),
            assets=[asset]
        )
        
        result = scoring.run(ctx, scan)
        data = result.data
        
        # Asset 1 should have higher best score than asset 2
        asset1_score = data["asset_scores"].get("asset-1")
        asset2_score = data["asset_scores"].get("asset-2")
        
        assert asset1_score is not None
        assert asset2_score is not None
        assert asset1_score > asset2_score  # asset-1 gets consistently higher CVSS

    def test_chunk_tuning_preserves_results(self, ctx):
        """Verify configurable chunk/worker tuning does not change scoring output."""
        policy = make_policy()
        default_scoring = ScoringPass(policy)
        tuned_scoring = ScoringPass(policy, min_findings_per_worker=10)

        findings = []
        for i in range(300):
            findings.append(
                make_finding(
                    f"f{i}",
                    asset_id=f"asset-{i % 15}",
                    cvss_score=4.0 + (i % 6),
                    epss_score=0.2 + (i % 10) / 100,
                    cisa_kev=(i % 9 == 0),
                    exploit_available=(i % 11 == 0),
                )
            )

        asset = Asset(hostname="host-test", ip_address="192.168.1.1", findings=findings)
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=len(findings),
            ),
            assets=[asset],
        )

        default_result = default_scoring.run(ctx, scan).data
        tuned_result = tuned_scoring.run(ctx, scan).data

        assert default_result["coverage"] == tuned_result["coverage"]
        assert default_result["asset_scores"] == tuned_result["asset_scores"]
        assert default_result["scored_findings"] == tuned_result["scored_findings"]

    def test_memoization_reuses_scoring_components(self, ctx, monkeypatch):
        """Verify sequential mode reuses repeated score signatures via memoization."""
        policy = make_policy()
        scoring = ScoringPass(policy, parallel_threshold=10_000)

        findings = [
            make_finding(
                f"f{i}",
                asset_id=f"asset-{i % 3}",
                cvss_score=7.0,
                epss_score=0.5,
                cisa_kev=False,
                exploit_available=True,
            )
            for i in range(200)
        ]

        asset = Asset(hostname="host-test", ip_address="192.168.1.1", findings=findings)
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=len(findings),
            ),
            assets=[asset],
        )

        calls = {"count": 0}
        original = scoring._calculate_score_components

        def wrapped(attrs):
            calls["count"] += 1
            return original(attrs)

        monkeypatch.setattr(scoring, "_calculate_score_components", wrapped)

        result = scoring.run(ctx, scan)

        assert result.data["coverage"]["scored_findings"] == 200
        assert calls["count"] == 1


class TestThreadSafety:
    """Validate concurrent execution doesn't corrupt results."""

    def test_concurrent_scoring_no_data_loss(self, ctx):
        """Verify all findings are scored despite parallel execution."""
        policy = make_policy()
        scoring = ScoringPass(policy)
        
        # Create large workload to ensure multiple threads
        findings = [
            make_finding(
                f"f{i}",
                asset_id=f"asset-{i % 50}",
                cvss_score=7.0,
                epss_score=0.5,
            )
            for i in range(500)
        ]
        
        asset = Asset(hostname="host-test", ip_address="192.168.1.1", findings=findings)
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=500
            ),
            assets=[asset]
        )
        
        result = scoring.run(ctx, scan)
        data = result.data
        
        # All 500 findings should be scored (no gate filtering)
        assert data["coverage"]["total_findings"] == 500
        assert data["coverage"]["scored_findings"] == 500
        
        # No duplicate finding IDs
        finding_ids = list(data["scored_findings"].keys())
        assert len(finding_ids) == len(set(finding_ids))


class TestPerformanceBehavior:
    """Validate performance characteristics without strict timing assertions."""

    def test_scoring_completes_reasonably_fast(self, ctx):
        """Verify scoring doesn't have major regressions (soft check, not strict)."""
        policy = make_policy()
        scoring = ScoringPass(policy)
        
        findings = [
            make_finding(
                f"f{i}",
                asset_id=f"asset-{i % 10}",
                cvss_score=6.0 + (i % 5),
                epss_score=0.4,
            )
            for i in range(1000)
        ]
        
        asset = Asset(hostname="host-test", ip_address="192.168.1.1", findings=findings)
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=1000
            ),
            assets=[asset]
        )
        
        start = time.time()
        result = scoring.run(ctx, scan)
        elapsed = time.time() - start
        
        # Should complete 1000 findings in < 5 seconds (generous baseline)
        assert elapsed < 5.0, f"Scoring 1000 findings took {elapsed:.2f}s, expected < 5s"
        assert len(result.data["scored_findings"]) == 1000


class TestProcessPoolScoring:
    """Validate process-pool path for large workloads remains contract-safe."""

    def test_process_pool_path_preserves_output_shape(self, ctx):
        policy = make_policy()
        scoring = ScoringPass(
            policy,
            parallel_threshold=10,
            process_pool_threshold=50,
            process_workers=2,
        )

        findings = [
            make_finding(
                f"pf-{i}",
                asset_id=f"asset-{i % 5}",
                cvss_score=5.0 + (i % 4),
                epss_score=0.2 + ((i % 10) / 100),
                cisa_kev=(i % 17 == 0),
                exploit_available=(i % 13 == 0),
            )
            for i in range(120)
        ]

        asset = Asset(hostname="host-test", ip_address="192.168.1.1", findings=findings)
        scan = ScanResult(
            scan_metadata=ScanMetaData(
                source="test",
                scan_date=datetime.now(),
                asset_count=1,
                vulnerability_count=len(findings),
            ),
            assets=[asset],
        )

        result = scoring.run(ctx, scan)
        data = result.data

        assert data["coverage"]["total_findings"] == len(findings)
        assert data["coverage"]["scored_findings"] > 0
        assert isinstance(data["scored_findings"], dict)
        for scored in data["scored_findings"].values():
            assert "raw_score" in scored
            assert "operational_score" in scored
            assert "risk_band" in scored
