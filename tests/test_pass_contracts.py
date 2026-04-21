import copy
from datetime import datetime

import pytest

from vulnparse_pin.core.classes.dataclass import (
    ScanResult,
    ScanMetaData,
    Asset,
    Finding,
    RunContext,
    AppPaths,
    Services,
)
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Nmap.nmap_adapter_pass import NmapAdapterPass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.classes.pass_classes import PassRunner, DerivedPassResult, PassMeta
from vulnparse_pin.app.index_builder import build_post_enrichment_index
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.io.pfhandler import PermFileHandler


# ---------- helpers ----------

def make_ctx(tmp_path) -> RunContext:
    """Minimal RunContext suitable for pass execution."""
    logger = LoggerWrapper(log_file=str(tmp_path / "log.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    paths = AppPaths.resolve(portable=True)
    return RunContext(paths=paths, pfh=pfh, logger=logger)


def make_sample_scan() -> ScanResult:
    """Create a tiny ScanResult with two findings on a single asset."""
    meta = ScanMetaData(
        source="unit-test", scan_date=datetime.now(), asset_count=0, vulnerability_count=0
    )
    f1 = Finding(
        finding_id="F1",
        vuln_id="V1",
        title="T1",
        description="D1",
        severity="Low",
        cves=[],
        cvss_score=5.0,
        epss_score=0.1,
        asset_id="A1",
    )
    f2 = Finding(
        finding_id="F2",
        vuln_id="V2",
        title="T2",
        description="D2",
        severity="High",
        cves=[],
        cvss_score=8.0,
        epss_score=0.9,
        asset_id="A1",
    )
    asset = Asset(hostname="A1", ip_address="1.1.1.1", findings=[f1, f2])
    return ScanResult(scan_metadata=meta, assets=[asset])


def get_policy() -> ScoringPolicyV1:
    # very permissive, simple numbers so we can guarantee scoring occurs
    return ScoringPolicyV1(
        epss_scale=1.0,
        epss_min=0.0,
        epss_max=1.0,
        kev_evd=1.0,
        exploit_evd=1.0,
        band_critical=10.0,
        band_high=7.0,
        band_medium=4.0,
        band_low=1.0,
        asset_aggregation="max",
        w_epss_high=1.0,
        w_epss_medium=1.0,
        w_kev=1.0,
        w_exploit=1.0,
        max_raw_risk=10.0,
        max_op_risk=10.0,
    )


# ---------- derived pass contract tests ----------


def _run_full_pipeline(ctx, scan):
    # Some test cases call helper with reversed argument order; normalize here.
    if hasattr(ctx, "assets") and hasattr(scan, "logger"):
        ctx, scan = scan, ctx

    scoring = ScoringPass(get_policy())
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([scoring, aci, topn])
    return runner.run_all(ctx, scan)


def test_scoring_pass_output_shape(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()

    scoring = ScoringPass(get_policy())
    result = scoring.run(ctx, scan)
    data = result.data

    # structural keys
    assert "scored_findings" in data
    assert "asset_scores" in data
    assert "coverage" in data

    cov = data["coverage"]
    assert cov["total_findings"] >= cov["scored_findings"] >= 0
    assert 0.0 <= cov["coverage_ratio"] <= 1.0


def test_topn_pass_output_shape(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()
    scan = _run_full_pipeline(ctx, scan)

    topn = scan.derived.passes.get("TopN@1.0")
    assert topn is not None, "TopN result should exist"
    data = topn.data

    assert "assets" in data and isinstance(data["assets"], (list, tuple))
    assert "findings_by_asset" in data and isinstance(data["findings_by_asset"], dict)
    assert "global_top_findings" in data and isinstance(data["global_top_findings"], (list, tuple))


def test_topn_ranks_are_dense(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()
    scan = _run_full_pipeline(ctx, scan)
    topn = scan.derived.passes["TopN@1.0"]
    data = topn.data

    for aid, flist in data.get("findings_by_asset", {}).items():
        ranks = [f.get("rank") for f in flist]
        assert ranks == list(range(1, len(ranks) + 1)), "ranks must be 1..N without gaps"


def test_topn_basis_matches_config(tmp_path):
    ctx = make_ctx(tmp_path)
    cfg = _safe_fallback_config()
    scan = make_sample_scan()

    scoring = ScoringPass(get_policy())
    topn = TopNPass(cfg)
    aci = AttackCapabilityInferencePass(cfg.aci)
    runner = PassRunner([scoring, aci, topn])
    scan = runner.run_all(ctx, scan)

    data = scan.derived.passes["TopN@1.0"].data
    assert data.get("rank_basis") == cfg.topn.rank_basis


def test_topn_references_exist_in_truth(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()
    scan = _run_full_pipeline(ctx, scan)

    # collect truth finding ids
    truth_ids = {f.finding_id for a in scan.assets for f in a.findings}

    data = scan.derived.passes["TopN@1.0"].data
    for fid, frec in data.get("findings_by_asset", {}).items():
        for f in frec:
            assert f.get("finding_id") in truth_ids


def test_nmap_adapter_pass_can_run_before_scoring_and_topn(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()

    nmap = NmapAdapterPass(None)
    scoring = ScoringPass(get_policy())
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([nmap, scoring, aci, topn])

    out = runner.run_all(ctx, scan)

    assert out.derived.get("nmap_adapter@1.0") is not None
    assert out.derived.get("Scoring@2.0") is not None
    assert out.derived.get("ACI@1.0") is not None
    assert out.derived.get("TopN@1.0") is not None


# ---------- determinism and dependency tests ----------


def test_pass_pipeline_is_deterministic(tmp_path):
    ctx = make_ctx(tmp_path)
    base_scan = make_sample_scan()

    scoring = ScoringPass(get_policy())
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([scoring, aci, topn])

    scan1 = copy.deepcopy(base_scan)
    scan2 = copy.deepcopy(base_scan)

    out1 = runner.run_all(ctx, scan1)
    out2 = runner.run_all(ctx, scan2)

    # only compare derived data payloads (ignore timestamps)
    for key in out1.derived.passes:
        d1 = out1.derived.passes[key]
        d2 = out2.derived.passes[key]
        # names/versions should match
        assert d1.meta.name == d2.meta.name
        assert d1.meta.version == d2.meta.version
        assert d1.data == d2.data


def test_missing_pass_dependency_behavior(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()

    cfg = _safe_fallback_config()
    topn = TopNPass(cfg)
    # when scoring output is missing, TopN.run emits a soft no-op artifact
    result = topn.run(ctx, scan)
    assert result.meta.name == "TopN"
    assert result.data.get("status") == "skipped"
    err = result.data.get("error", {})
    assert err.get("code") == "missing_dependency"
    assert "Scoring@2.0" in err.get("missing", [])
    assert result.data.get("assets") in ([], ())
    assert result.data.get("findings_by_asset") == {}


def test_downstream_uses_asset_level_asset_id(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()

    scan.assets[0].asset_id = "ASSET-CANONICAL"
    for finding in scan.assets[0].findings:
        finding.asset_id = "ASSET-LEGACY"

    scan = _run_full_pipeline(ctx, scan)

    scoring = scan.derived.passes["Scoring@2.0"].data
    topn = scan.derived.passes["TopN@1.0"].data

    assert "ASSET-CANONICAL" in scoring.get("asset_scores", {})
    assert "ASSET-LEGACY" not in scoring.get("asset_scores", {})
    assert "ASSET-CANONICAL" in topn.get("findings_by_asset", {})
    assert "ASSET-LEGACY" not in topn.get("findings_by_asset", {})


def test_scoring_derives_and_persists_asset_criticality(tmp_path):
    """ScoringPass should derive asset criticality from risk-band counts and persist it on ScanResult assets."""
    ctx = make_ctx(tmp_path)

    findings = []
    for i in range(3):
        findings.append(
            Finding(
                finding_id=f"FCRIT-{i}",
                vuln_id=f"VCRIT-{i}",
                title=f"Critical-{i}",
                description="critical finding",
                severity="Critical",
                cves=[],
                cvss_score=10.0,
                asset_id="A1",
            )
        )

    asset = Asset(hostname="A1", ip_address="1.1.1.1", findings=findings)
    asset.asset_id = "A1"
    asset.criticality = None

    scan = ScanResult(
        scan_metadata=ScanMetaData(
            source="unit-test",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=3,
        ),
        assets=[asset],
    )

    scoring = ScoringPass(get_policy())
    result = scoring.run(ctx, scan)

    assert scan.assets[0].criticality == "Extreme"
    assert result.data["asset_criticality"]["A1"] == "Extreme"
    assert result.data["asset_band_counts"]["A1"]["Critical"] == 3


def test_topn_prefers_updated_scan_criticality_over_stale_index(tmp_path):
    """TopN should honor Scoring-updated criticality even when the post-enrichment index is stale."""
    ctx = make_ctx(tmp_path)

    # Asset with Extreme criticality after scoring (3 Critical findings).
    z_extreme_findings = [
        Finding(
            finding_id=f"ZE-{i}",
            vuln_id=f"V-ZE-{i}",
            title=f"ZE-{i}",
            description="extreme",
            severity="Critical",
            cves=[],
            cvss_score=10.0,
            asset_id="Z-EXTREME",
        )
        for i in range(3)
    ]
    z_extreme = Asset(hostname="z-extreme", ip_address="10.0.0.10", findings=z_extreme_findings)
    z_extreme.asset_id = "Z-EXTREME"

    # Asset with High criticality after scoring (2 Critical + 1 High => crit_high ties with Z-EXTREME).
    a_high_findings = [
        Finding(
            finding_id="AH-1",
            vuln_id="V-AH-1",
            title="AH-1",
            description="high",
            severity="Critical",
            cves=[],
            cvss_score=10.0,
            asset_id="A-HIGH",
        ),
        Finding(
            finding_id="AH-2",
            vuln_id="V-AH-2",
            title="AH-2",
            description="high",
            severity="Critical",
            cves=[],
            cvss_score=10.0,
            asset_id="A-HIGH",
        ),
        Finding(
            finding_id="AH-3",
            vuln_id="V-AH-3",
            title="AH-3",
            description="high",
            severity="High",
            cves=[],
            cvss_score=8.0,
            asset_id="A-HIGH",
        ),
    ]
    a_high = Asset(hostname="a-high", ip_address="10.0.0.20", findings=a_high_findings)
    a_high.asset_id = "A-HIGH"

    scan = ScanResult(
        scan_metadata=ScanMetaData(
            source="unit-test",
            scan_date=datetime.now(),
            asset_count=2,
            vulnerability_count=6,
        ),
        assets=[z_extreme, a_high],
    )

    # Build stale index before scoring derives and writes asset criticality.
    stale_index = build_post_enrichment_index(scan)
    ctx = RunContext(
        paths=ctx.paths,
        pfh=ctx.pfh,
        logger=ctx.logger,
        services=Services(post_enrichment_index=stale_index),
    )

    scoring = ScoringPass(get_policy())
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    out = PassRunner([scoring, aci, topn]).run_all(ctx, scan)

    ranked_assets = out.derived.passes["TopN@1.0"].data["assets"]
    assert ranked_assets[0]["asset_id"] == "Z-EXTREME"


# ---------- TopN mapping contract tests (Phase 2 verification) ----------

def test_topn_asset_exhaustiveness(tmp_path):
    """All input assets must appear in TopN output."""
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()
    
    # ensure asset_id is set on the sample asset
    scan.assets[0].asset_id = "A1"
    
    # create multi-asset dataset
    f3 = Finding(
        finding_id="F3",
        vuln_id="V3",
        title="T3",
        description="D3",
        severity="Medium",
        cves=[],
        cvss_score=6.0,
        epss_score=0.5,
        asset_id="A2",
    )
    asset2 = Asset(hostname="A2", ip_address="2.2.2.2", findings=[f3])
    asset2.asset_id = "A2"
    scan.assets.append(asset2)
    
    scan = _run_full_pipeline(scan, ctx)
    
    input_asset_ids = {a.asset_id for a in scan.assets if a.asset_id}
    output_findings_by_asset = scan.derived.passes["TopN@1.0"].data.get("findings_by_asset", {})
    output_asset_ids = set(output_findings_by_asset.keys())
    
    assert input_asset_ids == output_asset_ids, "All input assets must be in TopN output"


def test_topn_finding_completeness_single_asset(tmp_path):
    """All findings for an asset must be accounted for in TopN output."""
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()
    
    # ensure asset_id is set
    scan.assets[0].asset_id = "A1"
    
    scan = _run_full_pipeline(scan, ctx)
    
    input_findings_f1 = {f.finding_id for f in scan.assets[0].findings}
    output_findings = scan.derived.passes["TopN@1.0"].data.get("findings_by_asset", {}).get("A1", [])
    output_findings_ids = {f.get("finding_id") for f in output_findings}
    
    assert input_findings_f1 == output_findings_ids, "All findings must appear in TopN output"


def test_topn_no_cross_asset_leakage(tmp_path):
    """Findings from one asset must never appear under another asset's TopN list."""
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()
    
    # ensure asset_id is set on the sample asset
    scan.assets[0].asset_id = "A1"
    
    # add second asset
    f3 = Finding(
        finding_id="F3",
        vuln_id="V3",
        title="T3",
        description="D3",
        severity="Medium",
        cves=[],
        cvss_score=6.0,
        epss_score=0.5,
        asset_id="A2",
    )
    asset2 = Asset(hostname="A2", ip_address="2.2.2.2", findings=[f3])
    asset2.asset_id = "A2"
    scan.assets.append(asset2)
    
    scan = _run_full_pipeline(scan, ctx)
    
    truth_by_asset = {a.asset_id: {f.finding_id for f in a.findings} for a in scan.assets if a.asset_id}
    output_findings_by_asset = scan.derived.passes["TopN@1.0"].data.get("findings_by_asset", {})
    
    for asset_id, output_findings in output_findings_by_asset.items():
        output_fids = {f.get("finding_id") for f in output_findings}
        expected_fids = truth_by_asset.get(asset_id, set())
        
        assert output_fids == expected_fids, f"Asset {asset_id} has finding leakage or missing findings"


def test_topn_index_sorting_determinism(tmp_path):
    """Finding indices must sort consistently across runs."""
    ctx = make_ctx(tmp_path)
    base_scan = make_sample_scan()
    
    # ensure asset_id is set
    base_scan.assets[0].asset_id = "A1"
    
    scoring = ScoringPass(get_policy())
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([scoring, aci, topn])
    
    scan1 = copy.deepcopy(base_scan)
    scan2 = copy.deepcopy(base_scan)
    
    out1 = runner.run_all(ctx, scan1)
    out2 = runner.run_all(ctx, scan2)
    
    data1 = out1.derived.passes["TopN@1.0"].data.get("findings_by_asset", {})
    data2 = out2.derived.passes["TopN@1.0"].data.get("findings_by_asset", {})
    
    # check that the same asset ranks are preserved
    for asset_id in data1.keys():
        list1_ids = [f.get("finding_id") for f in data1[asset_id]]
        list2_ids = [f.get("finding_id") for f in data2[asset_id]]
        assert list1_ids == list2_ids, f"Asset {asset_id} finding order must be deterministic"


def test_topn_score_rank_consistency(tmp_path):
    """Higher scores should correlate with lower ranks (rank 1 = highest priority)."""
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()
    
    # ensure asset_id is set
    scan.assets[0].asset_id = "A1"
    
    scan = _run_full_pipeline(ctx, scan)
    
    output_findings = scan.derived.passes["TopN@1.0"].data.get("findings_by_asset", {}).get("A1", [])
    
    # since F2 has higher EPSS/CVSS than F1, it should rank higher (lower rank number)
    f1_rec = next((f for f in output_findings if f.get("finding_id") == "F1"), None)
    f2_rec = next((f for f in output_findings if f.get("finding_id") == "F2"), None)
    
    assert f1_rec and f2_rec, "Both findings should appear in output"
    assert f2_rec.get("rank", float('inf')) < f1_rec.get("rank", float('inf')), \
        "Finding with higher EPSS/CVSS should have lower (better) rank"


def test_pass_runner_rejects_missing_declared_dependency(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()

    class _DependentOnlyPass:
        name = "DependentOnly"
        version = "1.0"
        requires_passes = ("Scoring@2.0",)

        def run(self, _ctx, _scan):
            return DerivedPassResult(
                meta=PassMeta(name=self.name, version=self.version, created_at_utc=datetime.now().isoformat()),
                data={"ok": True},
            )

    runner = PassRunner([_DependentOnlyPass()])
    with pytest.raises(ValueError, match="requires missing dependency"):
        runner.run_all(ctx, scan)


def test_pass_runner_rejects_wrong_dependency_order(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()

    class _FakeScoring:
        name = "Scoring"
        version = "2.0"
        requires_passes = ()

        def run(self, _ctx, _scan):
            return DerivedPassResult(
                meta=PassMeta(name=self.name, version=self.version, created_at_utc=datetime.now().isoformat()),
                data={"scored_findings": {}},
            )

    class _NeedsScoring:
        name = "NeedsScoring"
        version = "1.0"
        requires_passes = ("Scoring@2.0",)

        def run(self, _ctx, _scan):
            return DerivedPassResult(
                meta=PassMeta(name=self.name, version=self.version, created_at_utc=datetime.now().isoformat()),
                data={"ok": True},
            )

    runner = PassRunner([_NeedsScoring(), _FakeScoring()])
    with pytest.raises(ValueError, match="must run after dependency"):
        runner.run_all(ctx, scan)