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
)
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.classes.pass_classes import PassRunner
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
    scoring = ScoringPass(get_policy())
    topn = TopNPass(_safe_fallback_config())
    runner = PassRunner([scoring, topn])
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
    runner = PassRunner([scoring, topn])
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


# ---------- determinism and dependency tests ----------


def test_pass_pipeline_is_deterministic(tmp_path):
    ctx = make_ctx(tmp_path)
    base_scan = make_sample_scan()

    scoring = ScoringPass(get_policy())
    topn = TopNPass(_safe_fallback_config())
    runner = PassRunner([scoring, topn])

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
    # when scoring output is missing, TopN.run returns the original scan unchanged
    result = topn.run(ctx, scan)
    assert result == scan
    # derived context should still be empty
    assert not scan.derived.passes, "Derived context should remain empty if TopN skipped"


def test_downstream_uses_asset_level_asset_id(tmp_path):
    ctx = make_ctx(tmp_path)
    scan = make_sample_scan()

    scan.assets[0].asset_id = "ASSET-CANONICAL"
    for finding in scan.assets[0].findings:
        finding.asset_id = "ASSET-LEGACY"

    scan = _run_full_pipeline(ctx, scan)

    scoring = scan.derived.passes["Scoring@1.0"].data
    topn = scan.derived.passes["TopN@1.0"].data

    assert "ASSET-CANONICAL" in scoring.get("asset_scores", {})
    assert "ASSET-LEGACY" not in scoring.get("asset_scores", {})
    assert "ASSET-CANONICAL" in topn.get("findings_by_asset", {})
    assert "ASSET-LEGACY" not in topn.get("findings_by_asset", {})