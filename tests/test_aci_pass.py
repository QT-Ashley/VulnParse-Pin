from dataclasses import replace
from datetime import datetime

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import Asset, Finding, RunContext, ScanMetaData, ScanResult
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.logger import LoggerWrapper


def _ctx(tmp_path):
    logger = LoggerWrapper(log_file=str(tmp_path / "aci.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    paths = AppPaths.resolve(portable=True)
    return RunContext(paths=paths, pfh=pfh, logger=logger)


def _policy() -> ScoringPolicyV1:
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


def _scan() -> ScanResult:
    f1 = Finding(
        finding_id="F-RCE",
        vuln_id="V-1",
        title="Remote code execution in edge service",
        description="Critical remote code execution can leak credential hash",
        severity="High",
        cves=["CVE-2026-0001"],
        cvss_score=8.0,
        exploit_available=False,
        cve_analysis=[{"cwe_ids": ["79", "CWE-89"], "exploit_available": False}],
        affected_port=443,
        asset_id="A-1",
    )
    f2 = Finding(
        finding_id="F-BASE",
        vuln_id="V-2",
        title="Generic vulnerability",
        description="No special signal",
        severity="High",
        cves=["CVE-2026-0002"],
        cvss_score=8.0,
        affected_port=65000,
        asset_id="A-1",
    )
    asset = Asset(hostname="edge", ip_address="8.8.8.8", findings=[f1, f2])
    asset.asset_id = "A-1"
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="unit-test",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=2,
        ),
        assets=[asset],
    )


def _scan_custom_marker(description: str) -> ScanResult:
    finding = Finding(
        finding_id="F-CUSTOM",
        vuln_id="V-CUSTOM",
        title="Custom marker vulnerability",
        description=description,
        severity="High",
        cves=["CVE-2026-9000"],
        cvss_score=8.0,
        exploit_available=False,
        cve_analysis=[],
        affected_port=65000,
        asset_id="A-CUSTOM",
    )
    asset = Asset(hostname="custom", ip_address="10.0.0.10", findings=[finding])
    asset.asset_id = "A-CUSTOM"
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="unit-test",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=1,
        ),
        assets=[asset],
    )


def _scan_remote_service_only() -> ScanResult:
    finding = Finding(
        finding_id="F-REMOTE-ONLY",
        vuln_id="V-REMOTE-ONLY",
        title="Open TLS service",
        description="Network endpoint observed; manual review required",
        severity="Medium",
        cves=["CVE-2026-9999"],
        cvss_score=5.0,
        exploit_available=False,
        cve_analysis=[],
        affected_port=443,
        asset_id="A-REMOTE-ONLY",
    )
    asset = Asset(hostname="web", ip_address="10.0.0.20", findings=[finding])
    asset.asset_id = "A-REMOTE-ONLY"
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="unit-test",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=1,
        ),
        assets=[asset],
    )


def _scan_protocol_only() -> ScanResult:
    finding = Finding(
        finding_id="F-PROTOCOL-ONLY",
        vuln_id="V-PROTOCOL-ONLY",
        title="SSH service detected",
        description="Administrative endpoint observed; manual review required",
        severity="Medium",
        cves=["CVE-2026-9998"],
        cvss_score=5.0,
        exploit_available=False,
        cve_analysis=[],
        affected_port=22,
        asset_id="A-PROTOCOL-ONLY",
    )
    asset = Asset(hostname="admin", ip_address="10.0.0.30", findings=[finding])
    asset.asset_id = "A-PROTOCOL-ONLY"
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="unit-test",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=1,
        ),
        assets=[asset],
    )


def _aci_enabled_cfg():
    base = _safe_fallback_config()
    aci_cfg = replace(
        base.aci,
        enabled=True,
        min_confidence=0.2,
        max_uplift=2.0,
        asset_uplift_weight=0.5,
    )
    return replace(base, aci=aci_cfg)


def test_aci_pass_emits_capabilities_and_cwe_ids(tmp_path):
    ctx = _ctx(tmp_path)
    scan = _scan()
    cfg = _aci_enabled_cfg()

    runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(cfg.aci)])
    out = runner.run_all(ctx, scan)

    aci = out.derived.passes["ACI@1.0"].data
    metrics = aci["metrics"]
    assert metrics["total_findings"] == 2
    assert metrics["inferred_findings"] >= 1

    f_rce = aci["finding_semantics"]["F-RCE"]
    assert f_rce["rank_uplift"] > 0.0
    assert "CWE-79" in f_rce["cwe_ids"]
    assert "CWE-89" in f_rce["cwe_ids"]


def test_topn_aci_uplift_is_tiebreak_only(tmp_path):
    ctx = _ctx(tmp_path)
    scan = _scan()
    cfg = _aci_enabled_cfg()

    runner = PassRunner([
        ScoringPass(_policy()),
        AttackCapabilityInferencePass(cfg.aci),
        TopNPass(cfg, process_pool_threshold=10000),
    ])
    out = runner.run_all(ctx, scan)

    topn = out.derived.passes["TopN@1.0"].data
    ranked = topn["findings_by_asset"]["A-1"]
    assert ranked[0]["finding_id"] == "F-RCE"
    assert ranked[0]["score"] == ranked[1]["score"]
    assert any("ACI Uplift" in reason for reason in ranked[0]["reasons"])


def test_topn_aci_parallel_parity(tmp_path):
    ctx = _ctx(tmp_path)
    scan_a = _scan()
    scan_b = _scan()
    cfg = _aci_enabled_cfg()

    seq_runner = PassRunner([
        ScoringPass(_policy()),
        AttackCapabilityInferencePass(cfg.aci),
        TopNPass(cfg, process_pool_threshold=10000),
    ])
    par_runner = PassRunner([
        ScoringPass(_policy()),
        AttackCapabilityInferencePass(cfg.aci),
        TopNPass(cfg, process_pool_threshold=1),
    ])

    out_seq = seq_runner.run_all(ctx, scan_a)
    out_par = par_runner.run_all(ctx, scan_b)

    assert out_seq.derived.passes["TopN@1.0"].data == out_par.derived.passes["TopN@1.0"].data


def test_aci_replace_mode_uses_config_alias_tokens(tmp_path):
    ctx = _ctx(tmp_path)
    scan = _scan_custom_marker("contains acme-rce-marker only")
    base = _safe_fallback_config()
    aci_cfg = replace(
        base.aci,
        enabled=True,
        min_confidence=0.2,
        token_mode="replace",
        signal_aliases=(("acme-rce-marker", "rce"),),
    )

    runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(aci_cfg)])
    out = runner.run_all(ctx, scan)

    aci = out.derived.passes["ACI@1.0"].data
    finding = aci["finding_semantics"]["F-CUSTOM"]
    assert "remote_execution" in finding["capabilities"]
    assert aci["metrics"]["inferred_findings"] == 1


def test_aci_merge_mode_can_disable_core_tokens(tmp_path):
    ctx = _ctx(tmp_path)
    scan = _scan_custom_marker("remote code execution")
    base = _safe_fallback_config()
    aci_cfg = replace(
        base.aci,
        enabled=True,
        min_confidence=0.2,
        token_mode="merge",
        disabled_core_tokens=("remote code execution",),
    )

    runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(aci_cfg)])
    out = runner.run_all(ctx, scan)

    aci = out.derived.passes["ACI@1.0"].data
    finding = aci["finding_semantics"]["F-CUSTOM"]
    assert "remote_execution" not in finding["capabilities"]


def test_aci_remote_service_only_does_not_imply_remote_exec_or_initial_access(tmp_path):
    ctx = _ctx(tmp_path)
    scan = _scan_remote_service_only()
    cfg = _aci_enabled_cfg()

    runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(cfg.aci)])
    out = runner.run_all(ctx, scan)

    aci = out.derived.passes["ACI@1.0"].data
    finding = aci["finding_semantics"]["F-REMOTE-ONLY"]
    assert "remote_execution" not in finding["capabilities"]
    assert "initial_access" not in finding["capabilities"]


def test_aci_generic_exposure_does_not_imply_information_disclosure(tmp_path):
    ctx = _ctx(tmp_path)
    scan = _scan_custom_marker("General exposure rating only")
    cfg = _aci_enabled_cfg()

    runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(cfg.aci)])
    out = runner.run_all(ctx, scan)

    aci = out.derived.passes["ACI@1.0"].data
    finding = aci["finding_semantics"]["F-CUSTOM"]
    assert "information_disclosure" not in finding["capabilities"]


def test_aci_protocol_only_does_not_imply_lateral_movement(tmp_path):
    ctx = _ctx(tmp_path)
    scan = _scan_protocol_only()
    cfg = _aci_enabled_cfg()

    runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(cfg.aci)])
    out = runner.run_all(ctx, scan)

    aci = out.derived.passes["ACI@1.0"].data
    finding = aci["finding_semantics"]["F-PROTOCOL-ONLY"]
    assert "lateral_movement" not in finding["capabilities"]
