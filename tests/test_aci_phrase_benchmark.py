import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import Asset, Finding, RunContext, ScanMetaData, ScanResult
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.logger import LoggerWrapper


def _ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "aci-bench.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


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


def _load_cases() -> list[dict]:
    case_file = Path(__file__).parent / "benchmarks" / "aci_phrase_benchmark.json"
    return json.loads(case_file.read_text(encoding="utf-8"))


def _build_scan(case_id: str, title: str, description: str, affected_port: int, exploit_available: bool) -> ScanResult:
    finding = Finding(
        finding_id=f"F-{case_id}",
        vuln_id=f"V-{case_id}",
        title=title,
        description=description,
        severity="High",
        cves=["CVE-2026-9999"],
        cvss_score=8.0,
        exploit_available=bool(exploit_available),
        affected_port=int(affected_port),
        asset_id="A-BENCH",
    )
    asset = Asset(hostname="bench", ip_address="10.0.0.99", findings=[finding])
    asset.asset_id = "A-BENCH"
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="aci-phrase-benchmark",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=1,
        ),
        assets=[asset],
    )


def test_aci_phrase_benchmark_cases(tmp_path):
    ctx = _ctx(tmp_path)
    cfg = _aci_enabled_cfg()
    cases = _load_cases()

    assert cases, "Benchmark case list is empty"

    failures: list[str] = []

    for case in cases:
        case_id = str(case.get("id", "")).strip() or "unknown"
        scan = _build_scan(
            case_id=case_id,
            title=str(case.get("title", "")),
            description=str(case.get("description", "")),
            affected_port=int(case.get("affected_port", 0) or 0),
            exploit_available=bool(case.get("exploit_available", False)),
        )

        runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(cfg.aci)])
        out = runner.run_all(ctx, scan)
        rec = out.derived.passes["ACI@1.0"].data["finding_semantics"][f"F-{case_id}"]

        caps = set(rec.get("capabilities", []))
        confidence = float(rec.get("confidence", 0.0) or 0.0)

        expect_caps = set(case.get("expect_capabilities", []))
        reject_caps = set(case.get("reject_capabilities", []))

        missing = sorted(expect_caps - caps)
        unexpected = sorted(caps.intersection(reject_caps))

        if missing:
            failures.append(f"[{case_id}] missing expected capabilities: {missing}; got={sorted(caps)}")
        if unexpected:
            failures.append(f"[{case_id}] found rejected capabilities: {unexpected}; got={sorted(caps)}")

        min_conf = case.get("min_confidence")
        if min_conf is not None and confidence < float(min_conf):
            failures.append(f"[{case_id}] confidence {confidence:.3f} below min_confidence {float(min_conf):.3f}")

        max_conf = case.get("max_confidence")
        if max_conf is not None and confidence > float(max_conf):
            failures.append(f"[{case_id}] confidence {confidence:.3f} above max_confidence {float(max_conf):.3f}")

    assert not failures, "\n".join(failures)
