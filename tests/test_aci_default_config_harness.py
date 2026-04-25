from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class ACICase:
    case_id: str
    title: str
    description: str
    port: int
    exploit_available: bool
    expect_caps: tuple[str, ...]
    reject_caps: tuple[str, ...]
    should_infer: bool


def _ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "aci-default-harness.log"))
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


def _harness_cases() -> list[ACICase]:
    return [
        ACICase(
            case_id="POS-RCE-EXPLOIT",
            title="Remote code execution in internet-facing service",
            description="Unauthenticated remote code execution and command injection observed.",
            port=443,
            exploit_available=True,
            expect_caps=("remote_execution", "command_execution", "initial_access"),
            reject_caps=(),
            should_infer=True,
        ),
        ACICase(
            case_id="POS-SQLI-DISCLOSURE",
            title="SQL injection in login endpoint",
            description="SQL injection allows UNION SELECT database query and sensitive data leak.",
            port=443,
            exploit_available=False,
            expect_caps=("sql_injection", "information_disclosure"),
            reject_caps=(),
            should_infer=True,
        ),
        ACICase(
            case_id="POS-PRIVESC",
            title="Kernel privilege escalation",
            description="Local privilege escalation via vulnerable kernel and sudo path.",
            port=65000,
            exploit_available=False,
            expect_caps=("privilege_escalation",),
            reject_caps=(),
            should_infer=True,
        ),
        ACICase(
            case_id="POS-AUTH-BYPASS",
            title="Authentication bypass with default credential",
            description="Bypass login and use default credential to access administrative functions.",
            port=443,
            exploit_available=False,
            expect_caps=("auth_bypass", "credential_access"),
            reject_caps=(),
            should_infer=True,
        ),
        ACICase(
            case_id="POS-LFI",
            title="Local file inclusion",
            description="Path traversal and local file inclusion can read /etc/passwd on target.",
            port=80,
            exploit_available=False,
            expect_caps=("local_file_inclusion",),
            reject_caps=(),
            should_infer=True,
        ),
        ACICase(
            case_id="EVIDENCE-INFO-BELOW-THRESH",
            title="Information disclosure warning",
            description="Information disclosure may leak sensitive data.",
            port=65000,
            exploit_available=False,
            expect_caps=("information_disclosure",),
            reject_caps=(),
            should_infer=False,
        ),
        ACICase(
            case_id="NEG-REMOTE-SERVICE-ONLY",
            title="Open TLS service",
            description="Network endpoint observed; manual review required.",
            port=443,
            exploit_available=False,
            expect_caps=(),
            reject_caps=("remote_execution", "initial_access"),
            should_infer=False,
        ),
        ACICase(
            case_id="NEG-PROTOCOL-ONLY",
            title="SSH service detected",
            description="Administrative endpoint observed; manual review required.",
            port=22,
            exploit_available=False,
            expect_caps=(),
            reject_caps=("lateral_movement",),
            should_infer=False,
        ),
        ACICase(
            case_id="NEG-GENERIC-EXPOSURE",
            title="General exposure rating",
            description="General exposure noted, no direct attack semantics supplied.",
            port=65000,
            exploit_available=False,
            expect_caps=(),
            reject_caps=("information_disclosure", "remote_execution", "initial_access"),
            should_infer=False,
        ),
    ]


def _build_scan(cases: list[ACICase]) -> ScanResult:
    findings: list[Finding] = []
    for case in cases:
        findings.append(
            Finding(
                finding_id=f"F-{case.case_id}",
                vuln_id=f"V-{case.case_id}",
                title=case.title,
                description=case.description,
                severity="High",
                cves=["CVE-2026-9999"],
                cvss_score=8.0,
                exploit_available=case.exploit_available,
                cve_analysis=[],
                affected_port=case.port,
                asset_id="A-HARNESS",
            )
        )

    asset = Asset(hostname="harness-host", ip_address="10.10.10.10", findings=findings)
    asset.asset_id = "A-HARNESS"
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="aci-default-harness",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=len(findings),
        ),
        assets=[asset],
    )


def test_aci_default_config_harness_balances_strictness_and_evidence(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    cfg = _safe_fallback_config()
    cases = _harness_cases()
    scan = _build_scan(cases)

    assert cfg.aci.min_confidence == 0.6

    runner = PassRunner([ScoringPass(_policy()), AttackCapabilityInferencePass(cfg.aci)])
    out = runner.run_all(ctx, scan)

    aci = out.derived.passes["ACI@1.0"].data
    metrics = aci["metrics"]
    semantics = aci["finding_semantics"]

    failures: list[str] = []
    expected_inferred = 0
    actual_inferred = 0
    controls = 0
    control_false_positives = 0

    for case in cases:
        rec = semantics[f"F-{case.case_id}"]
        caps = set(rec.get("capabilities", []))
        confidence = float(rec.get("confidence", 0.0) or 0.0)
        inferred = bool(caps) and confidence >= float(cfg.aci.min_confidence)

        if case.should_infer:
            expected_inferred += 1
        else:
            controls += 1
        if inferred:
            actual_inferred += 1

        missing = sorted(set(case.expect_caps) - caps)
        unexpected = sorted(caps.intersection(set(case.reject_caps)))
        if missing:
            failures.append(f"[{case.case_id}] missing expected capabilities: {missing}; got={sorted(caps)}")
        if unexpected:
            failures.append(f"[{case.case_id}] unexpected capabilities: {unexpected}; got={sorted(caps)}")

        if case.should_infer and not inferred:
            failures.append(
                f"[{case.case_id}] should infer under default threshold {cfg.aci.min_confidence}, got confidence={confidence:.3f}"
            )
        if not case.should_infer and inferred:
            control_false_positives += 1

    recall = (actual_inferred / expected_inferred) if expected_inferred else 1.0
    false_positive_rate = (control_false_positives / controls) if controls else 0.0

    if recall < 1.0:
        failures.append(f"default-config recall dropped below target: {recall:.3f} < 1.000")
    if false_positive_rate > 0.0:
        failures.append(f"default-config control false positive rate too high: {false_positive_rate:.3f} > 0.000")

    # Ensure below-threshold evidence still survives in capability traces.
    evidence_case = semantics["F-EVIDENCE-INFO-BELOW-THRESH"]
    assert "information_disclosure" in set(evidence_case.get("capabilities", []))
    assert float(evidence_case.get("confidence", 0.0) or 0.0) < float(cfg.aci.min_confidence)
    assert float(evidence_case.get("rank_uplift", 0.0) or 0.0) == 0.0

    assert metrics["inferred_findings"] == actual_inferred
    assert not failures, "\n".join(failures)
