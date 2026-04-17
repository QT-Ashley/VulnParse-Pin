from datetime import datetime
from pathlib import Path

from vulnparse_pin.utils.enricher import (
    enrich_scan_results,
    _ghsa_high_severity_exploit_signal,
    _normalize_confidence_policy,
    _score_confidence_from_sources,
)
from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import Asset, Finding, RunContext, ScanMetaData, ScanResult
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.logger import LoggerWrapper


def test_normalize_confidence_policy_applies_defaults_and_bounds():
    policy = {
        "model_version": "v1",
        "max_score": 250,
        "base_scanner": -5,
        "weights": {
            "nvd": 30,
            "kev": -2,
            "epss": 11,
            "exploitdb": 12,
            "ghsa": 150,
        },
        "ghsa_signals": {
            "advisory_confidence_bonus": 999,
            "max_advisory_confidence_bonus": -4,
            "exploit_signal_on_high_severity": True,
            "exploit_signal_confidence_bonus": 101,
        },
    }

    out = _normalize_confidence_policy(policy)
    assert out["model_version"] == "v1"
    assert out["max_score"] == 100
    assert out["base_scanner"] == 0
    assert out["weights"]["nvd"] == 30
    assert out["weights"]["kev"] == 0
    assert out["weights"]["ghsa"] == 100
    assert out["ghsa_signals"]["advisory_confidence_bonus"] == 100
    assert out["ghsa_signals"]["max_advisory_confidence_bonus"] == 0
    assert out["ghsa_signals"]["exploit_signal_on_high_severity"] is True
    assert out["ghsa_signals"]["exploit_signal_confidence_bonus"] == 100


def test_score_confidence_from_sources_returns_audit_evidence():
    policy = _normalize_confidence_policy(
        {
            "model_version": "v1",
            "max_score": 100,
            "base_scanner": 35,
            "weights": {
                "nvd": 25,
                "kev": 15,
                "epss": 10,
                "exploitdb": 10,
                "ghsa": 15,
            },
            "ghsa_signals": {
                "advisory_confidence_bonus": 2,
                "max_advisory_confidence_bonus": 6,
                "exploit_signal_on_high_severity": True,
                "exploit_signal_confidence_bonus": 5,
            },
        }
    )

    score, evidence = _score_confidence_from_sources(
        ["scanner", "nvd", "ghsa"],
        policy,
        ghsa_advisory_count=2,
        ghsa_exploit_signal=True,
    )
    assert score == 84
    assert evidence["base_scanner"] == 35
    assert evidence["nvd"] == 25
    assert evidence["ghsa"] == 15
    assert evidence["ghsa_bonus"] == 4
    assert evidence["ghsa_exploit_signal"] == 5
    assert evidence["final"] == 84
    assert evidence["max_score"] == 100


def test_ghsa_high_severity_exploit_signal_requires_active_high_or_critical_advisory():
    advisories = [
        {"severity": "low"},
        {"database_specific": {"severity": "critical"}},
        {"severity": "high", "withdrawn_at": "2026-01-01T00:00:00Z"},
    ]

    assert _ghsa_high_severity_exploit_signal(advisories) is True


def _make_ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "enrichment_signal.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


def test_enrich_scan_results_promotes_exploit_available_on_high_severity_ghsa_signal(tmp_path: Path):
    meta = ScanMetaData(
        source="unit-test",
        scan_date=datetime.now(),
        asset_count=1,
        vulnerability_count=1,
    )
    finding = Finding(
        finding_id="F-GHSA-1",
        vuln_id="V-GHSA-1",
        title="Demo vulnerable package",
        description="demo",
        severity="Medium",
        cves=["CVE-2026-42424"],
        asset_id="A-1",
    )
    scan = ScanResult(
        scan_metadata=meta,
        assets=[Asset(hostname="host1", ip_address="10.0.0.10", asset_id="A-1", findings=[finding])],
    )

    ghsa_data = {
        "CVE-2026-42424": [
            {
                "id": "GHSA-test-high-signal",
                "severity": "HIGH",
                "references": [{"url": "https://github.com/advisories/GHSA-test-high-signal"}],
            }
        ]
    }
    policy = {
        "model_version": "v1",
        "max_score": 100,
        "base_scanner": 35,
        "weights": {
            "nvd": 25,
            "kev": 15,
            "epss": 10,
            "exploitdb": 10,
            "ghsa": 15,
        },
        "ghsa_signals": {
            "advisory_confidence_bonus": 3,
            "max_advisory_confidence_bonus": 9,
            "exploit_signal_on_high_severity": True,
            "exploit_signal_confidence_bonus": 5,
        },
    }

    enrich_scan_results(
        _make_ctx(tmp_path),
        scan,
        kev_data={},
        epss_data={},
        ghsa_data=ghsa_data,
        ghsa_package_data={},
        offline_mode=True,
        nvd_cache=None,
        confidence_policy=policy,
    )

    out = scan.assets[0].findings[0]
    assert out.exploit_available is True
    assert "ghsa" in out.enrichment_sources
    assert out.confidence_evidence.get("ghsa_exploit_signal", 0) > 0
