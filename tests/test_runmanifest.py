import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnparse_pin.core.classes.dataclass import ScanMetaData, ScanResult
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.pass_classes import DerivedContext, DerivedPassResult, PassMeta
from vulnparse_pin.utils.runmanifest import (
    build_runmanifest,
    verify_runmanifest_integrity,
    verify_runmanifest_file,
    write_runmanifest,
)
from vulnparse_pin.utils.schema_validate import validate_runmanifest_schema


class _PfhStub:
    @contextmanager
    def open_for_write(self, output_path: Path, mode: str = "w", encoding: str = "utf-8", label: str = ""):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open(mode=mode, encoding=encoding) as handle:
            yield handle


def _make_context(tmp_path: Path):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "config.yaml").write_text("summary: {}\n", encoding="utf-8")
    (config_dir / "scoring.json").write_text("{}\n", encoding="utf-8")
    (config_dir / "tn_triage.json").write_text("{}\n", encoding="utf-8")

    ledger = LedgerService()
    services = SimpleNamespace(ledger=ledger)
    paths = SimpleNamespace(config_dir=config_dir)
    return SimpleNamespace(paths=paths, services=services, pfh=_PfhStub())


def _make_scan_result() -> ScanResult:
    md = ScanMetaData(
        source="Nessus",
        scan_date="2026-03-29T00:00:00Z",
        asset_count=0,
        vulnerability_count=0,
        parsed_at="2026-03-29T00:00:00Z",
    )
    return ScanResult(scan_metadata=md, assets=[])


def _make_scan_result_with_passes() -> ScanResult:
    scan = _make_scan_result()

    scoring = DerivedPassResult(
        meta=PassMeta(name="Scoring", version="1.0", created_at_utc="2026-03-29T00:00:00Z"),
        data={
            "coverage": {"total_findings": 10, "scored_findings": 8, "coverage_ratio": 0.8},
            "asset_scores": {"asset-a": 7.5, "asset-b": 5.1},
            "asset_criticality": {"asset-a": "High", "asset-b": "Medium"},
            "highest_risk_asset": "asset-a",
            "highest_risk_asset_score": 7.5,
            "avg_scored_risk": 6.2,
            "avg_operational_risk": 5.7,
        },
    )
    topn = DerivedPassResult(
        meta=PassMeta(name="TopN", version="1.0", created_at_utc="2026-03-29T00:00:01Z"),
        data={
            "rank_basis": "operational",
            "k": 3,
            "decay": [1.0, 0.7, 0.4],
            "assets": [{"asset_id": "asset-a", "rank": 1}],
            "findings_by_asset": {"asset-a": [{"finding_id": "f-1", "rank": 1}]},
            "global_top_findings": [{"finding_id": "f-1", "rank": 1}],
        },
    )
    summary = DerivedPassResult(
        meta=PassMeta(name="Summary", version="1.0", created_at_utc="2026-03-29T00:00:02Z"),
        data={
            "overview": {"total_assets": 2, "total_findings": 10},
            "top_risks": [{"finding_id": "f-1"}],
        },
    )

    scan.derived = DerivedContext(
        passes={
            "Scoring@1.0": scoring,
            "TopN@1.0": topn,
            "Summary@1.0": summary,
        }
    )
    return scan


def test_runmanifest_schema_and_integrity(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan_result = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    # Seed a small chain.
    ctx.services.ledger.append_event(
        component="Enrichment",
        event_type="phase_start",
        subject_ref="phase:enrichment",
        reason_code="ENRICHMENT_PHASE_STARTED",
        reason_text="Enrichment pipeline started.",
        factor_refs=["kev", "epss"],
    )
    ctx.services.ledger.append_event(
        component="PassRunner",
        event_type="pass_start",
        subject_ref="pass:Scoring@1.0",
        reason_code="PASS_EXECUTION_STARTED",
        reason_text="Starting pass.",
        factor_refs=["pass.name", "pass.version"],
    )

    sources = {
        "exploitdb": True,
        "kev": True,
        "epss": True,
        "nvd": "Enabled",
        "stats": {"kev_hits": 1, "epss_hits": 2, "exploit_hits": 3},
    }

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources=sources,
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )

    validate_runmanifest_schema(manifest)
    verify_runmanifest_integrity(manifest)

    assert manifest["decision_ledger"]["entry_count"] == 2
    assert manifest["verification"]["manifest_digest"].startswith("sha256:")


def test_runmanifest_integrity_detects_tampering(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan_result = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    ctx.services.ledger.append_event(
        component="PassRunner",
        event_type="pass_start",
        subject_ref="pass:Scoring@1.0",
        reason_code="PASS_EXECUTION_STARTED",
        reason_text="Starting pass.",
        factor_refs=["pass.name"],
    )

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )

    tampered = json.loads(json.dumps(manifest))
    tampered["decision_ledger"]["entries"][0]["why"]["reason_text"] = "Tampered"

    with pytest.raises(ValueError, match="entry_hash mismatch"):
        verify_runmanifest_integrity(tampered)


def test_runmanifest_includes_decision_reason_codes(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan_result = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    reason_codes = [
        DecisionReasonCodes.SCORING_SUMMARY_COMPUTED,
        DecisionReasonCodes.HIGHEST_RISK_ASSET_SELECTED,
        DecisionReasonCodes.ASSET_CRITICALITY_DERIVED,
        DecisionReasonCodes.TOPN_RANKING_COMPLETED,
        DecisionReasonCodes.TOP_ASSET_SELECTED,
        DecisionReasonCodes.EXPOSURE_INFERENCE_SUMMARY,
    ]

    for idx, code in enumerate(reason_codes, start=1):
        ctx.services.ledger.append_event(
            component="Test",
            event_type="decision",
            subject_ref=f"test:{idx}",
            reason_code=code,
            reason_text=f"reason={code}",
            factor_refs=["test.factor"],
        )

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )
    validate_runmanifest_schema(manifest)
    verify_runmanifest_integrity(manifest)

    present = {
        e["why"]["reason_code"]
        for e in manifest["decision_ledger"]["entries"]
        if e.get("event_type") == "decision"
    }
    for code in reason_codes:
        assert code in present


def test_runmanifest_populates_pass_metrics_and_mode(tmp_path: Path):
    ctx = _make_context(tmp_path)
    ctx.services.runmanifest_mode = "expanded"
    scan_result = _make_scan_result_with_passes()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )

    validate_runmanifest_schema(manifest)
    verify_runmanifest_integrity(manifest)

    assert manifest["runmanifest_mode"] == "expanded"
    metrics_by_name = {p["name"]: p["metrics"] for p in manifest["pass_summaries"]}
    assert metrics_by_name["Scoring"]["scored_findings"] == 8
    assert metrics_by_name["TopN"]["ranked_assets"] == 1
    assert metrics_by_name["Summary"]["total_assets"] == 2


def test_runmanifest_topn_skipped_artifact_metrics(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    topn_skipped = DerivedPassResult(
        meta=PassMeta(name="TopN", version="1.0", created_at_utc="2026-03-29T00:00:01Z"),
        data={
            "rank_basis": "raw",
            "k": 5,
            "decay": [1.0, 0.7, 0.5, 0.35, 0.25],
            "assets": [],
            "findings_by_asset": {},
            "global_top_findings": [],
            "status": "skipped",
            "error": {
                "code": "missing_dependency",
                "missing": ["Scoring@1.0"],
            },
        },
    )
    scan.derived = DerivedContext(passes={"TopN@1.0": topn_skipped})

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )

    validate_runmanifest_schema(manifest)
    verify_runmanifest_integrity(manifest)

    metrics_by_name = {p["name"]: p["metrics"] for p in manifest["pass_summaries"]}
    topn_metrics = metrics_by_name["TopN"]
    assert topn_metrics["status"] == "skipped"
    assert topn_metrics["error_code"] == "missing_dependency"
    assert topn_metrics["ranked_assets"] == 0


def test_verify_runmanifest_file_success(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan_result = _make_scan_result_with_passes()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )
    manifest_path = tmp_path / "runmanifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    verified = verify_runmanifest_file(manifest_path)
    assert verified["manifest_version"] == "1.0"


def test_verify_runmanifest_file_detects_tamper(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan_result = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    ctx.services.ledger.append_event(
        component="PassRunner",
        event_type="pass_start",
        subject_ref="pass:Scoring@1.0",
        reason_code="PASS_EXECUTION_STARTED",
        reason_text="Starting pass.",
        factor_refs=["pass.name"],
    )

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )
    manifest["decision_ledger"]["entries"][0]["why"]["reason_text"] = "tampered"
    manifest_path = tmp_path / "runmanifest_tampered.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="entry_hash mismatch"):
        verify_runmanifest_file(manifest_path)


def test_runmanifest_overwrite_replaces_tampered_file(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan_result = _make_scan_result_with_passes()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")
    manifest_path = tmp_path / "runmanifest_overwrite_test.json"

    # First write: valid manifest.
    baseline = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )
    write_runmanifest(ctx, baseline, manifest_path)

    baseline_hash = manifest_path.read_bytes()

    # Tamper same file and confirm verifier catches it.
    tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
    tampered["run_id"] = "TAMPERED_BY_TEST"
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="manifest_digest mismatch"):
        verify_runmanifest_file(manifest_path)

    # Re-write to the exact same path and verify it becomes trusted again.
    rewritten = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )
    write_runmanifest(ctx, rewritten, manifest_path)
    verified = verify_runmanifest_file(manifest_path)

    assert verified["manifest_version"] == "1.0"
    assert "TAMPERED_BY_TEST" not in manifest_path.read_text(encoding="utf-8")
    assert baseline_hash != manifest_path.read_bytes()
