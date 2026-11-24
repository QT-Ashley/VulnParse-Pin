# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

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
        del label
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

    nmap_adapter = DerivedPassResult(
        meta=PassMeta(name="nmap_adapter", version="1.0", created_at_utc="2026-03-29T00:00:00Z"),
        data={
            "status": "enabled",
            "source_file": "sample_nmap.xml",
            "host_count": 1,
            "matched_asset_count": 1,
            "unmatched_asset_ids": ["asset-b"],
            "asset_open_ports": {"asset-a": [22, 443]},
            "nse_cves_by_asset": {"asset-a": ["CVE-2021-44228"]},
        },
    )
    scoring = DerivedPassResult(
        meta=PassMeta(name="Scoring", version="1.0", created_at_utc="2026-03-29T00:00:01Z"),
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
        meta=PassMeta(name="TopN", version="1.0", created_at_utc="2026-03-29T00:00:02Z"),
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
        meta=PassMeta(name="Summary", version="1.0", created_at_utc="2026-03-29T00:00:03Z"),
        data={
            "overview": {"total_assets": 2, "total_findings": 10},
            "top_risks": [{"finding_id": "f-1"}],
        },
    )

    scan.derived = DerivedContext(
        passes={
            "nmap_adapter@1.0": nmap_adapter,
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
    assert metrics_by_name["nmap_adapter"]["status"] == "enabled"
    assert metrics_by_name["nmap_adapter"]["host_count"] == 1
    assert metrics_by_name["nmap_adapter"]["matched_asset_count"] == 1
    assert metrics_by_name["nmap_adapter"]["assets_with_open_ports"] == 1
    assert metrics_by_name["nmap_adapter"]["open_port_bindings"] == 2
    assert metrics_by_name["Scoring"]["scored_findings"] == 8
    assert metrics_by_name["TopN"]["ranked_assets"] == 1
    assert metrics_by_name["Summary"]["total_assets"] == 2


def test_runmanifest_enrichment_stats_include_ghsa_auth_rejections(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan_result = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan_result,
        sources={
            "exploitdb": False,
            "kev": True,
            "epss": True,
            "nvd": "Enabled",
            "stats": {
                "kev_hits": 1,
                "epss_hits": 1,
                "exploit_hits": 0,
                "ghsa_auth_token_rejections": 2,
            },
        },
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )

    assert manifest["enrichment_summary"]["stats"]["ghsa_auth_token_rejections"] == 2


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


def test_runmanifest_captures_whole_cve_alignment_metrics(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    scoring = DerivedPassResult(
        meta=PassMeta(name="Scoring", version="2.0", created_at_utc="2026-03-29T00:00:00Z"),
        data={
            "coverage": {"total_findings": 2, "scored_findings": 2, "coverage_ratio": 1.0},
            "scored_findings": {
                "F1": {
                    "raw_score": 9.1,
                    "operational_score": 9.1,
                    "risk_band": "Critical",
                    "reason": "Whole-of-CVEs Aggregated",
                    "score_trace": {
                        "aggregation_mode": "stacked_decay",
                        "union_flags": {"exploit": True, "kev": False},
                    },
                },
                "F2": {
                    "raw_score": 8.2,
                    "operational_score": 8.2,
                    "risk_band": "High",
                    "reason": "Whole-of-CVEs Aggregated",
                    "score_trace": {
                        "aggregation_mode": "stacked_decay",
                        "union_flags": {"exploit": False, "kev": True},
                    },
                },
            },
        },
    )

    topn = DerivedPassResult(
        meta=PassMeta(name="TopN", version="1.0", created_at_utc="2026-03-29T00:00:01Z"),
        data={
            "rank_basis": "raw",
            "k": 3,
            "decay": [1.0, 0.7, 0.4],
            "assets": [{"asset_id": "asset-a", "rank": 1}],
            "findings_by_asset": {
                "asset-a": [
                    {"finding_id": "F1", "rank": 1, "reasons": ["Whole-of-CVEs Aggregated", "Nmap Port Observed"]},
                    {"finding_id": "F2", "rank": 2, "reasons": ["Whole-of-CVEs Aggregated"]},
                ]
            },
            "global_top_findings": [{"finding_id": "F1", "rank": 1}],
        },
    )

    summary = DerivedPassResult(
        meta=PassMeta(name="Summary", version="1.0", created_at_utc="2026-03-29T00:00:02Z"),
        data={
            "overview": {"total_assets": 1, "total_findings": 2},
            "top_risks": [
                {
                    "cve": "CVE-2026-5000",
                    "finding_risk_score": 9.1,
                    "aggregated_cve_count": 3,
                    "aggregated_exploitable_cve_count": 1,
                }
            ],
            "remediation_priorities": {
                "immediate_action": 1,
                "high_priority": 1,
                "medium_priority": 0,
            },
        },
    )

    scan.derived = DerivedContext(
        passes={
            "Scoring@2.0": scoring,
            "TopN@1.0": topn,
            "Summary@1.0": summary,
        }
    )

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )

    metrics_by_name = {p["name"]: p["metrics"] for p in manifest["pass_summaries"]}

    assert metrics_by_name["Scoring"]["whole_cve_trace_findings"] == 2
    assert metrics_by_name["Scoring"]["union_exploit_findings"] == 1
    assert metrics_by_name["Scoring"]["union_kev_findings"] == 1

    assert metrics_by_name["TopN"]["whole_cve_reason_mentions"] == 2

    assert metrics_by_name["Summary"]["top_risks_with_aggregated_context"] == 1
    assert metrics_by_name["Summary"]["immediate_action"] == 1
    assert metrics_by_name["Summary"]["high_priority"] == 1


def test_runmanifest_handles_tuple_and_namespace_pass_payloads(tmp_path: Path):
    ctx = _make_context(tmp_path)
    scan = _make_scan_result()
    scanner_input = tmp_path / "input.nessus"
    scanner_input.write_text("dummy", encoding="utf-8")

    topn = DerivedPassResult(
        meta=PassMeta(name="TopN", version="1.0", created_at_utc="2026-03-29T00:00:01Z"),
        data={
            "rank_basis": "raw",
            "k": 5,
            "decay": (1.0, 0.7, 0.4),
            "assets": ({"asset_id": "asset-a", "rank": 1},),
            "findings_by_asset": {
                "asset-a": (
                    {"finding_id": "F1", "rank": 1, "reasons": ("Whole-of-CVEs Aggregated",)},
                )
            },
            "global_top_findings": ({"finding_id": "F1", "rank": 1},),
        },
    )

    summary_data = SimpleNamespace(
        overview={"total_assets": 1, "total_findings": 2},
        top_risks=(
            {
                "cve": "CVE-2026-5000",
                "finding_risk_score": 9.1,
                "aggregated_cve_count": 2,
            },
        ),
        remediation_priorities={"immediate_action": 1, "high_priority": 1, "medium_priority": 0},
    )
    summary = DerivedPassResult(
        meta=PassMeta(name="Summary", version="1.0", created_at_utc="2026-03-29T00:00:02Z"),
        data=summary_data,
    )

    scan.derived = DerivedContext(passes={"TopN@1.0": topn, "Summary@1.0": summary})

    manifest = build_runmanifest(
        ctx=ctx,
        _args=SimpleNamespace(),
        scan_result=scan,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        scanner_input=scanner_input,
        output_paths={"json": None, "csv": None, "md": None, "md_technical": None},
    )

    metrics_by_name = {p["name"]: p["metrics"] for p in manifest["pass_summaries"]}
    assert metrics_by_name["TopN"]["decay_weights"] == 3
    assert metrics_by_name["TopN"]["ranked_assets"] == 1
    assert metrics_by_name["TopN"]["global_top_findings"] == 1
    assert metrics_by_name["Summary"]["total_assets"] == 1
    assert metrics_by_name["Summary"]["top_risks"] == 1


def test_file_sha256_streams_large_files_accurately(tmp_path: Path):
    import hashlib
    from vulnparse_pin.utils.runmanifest import _file_sha256

    big_file = tmp_path / "big.bin"
    payload = (b"A1B2C3D4" * 300_000) + b"TAIL"  # ~2.4 MB (> 2x 1 MiB chunk)
    big_file.write_bytes(payload)

    expected = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    assert _file_sha256(big_file) == expected
    assert _file_sha256(tmp_path / "missing.bin") is None


def test_build_runmanifest_from_db_and_ledger_tamper_detection(tmp_path: Path):
    from vulnparse_pin.storage.db import VppDatabase
    from vulnparse_pin.storage.repositories import (
        ensure_run,
        ingest_normalized_batches,
        insert_ledger_events,
        upsert_enrichment_snapshots,
        upsert_scores,
        upsert_triage_decisions,
    )
    from vulnparse_pin.utils.runmanifest import build_runmanifest_from_db, verify_runmanifest

    db = VppDatabase(tmp_path / "manifest.db")
    run_id = "run-db-manifest"
    ensure_run(
        db,
        run_id,
        created_at_utc="2026-11-24T00:00:00Z",
        vpp_version="2.0.0",
        profile="bod-26-04",
        config_sha256="sha256:cfg",
        assets_sha256="sha256:assets",
        decisions_sha256="sha256:decisions",
        intel_metadata={
            "epss_model_version": "v2025.03.14",
            "epss_score_date": "2026-11-24",
            "kev_catalog_version": "2026.11.24",
            "nvd_status": "local-cache",
            "ghsa_enabled": True,
            "osv_enabled": True,
        },
        input_files=["scan.nessus"],
    )
    ingest_normalized_batches(
        db,
        run_id,
        [
            [
                {
                    "ip_address": "10.0.0.1",
                    "hostname": "app-1.local",
                    "source_format": "nessus-xml",
                    "scanner_sig": "nessus:1",
                    "title": "Sample CVE",
                    "severity": "High",
                    "cves": ["CVE-2024-1111"],
                    "detection_mode": "credentialed_host",
                    "ingestion_confidence": 0.95,
                }
            ]
        ],
    )
    fid = db.query_findings_page(run_id)[0][0]["finding_id"]
    aid = db.query_findings_page(run_id)[0][0]["asset_id"]
    upsert_enrichment_snapshots(
        db,
        run_id,
        [
            {
                "cve_id": "CVE-2024-1111",
                "cvss_score": 8.0,
                "cvss_version": "3.1",
                "cvss_provenance": "NVD",
                "epss_score": 0.12,
                "epss_percentile": 0.93,
                "in_kev": True,
                "verified_exploit": True,
            }
        ],
    )
    upsert_scores(
        db,
        run_id,
        [
            {
                "finding_id": fid,
                "asset_id": aid,
                "scoring_track": "cve_threat",
                "raw_risk_score": 13.0,
                "operational_score": 8.125,
                "risk_band": "Critical",
                "score_trace": {"cvss_provenance": "NVD"},
            }
        ],
    )
    upsert_triage_decisions(
        db,
        run_id,
        [
            {
                "finding_id": fid,
                "asset_id": aid,
                "profile": "bod-26-04",
                "priority_tier": "P1",
                "oal_compat": "OAL-1",
                "ssvc_action": "Act",
                "sla_bucket": "14-day",
                "sla_days": 14,
                "decision_status": "active",
            }
        ],
    )

    ledger = LedgerService()
    ledger.append_event(
        component="Scoring",
        event_type="decision",
        subject_ref="scoring:summary",
        reason_code="SCORING_SUMMARY_COMPUTED",
        reason_text="Scored 1 finding.",
        factor_refs=["epss_v5", "kev"],
    )
    snap = ledger.snapshot()
    insert_ledger_events(
        db,
        run_id,
        [
            {
                "seq": e.seq,
                "ts": e.ts,
                "component": e.component,
                "event_type": e.event_type,
                "subject_ref": e.subject_ref,
                "why": {
                    "reason_code": e.why.reason_code,
                    "reason_text": e.why.reason_text,
                    "factor_refs": e.why.factor_refs,
                    "confidence": e.why.confidence,
                    "weight_context": e.why.weight_context,
                },
                "evidence_digest": e.evidence_digest,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in snap.entries
        ],
    )

    manifest = build_runmanifest_from_db(
        db,
        run_id,
        config_hashes={"config_yaml_sha256": "sha256:cfg", "scoring_json_sha256": "sha256:sc", "tn_triage_json_sha256": "sha256:tn"},
        outputs={"csv": str(tmp_path / "out.csv"), "dossier_html": str(tmp_path / "dossier.html")},
        mode="compact",
    )
    verified = verify_runmanifest(manifest)
    assert verified["manifest_version"] == "2.0"
    assert verified["profile"] == "bod-26-04"
    assert verified["assets_sha256"] == "sha256:assets"
    assert verified["decisions_sha256"] == "sha256:decisions"
    assert verified["decision_ledger"]["entry_count"] == 1

    out_path = tmp_path / "db_manifest.json"
    write_runmanifest(None, manifest, out_path)
    assert verify_runmanifest(out_path)["run_id"] == run_id

    # Tamper ledger event stored in DuckDB and confirm verify_runmanifest detects it
    db.execute(
        "UPDATE ledger_events SET entry_hash = 'sha256:tampered' WHERE run_id = ? AND seq = 1",
        [run_id],
    )
    tampered_manifest = build_runmanifest_from_db(db, run_id)
    with pytest.raises(ValueError, match="entry_hash mismatch"):
        verify_runmanifest(tampered_manifest)
