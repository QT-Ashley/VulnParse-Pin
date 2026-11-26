# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from vulnparse_pin.utils.csv_exporter import (
    _sanitize_csv_cell,
    _sanitize_csv_row,
    ANALYST_PROFILE_COLUMNS,
    AUDIT_PROFILE_COLUMNS,
    FULL_PROFILE_COLUMNS,
)

def test_sanitize_csv_cell_dangerous_prefix():
    """
    Cells starting with =, +, -, @ MUST be prefixed with a single quote.
    """
    cases = {
        "=SUM(1,2)": "'=SUM(1,2)",
        "+1+2": "'+1+2",
        "-IMPERSONATION": "'-IMPERSONATION",
        r"@HYPERLINK(\"http://evil\")": r"'@HYPERLINK(\"http://evil\")",
    }

    for value, expected in cases.items():
        assert _sanitize_csv_cell(value) == expected

def test_sanitize_csv_cell_safe_values_unchanged():
    """
    Normal values, empty strings, and None should pass through unchanged.
    """
    assert _sanitize_csv_cell("normal text") == "normal text"
    assert _sanitize_csv_cell("12345") == "12345"
    assert _sanitize_csv_cell("") == ""
    assert _sanitize_csv_cell(None) is None

    # Non-strings should be returned as-is
    assert _sanitize_csv_cell(42) == 42
    assert _sanitize_csv_cell(3.14) == 3.14
    assert _sanitize_csv_cell(True) is True


def test_sanitize_csv_row_mixed_types():
    """
    Only string values in the row should be sanitized. Other types stay intact.
    """
    row = {
        "dangerous_eq": "=SUM(1,2)",
        "dangerous_plus": "+1+2",
        "safe_text": "hello",
        "int_value": 10,
        "float_value": 9.8,
        "none_value": None,
    }

    safe = _sanitize_csv_row(row)

    assert safe["dangerous_eq"] == "'=SUM(1,2)"
    assert safe["dangerous_plus"] == "'+1+2"
    assert safe["safe_text"] == "hello"
    assert safe["int_value"] == 10
    assert safe["float_value"] == 9.8
    assert safe["none_value"] is None


def test_csv_unicode_whitespace_normalization():
    """Leading unicode whitespace should still result in formula-prefixing."""
    val = "\u2000=evil"
    out = _sanitize_csv_cell(val)
    # original whitespace should be preserved and a quote inserted before stripped portion
    assert "'" in out
    assert out.strip().endswith("evil")


def test_csv_crlf_injection_neutralized():
    """Newlines and carriage returns should be escaped with literal \n."""
    inp = "line1\nline2\r\nline3"
    assert _sanitize_csv_cell(inp) == "line1\\nline2\\nline3"


def test_csv_preserves_numeric_types():
    """Numeric values in rows should not be coerced to strings during sanitization."""
    row = {"num": 123, "flt": 4.56, "txt": "hello"}
    safe = _sanitize_csv_row(row)
    assert isinstance(safe["num"], int)
    assert isinstance(safe["flt"], float)
    assert safe["txt"] == "hello"


def test_csv_export_includes_derived_fields_when_present(tmp_path):
    """When a scan has TopN/scoring results the resulting CSV should contain ranking columns."""
    from vulnparse_pin.utils.csv_exporter import export_to_csv
    from datetime import datetime
    from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
    from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
    from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
    from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
    from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
    from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
    from vulnparse_pin.core.classes.pass_classes import PassRunner
    from vulnparse_pin.utils.logger import LoggerWrapper
    from vulnparse_pin.io.pfhandler import PermFileHandler

    # build basic context and scan with one finding
    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)
    meta = ScanMetaData(source="unit", scan_date=datetime.now(), asset_count=0, vulnerability_count=0)
    f = Finding(finding_id="F", vuln_id="V", title="T", description="D", severity="Low", cves=[], asset_id="A")
    asset = Asset(hostname="A", ip_address="1.2.3.4", findings=[f])
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    # run passes to populate derived
    policy = ScoringPolicyV1(
        epss_scale=1, epss_min=0, epss_max=1,
        kev_evd=1, exploit_evd=1,
        band_critical=10, band_high=7, band_medium=4, band_low=1,
        asset_aggregation="max", w_epss_high=1, w_epss_medium=1, w_kev=1, w_exploit=1,
        max_raw_risk=10, max_op_risk=10,
    )
    scoring = ScoringPass(policy)
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([scoring, aci, topn])
    scan = runner.run_all(ctx, scan)

    # export
    csvfile = tmp_path / "out.csv"
    export_to_csv(ctx, scan, csv_path=csvfile)

    text = csvfile.read_text(encoding="utf-8")
    assert "topn_asset_rank" in text
    assert "topn_finding_rank" in text


def test_csv_export_handles_none_scores_gracefully(tmp_path):
    """CSV exporter should not crash with TypeError when findings have None/missing scores."""
    from vulnparse_pin.utils.csv_exporter import export_to_csv
    from datetime import datetime
    from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
    from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
    from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
    from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
    from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
    from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
    from vulnparse_pin.core.classes.pass_classes import PassRunner
    from vulnparse_pin.utils.logger import LoggerWrapper
    from vulnparse_pin.io.pfhandler import PermFileHandler

    # build context with a finding that will have no scores after enrichment
    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)
    meta = ScanMetaData(source="unit", scan_date=datetime.now(), asset_count=0, vulnerability_count=0)
    
    # finding with no CVE (will have no score)
    no_cve_finding = Finding(
        finding_id="F_NOCVE", vuln_id="V_NOCVE", title="No CVE", 
        description="Finding without CVE", severity="Low", cves=[], asset_id="A"
    )
    asset = Asset(hostname="A", ip_address="1.2.3.4", findings=[no_cve_finding])
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    # run passes; finding may have None score if enrichment doesn't cover it
    policy = ScoringPolicyV1(
        epss_scale=1, epss_min=0, epss_max=1,
        kev_evd=1, exploit_evd=1,
        band_critical=10, band_high=7, band_medium=4, band_low=1,
        asset_aggregation="max", w_epss_high=1, w_epss_medium=1, w_kev=1, w_exploit=1,
        max_raw_risk=10, max_op_risk=10,
    )
    scoring = ScoringPass(policy)
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([scoring, aci, topn])
    scan = runner.run_all(ctx, scan)

    # export; should NOT raise TypeError even if scores are None
    csvfile = tmp_path / "out_with_none_scores.csv"
    export_to_csv(ctx, scan, csv_path=csvfile)

    # verify export succeeded and contains data
    assert csvfile.exists()
    text = csvfile.read_text(encoding="utf-8")
    assert "F_NOCVE" in text, "Finding ID should be in CSV even with None scores"
    # verify sentinel values are used (fallback -1.0 for None scores)
    lines = text.split("\n")
    assert len(lines) > 1, "CSV should have header and data rows"

    # parse header and data row for F_NOCVE
    header = lines[0].split(",")
    # find the first non-empty data line that corresponds to F_NOCVE
    data_lines = [line for line in lines[1:] if line.strip()]
    fnocve_line = next((line for line in data_lines if "F_NOCVE" in line), None)
    assert fnocve_line is not None, "Data row for F_NOCVE should exist"
    fnocve_cols = fnocve_line.split(",")

    # identify numeric score columns that must use SENTINEL_SCORE (-1.0) when no enrichment data is present
    # Only check columns that are strictly numeric and expected to be None/sentinel for no-CVE findings.
    # Excluding: boolean fields (cisa_kev, exploit_available), string fields (exploit_ids, score_reason(s)),
    # and pass-computed scores like topn_exposure_score / topn_weighted_asset_score (always populated).
    _sentinel_cols = {"cvss_score", "epss_score", "raw_score", "operational_score", "asset_avg_risk_score"}
    score_indices = [idx for idx, col_name in enumerate(header) if col_name in _sentinel_cols]
    # ensure we actually detected some score-related columns
    assert score_indices, "Expected at least one sentinel-eligible numeric score column in CSV header"

    # all sentinel-eligible numeric columns for F_NOCVE should use the sentinel -1.0
    for idx in score_indices:
        assert fnocve_cols[idx] == "-1.0", (
            f"Expected sentinel -1.0 for column '{header[idx]}' "
            f"when scores are missing for F_NOCVE, got {fnocve_cols[idx]!r}"
        )


def test_csv_profile_full_preserves_legacy_header_order(tmp_path):
    """Default/full profile must preserve existing CSV schema ordering for compatibility."""
    from datetime import datetime
    from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
    from vulnparse_pin.utils.csv_exporter import export_to_csv
    from vulnparse_pin.utils.logger import LoggerWrapper
    from vulnparse_pin.io.pfhandler import PermFileHandler

    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)

    meta = ScanMetaData(source="unit", scan_date=datetime.now(), asset_count=1, vulnerability_count=1)
    finding = Finding(
        finding_id="F1",
        vuln_id="V1",
        title="Example",
        description="desc",
        severity="Low",
        cves=["CVE-2026-0001"],
        asset_id="A1",
    )
    asset = Asset(hostname="host1", ip_address="10.0.0.1", findings=[finding])
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    csvfile = tmp_path / "full.csv"
    export_to_csv(ctx, scan, csv_path=csvfile, csv_profile="full")
    header = csvfile.read_text(encoding="utf-8").splitlines()[0].split(",")

    assert header == FULL_PROFILE_COLUMNS


def test_csv_profile_analyst_outputs_targeted_columns(tmp_path):
    """Analyst profile should emit triage-focused columns only."""
    from datetime import datetime
    from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
    from vulnparse_pin.utils.csv_exporter import export_to_csv
    from vulnparse_pin.utils.logger import LoggerWrapper
    from vulnparse_pin.io.pfhandler import PermFileHandler

    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)

    meta = ScanMetaData(source="unit", scan_date=datetime.now(), asset_count=1, vulnerability_count=1)
    finding = Finding(
        finding_id="F2",
        vuln_id="V2",
        title="Example2",
        description="desc",
        severity="High",
        cves=["CVE-2026-0002"],
        asset_id="A2",
    )
    asset = Asset(hostname="host2", ip_address="10.0.0.2", findings=[finding])
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    csvfile = tmp_path / "analyst.csv"
    export_to_csv(ctx, scan, csv_path=csvfile, csv_profile="analyst")
    header = csvfile.read_text(encoding="utf-8").splitlines()[0].split(",")

    assert header == ANALYST_PROFILE_COLUMNS
    assert "solution" not in header
    assert "description" not in header


def test_csv_profile_audit_includes_traceability_columns(tmp_path):
    """Audit profile should include aggregation and contributor traceability columns."""
    from datetime import datetime
    from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
    from vulnparse_pin.utils.csv_exporter import export_to_csv
    from vulnparse_pin.utils.logger import LoggerWrapper
    from vulnparse_pin.io.pfhandler import PermFileHandler

    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)

    meta = ScanMetaData(source="unit", scan_date=datetime.now(), asset_count=1, vulnerability_count=1)
    finding = Finding(
        finding_id="F3",
        vuln_id="V3",
        title="Example3",
        description="desc",
        severity="Critical",
        cves=["CVE-2026-0003"],
        asset_id="A3",
    )
    asset = Asset(hostname="host3", ip_address="10.0.0.3", findings=[finding])
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    csvfile = tmp_path / "audit.csv"
    export_to_csv(ctx, scan, csv_path=csvfile, csv_profile="audit")
    header = csvfile.read_text(encoding="utf-8").splitlines()[0].split(",")

    assert header == AUDIT_PROFILE_COLUMNS
    assert "aggregation_mode" in header
    assert "top_contributor_1_cve" in header


def test_csv_profiles_surface_ghsa_visibility_fields(tmp_path):
    from datetime import datetime
    import csv
    from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
    from vulnparse_pin.utils.csv_exporter import export_to_csv
    from vulnparse_pin.utils.logger import LoggerWrapper
    from vulnparse_pin.io.pfhandler import PermFileHandler

    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)

    meta = ScanMetaData(source="unit", scan_date=datetime.now(), asset_count=1, vulnerability_count=1)
    finding = Finding(
        finding_id="FGHSA",
        vuln_id="VGHSA",
        title="GHSA Finding",
        description="desc",
        severity="Medium",
        cves=["CVE-2026-1234"],
        asset_id="AGHSA",
    )
    finding.references = ["https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"]

    asset = Asset(hostname="host-ghsa", ip_address="10.0.9.9", findings=[finding])
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    analyst_csv = tmp_path / "analyst_ghsa.csv"
    export_to_csv(ctx, scan, csv_path=analyst_csv, csv_profile="analyst")
    with analyst_csv.open("r", encoding="utf-8", newline="") as fh:
        row = next(csv.DictReader(fh))
    assert row["ghsa_advisory_match"] == "True"
    assert row["ghsa_reference_count"] == "1"

    audit_csv = tmp_path / "audit_ghsa.csv"
    export_to_csv(ctx, scan, csv_path=audit_csv, csv_profile="audit")
    with audit_csv.open("r", encoding="utf-8", newline="") as fh:
        row = next(csv.DictReader(fh))
    assert "GHSA-xxxx-yyyy-zzzz" in row["ghsa_references"]


def test_csv_export_does_not_write_doubled_crlf_on_windows_style_writer(tmp_path):
    from datetime import datetime
    from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding, RunContext, AppPaths
    from vulnparse_pin.utils.csv_exporter import export_to_csv
    from vulnparse_pin.utils.logger import LoggerWrapper
    from vulnparse_pin.io.pfhandler import PermFileHandler

    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)

    meta = ScanMetaData(source="unit", scan_date=datetime.now(), asset_count=1, vulnerability_count=1)
    finding = Finding(
        finding_id="FCRLF",
        vuln_id="VCRLF",
        title="Example",
        description="desc",
        severity="Low",
        cves=["CVE-2026-0001"],
        asset_id="ACRLF",
    )
    asset = Asset(hostname="host-crlf", ip_address="10.0.0.10", findings=[finding])
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    csvfile = tmp_path / "newline.csv"
    export_to_csv(ctx, scan, csv_path=csvfile)

    assert b"\r\r\n" not in csvfile.read_bytes()


def test_export_duckdb_csv_sanitizes_all_cells_and_supports_all_profiles(tmp_path):
    import csv
    import pytest
    from vulnparse_pin.storage.db import VppDatabase
    from vulnparse_pin.storage.repositories import (
        ensure_run,
        ingest_normalized_batches,
        upsert_enrichment_snapshots,
        upsert_scores,
        upsert_triage_decisions,
    )
    from vulnparse_pin.utils.csv_exporter import (
        V2_ANALYST_PROFILE_COLUMNS,
        V2_AUDIT_PROFILE_COLUMNS,
        V2_FULL_PROFILE_COLUMNS,
        export_duckdb_csv,
    )

    db = VppDatabase(tmp_path / "csv_v2.db")
    run_id = "run-csv-v2"
    ensure_run(db, run_id, vpp_version="2.0.0", profile="bod-26-04")
    ingest_normalized_batches(
        db,
        run_id,
        [
            [
                {
                    "ip_address": "10.0.0.5",
                    "hostname": "=HOST_EVIL()",
                    "source_format": "nessus-xml",
                    "scanner_sig": "nessus:1",
                    "title": "+SUM(1,2)\r\nline2",
                    "description": "\u2000@HYPERLINK(\"http://evil\")",
                    "solution": "-IMPERSONATION",
                    "severity": "Critical",
                    "cves": ["CVE-2024-5555"],
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
                "cve_id": "CVE-2024-5555",
                "cvss_score": 9.8,
                "cvss_version": "3.1",
                "cvss_provenance": "NVD",
                "epss_score": 0.45,
                "epss_percentile": 0.98,
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
                "raw_risk_score": 14.5,
                "operational_score": 9.0625,
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
                "sla_bucket": "3-day + Forensic Triage",
                "sla_days": 3,
                "decision_status": "active",
                "rationale_summary": "\t=TAB_EVIL()",
            }
        ],
    )

    for prof, expected_cols in (
        ("full", V2_FULL_PROFILE_COLUMNS),
        ("analyst", V2_ANALYST_PROFILE_COLUMNS),
        ("audit", V2_AUDIT_PROFILE_COLUMNS),
    ):
        out_csv = tmp_path / f"v2_{prof}.csv"
        export_duckdb_csv(db, run_id, out_csv, profile=prof)
        with out_csv.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            assert reader.fieldnames == expected_cols
            row = next(reader)
            assert row["asset_hostname"] == "'=host_evil()"
            assert row["title"] == "'+SUM(1,2)\\nline2"
            assert row["epss_percentile"] == "0.98"
            assert row["cvss_provenance"] == "NVD"
            assert row["cvss_version"] == "3.1"
            assert row["ssvc_action"] == "Act"
            assert row["sla_bucket"] == "3-day + Forensic Triage"
            if prof == "full":
                assert row["description"] == "\u2002'@HYPERLINK(\"http://evil\")"
                assert row["solution"] == "'-IMPERSONATION"
            if prof == "audit":
                assert row["rationale_summary"] == "\t'=TAB_EVIL()"

    with pytest.raises(ValueError, match="Unknown csv_profile"):
        export_duckdb_csv(db, run_id, tmp_path / "bad.csv", profile="unknown")
