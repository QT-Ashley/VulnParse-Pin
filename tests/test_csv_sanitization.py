
from vulnparse_pin.utils.csv_exporter import (_sanitize_csv_cell, _sanitize_csv_row)

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
    runner = PassRunner([scoring, topn])
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
    runner = PassRunner([scoring, topn])
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
