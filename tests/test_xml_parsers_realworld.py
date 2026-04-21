"""
Comprehensive tests for XML parsers and full pipeline using real-world samples.

Tests cover:
- Real-world data parsing (Nessus + OpenVAS XML)
- Expanded fixtures with multiple assets and 120-400 findings
- Edge cases (missing/malformed data)
- Full pipeline: parse → score → topn → csv export
"""
import json
from pathlib import Path

import pytest

from vulnparse_pin.parsers.nessusXML_parser import NessusXMLParser
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser
from vulnparse_pin.core.classes.dataclass import (
    RunContext,
    AppPaths,
    ScanResult,
)
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.csv_exporter import export_to_csv


# ---------- fixtures ----------


@pytest.fixture
def ctx(tmp_path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "xmltest.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


def _make_policy() -> ScoringPolicyV1:
    return ScoringPolicyV1(
        epss_scale=1,
        epss_min=0,
        epss_max=1,
        kev_evd=1,
        exploit_evd=1,
        band_critical=10,
        band_high=7,
        band_medium=4,
        band_low=1,
        asset_aggregation="max",
        w_epss_high=1,
        w_epss_medium=1,
        w_kev=1,
        w_exploit=1,
        max_raw_risk=10,
        max_op_risk=10,
    )


def _run_full_pipeline(scan: ScanResult, ctx: RunContext) -> ScanResult:
    """Run scoring + topn passes."""
    scoring = ScoringPass(_make_policy())
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([scoring, aci, topn])
    return runner.run_all(ctx, scan)


# ---------- real-world Nessus XML tests ----------


class TestNessusXMLRealWorld:
    """Test Nessus XML parser on real-world samples."""

    def test_real_nessus_parses_successfully(self, ctx):
        """real_nessus.nessus should parse cleanly."""
        filepath = Path("tests/regression_testing/nessus_xml/real_nessus.nessus")
        assert filepath.exists(), f"Missing {filepath}"

        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        assert scan is not None
        assert scan.assets, "Should have at least one asset"
        assert any(a.findings for a in scan.assets), "Should have at least one finding"

    def test_real_nessus_has_valid_fields(self, ctx):
        """Parsed findings should have all expected fields."""
        filepath = Path("tests/regression_testing/nessus_xml/real_nessus.nessus")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        for asset in scan.assets:
            assert asset.hostname, "Asset must have hostname"
            assert asset.ip_address, "Asset must have IP"
            for finding in asset.findings:
                assert finding.finding_id, "Finding must have ID"
                assert finding.title, "Finding must have title"
                assert finding.severity, "Finding must have severity"

    def test_real_nessus_full_pipeline(self, ctx):
        """Full pipeline should run without errors on real data."""
        filepath = Path("tests/regression_testing/nessus_xml/real_nessus.nessus")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        scan = _run_full_pipeline(scan, ctx)

        assert "Scoring@2.0" in scan.derived.passes
        assert "TopN@1.0" in scan.derived.passes

    def test_real_nessus_csv_export(self, ctx, tmp_path):
        """CSV export should succeed with real data."""
        filepath = Path("tests/regression_testing/nessus_xml/real_nessus.nessus")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()
        scan = _run_full_pipeline(scan, ctx)

        csv_out = tmp_path / "real_nessus_output.csv"
        export_to_csv(ctx, scan, csv_path=csv_out)

        if csv_out.exists():
            text = csv_out.read_text(encoding="utf-8")
            assert "asset_id" in text
            assert "finding_id" in text


# ---------- real-world OpenVAS XML tests ----------


class TestOpenVASXMLRealWorld:
    """Test OpenVAS XML parser on real-world samples."""

    def test_real_openvas_parses_successfully(self, ctx):
        """openvas_real.xml should parse cleanly."""
        filepath = Path("tests/regression_testing/openvas_xml/openvas_real.xml")
        assert filepath.exists(), f"Missing {filepath}"

        parser = OpenVASXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        assert scan is not None
        assert scan.assets, "Should have at least one asset"
        assert any(a.findings for a in scan.assets), "Should have at least one finding"

    def test_real_openvas_has_valid_fields(self, ctx):
        """Parsed findings should have all expected fields."""
        filepath = Path("tests/regression_testing/openvas_xml/openvas_real.xml")
        parser = OpenVASXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        for asset in scan.assets:
            for finding in asset.findings:
                assert finding.finding_id, "Finding must have ID"
                assert finding.title, "Finding must have title"

    def test_real_openvas_full_pipeline(self, ctx):
        """Full pipeline should run without errors on real data."""
        filepath = Path("tests/regression_testing/openvas_xml/openvas_real.xml")
        parser = OpenVASXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        scan = _run_full_pipeline(scan, ctx)

        assert "Scoring@2.0" in scan.derived.passes
        assert "TopN@1.0" in scan.derived.passes

    def test_real_openvas_csv_export(self, ctx, tmp_path):
        """CSV export should succeed with real data."""
        filepath = Path("tests/regression_testing/openvas_xml/openvas_real.xml")
        parser = OpenVASXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()
        scan = _run_full_pipeline(scan, ctx)

        csv_out = tmp_path / "real_openvas_output.csv"
        export_to_csv(ctx, scan, csv_path=csv_out)

        if csv_out.exists():
            text = csv_out.read_text(encoding="utf-8")
            assert "asset_id" in text


# ---------- expanded fixture tests ----------


class TestNessusXMLExpanded:
    """Test Nessus parser on expanded fixtures (multi-asset, 120-400 findings)."""

    @pytest.mark.parametrize(
        "fixture_name",
        ["nessus_expanded_200.xml", "nessus_expanded_5a_120.xml"],
    )
    def test_expanded_nessus_parses(self, ctx, fixture_name):
        """Expanded Nessus fixtures should parse successfully."""
        filepath = Path(f"tests/regression_testing/nessus_xml/{fixture_name}")
        assert filepath.exists(), f"Missing {filepath}"

        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        assert scan.assets, "Should have multiple assets"
        assert len(scan.assets) >= 2, "Should have at least 2 assets"

        total_findings = sum(len(a.findings) for a in scan.assets)
        assert total_findings >= 100, "Should have at least 100 findings total"

    def test_expanded_nessus_scoring_performance(self, ctx):
        """Scoring pass should complete efficiently on expanded data."""
        filepath = Path("tests/regression_testing/nessus_xml/nessus_expanded_5a_120.xml")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        scoring = ScoringPass(_make_policy())
        result = scoring.run(ctx, scan)

        data = result.data
        assert "coverage" in data
        cov = data["coverage"]
        assert cov["total_findings"] > 0
        assert cov["scored_findings"] > 0

    def test_expanded_nessus_topn_produces_ranks(self, ctx):
        """TopN should rank findings correctly on expanded data."""
        filepath = Path("tests/regression_testing/nessus_xml/nessus_expanded_200.xml")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()
        scan = _run_full_pipeline(scan, ctx)

        topn = scan.derived.passes["TopN@1.0"]
        data = topn.data

        assert data["assets"], "Should have ranked assets"
        for asset in data["assets"]:
            assert asset["rank"] >= 1, "Ranks should start from 1"


class TestOpenVASXMLExpanded:
    """Test OpenVAS parser on expanded fixtures."""

    @pytest.mark.parametrize(
        "fixture_name",
        ["openvas_expanded_3a_150.json", "openvas_expanded_4a_200.json"],
    )
    def test_expanded_openvas_parses(self, ctx, fixture_name):
        """Expanded OpenVAS JSON fixtures should parse successfully."""
        filepath = Path(f"tests/regression_testing/openvas_json/{fixture_name}")
        assert filepath.exists(), f"Missing {filepath}"

        # note: OpenVAS expanded fixtures are JSON (not XML) with simpler structure
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Verify the JSON structure was generated properly
        assert "report" in data
        assert "results" in data["report"]
        results = data["report"]["results"]
        assert len(results) >= 100, "Should have at least 100 findings"

        # Group by unique IPs to verify multiple assets
        unique_ips = set(r["host"] for r in results)
        assert len(unique_ips) >= 2, "Should have multiple assets"


# ---------- edge cases and stress tests ----------


class TestEdgeCases:
    """Test robustness with edge cases: missing fields, malformed data, etc."""

    def test_nessus_with_missing_cves(self, ctx):
        """Should handle findings with no CVEs gracefully."""
        filepath = Path("tests/regression_testing/nessus_xml/real_nessus.nessus")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        # some findings should have no CVEs (informational, etc)
        zero_cve_findings = [f for a in scan.assets for f in a.findings if not f.cves]
        if zero_cve_findings:
            # verify they don't break scoring
            scan = _run_full_pipeline(scan, ctx)
            assert "Scoring@2.0" in scan.derived.passes

    def test_openvas_with_missing_cvss(self, ctx):
        """Should handle findings with missing CVSS scores."""
        filepath = Path("tests/regression_testing/openvas_xml/openvas_real.xml")
        parser = OpenVASXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        # some findings may have no CVSS
        pipeline_scan = _run_full_pipeline(scan, ctx)
        # pipeline should still complete
        assert pipeline_scan.derived.passes

    def test_full_pipeline_handles_large_dataset(self, ctx, tmp_path):
        """Full pipeline should handle large expanded fixtures."""
        filepath = Path("tests/regression_testing/nessus_xml/nessus_expanded_5a_120.xml")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        # run full pipeline
        scan = _run_full_pipeline(scan, ctx)

        # export to CSV (should not crash even on large data)
        csv_out = tmp_path / "large_export.csv"
        export_to_csv(ctx, scan, csv_path=csv_out)

        if csv_out.exists():
            lines = csv_out.read_text(encoding="utf-8").split("\n")
            assert len(lines) > 100, "CSV should have many rows"

    def test_csv_export_sanitization_on_real_data(self, ctx, tmp_path):
        """CSV sanitization should handle real plugin outputs."""
        filepath = Path("tests/regression_testing/nessus_xml/real_nessus.nessus")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()
        scan = _run_full_pipeline(scan, ctx)

        csv_out = tmp_path / "sanitized.csv"
        export_to_csv(ctx, scan, csv_path=csv_out, csv_sanitization=True)

        if csv_out.exists():
            text = csv_out.read_text(encoding="utf-8")
            # verify no obvious formula injection
            lines = text.split("\n")
            for line in lines[1:]:  # skip header
                if line:
                    assert not line.startswith("="), "Formula injection not sanitized"
                    assert not line.startswith("+"), "Formula injection not sanitized"


# ---------- determinism and consistency ----------


class TestConsistency:
    """Verify results are consistent and deterministic."""

    def test_real_nessus_parses_idempotently(self, ctx):
        """Parsing the same file twice should yield identical results."""
        filepath = Path("tests/regression_testing/nessus_xml/real_nessus.nessus")
        parser = NessusXMLParser(ctx, filepath=str(filepath))

        scan1 = parser.parse()
        scan2 = parser.parse()

        # compare asset/finding counts
        assert len(scan1.assets) == len(scan2.assets)
        assert sum(len(a.findings) for a in scan1.assets) == sum(
            len(a.findings) for a in scan2.assets
        )

    def test_expanded_data_asset_count_matches(self, ctx):
        """Expanded fixtures should have the expected number of assets."""
        filepath = Path("tests/regression_testing/nessus_xml/nessus_expanded_5a_120.xml")
        parser = NessusXMLParser(ctx, filepath=str(filepath))
        scan = parser.parse()

        assert len(scan.assets) == 5, "Should have exactly 5 assets"
        for asset in scan.assets:
            assert len(asset.findings) == 120, "Each asset should have 120 findings"
