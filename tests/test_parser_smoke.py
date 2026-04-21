import json
from pathlib import Path

import pytest

from vulnparse_pin.parsers.nessusXML_parser import NessusXMLParser
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser
from vulnparse_pin.parsers.nessus_parser import NessusParser
from vulnparse_pin.parsers.openvas_parser import OpenVASParser

from vulnparse_pin.core.classes.dataclass import (
    ScanResult,
    ScanMetaData,
    Asset,
    Finding,
    RunContext,
    AppPaths,
)
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.io.pfhandler import PermFileHandler


@pytest.fixture
def ctx(tmp_path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "parser.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


def _assert_basic_scan(scan: ScanResult):
    assert scan.assets and any(a.findings for a in scan.assets)
    for a in scan.assets:
        assert a.hostname
        for f in a.findings:
            assert f.finding_id


def _run_derived(scan: ScanResult, ctx: RunContext) -> ScanResult:
    scoring = ScoringPass(_make_policy())
    topn = TopNPass(_safe_fallback_config())
    aci = AttackCapabilityInferencePass(_safe_fallback_config().aci)
    runner = PassRunner([scoring, aci, topn])
    return runner.run_all(ctx, scan)


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


@pytest.mark.parametrize(
    "parser_cls, input_path, use_file, xfail",
    [
        (NessusXMLParser, Path("tests/regression_testing/nessus_xml/nessus_std.xml"), True, False),
        (OpenVASXMLParser, Path("tests/regression_testing/openvas_xml/openvas_std.xml"), True, False),
        # JSON parsers experimental/disabled – mark xfail
        (NessusParser, Path("tests/regression_testing/nessus_json/nessus_std.json"), False, True),
        (OpenVASParser, Path("tests/regression_testing/openvas_json/openvas_std.json"), False, True),
    ],
)
def test_parse_normalize_enrich_passes_smoke(ctx, parser_cls, input_path, use_file, xfail):
    # load data
    data = None
    if not use_file:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)

    # allow xfail for experimental json parsers
    if xfail:
        pytest.xfail("experimental/disabled parser")

    # instantiate parser
    if use_file:
        parser = parser_cls(ctx, filepath=str(input_path))
        scan = parser.parse()
    else:
        # bypass experimental parse() guard
        if parser_cls is NessusParser:
            parser = parser_cls(ctx, filepath=None)
            scan = parser._parse_json(data)
        else:
            # some constructors omit ctx; instantiate empty and attach data
            parser = parser_cls()
            scan = parser._parse_json(data)

    _assert_basic_scan(scan)
    scan2 = _run_derived(scan, ctx)
    # derived outputs should have been produced
    assert "Scoring@2.0" in scan2.derived.passes
    assert "TopN@1.0" in scan2.derived.passes
