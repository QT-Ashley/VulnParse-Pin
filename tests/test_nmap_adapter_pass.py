from __future__ import annotations

from datetime import datetime

from vulnparse_pin.core.classes.dataclass import Asset, RunContext, ScanMetaData, ScanResult
from vulnparse_pin.core.passes.Nmap.nmap_adapter_pass import NmapAdapterPass
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.classes.dataclass import Finding
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.core.apppaths import AppPaths


def _make_ctx(tmp_path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "nmap_pass.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    paths = AppPaths.resolve(portable=True)
    return RunContext(paths=paths, pfh=pfh, logger=logger)


def _make_scan() -> ScanResult:
    meta = ScanMetaData(
        source="unit-test",
        scan_date=datetime.now(),
        asset_count=2,
        vulnerability_count=0,
    )
    a1 = Asset(hostname="web-01", ip_address="10.0.0.10", findings=[], asset_id="ASSET-WEB")
    a2 = Asset(hostname="db-01", ip_address="10.0.0.11", findings=[], asset_id="ASSET-DB")
    return ScanResult(scan_metadata=meta, assets=[a1, a2])


def test_nmap_adapter_disabled_without_source(tmp_path) -> None:
    ctx = _make_ctx(tmp_path)
    scan = _make_scan()

    res = NmapAdapterPass(None).run(ctx, scan)

    assert res.meta.name == "nmap_adapter"
    assert res.data["status"] == "disabled"
    assert res.data["host_count"] == 0


def test_nmap_adapter_extracts_open_ports_and_matches_assets(tmp_path) -> None:
    ctx = _make_ctx(tmp_path)
    scan = _make_scan()

    nmap_xml = tmp_path / "scan.xml"
    nmap_xml.write_text(
        """
<nmaprun>
  <host>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web-01" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
      <port protocol="tcp" portid="443"><state state="open"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/></port>
    </ports>
    <hostscript>
      <script id="vulners" output="CVE-2024-10001\nCVE-2023-0002"/>
    </hostscript>
  </host>
</nmaprun>
        """.strip(),
        encoding="utf-8",
    )

    res = NmapAdapterPass(nmap_xml).run(ctx, scan)

    assert res.data["status"] == "enabled"
    assert res.data["host_count"] == 1
    assert res.data["matched_asset_count"] == 1
    assert tuple(res.data["asset_open_ports"]["ASSET-WEB"]) == (80, 443)
    assert set(res.data["nse_cves_by_asset"]["ASSET-WEB"]) == {"CVE-2024-10001", "CVE-2023-0002"}
    assert "ASSET-DB" in res.data["unmatched_asset_ids"]


def test_nmap_adapter_handles_non_nmap_root(tmp_path) -> None:
    ctx = _make_ctx(tmp_path)
    scan = _make_scan()

    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("<root></root>", encoding="utf-8")

    res = NmapAdapterPass(bad_xml).run(ctx, scan)

    assert res.data["status"] == "invalid_format"
    assert res.data["host_count"] == 0


def test_scoring_adds_nmap_observed_reason_for_matching_open_port(tmp_path) -> None:
    ctx = _make_ctx(tmp_path)

    meta = ScanMetaData(
        source="unit-test",
        scan_date=datetime.now(),
        asset_count=1,
        vulnerability_count=1,
    )
    finding = Finding(
        finding_id="F-1",
        vuln_id="V-1",
        title="Test finding",
        description="Test",
        severity="Medium",
        cves=[],
        cvss_score=6.0,
        epss_score=0.2,
        affected_port=443,
        protocol="tcp",
        asset_id="ASSET-WEB",
    )
    asset = Asset(hostname="web-01", ip_address="10.0.0.10", findings=[finding], asset_id="ASSET-WEB")
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    nmap_xml = tmp_path / "scan.xml"
    nmap_xml.write_text(
        """
<nmaprun>
  <host>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
        """.strip(),
        encoding="utf-8",
    )

    policy = ScoringPolicyV1(
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

    runner = PassRunner([NmapAdapterPass(nmap_xml), ScoringPass(policy)])
    out = runner.run_all(ctx, scan)

    scoring = out.derived.get("Scoring@2.0")
    assert scoring is not None
    rec = scoring.data["scored_findings"]["F-1"]
    assert "Nmap Port Observed" in rec["reason"]


def test_topn_nmap_tiebreak_floats_confirmed_port_finding_first(tmp_path) -> None:
    """Two equal-score findings on the same asset: the Nmap-confirmed port finding must rank first."""
    ctx = _make_ctx(tmp_path)

    meta = ScanMetaData(
        source="unit-test",
        scan_date=datetime.now(),
        asset_count=1,
        vulnerability_count=2,
    )
    # Both findings have identical CVSS/EPSS so scores will be equal.
    f_confirmed = Finding(
        finding_id="F-CONFIRMED",
        vuln_id="V-1",
        title="Finding on confirmed port",
        description="Test",
        severity="High",
        cves=[],
        cvss_score=7.5,
        epss_score=0.0,
        affected_port=443,
        protocol="tcp",
        asset_id="ASSET-WEB",
    )
    f_unconfirmed = Finding(
        finding_id="F-UNCONFIRMED",
        vuln_id="V-2",
        title="Finding on unconfirmed port",
        description="Test",
        severity="High",
        cves=[],
        cvss_score=7.5,
        epss_score=0.0,
        affected_port=8080,
        protocol="tcp",
        asset_id="ASSET-WEB",
    )
    asset = Asset(hostname="web-01", ip_address="10.0.0.10", findings=[f_confirmed, f_unconfirmed], asset_id="ASSET-WEB")
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    nmap_xml = tmp_path / "scan.xml"
    nmap_xml.write_text(
        """
<nmaprun>
  <host>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
        """.strip(),
        encoding="utf-8",
    )

    policy = ScoringPolicyV1(
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

    runner = PassRunner([
      NmapAdapterPass(nmap_xml),
      ScoringPass(policy),
      AttackCapabilityInferencePass(_safe_fallback_config().aci),
      TopNPass(_safe_fallback_config()),
    ])
    out = runner.run_all(ctx, scan)

    topn = out.derived.get("TopN@1.0")
    assert topn is not None
    findings_for_asset = topn.data["findings_by_asset"].get("ASSET-WEB", [])
    assert len(findings_for_asset) == 2
    ranked_ids = [f["finding_id"] for f in findings_for_asset]
    assert ranked_ids[0] == "F-CONFIRMED", (
        f"Expected Nmap-confirmed port finding to rank first, got {ranked_ids}"
    )
