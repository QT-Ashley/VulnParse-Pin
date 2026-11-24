# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tracemalloc

import pytest

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import RunContext, Services
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.parsers.base_parser import BaseParser, VALID_SEVERITIES
from vulnparse_pin.parsers.nessusXML_parser import NessusXMLParser
from vulnparse_pin.parsers.nessus_csv_parser import NessusCSVParser
from vulnparse_pin.parsers.nmap_parser import NmapXMLParser
from vulnparse_pin.parsers.nuclei_jsonl_parser import NucleiJSONLParser
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser
from vulnparse_pin.parsers.qualys_csv_parser import QualysCSVParser
from vulnparse_pin.parsers.qualys_parser import QualysXMLParser
from vulnparse_pin.parsers.sarif_parser import SarifParser
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema
from vulnparse_pin.utils.validations import FileInputValidator


REQUIRED_RECORD_KEYS = frozenset(
    {
        "ip_address",
        "hostname",
        "target_uri",
        "image_or_repo",
        "os",
        "asset_metadata",
        "source_format",
        "scanner_sig",
        "title",
        "description",
        "solution",
        "plugin_output",
        "severity",
        "cves",
        "cwes",
        "ghsa_ids",
        "affected_port",
        "protocol",
        "service_name",
        "location_uri",
        "line_number",
        "package_purl",
        "scanner_cvss_score",
        "scanner_cvss_vector",
        "detection_mode",
        "fidelity_tier",
        "ingestion_confidence",
        "missing_fields",
        "degraded_input",
        "references",
        "tags",
        "exploit_evidence",
        "raw_evidence_excerpt",
    }
)

VALID_DETECTION_MODES = frozenset(
    {
        "credentialed_host",
        "uncredentialed_banner",
        "active_dast",
        "sca_container",
        "static_sast",
        "network_probe",
    }
)
VALID_FIDELITY = frozenset({"high", "medium", "low"})


def _make_ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "streaming_test.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    return RunContext(
        paths=AppPaths.resolve(portable=True),
        pfh=pfh,
        logger=logger,
        services=Services(ledger=LedgerService()),
    )


def _assert_record_contract(rec: dict) -> None:
    assert set(rec.keys()) == REQUIRED_RECORD_KEYS
    assert rec["severity"] in VALID_SEVERITIES
    assert rec["detection_mode"] in VALID_DETECTION_MODES
    assert rec["fidelity_tier"] in VALID_FIDELITY
    assert isinstance(rec["ingestion_confidence"], float)
    assert 0.0 <= rec["ingestion_confidence"] <= 1.0
    assert isinstance(rec["cves"], list)
    assert "SENTINEL:No_CVE_Listed" not in rec["cves"]
    assert isinstance(rec["cwes"], list)
    assert isinstance(rec["ghsa_ids"], list)
    assert isinstance(rec["asset_metadata"], dict)
    assert isinstance(rec["missing_fields"], list)
    assert isinstance(rec["degraded_input"], bool)
    assert isinstance(rec["references"], list)
    assert isinstance(rec["tags"], list)
    assert isinstance(rec["raw_evidence_excerpt"], str)


def test_nessus_xml_credentialed_no_truncation_v2_vector_and_no_cve_sentinel(tmp_path: Path) -> None:
    long_desc = "D" * 600 + " CWE-79"
    long_sol = "S" * 600
    long_out = "O" * 600
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="CredScan">
    <ReportHost name="web-01.internal">
      <HostProperties>
        <tag name="host-ip">10.10.20.5</tag>
        <tag name="host-fqdn">web-01.internal</tag>
        <tag name="Credentialed_checks">yes</tag>
        <tag name="operating-system">Ubuntu 24.04</tag>
      </HostProperties>
      <ReportItem pluginID="90001" pluginName="Long Finding" severity="3" port="8443" protocol="tcp" svc_name="https">
        <description>{long_desc}</description>
        <solution>{long_sol}</solution>
        <plugin_output>{long_out}</plugin_output>
        <risk_factor>High</risk_factor>
        <cvss_base_score>7.5</cvss_base_score>
        <cvss_vector>AV:N/AC:L/Au:N/C:P/I:P/A:P</cvss_vector>
        <see_also>https://example.org/advisory</see_also>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.10.20.6">
      <HostProperties>
        <tag name="host-ip">10.10.20.6</tag>
        <tag name="Credentialed_checks">no</tag>
      </HostProperties>
      <ReportItem pluginID="90002" pluginName="Uncred Finding" severity="2" port="80" protocol="tcp" svc_name="http">
        <description>Short desc</description>
        <cve>CVE-2024-5555</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
    f = tmp_path / "cred.nessus"
    f.write_text(xml, encoding="utf-8")
    ctx = _make_ctx(tmp_path)

    parser = NessusXMLParser(ctx, f)
    records = [r for batch in parser.iter_batches(batch_size=1) for r in batch]
    assert len(records) == 2
    for r in records:
        _assert_record_contract(r)

    r0, r1 = records[0], records[1]
    assert r0["source_format"] == "nessus-xml"
    assert r0["detection_mode"] == "credentialed_host"
    assert r0["asset_metadata"]["credentialed"] is True
    assert len(r0["description"]) > 500
    assert len(r0["solution"]) > 500
    assert len(r0["plugin_output"]) > 500
    assert r0["scanner_cvss_vector"] == "AV:N/AC:L/Au:N/C:P/I:P/A:P"
    assert r0["cves"] == []
    assert "CWE-79" in r0["cwes"]

    assert r1["detection_mode"] == "uncredentialed_banner"
    assert r1["asset_metadata"]["credentialed"] is False
    assert r1["cves"] == ["CVE-2024-5555"]

    scan = parser.parse()
    validate_scan_result_schema(scan)
    assert scan.assets[0].findings[0].cves == []
    assert len(scan.assets[0].findings[0].description) > 500


def test_openvas_xml_fixes_typo_populates_v2_fields_and_extracts_tags_cves(tmp_path: Path) -> None:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<report id="gvm-scan-1">
  <creation_time>2026-10-01T12:00:00Z</creation_time>
  <results>
    <result id="res-1">
      <host>192.168.50.10<hostname>app.local</hostname></host>
      <port>443/tcp</port>
      <threat>High</threat>
      <description>TLS issue CWE-326</description>
      <qod><type>remote_banner</type></qod>
      <nvt oid="1.3.6.1.4.1.25623.1.0.99999">
        <name>Weak TLS</name>
        <tags>cvss_base_vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N|summary=Found weak TLS|cve=CVE-2023-9999</tags>
        <cvss_base>7.5</cvss_base>
        <solution>Disable weak ciphers</solution>
      </nvt>
    </result>
    <result id="res-2">
      <host>192.168.50.11</host>
      <port>general/tcp</port>
      <threat>Low</threat>
      <description>No nvt block</description>
    </result>
  </results>
</report>"""
    f = tmp_path / "openvas.xml"
    f.write_text(xml, encoding="utf-8")
    ctx = _make_ctx(tmp_path)

    parser = OpenVASXMLParser(ctx, f)
    records = [r for batch in parser.iter_batches(batch_size=10) for r in batch]
    assert len(records) == 2
    for r in records:
        _assert_record_contract(r)
        assert r["source_format"] == "openvas-xml"
        assert "SENINTEL" not in r["plugin_output"]

    assert records[0]["cves"] == ["CVE-2023-9999"]
    assert "CWE-326" in records[0]["cwes"]
    assert records[0]["hostname"] == "app.local"
    assert records[1]["cves"] == []
    assert records[1]["plugin_output"] == ""

    scan = parser.parse()
    validate_scan_result_schema(scan)
    for asset in scan.assets:
        for finding in asset.findings:
            assert "SENINTEL" not in (finding.plugin_output or "")
            assert "SENTINEL:No_CVE_Listed" not in (finding.cves or [])


def test_nmap_xml_streaming_parser_handles_ports_os_and_nse_cves(tmp_path: Path) -> None:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1776910608">
  <host>
    <status state="up"/>
    <address addr="10.20.30.40" addrtype="ipv4"/>
    <hostnames><hostname name="edge.example.com" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.15" accuracy="98"/></os>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
        <script id="http-vuln-cve2021-23017" output="VULNERABLE: CVE-2021-23017 CWE-190">
          <elem key="cvss">7.7</elem>
        </script>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2p1"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    f = tmp_path / "scan_nmap.xml"
    f.write_text(xml, encoding="utf-8")
    ctx = _make_ctx(tmp_path)

    conf, _ = NmapXMLParser.detect_file(f, ctx=ctx)
    assert conf >= 0.80

    parser = NmapXMLParser(ctx, f)
    records = [r for batch in parser.iter_batches(batch_size=1) for r in batch]
    assert len(records) == 2
    for r in records:
        _assert_record_contract(r)
        assert r["source_format"] == "nmap-xml"
        assert r["detection_mode"] == "network_probe"
        assert r["os"] == "Linux 5.15"
        assert r["asset_metadata"]["open_ports"] == [22, 443]

    https_rec = next(r for r in records if r["affected_port"] == 443)
    assert https_rec["cves"] == ["CVE-2021-23017"]
    assert "CWE-190" in https_rec["cwes"]
    assert https_rec["scanner_cvss_score"] == 7.7
    assert https_rec["severity"] == "High"

    # Also validate packaged Nmap resource
    demo_nmap = Path("src/vulnparse_pin/resources/base_test_nmap.xml")
    demo_scan = NmapXMLParser(ctx, demo_nmap).parse()
    validate_scan_result_schema(demo_scan)
    assert len(demo_scan.assets) == 1
    assert len(demo_scan.assets[0].findings) == 3


def test_csv_parsers_streaming_cwes_and_bom_support(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)

    nessus_csv = tmp_path / "nessus_bom.csv"
    nessus_csv.write_bytes(
        b"\xef\xbb\xbfHost,Plugin ID,Plugin Name,Risk,CVE,CWE,CVSS Vector,Plugin Output,Port,Protocol,Description\n"
        b"10.0.0.10,1234,XSS Bug,High,CVE-2024-1000,CWE-79,CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N,Credentialed checks : yes,443,tcp,XSS CWE-79\n"
    )
    n_recs = [r for b in NessusCSVParser(ctx, nessus_csv).iter_batches(batch_size=5) for r in b]
    assert len(n_recs) == 1
    _assert_record_contract(n_recs[0])
    assert n_recs[0]["cwes"] == ["CWE-79"]
    assert n_recs[0]["detection_mode"] == "credentialed_host"
    validate_scan_result_schema(NessusCSVParser(ctx, nessus_csv).parse())

    qualys_csv = tmp_path / "qualys_bom.csv"
    qualys_csv.write_bytes(
        b"\xef\xbb\xbfIP,QID,Title,Severity,CVE,CWE,CVSS Vector,Result,Port,Protocol\n"
        b"10.0.0.11,91000,SQLi Bug,5,CVE-2024-2000,CWE-89,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,Confirmed SQLi,443,tcp\n"
    )
    q_recs = [r for b in QualysCSVParser(ctx, qualys_csv).iter_batches(batch_size=5) for r in b]
    assert len(q_recs) == 1
    _assert_record_contract(q_recs[0])
    assert q_recs[0]["cwes"] == ["CWE-89"]
    validate_scan_result_schema(QualysCSVParser(ctx, qualys_csv).parse())


def test_file_input_validator_and_schema_detector_formats_bom_and_deep_sarif(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    detector = SchemaDetector(PARSER_SPECS)

    # 1. Deeply nested SARIF (>15 levels) with UTF-8 BOM + leading whitespace
    deep_obj: dict = {"leaf": "ok"}
    for idx in range(18):
        deep_obj = {f"lvl_{idx}": deep_obj}
    sarif_payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep", "rules": []}},
                "properties": deep_obj,
                "results": [
                    {
                        "ruleId": "python.lang.security.audit.eval",
                        "level": "error",
                        "message": {"text": "Use of eval detected"},
                    }
                ],
            }
        ],
    }
    sarif_file = tmp_path / "deep.sarif"
    sarif_file.write_bytes(b"\xef\xbb\xbf  \n" + json.dumps(sarif_payload).encode("utf-8"))

    validated = FileInputValidator(ctx, sarif_file).validate()
    assert validated == sarif_file
    assert detector._sniff_format(ctx, sarif_file) == "sarif"
    assert detector.select(ctx, sarif_file).parser_cls is SarifParser

    # 2. Nuclei JSONL (.jsonl & .ndjson) with UTF-8 BOM
    nuclei_file = tmp_path / "scan.ndjson"
    nuclei_file.write_bytes(
        b"\xef\xbb\xbf"
        + b'{"template-id":"cve-2021-44228","info":{"name":"Log4j","severity":"critical"},"host":"https://a.example","matched-at":"https://a.example/"}\n'
    )
    assert FileInputValidator(ctx, nuclei_file).validate() == nuclei_file
    assert detector._sniff_format(ctx, nuclei_file) == "jsonl"
    assert detector.select(ctx, nuclei_file).parser_cls is NucleiJSONLParser

    # 3. CSV with BOM
    csv_file = tmp_path / "scan.csv"
    csv_file.write_bytes(
        b"\xef\xbb\xbfHost,Plugin ID,Plugin Name,Risk,CVE\n10.0.0.1,100,Test,High,CVE-2024-1111\n"
    )
    assert FileInputValidator(ctx, csv_file).validate() == csv_file
    assert detector._sniff_format(ctx, csv_file) == "csv"
    assert detector.select(ctx, csv_file).parser_cls is NessusCSVParser

    # 4. XML with BOM + whitespace
    xml_file = tmp_path / "scan.xml"
    xml_file.write_bytes(
        b"\xef\xbb\xbf  \n<SCAN><ASSET><IP>1.2.3.4</IP><VULN><QID>123</QID><TITLE>T</TITLE></VULN></ASSET></SCAN>"
    )
    assert FileInputValidator(ctx, xml_file).validate() == xml_file
    assert detector._sniff_format(ctx, xml_file) == "xml"
    assert detector.select(ctx, xml_file).parser_cls is QualysXMLParser

    # 5. Plain JSON vs unknown
    plain_json = tmp_path / "plain.json"
    plain_json.write_text('{"hello": "world"}', encoding="utf-8")
    assert detector._sniff_format(ctx, plain_json) == "json"

    unknown_file = tmp_path / "notes.txt"
    unknown_file.write_text("just some plain text without delimiters", encoding="utf-8")
    assert detector._sniff_format(ctx, unknown_file) == "unknown"


def test_allow_large_honored_across_validator_and_parsers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _make_ctx(tmp_path)
    nessus_file = tmp_path / "giant.nessus"
    nessus_file.write_text(
        "<NessusClientData_v2><Report name='Big'><ReportHost name='10.0.0.1'>"
        "<ReportItem pluginID='1' pluginName='P' severity='2' port='80' protocol='tcp'/>"
        "</ReportHost></Report></NessusClientData_v2>",
        encoding="utf-8",
    )

    fake_size = 750 * 1024 * 1024  # 750 MB (> 500 MB default cap, < 50 GB allow_large cap)
    real_stat = Path.stat
    real_getsize = Path.stat

    class _StatObj:
        def __init__(self, real):
            self._real = real
            self.st_mode = real.st_mode
            self.st_size = fake_size

        def __getattr__(self, name):
            return getattr(self._real, name)

    monkeypatch.setattr(Path, "stat", lambda self, *a, **kw: _StatObj(real_stat(self, *a, **kw)) if self == nessus_file else real_stat(self, *a, **kw))
    monkeypatch.setattr("os.path.getsize", lambda p: fake_size if Path(p) == nessus_file else real_getsize(Path(p)).st_size)

    # Without allow_large: FileInputValidator exits and parsers reject
    with pytest.raises(SystemExit):
        FileInputValidator(ctx, nessus_file, allow_large=False).validate()
    assert NessusXMLParser.detect_file(nessus_file, ctx=ctx, allow_large=False)[0] == 0.0
    with pytest.raises(ValueError, match="allow-large"):
        NessusXMLParser(ctx, nessus_file, allow_large=False).parse()

    # With allow_large=True: FileInputValidator, SchemaDetector, detect_file, iter_batches, and parse succeed
    assert FileInputValidator(ctx, nessus_file, allow_large=True).validate() == nessus_file
    conf, _ = NessusXMLParser.detect_file(nessus_file, ctx=ctx, allow_large=True)
    assert conf >= 0.90
    detector = SchemaDetector(PARSER_SPECS)
    assert detector.select(ctx, nessus_file).parser_cls is NessusXMLParser
    batches = list(NessusXMLParser(ctx, nessus_file).iter_batches())
    assert len(batches) == 1 and len(batches[0]) == 1


def test_detect_file_reads_at_most_64kb_and_streams_in_bounded_memory(tmp_path: Path) -> None:
    # Build a ~4 MB Nessus XML where <Policy> alone is > 1.5 MB and 1500 findings follow
    padding = "12345;" * 250_000  # 1.5 MB
    items = "\n".join(
        f'<ReportItem pluginID="{10000 + i}" pluginName="Finding {i}" severity="2" port="443" protocol="tcp">'
        f"<description>Desc {i}</description><cve>CVE-2024-{1000 + (i % 500):04d}</cve></ReportItem>"
        for i in range(1500)
    )
    big_nessus = tmp_path / "big.nessus"
    big_nessus.write_text(
        f'<?xml version="1.0"?><NessusClientData_v2><Policy><Preferences><ServerPreferences>'
        f'<preference><name>plugin_set</name><value>{padding}</value></preference>'
        f'</ServerPreferences></Preferences></Policy>'
        f'<Report name="Big"><ReportHost name="10.0.0.1">{items}</ReportHost></Report></NessusClientData_v2>',
        encoding="utf-8",
    )

    bytes_read_by_detect: list[int] = []

    class _CountingStream:
        def __init__(self, inner):
            self._inner = inner

        def read(self, n=-1):
            chunk = self._inner.read(n)
            bytes_read_by_detect.append(len(chunk))
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self._inner.close()
            return False

    class _SpyPFH:
        def ensure_readable_file(self, p, **_kw):
            return Path(p)

        def open_for_read(self, p, mode="rb", **_kw):
            return _CountingStream(open(p, mode))

    ctx = SimpleNamespace(
        pfh=_SpyPFH(),
        logger=LoggerWrapper(log_file=str(tmp_path / "spy.log")),
        services=Services(),
    )

    detector = SchemaDetector(PARSER_SPECS)
    det = detector.select(ctx, big_nessus)
    assert det.parser_cls is NessusXMLParser
    assert sum(bytes_read_by_detect) <= 65_536

    # Verify streaming iter_batches consumes all 1500 findings with bounded memory
    tracemalloc.start()
    count = 0
    for batch in NessusXMLParser(_make_ctx(tmp_path), big_nessus).iter_batches(batch_size=200):
        count += len(batch)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert count == 1500
    assert peak_bytes < 16 * 1024 * 1024


def test_base_parser_iter_batches_fallback_works_for_custom_subclass(tmp_path: Path) -> None:
    from datetime import datetime, timezone
    from vulnparse_pin.core.classes.dataclass import Asset, Finding, ScanMetaData, ScanResult

    class _LegacyOnlyParser(BaseParser):
        NAME = "legacy-test"

        def parse(self) -> ScanResult:
            f = Finding(
                finding_id="fid_1",
                vuln_id="101",
                title="Legacy Vuln",
                description="desc",
                severity="High",
                cves=["CVE-2024-0001", "SENTINEL:No_CVE_Listed"],
                cvss_score=7.5,
                cvss_vector="SENTINEL:Vector_Unavailable",
                asset_id="aid_1",
            )
            a = Asset(hostname="legacy-host", ip_address="10.0.0.99", findings=[f], asset_id="aid_1")
            m = ScanMetaData(
                source="Legacy",
                scan_date=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                asset_count=1,
                vulnerability_count=1,
            )
            return ScanResult(scan_metadata=m, assets=[a])

    p = _LegacyOnlyParser(_make_ctx(tmp_path), None)
    batches = list(p.iter_batches(batch_size=10))
    assert len(batches) == 1
    rec = batches[0][0]
    _assert_record_contract(rec)
    assert rec["cves"] == ["CVE-2024-0001"]
    assert rec["scanner_cvss_vector"] is None


def test_file_input_validator_large_sarif_streaming_and_corrupt_rejection(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)

    # Large (> 2 MB) valid SARIF exercises bounded prefix+tail validator without json.load()
    results = [
        {
            "ruleId": f"rule-{i}",
            "level": "warning",
            "message": {"text": "x" * 200},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": f"src/f{i}.py"}, "region": {"startLine": i + 1}}}
            ],
        }
        for i in range(9000)
    ]
    big_sarif = tmp_path / "big.sarif"
    big_sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": []}}, "results": results}],
            }
        ),
        encoding="utf-8",
    )
    assert big_sarif.stat().st_size > 2 * 1024 * 1024
    assert FileInputValidator(ctx, big_sarif).validate() == big_sarif

    parsed_count = sum(len(b) for b in SarifParser(ctx, big_sarif).iter_batches(batch_size=1000))
    assert parsed_count == 9000

    # Truncated > 2 MB SARIF fails closed
    trunc_sarif = tmp_path / "trunc.sarif"
    trunc_sarif.write_bytes(big_sarif.read_bytes()[:-50])
    with pytest.raises(SystemExit):
        FileInputValidator(ctx, trunc_sarif).validate()

    # Corrupted small JSON, array-root JSON, and empty JSONL fail closed
    bad_json = tmp_path / "corrupt.sarif"
    bad_json.write_text('{"version": "2.1.0", broken}', encoding="utf-8")
    with pytest.raises(SystemExit):
        FileInputValidator(ctx, bad_json).validate()

    array_json = tmp_path / "arr.json"
    array_json.write_text('[1, 2, 3]', encoding="utf-8")
    with pytest.raises(SystemExit):
        FileInputValidator(ctx, array_json).validate()

    empty_jsonl = tmp_path / "empty.jsonl"
    empty_jsonl.write_text("\n  \n", encoding="utf-8")
    with pytest.raises(SystemExit):
        FileInputValidator(ctx, empty_jsonl).validate()

