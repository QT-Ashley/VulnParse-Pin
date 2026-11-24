# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from pathlib import Path
import time

import pytest

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import RunContext, Services
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.parsers.nessusXML_parser import NessusXMLParser
from vulnparse_pin.parsers.nmap_parser import NmapXMLParser
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser
from vulnparse_pin.parsers.qualys_parser import QualysXMLParser
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema


def _ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "xxe.log"))
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
        services=Services(),
    )


def _xml_bodies(secret_uri: str) -> dict[str, tuple[str, str]]:
    """Return (valid_body_with_xxe_ref, doctype_target_name) per parser."""
    return {
        "nessus": (
            f'<NessusClientData_v2><Report name="Scan"><ReportHost name="10.0.0.1">'
            f'<ReportItem pluginID="100" pluginName="Test" severity="2" port="80" protocol="tcp">'
            f'<description>&xxe;</description></ReportItem></ReportHost></Report></NessusClientData_v2>',
            "NessusClientData_v2",
        ),
        "openvas": (
            f'<report><results><result><host>10.0.0.1</host><port>80/tcp</port>'
            f'<description>&xxe;</description><nvt oid="1.3.6.1.4.1.25623.1.0.100"><name>NVT</name></nvt>'
            f'</result></results></report>',
            "report",
        ),
        "qualys": (
            f'<SCAN><ASSET><IP>10.0.0.1</IP><VULN><QID>100</QID><TITLE>T</TITLE>'
            f'<DESCRIPTION>&xxe;</DESCRIPTION></VULN></ASSET></SCAN>',
            "SCAN",
        ),
        "nmap": (
            f'<nmaprun scanner="nmap"><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
            f'<script id="http-title" output="&xxe;"/></port></ports></host></nmaprun>',
            "nmaprun",
        ),
    }


PARSER_MAP = {
    "nessus": NessusXMLParser,
    "openvas": OpenVASXMLParser,
    "qualys": QualysXMLParser,
    "nmap": NmapXMLParser,
}


@pytest.mark.parametrize("scanner", ["nessus", "openvas", "qualys", "nmap"])
def test_xxe_file_entity_blocked_fail_closed(tmp_path: Path, scanner: str) -> None:
    secret_file = tmp_path / "secret_token.txt"
    secret_file.write_text("TOP_SECRET_CANARY_VALUE", encoding="utf-8")
    body, root_name = _xml_bodies(secret_file.as_uri())[scanner]

    xxe_xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE {root_name} [<!ENTITY xxe SYSTEM "{secret_file.as_uri()}">]>\n'
        f'{body}'
    )
    xml_path = tmp_path / f"xxe_{scanner}.xml"
    xml_path.write_text(xxe_xml, encoding="utf-8")

    ctx = _ctx(tmp_path)
    parser_cls = PARSER_MAP[scanner]

    conf, _ = parser_cls.detect_file(xml_path, ctx=ctx)
    assert conf == 0.0

    with pytest.raises(ValueError):
        SchemaDetector(PARSER_SPECS).select(ctx, xml_path)

    with pytest.raises(ValueError):
        list(parser_cls(ctx, xml_path).iter_batches())

    with pytest.raises(ValueError):
        parser_cls(ctx, xml_path).parse()


@pytest.mark.parametrize("scanner", ["nessus", "openvas", "qualys", "nmap"])
def test_external_dtd_and_parameter_entity_blocked(tmp_path: Path, scanner: str) -> None:
    body, root_name = _xml_bodies("http://127.0.0.1:9/evil.dtd")[scanner]
    ctx = _ctx(tmp_path)
    parser_cls = PARSER_MAP[scanner]

    ext_dtd = f'<?xml version="1.0"?>\n<!DOCTYPE {root_name} SYSTEM "http://127.0.0.1:9/evil.dtd">\n{body}'
    p1 = tmp_path / f"ext_{scanner}.xml"
    p1.write_text(ext_dtd, encoding="utf-8")
    assert parser_cls.detect_file(p1, ctx=ctx)[0] == 0.0
    with pytest.raises(ValueError):
        parser_cls(ctx, p1).parse()

    param_dtd = (
        f'<?xml version="1.0"?>\n'
        f'<!DOCTYPE {root_name} [<!ENTITY % sp SYSTEM "http://127.0.0.1:9/evil.dtd"> %sp;]>\n'
        f'{body.replace("&xxe;", "ok")}'
    )
    p2 = tmp_path / f"param_{scanner}.xml"
    p2.write_text(param_dtd, encoding="utf-8")
    assert parser_cls.detect_file(p2, ctx=ctx)[0] == 0.0
    with pytest.raises(ValueError):
        list(parser_cls(ctx, p2).iter_batches())


@pytest.mark.parametrize("scanner", ["nessus", "openvas", "qualys", "nmap"])
def test_billion_laughs_blocked_without_expansion(tmp_path: Path, scanner: str) -> None:
    body, root_name = _xml_bodies("")[scanner]
    body_lol = body.replace("&xxe;", "&lol9;")
    entities = "\n".join(
        ['<!ENTITY lol "lol">']
        + [
            f'<!ENTITY lol{i} "' + (f"&lol{i-1};" * 10 if i > 1 else "&lol;" * 10) + '">'
            for i in range(1, 10)
        ]
    )
    bl_xml = f'<?xml version="1.0"?>\n<!DOCTYPE {root_name} [\n{entities}\n]>\n{body_lol}'
    p = tmp_path / f"bl_{scanner}.xml"
    p.write_text(bl_xml, encoding="utf-8")

    ctx = _ctx(tmp_path)
    parser_cls = PARSER_MAP[scanner]

    t0 = time.monotonic()
    assert parser_cls.detect_file(p, ctx=ctx)[0] == 0.0
    with pytest.raises(ValueError):
        parser_cls(ctx, p).parse()
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0


def test_utf16_xxe_blocked_fail_closed(tmp_path: Path) -> None:
    xml = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<!DOCTYPE SCAN [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<SCAN><ASSET><IP>1.2.3.4</IP><VULN><QID>1</QID><TITLE>&xxe;</TITLE></VULN></ASSET></SCAN>'
    )
    p = tmp_path / "utf16_xxe.xml"
    p.write_bytes(xml.encode("utf-16"))
    ctx = _ctx(tmp_path)
    assert QualysXMLParser.detect_file(p, ctx=ctx)[0] == 0.0
    with pytest.raises(ValueError):
        QualysXMLParser(ctx, p).parse()


def test_valid_nmap_and_qualys_harmless_doctypes_succeed(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    detector = SchemaDetector(PARSER_SPECS)

    nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1776910608">
  <host>
    <status state="up"/>
    <address addr="192.168.10.20" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port></ports>
  </host>
</nmaprun>"""
    nmap_file = tmp_path / "valid_nmap.xml"
    nmap_file.write_text(nmap_xml, encoding="utf-8")
    assert detector.select(ctx, nmap_file).parser_cls is NmapXMLParser
    nmap_scan = NmapXMLParser(ctx, nmap_file).parse()
    validate_scan_result_schema(nmap_scan)
    assert nmap_scan.scan_metadata.vulnerability_count == 1

    qualys_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE SCAN>
<SCAN id="qualys-doctype">
  <SCAN_DATETIME>2026-10-01T00:00:00Z</SCAN_DATETIME>
  <ASSET>
    <IP>192.168.10.30</IP>
    <VULN>
      <QID>38173</QID>
      <TITLE>SSL Weak Cipher</TITLE>
      <PORT>443/tcp</PORT>
      <SEVERITY>4</SEVERITY>
      <CVE_ID>CVE-2023-0286</CVE_ID>
    </VULN>
  </ASSET>
</SCAN>"""
    qualys_file = tmp_path / "valid_qualys.xml"
    qualys_file.write_text(qualys_xml, encoding="utf-8")
    assert detector.select(ctx, qualys_file).parser_cls is QualysXMLParser
    qualys_scan = QualysXMLParser(ctx, qualys_file).parse()
    validate_scan_result_schema(qualys_scan)
    assert qualys_scan.scan_metadata.vulnerability_count == 1


def test_cdata_containing_entity_text_inside_plugin_output_does_not_false_positive(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="XXEFindingReport">
    <ReportHost name="10.0.0.5">
      <ReportItem pluginID="55555" pluginName="XXE Vulnerability Detected" severity="3" port="8080" protocol="tcp">
        <description>The target application is vulnerable to XXE injection.</description>
        <plugin_output><![CDATA[Sent payload: <!ENTITY xxe SYSTEM "file:///etc/passwd">]]></plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
    f = tmp_path / "xxe_report.nessus"
    f.write_text(xml, encoding="utf-8")
    records = [r for b in NessusXMLParser(ctx, f).iter_batches() for r in b]
    assert len(records) == 1
    assert "<!ENTITY xxe" in records[0]["plugin_output"]


def test_no_defusedxml_imports_in_parsers() -> None:
    parsers_dir = Path("src/vulnparse_pin/parsers")
    for py_file in parsers_dir.glob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        assert "defusedxml" not in text, f"Unexpected defusedxml reference in {py_file}"
