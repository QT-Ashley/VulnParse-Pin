# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import RunContext, Services
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.parsers.base_parser import VALID_SEVERITIES
from vulnparse_pin.parsers.nessusXML_parser import NessusXMLParser
from vulnparse_pin.parsers.nessus_csv_parser import NessusCSVParser
from vulnparse_pin.parsers.nmap_parser import NmapXMLParser
from vulnparse_pin.parsers.nuclei_jsonl_parser import NucleiJSONLParser
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser
from vulnparse_pin.parsers.qualys_csv_parser import QualysCSVParser
from vulnparse_pin.parsers.qualys_parser import QualysXMLParser
from vulnparse_pin.parsers.sarif_parser import SarifParser
from vulnparse_pin.storage.repositories import _default_signal_reliability
from vulnparse_pin.utils.cvss_utils import detect_cvss_exact_version, is_valid_cvss_vector
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema


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


def _ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "vendor_torture.log"))
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


def _assert_contract(rec: dict) -> None:
    assert set(rec.keys()) == REQUIRED_RECORD_KEYS
    assert rec["severity"] in VALID_SEVERITIES
    assert isinstance(rec["cves"], list)
    assert isinstance(rec["cwes"], list)
    assert isinstance(rec["ghsa_ids"], list)
    assert isinstance(rec["references"], list)
    assert isinstance(rec["tags"], list)
    assert isinstance(rec["missing_fields"], list)
    if rec["scanner_cvss_vector"] is not None:
        assert is_valid_cvss_vector(rec["scanner_cvss_vector"]), (
            f"Invalid normalized vector: {rec['scanner_cvss_vector']}"
        )


def test_nessus_xml_cvss4_precedence_exploit_tags_and_19506_late_stamping(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="Nessus107Torture">
    <ReportHost name="app-late-props">
      <ReportItem pluginID="20001" pluginName="CVSS4 Precedence Finding" severity="4" port="443" protocol="tcp" svc_name="https">
        <description>Supports v4, v3, and v2 vectors.</description>
        <cve>CVE-2024-10001</cve>
        <cvss_base_score>6.8</cvss_base_score>
        <cvss_vector>CVSS2#(AV:N/AC:M/Au:N/C:P/I:P/A:P)</cvss_vector>
        <cvss3_base_score>8.1</cvss3_base_score>
        <cvss3_vector>CVSS3#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector>
        <cvss4_base_score>9.3</cvss4_base_score>
        <cvss4_vector>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</cvss4_vector>
        <exploit_available>false</exploit_available>
        <exploit_framework_metasploit>true</exploit_framework_metasploit>
      </ReportItem>
      <ReportItem pluginID="20002" pluginName="CVSS3 Precedence Finding" severity="3" port="8443" protocol="tcp" svc_name="https">
        <description>Supports v3 and v2 vectors.</description>
        <cve>CVE-2024-10002</cve>
        <cvss_base_score>5.0</cvss_base_score>
        <cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N</cvss_vector>
        <cvss3_base_score>7.5</cvss3_base_score>
        <cvss3_vector>(CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)</cvss3_vector>
        <exploited_by_malware>yes</exploited_by_malware>
      </ReportItem>
      <ReportItem pluginID="20003" pluginName="CVSS2 Fallback Finding" severity="2" port="22" protocol="tcp" svc_name="ssh">
        <description>Supports v2 only.</description>
        <cve>CVE-2024-10003</cve>
        <cvss_base_score>4.3</cvss_base_score>
        <cvss_vector>CVSS2#(AV:N/AC:M/Au:N/C:N/I:P/A:N)</cvss_vector>
        <exploited_by_nessus>1</exploited_by_nessus>
      </ReportItem>
      <ReportItem pluginID="19506" pluginName="Nessus Scan Information" severity="0" port="0" protocol="tcp">
        <plugin_output>Information about this scan :
Nessus version : 10.7.2
Credentialed checks : YES
</plugin_output>
      </ReportItem>
      <HostProperties>
        <tag name="host-ip">10.42.0.15</tag>
        <tag name="host-fqdn">app-late-props.corp.local</tag>
        <tag name="operating-system">Red Hat Enterprise Linux 9</tag>
      </HostProperties>
    </ReportHost>
    <ReportHost name="10.42.0.16">
      <HostProperties>
        <tag name="host-ip">10.42.0.16</tag>
      </HostProperties>
      <ReportItem pluginID="20004" pluginName="Uncredentialed Banner" severity="1" port="80" protocol="tcp">
        <description>Banner only.</description>
        <exploit_framework_canvas>false</exploit_framework_canvas>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
    nessus_file = tmp_path / "nessus_10_7.nessus"
    nessus_file.write_text(xml, encoding="utf-8")

    batches = list(NessusXMLParser(ctx, nessus_file).iter_batches(batch_size=2))
    assert [len(b) for b in batches] == [2, 2, 1]
    records = [r for b in batches for r in b]
    for rec in records:
        _assert_contract(rec)

    r0, r1, r2, r19506, r_uncred = records
    # Late HostProperties + late Plugin 19506 stamped onto ALL items of first host
    for rec in (r0, r1, r2, r19506):
        assert rec["ip_address"] == "10.42.0.15"
        assert rec["hostname"] == "app-late-props.corp.local"
        assert rec["asset_metadata"]["credentialed"] is True
        assert rec["detection_mode"] == "credentialed_host"
        assert _default_signal_reliability(rec["detection_mode"], rec["ingestion_confidence"]) == 1.0

    assert r0["scanner_cvss_score"] == 9.3
    assert r0["scanner_cvss_vector"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert detect_cvss_exact_version(r0["scanner_cvss_vector"]) == "4.0"
    assert r0["exploit_evidence"] is True

    assert r1["scanner_cvss_score"] == 7.5
    assert r1["scanner_cvss_vector"] == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert detect_cvss_exact_version(r1["scanner_cvss_vector"]) == "3.0"
    assert r1["exploit_evidence"] is True

    assert r2["scanner_cvss_score"] == 4.3
    assert r2["scanner_cvss_vector"] == "AV:N/AC:M/Au:N/C:N/I:P/A:N"
    assert detect_cvss_exact_version(r2["scanner_cvss_vector"]) == "2.0"
    assert r2["exploit_evidence"] is True

    assert r_uncred["asset_metadata"]["credentialed"] is False
    assert r_uncred["detection_mode"] == "uncredentialed_banner"
    assert r_uncred["exploit_evidence"] is False

    scan = NessusXMLParser(ctx, nessus_file).parse()
    validate_scan_result_schema(scan)
    assert len(scan.assets) == 2


def test_nessus_csv_cvss_precedence_fallback_multiline_and_formula_cells(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    csv_text = (
        "Plugin ID,CVE,CVSS v2.0 Base Score,CVSS v2.0 Vector,CVSS v3.0 Base Score,CVSS v3.0 Vector,"
        "CVSS v4.0 Base Score,CVSS v4.0 Vector,Risk,DNS Name,NetBIOS Name,Port,Protocol,Name,Plugin Text\n"
        '30001,CVE-2024-20001,5.0,CVSS2#(AV:N/AC:L/Au:N/C:P/I:N/A:N),7.5,CVSS3#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N,'
        '9.3,CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N,Critical,web01.example.com,WEB01,443,tcp,'
        'v4 Wins,"Line 1 evidence\nCredentialed checks : yes"\n'
        '30002,CVE-2024-20002,5.0,(AV:N/AC:L/Au:N/C:P/I:N/A:N),8.8,(CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H),'
        ',,High,web02.example.com,WEB02,8443,tcp,v3 Wins,"=CMD|\'/C calc\'!A0"\n'
        '30003,CVE-2024-20003,6.4,CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N,,,,,'
        'Medium,,NETBIOS-ONLY,80,tcp,v2 Fallback,"+SUM(1,2)\n@HYPERLINK(\\"http://evil\\")"\n'
    )
    csv_path = tmp_path / "nessus_tenable_sc.csv"
    csv_path.write_text(csv_text, encoding="utf-8")

    conf, _ = NessusCSVParser.detect_file(csv_path, ctx=ctx)
    assert conf >= 0.80

    batches = list(NessusCSVParser(ctx, csv_path).iter_batches(batch_size=2))
    assert [len(b) for b in batches] == [2, 1]
    r0, r1, r2 = [r for b in batches for r in b]
    for rec in (r0, r1, r2):
        _assert_contract(rec)

    assert r0["scanner_cvss_score"] == 9.3
    assert r0["scanner_cvss_vector"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert r0["hostname"] == "web01.example.com"
    assert r0["detection_mode"] == "credentialed_host"
    assert "Line 1 evidence" in r0["plugin_output"]

    assert r1["scanner_cvss_score"] == 8.8
    assert r1["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert r1["plugin_output"].startswith("=CMD")

    assert r2["scanner_cvss_score"] == 6.4
    assert r2["scanner_cvss_vector"] == "AV:N/AC:L/Au:N/C:P/I:P/A:N"
    assert r2["hostname"] == "NETBIOS-ONLY"

    validate_scan_result_schema(NessusCSVParser(ctx, csv_path).parse())


def test_qualys_xml_all_three_schemas_cvss_precedence_and_glossary(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    detector = SchemaDetector(PARSER_SPECS)

    # 1. Scan Report XML with v2 tags appearing BEFORE v3.1 tags
    scan_xml = tmp_path / "qualys_scan_report.xml"
    scan_xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<SCAN_REPORT id="q-scan-1">
  <SCAN_DATETIME>2026-06-01T00:00:00Z</SCAN_DATETIME>
  <ASSET>
    <IP>10.1.1.10</IP>
    <VULN>
      <QID>38173</QID>
      <TITLE>TLS Weakness</TITLE>
      <PORT>443/tcp</PORT>
      <SEVERITY>4</SEVERITY>
      <CVSS_BASE>5.0</CVSS_BASE>
      <CVSS_VECTOR>CVSS2#(AV:N/AC:L/Au:N/C:P/I:N/A:N)</CVSS_VECTOR>
      <CVSS3_1_BASE>7.5</CVSS3_1_BASE>
      <CVSS3_1_VECTOR>CVSS3#(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)</CVSS3_1_VECTOR>
      <CVE_ID>CVE-2023-0286</CVE_ID>
    </VULN>
  </ASSET>
</SCAN_REPORT>""",
        encoding="utf-8",
    )
    assert detector.select(ctx, scan_xml).parser_cls is QualysXMLParser
    scan_recs = [r for b in QualysXMLParser(ctx, scan_xml).iter_batches(batch_size=2) for r in b]
    assert len(scan_recs) == 1
    _assert_contract(scan_recs[0])
    assert scan_recs[0]["scanner_cvss_score"] == 7.5
    assert scan_recs[0]["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

    # 2. Asset Data Report XML with <GLOSSARY> AFTER <HOST_LIST>
    asset_data_xml = tmp_path / "qualys_asset_data.xml"
    asset_data_xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<ASSET_DATA_REPORT>
  <HEADER>
    <KEY value="REPORT_TITLE">Enterprise Asset Data Export</KEY>
    <GENERATION_DATETIME>2026-06-02T12:00:00Z</GENERATION_DATETIME>
  </HEADER>
  <HOST_LIST>
    <HOST>
      <IP>10.2.2.20</IP>
      <DNS>db01.prod.local</DNS>
      <OPERATING_SYSTEM>Ubuntu 24.04</OPERATING_SYSTEM>
      <VULN_INFO_LIST>
        <VULN_INFO>
          <QID id="qid_90001">90001</QID>
          <PORT>5432</PORT>
          <PROTOCOL>tcp</PROTOCOL>
          <RESULT>PostgreSQL 14.1 listening</RESULT>
        </VULN_INFO>
        <VULN_INFO>
          <QID id="qid_90002">90002</QID>
          <PORT>53</PORT>
          <PROTOCOL>udp</PROTOCOL>
          <RESULT>DNS recursion enabled</RESULT>
        </VULN_INFO>
      </VULN_INFO_LIST>
    </HOST>
    <HOST>
      <IP>10.2.2.21</IP>
      <VULN_INFO_LIST>
        <VULN_INFO>
          <QID id="qid_90001">90001</QID>
          <PORT>5432</PORT>
          <PROTOCOL>tcp</PROTOCOL>
          <RESULT>PostgreSQL 14.2 listening</RESULT>
        </VULN_INFO>
      </VULN_INFO_LIST>
    </HOST>
  </HOST_LIST>
  <GLOSSARY>
    <VULN_DETAILS_LIST>
      <VULN_DETAILS id="qid_90001">
        <QID id="qid_90001">90001</QID>
        <TITLE>PostgreSQL Remote Auth Bypass</TITLE>
        <SEVERITY>5</SEVERITY>
        <THREAT>Critical authentication bypass in PostgreSQL.</THREAT>
        <SOLUTION>Upgrade PostgreSQL to 14.12+.</SOLUTION>
        <CVE_ID_LIST><CVE_ID><ID>CVE-2024-90001</ID></CVE_ID></CVE_ID_LIST>
        <CVSS_SCORE><CVSS_BASE>7.5</CVSS_BASE></CVSS_SCORE>
        <CVSS3_SCORE><CVSS3_BASE>9.8</CVSS3_BASE><CVSS3_VECTOR>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</CVSS3_VECTOR></CVSS3_SCORE>
      </VULN_DETAILS>
      <VULN_DETAILS id="qid_90002">
        <QID id="qid_90002">90002</QID>
        <TITLE>Open DNS Resolver</TITLE>
        <SEVERITY>3</SEVERITY>
        <THREAT>DNS amplification exposure.</THREAT>
        <SOLUTION>Restrict recursion to internal subnets.</SOLUTION>
        <CVSS_SCORE><CVSS_BASE>5.0</CVSS_BASE><CVSS_VECTOR>(AV:N/AC:L/Au:N/C:N/I:N/A:P)</CVSS_VECTOR></CVSS_SCORE>
      </VULN_DETAILS>
    </VULN_DETAILS_LIST>
  </GLOSSARY>
</ASSET_DATA_REPORT>""",
        encoding="utf-8",
    )
    assert detector.select(ctx, asset_data_xml).parser_cls is QualysXMLParser
    ad_batches = list(QualysXMLParser(ctx, asset_data_xml).iter_batches(batch_size=2))
    assert [len(b) for b in ad_batches] == [2, 1]
    ad_recs = [r for b in ad_batches for r in b]
    for rec in ad_recs:
        _assert_contract(rec)
    assert ad_recs[0]["title"] == "PostgreSQL Remote Auth Bypass"
    assert ad_recs[0]["cves"] == ["CVE-2024-90001"]
    assert ad_recs[0]["scanner_cvss_score"] == 9.8
    assert ad_recs[0]["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert ad_recs[0]["severity"] == "Critical"
    assert ad_recs[1]["protocol"] == "udp"
    assert ad_recs[1]["scanner_cvss_vector"] == "AV:N/AC:L/Au:N/C:N/I:N/A:P"
    validate_scan_result_schema(QualysXMLParser(ctx, asset_data_xml).parse())

    # 3. VM Detection API XML with harmless DOCTYPE
    vm_det_xml = tmp_path / "qualys_vm_detection.xml"
    vm_det_xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-06-03T08:00:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <IP>10.3.3.30</IP>
        <DNS_DATA>
          <HOSTNAME>api01</HOSTNAME>
          <FQDN>api01.example.com</FQDN>
        </DNS_DATA>
        <OS>Linux 6.1</OS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>38173</QID>
            <SEVERITY>4</SEVERITY>
            <PORT>443</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>Cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA enabled</RESULTS>
            <CVSS3_BASE>7.4</CVSS3_BASE>
            <CVSS3_VECTOR>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N</CVSS3_VECTOR>
          </DETECTION>
          <DETECTION>
            <QID>11827</QID>
            <SEVERITY>2</SEVERITY>
            <PORT>161</PORT>
            <PROTOCOL>udp</PROTOCOL>
            <RESULTS>SNMP v2c default community</RESULTS>
          </DETECTION>
          <DETECTION>
            <QID>45038</QID>
            <SEVERITY>1</SEVERITY>
            <RESULTS>Host Scan Time: 42 seconds</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>""",
        encoding="utf-8",
    )
    assert detector.select(ctx, vm_det_xml).parser_cls is QualysXMLParser
    vm_batches = list(QualysXMLParser(ctx, vm_det_xml).iter_batches(batch_size=2))
    assert [len(b) for b in vm_batches] == [2, 1]
    vm_recs = [r for b in vm_batches for r in b]
    for rec in vm_recs:
        _assert_contract(rec)
    assert vm_recs[0]["hostname"] == "api01.example.com"
    assert vm_recs[0]["title"] == "Qualys QID 38173"
    assert "Cipher suite" in vm_recs[0]["plugin_output"]
    assert vm_recs[1]["protocol"] == "udp"
    assert vm_recs[1]["affected_port"] == 161
    validate_scan_result_schema(QualysXMLParser(ctx, vm_det_xml).parse())


def test_qualys_csv_metadata_preamble_cvss_fallback_and_formula_cells(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    detector = SchemaDetector(PARSER_SPECS)

    # Comma-delimited Qualys VMDR CSV with 7-row metadata preamble + multiline Results + formula cell
    q_csv = tmp_path / "qualys_vmdr_preamble.csv"
    q_csv.write_text(
        '"Qualys Vulnerability Management Report"\n'
        '"Company","Acme Security"\n'
        '"Report Title","Weekly Prod Scan"\n'
        '"Date","2026-06-04T09:00:00Z"\n'
        '"Total Hosts","2"\n'
        '"Active Hosts","2"\n'
        "\n"
        '"IP","DNS","NetBIOS","QID","Title","Type","Severity","Port","Protocol","CVE ID","CVSS Base","CVSS Vector","CVSS3 Base","CVSS3 Vector","CVSS3.1 Base","CVSS3.1 Vector","Results"\n'
        '"10.9.0.1","edge01.example.com","EDGE01","38173","SSL Weak Cipher","Vuln","4","443","tcp","CVE-2023-0286","5.0","CVSS2#(AV:N/AC:L/Au:N/C:P/I:N/A:N)","7.4","CVSS3#CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N","8.2","(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)","Line1\nLine2"\n'
        '"10.9.0.2","","NETB02","38174","SSH Legacy MAC","Vuln","3","22","tcp","CVE-2023-48795","5.9","(AV:N/AC:M/Au:N/C:P/I:P/A:N)","","","","","=HYPERLINK(\\"http://evil\\")"\n'
        '"10.9.0.3","db03.example.com","","38175","Deprecated TLS 1.1","Vuln","3","443","tcp","CVE-2020-0001","4.3","AV:N/AC:M/Au:N/C:N/I:P/A:N","6.5","CVSS3#CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N","","","Detected TLS 1.1"\n',
        encoding="utf-8",
    )

    conf, _ = QualysCSVParser.detect_file(q_csv, ctx=ctx)
    assert conf >= 0.85
    assert detector.select(ctx, q_csv).parser_cls is QualysCSVParser

    batches = list(QualysCSVParser(ctx, q_csv).iter_batches(batch_size=2))
    assert [len(b) for b in batches] == [2, 1]
    r0, r1, r2 = [r for b in batches for r in b]
    for rec in (r0, r1, r2):
        _assert_contract(rec)

    assert r0["scanner_cvss_score"] == 8.2
    assert r0["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    assert "Line1\nLine2" in r0["plugin_output"]

    assert r1["scanner_cvss_score"] == 5.9
    assert r1["scanner_cvss_vector"] == "AV:N/AC:M/Au:N/C:P/I:P/A:N"
    assert r1["hostname"] == "NETB02"
    assert r1["plugin_output"].startswith("=HYPERLINK")

    assert r2["scanner_cvss_score"] == 6.5
    assert r2["scanner_cvss_vector"] == "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
    validate_scan_result_schema(QualysCSVParser(ctx, q_csv).parse())

    # Semicolon-delimited Qualys CSV with single-column banner + metadata preamble
    semi_csv = tmp_path / "qualys_semicolon_preamble.csv"
    semi_csv.write_text(
        "Qualys Report\n"
        "Org;Acme\n"
        "IP;QID;Title;Severity;Results\n"
        "10.9.1.1;1001;Check A;4;Evidence A\n",
        encoding="utf-8",
    )
    assert QualysCSVParser.detect_file(semi_csv, ctx=ctx)[0] >= 0.70
    semi_recs = [r for b in QualysCSVParser(ctx, semi_csv).iter_batches(batch_size=2) for r in b]
    assert len(semi_recs) == 1
    assert semi_recs[0]["plugin_output"] == "Evidence A"


def test_audited_parsers_cvss_normalization_missing_fields_and_batch_boundaries(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    # 1. OpenVAS XML: v3 severity node preferred over v2 cvss_base, prefix/paren normalization, hostname-only <host>
    ov_xml = tmp_path / "openvas_torture.xml"
    ov_xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<report id="gvm-torture">
  <results>
    <result>
      <host><hostname>only-name.internal</hostname></host>
      <port>443/tcp</port>
      <threat>High</threat>
      <nvt oid="1.3.6.1.4.1.25623.1.0.100">
        <name>OpenSSL Issue</name>
        <cvss_base>5.0</cvss_base>
        <tags>cvss_base_vector=CVSS2#(AV:N/AC:L/Au:N/C:P/I:N/A:N)|summary=Found OpenSSL issue</tags>
        <severities>
          <severity type="cvss_base_v3">
            <score>8.6</score>
            <value>CVSS3#(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)</value>
          </severity>
        </severities>
      </nvt>
    </result>
    <result>
      <host>10.5.5.5</host>
      <port>22/tcp</port>
      <threat>Medium</threat>
      <nvt oid="1.3.6.1.4.1.25623.1.0.101"><name>SSH Check</name></nvt>
    </result>
    <result>
      <host>10.5.5.6</host>
      <port>80/tcp</port>
      <threat>Low</threat>
      <nvt oid="1.3.6.1.4.1.25623.1.0.102"><name>HTTP Check</name></nvt>
    </result>
  </results>
</report>""",
        encoding="utf-8",
    )
    ov_batches = list(OpenVASXMLParser(ctx, ov_xml).iter_batches(batch_size=2))
    assert [len(b) for b in ov_batches] == [2, 1]
    ov0 = ov_batches[0][0]
    _assert_contract(ov0)
    assert ov0["hostname"] == "only-name.internal"
    assert ov0["scanner_cvss_score"] == 8.6
    assert ov0["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"

    # 2. SARIF: CVSS3# / parens stripped, v2 AV: vector allowed, batch_size=2 across 2 runs
    sarif_path = tmp_path / "sarif_torture.sarif"
    sarif_payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy", "rules": []}},
                "results": [
                    {
                        "ruleId": "CVE-2024-5001",
                        "message": {"text": "Vuln 1"},
                        "properties": {
                            "cvss": {
                                "nvd": {
                                    "V3Score": 9.8,
                                    "V3Vector": "CVSS3#(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                                }
                            }
                        },
                    },
                    {
                        "ruleId": "CVE-2024-5002",
                        "message": {"text": "Vuln 2"},
                        "properties": {"cvss_vector": "(AV:N/AC:L/Au:N/C:P/I:P/A:P)"},
                    },
                ],
            },
            {
                "tool": {"driver": {"name": "Semgrep", "rules": []}},
                "results": [
                    {
                        "ruleId": "py.sqli",
                        "message": {"text": "SQLi"},
                    }
                ],
            },
        ],
    }
    sarif_path.write_text(json.dumps(sarif_payload), encoding="utf-8")
    sarif_batches = list(SarifParser(ctx, sarif_path).iter_batches(batch_size=2))
    assert [len(b) for b in sarif_batches] == [2, 1]
    s0, s1, s2 = [r for b in sarif_batches for r in b]
    for rec in (s0, s1, s2):
        _assert_contract(rec)
    assert s0["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert s1["scanner_cvss_vector"] == "AV:N/AC:L/Au:N/C:P/I:P/A:P"
    assert s1["scanner_cvss_score"] == 7.5

    # 3. Nuclei JSONL: CVSS3# / parens normalization + auto-computed base score + batch_size=2
    nuclei_path = tmp_path / "nuclei_torture.jsonl"
    nuclei_rows = [
        {
            "template-id": "CVE-2024-6001",
            "info": {
                "name": "Nuclei Vuln 1",
                "severity": "high",
                "classification": {
                    "cvss-metrics": "CVSS3#(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                },
            },
            "host": "https://app1.example.com",
            "matched-at": "https://app1.example.com/login",
        },
        {
            "template-id": "CVE-2024-6002",
            "info": {"name": "Nuclei Vuln 2", "severity": "medium"},
            "host": "10.0.0.5:8080",
        },
        {
            "template-id": "CVE-2024-6003",
            "info": {"name": "Nuclei Vuln 3", "severity": "low"},
            "host": "https://app3.example.com",
        },
    ]
    nuclei_path.write_text("\n".join(json.dumps(r) for r in nuclei_rows) + "\n", encoding="utf-8")
    nuc_batches = list(NucleiJSONLParser(ctx, nuclei_path).iter_batches(batch_size=2))
    assert [len(b) for b in nuc_batches] == [2, 1]
    nuc0 = nuc_batches[0][0]
    _assert_contract(nuc0)
    assert nuc0["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert nuc0["scanner_cvss_score"] == 7.5

    # 4. Nmap XML: NSE cvss_vector normalization + hostscript CVSS + batch_size=2
    nmap_path = tmp_path / "nmap_torture.xml"
    nmap_path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1776910608">
  <host>
    <status state="up"/>
    <address addr="10.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="vulners" output="CVE-2024-7001">
          <elem key="cvss3">8.8</elem>
          <elem key="cvss3_vector">CVSS3#(CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)</elem>
        </script>
      </port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="VULNERABLE: CVE-2017-0144">
        <elem key="cvss3">8.1</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>""",
        encoding="utf-8",
    )
    nm_batches = list(NmapXMLParser(ctx, nmap_path).iter_batches(batch_size=2))
    assert [len(b) for b in nm_batches] == [2, 1]
    nm_recs = [r for b in nm_batches for r in b]
    for rec in nm_recs:
        _assert_contract(rec)
    assert nm_recs[0]["scanner_cvss_score"] == 8.8
    assert nm_recs[0]["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert nm_recs[2]["scanner_sig"] == "nmap:hostscript:smb-vuln-ms17-010"
    assert nm_recs[2]["scanner_cvss_score"] == 8.1


@pytest.mark.parametrize(
    ("root_tag", "body"),
    [
        (
            "SCAN",
            "<SCAN><ASSET><IP>1.2.3.4</IP><VULN><QID>1</QID><TITLE>&xxe;</TITLE></VULN></ASSET></SCAN>",
        ),
        (
            "ASSET_DATA_REPORT",
            "<ASSET_DATA_REPORT><HOST_LIST><HOST><IP>1.2.3.4</IP><VULN_INFO_LIST><VULN_INFO><QID>1</QID><RESULT>&xxe;</RESULT></VULN_INFO></VULN_INFO_LIST></HOST></HOST_LIST></ASSET_DATA_REPORT>",
        ),
        (
            "HOST_LIST_VM_DETECTION_OUTPUT",
            "<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><IP>1.2.3.4</IP><DETECTION_LIST><DETECTION><QID>1</QID><RESULTS>&xxe;</RESULTS></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>",
        ),
    ],
)
def test_qualys_all_xml_schemas_reject_xxe_and_external_dtd_fail_closed(
    tmp_path: Path, root_tag: str, body: str
) -> None:
    ctx = _ctx(tmp_path)

    xxe_file = tmp_path / f"xxe_{root_tag}.xml"
    xxe_file.write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE {root_tag} [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        f"{body}",
        encoding="utf-8",
    )
    assert QualysXMLParser.detect_file(xxe_file, ctx=ctx)[0] == 0.0
    with pytest.raises(ValueError):
        list(QualysXMLParser(ctx, xxe_file).iter_batches())

    ext_dtd_file = tmp_path / f"ext_{root_tag}.xml"
    ext_dtd_file.write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE {root_tag} SYSTEM "https://qualysapi.qualys.com/evil.dtd">\n'
        f'{body.replace("&xxe;", "ok")}',
        encoding="utf-8",
    )
    assert QualysXMLParser.detect_file(ext_dtd_file, ctx=ctx)[0] == 0.0
    with pytest.raises(ValueError):
        QualysXMLParser(ctx, ext_dtd_file).parse()
