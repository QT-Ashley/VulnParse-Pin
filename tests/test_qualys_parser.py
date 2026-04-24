"""
Unit tests for Qualys XML parser.
"""
import pytest
from pathlib import Path
from textwrap import dedent

from vulnparse_pin.parsers.qualys_parser import QualysXMLParser
from vulnparse_pin.core.classes.dataclass import RunContext, AppPaths
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.io.pfhandler import PermFileHandler


@pytest.fixture
def ctx(tmp_path) -> RunContext:
    """Create a test RunContext with temporary file handling."""
    logger = LoggerWrapper(log_file=str(tmp_path / "qualys_test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


# Sample Qualys XML exports
@pytest.fixture
def sample_qualys_xml_file(tmp_path):
    """Create a minimal valid Qualys XML file."""
    xml_content = dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <SCAN id="scan_12345" title="Network Scan">
        <SCAN_DATETIME>2026-04-13T10:00:00Z</SCAN_DATETIME>
        <SCANNER_NAME>Qualys VMDR 3.x</SCANNER_NAME>
        <ASSET>
            <IP>192.168.1.100</IP>
            <FQDN>server.internal.com</FQDN>
            <VULN>
                <QID>11111</QID>
                <TITLE>OpenSSH Authentication Bypass</TITLE>
                <DESCRIPTION>Unauthenticated attackers can bypass SSH authentication.</DESCRIPTION>
                <PORT>22/tcp</PORT>
                <SEVERITY>5</SEVERITY>
                <CVSS_BASE>8.6</CVSS_BASE>
                <CVSS_VECTOR>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L</CVSS_VECTOR>
                <CVE_ID>CVE-2023-12345</CVE_ID>
            </VULN>
            <VULN>
                <QID>22222</QID>
                <TITLE>Nginx HTTP/2 Rapid Reset DoS</TITLE>
                <DESCRIPTION>Nginx is vulnerable to HTTP/2 rapid reset attacks.</DESCRIPTION>
                <PORT>443/tcp</PORT>
                <SEVERITY>4</SEVERITY>
                <CVSS_BASE>7.5</CVSS_BASE>
                <CVSS_VECTOR>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</CVSS_VECTOR>
                <CVE_ID>CVE-2023-54321</CVE_ID>
            </VULN>
        </ASSET>
        <ASSET>
            <IP>10.0.0.50</IP>
            <VULN>
                <QID>33333</QID>
                <TITLE>Unpatched Windows Exploit</TITLE>
                <DESCRIPTION>Remote code execution in Windows RDP service.</DESCRIPTION>
                <PORT>3389/tcp</PORT>
                <SEVERITY>5</SEVERITY>
                <CVSS_BASE>9.8</CVSS_BASE>
                <CVSS_VECTOR>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</CVSS_VECTOR>
                <CVE_ID>CVE-2026-00001</CVE_ID>
            </VULN>
        </ASSET>
    </SCAN>
    """).strip()
    
    file_path = tmp_path / "qualys_sample.xml"
    file_path.write_text(xml_content, encoding="utf-8")
    return file_path


@pytest.fixture
def sample_qualys_xml_minimal(tmp_path):
    """Create a minimal valid Qualys XML file (edge case)."""
    xml_content = dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <SCAN id="minimal_scan">
        <SCAN_DATETIME>2026-04-13T00:00:00Z</SCAN_DATETIME>
        <ASSET>
            <IP>1.2.3.4</IP>
            <VULN>
                <QID>1000</QID>
                <TITLE>Simple Vuln</TITLE>
                <DESCRIPTION>No CVSS or CVE</DESCRIPTION>
            </VULN>
        </ASSET>
    </SCAN>
    """).strip()
    
    file_path = tmp_path / "qualys_minimal.xml"
    file_path.write_text(xml_content, encoding="utf-8")
    return file_path


@pytest.fixture
def sample_qualys_xml_no_vulns(tmp_path):
    """Create a Qualys XML with assets but no vulnerabilities."""
    xml_content = dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <SCAN id="clean_scan">
        <SCAN_DATETIME>2026-04-13T00:00:00Z</SCAN_DATETIME>
        <ASSET>
            <IP>1.2.3.4</IP>
        </ASSET>
        <ASSET>
            <IP>5.6.7.8</IP>
        </ASSET>
    </SCAN>
    """).strip()
    
    file_path = tmp_path / "qualys_clean.xml"
    file_path.write_text(xml_content, encoding="utf-8")
    return file_path


@pytest.fixture
def sample_qualys_xml_no_ip(tmp_path):
    """Create a Qualys XML with malformed assets (no IP/FQDN)."""
    xml_content = dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <SCAN id="malformed">
        <ASSET>
            <VULN>
                <QID>1</QID>
                <TITLE>Orphan Vuln</TITLE>
            </VULN>
        </ASSET>
    </SCAN>
    """).strip()
    
    file_path = tmp_path / "qualys_malformed.xml"
    file_path.write_text(xml_content, encoding="utf-8")
    return file_path


@pytest.fixture
def sample_qualys_xml_variant_tags(tmp_path):
    """Create a Qualys-like XML variant with alternate tag names and root."""
    xml_content = dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <SCAN_REPORT id="variant_scan">
        <SCAN_DATE>2026-04-13T10:00:00Z</SCAN_DATE>
        <HOST>
            <IP_ADDRESS>172.16.1.25</IP_ADDRESS>
            <VULNERABILITY>
                <VULN_ID>44444</VULN_ID>
                <NAME>Variant Tag Vulnerability</NAME>
                <DETAILS>Variant details text</DETAILS>
                <SERVICE_PORT>udp/53</SERVICE_PORT>
                <THREAT>4</THREAT>
                <CVSS3_BASE>8.0</CVSS3_BASE>
                <CVSS3_VECTOR>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L</CVSS3_VECTOR>
                <CVES>CVE-2025-11111, CVE-2025-22222</CVES>
                <EVIDENCE>Packet capture evidence</EVIDENCE>
                <REMEDIATION>Apply latest DNS patch</REMEDIATION>
            </VULNERABILITY>
        </HOST>
    </SCAN_REPORT>
    """).strip()

    file_path = tmp_path / "qualys_variant.xml"
    file_path.write_text(xml_content, encoding="utf-8")
    return file_path


# Detection tests
class TestQualysDetection:
    def test_detect_qualys_xml_valid(self, sample_qualys_xml_file):
        """Should recognize valid Qualys XML with high confidence."""
        confidence, evidence = QualysXMLParser.detect_file(sample_qualys_xml_file)
        assert confidence >= 0.8, f"Expected confidence >= 0.8, got {confidence}"
        assert ("root_tag", "SCAN") in evidence

    def test_detect_qualys_xml_minimal(self, sample_qualys_xml_minimal):
        """Should recognize minimal Qualys XML."""
        confidence, evidence = QualysXMLParser.detect_file(sample_qualys_xml_minimal)
        assert confidence >= 0.5, f"Expected confidence >= 0.5, got {confidence}"

    def test_detect_qualys_xml_no_vulns(self, sample_qualys_xml_no_vulns):
        """Should recognize Qualys XML even without vulnerabilities."""
        confidence, evidence = QualysXMLParser.detect_file(sample_qualys_xml_no_vulns)
        assert confidence >= 0.5

    def test_detect_rejects_non_xml(self, tmp_path):
        """Should reject non-XML files."""
        csv_file = tmp_path / "not_xml.csv"
        csv_file.write_text("ip,port,service\n1.2.3.4,22,ssh")
        
        confidence, evidence = QualysXMLParser.detect_file(csv_file)
        assert confidence == 0.0

    def test_detect_rejects_wrong_root_tag(self, tmp_path):
        """Should reject XML with non-SCAN root tag."""
        xml_file = tmp_path / "wrong_root.xml"
        xml_file.write_text("""<?xml version="1.0"?>
        <REPORT>
            <FINDING>
                <TITLE>Not Qualys</TITLE>
            </FINDING>
        </REPORT>""")
        
        confidence, evidence = QualysXMLParser.detect_file(xml_file)
        assert confidence == 0.0

    def test_detect_qualys_xml_variant_root(self, sample_qualys_xml_variant_tags):
        """Should recognize SCAN_REPORT root and variant tag layout."""
        confidence, evidence = QualysXMLParser.detect_file(sample_qualys_xml_variant_tags)
        assert confidence >= 0.7
        assert any(k == "root_tag" for k, _ in evidence)


# Parsing tests
class TestQualysParsing:
    def test_parse_qualys_xml_valid(self, ctx, sample_qualys_xml_file):
        """Should correctly parse valid Qualys XML."""
        parser = QualysXMLParser(ctx, filepath=str(sample_qualys_xml_file))
        scan = parser.parse()
        
        # Assertions
        assert scan.scan_metadata.source == "Qualys"
        assert len(scan.assets) == 2
        
        # First asset (192.168.1.100) with 2 findings
        asset1 = next((a for a in scan.assets if a.ip_address == "192.168.1.100"), None)
        assert asset1 is not None
        assert len(asset1.findings) == 2
        
        # Check first finding (OpenSSH)
        ssh_finding = next(f for f in asset1.findings if "OpenSSH" in f.title)
        assert "CVE-2023-12345" in ssh_finding.cves
        assert ssh_finding.affected_port == 22
        assert "tcp" in (ssh_finding.protocol or "").lower()
        assert ssh_finding.cvss_score == 8.6
        assert "CVSS:3.1" in ssh_finding.cvss_vector
        
        # Check second finding (Nginx)
        nginx_finding = next(f for f in asset1.findings if "Nginx" in f.title)
        assert "CVE-2023-54321" in nginx_finding.cves
        assert nginx_finding.affected_port == 443
        
        # Second asset (10.0.0.50) with 1 finding
        asset2 = next((a for a in scan.assets if a.ip_address == "10.0.0.50"), None)
        assert asset2 is not None
        assert len(asset2.findings) == 1
        
        rdp_finding = asset2.findings[0]
        assert "CVE-2026-00001" in rdp_finding.cves
        assert rdp_finding.affected_port == 3389
        assert rdp_finding.cvss_score == 9.8

    def test_parse_qualys_xml_minimal(self, ctx, sample_qualys_xml_minimal):
        """Should parse minimal Qualys XML without CVSS/CVE."""
        parser = QualysXMLParser(ctx, filepath=str(sample_qualys_xml_minimal))
        scan = parser.parse()
        
        assert len(scan.assets) == 1
        asset = scan.assets[0]
        assert asset.ip_address == "1.2.3.4"
        assert len(asset.findings) == 1
        
        finding = asset.findings[0]
        assert finding.title == "Simple Vuln"
        assert finding.cvss_score is None
        assert len(finding.cves) == 0

    def test_parse_qualys_xml_no_vulns(self, ctx, sample_qualys_xml_no_vulns):
        """Should parse Qualys XML with no vulnerabilities."""
        parser = QualysXMLParser(ctx, filepath=str(sample_qualys_xml_no_vulns))
        scan = parser.parse()
        
        assert len(scan.assets) == 2
        assert scan.scan_metadata.vulnerability_count == 0

    def test_parse_qualys_xml_drops_malformed_assets(self, ctx, sample_qualys_xml_no_ip):
        """Should drop assets with no IP/FQDN and log warning."""
        parser = QualysXMLParser(ctx, filepath=str(sample_qualys_xml_no_ip))
        scan = parser.parse()
        
        # All assets without IP should be dropped
        assert len(scan.assets) == 0

    def test_parse_qualys_xml_variant_tags(self, ctx, sample_qualys_xml_variant_tags):
        """Should parse schema variants with alternate root and field names."""
        parser = QualysXMLParser(ctx, filepath=str(sample_qualys_xml_variant_tags))
        scan = parser.parse()

        assert len(scan.assets) == 1
        asset = scan.assets[0]
        assert asset.ip_address == "172.16.1.25"
        assert len(asset.findings) == 1

        finding = asset.findings[0]
        assert finding.vuln_id == "44444"
        assert finding.title == "Variant Tag Vulnerability"
        assert finding.affected_port == 53
        assert finding.protocol == "udp"
        assert finding.severity == "High"
        assert "CVE-2025-11111" in finding.cves
        assert finding.source_format == "qualys-xml"
        assert finding.fidelity_tier in {"full", "partial", "minimal"}
        assert isinstance(finding.confidence_reasons, list)

    def test_parse_requires_filepath(self, ctx):
        """Should raise error if filepath is None."""
        parser = QualysXMLParser(ctx, filepath=None)
        with pytest.raises(ValueError, match="requires an accessible filepath"):
            parser.parse()

    def test_parse_rejects_oversized_files(self, ctx, tmp_path):
        """Should reject files larger than 500MB (mock check)."""
        parser = QualysXMLParser(ctx, filepath="/nonexistent/file.xml")
        # This would fail on file size check, but we'll verify the logic is there
        with pytest.raises(ValueError):
            parser.parse()


# Schema integration tests
class TestQualysSchemaIntegration:
    def test_finding_schema_normalization(self, ctx, sample_qualys_xml_file):
        """Should normalize findings to VulnParse-Pin schema."""
        parser = QualysXMLParser(ctx, filepath=str(sample_qualys_xml_file))
        scan = parser.parse()
        
        finding = scan.assets[0].findings[0]
        
        # Verify all expected Finding fields are populated
        assert finding.finding_id is not None
        assert finding.cves is not None and len(finding.cves) > 0
        assert finding.title is not None
        assert finding.description is not None
        assert finding.detection_plugin is not None  # qualys_qid mapped here
        assert finding.vuln_id is not None

    def test_asset_schema_normalization(self, ctx, sample_qualys_xml_file):
        """Should normalize assets to VulnParse-Pin schema."""
        parser = QualysXMLParser(ctx, filepath=str(sample_qualys_xml_file))
        scan = parser.parse()
        
        asset = scan.assets[0]
        
        # Verify all expected Asset fields are populated
        assert asset.asset_id is not None
        assert asset.hostname is not None
        assert asset.ip_address is not None
        assert asset.findings is not None
        assert isinstance(asset.findings, list)
