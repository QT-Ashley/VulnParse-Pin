import pytest
from parsers.openvas_parser import OpenVASParser
from classes.dataclass import ScanResult, Asset
from utils.logger import LoggerWrapper
from typing import Any
import re

@pytest.fixture(scope='session', autouse=True)
def setup_logging():
    import utils.logger_instance as log
    if not getattr(log, 'log', None):
        log.log = LoggerWrapper(log_file='logs/pytest.log')
        log.log.print_info("Pytest logging initialized.")

@pytest.fixture
def openvas_sample_report():
    return {
            "report": {
            "scan_start": "N/A",
            "scan_end": "N/A",
            "results": [
                {
                    "host": "webserver-01.example.com",
                    "port": "443/tcp",
                    "threat": "High",
                    "severity": "7.5",
                    "description": "The remote web server is running an outdated version of Apache HTTPD.",
                    "result": "Vulnerable version detected.",
                    "solution": "Update Apache HTTPD to the latest available version.",
                    "creation_time": "2025-06-13T14:05:00Z",
                    "modification_time": "2025-06-13T14:10:00Z",
                    "scan_nvt_version": "2025061301",
                    "nvt": {
                    "oid": "1.3.6.1.4.1.25623.1.0.12345",
                    "name": "Apache HTTPD Version Detection",
                    "cve": "CVE-2024-1234,CVE-2024-5678",
                    "cvss_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "tags": "cvss_base_vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H;cvss_base_score=9.8;solution=Update Apache;see_also=https://httpd.apache.org/security/vulnerabilities_24.html"
                    }
                }
            ]
        }
    }
    
def test_openvas_parser_basic(openvas_sample_report):
    parser = OpenVASParser()
    scan_result = parser.parse(openvas_sample_report)
    
    assert isinstance(scan_result, ScanResult)
    assert len(scan_result.assets) == 1
    asset = scan_result.assets[0]
    assert isinstance(asset, Asset)
    assert asset.hostname == "webserver-01.example.com"
    assert len(asset.findings) == 1
    vuln = asset.findings[0]
    assert len(vuln.cves) == 2
    assert isinstance(vuln.cvss_score, float)

@pytest.fixture
def openvas_missing_fields_sample() -> dict[str, dict[str, Any]]:
    return {
            "report": {
            "scan_start": "N/A",
            "scan_end": "N/A",
            "results": [
                {
                    "host": "webserver-01.example.com",
                    "port": "443/tcp",
                    "threat": "High",
                    "severity": "7.5",
                    "description": None,
                    "result": None,
                    "solution": "Update Apache HTTPD to the latest available version.",
                    "creation_time": "2025-06-13T14:05:00Z",
                    "modification_time": "2025-06-13T14:10:00Z",
                    "scan_nvt_version": "2025061301",
                    "port": None,
                    "protocol": "tcp",
                    "nvt": {
                        "oid": "",
                        "name": None,
                        "cve": [],
                        "cvss_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "tags": None
                    }
                }
            ]
        }
    }
    
def test_openvas_missing_fields(openvas_missing_fields_sample: dict[str, dict[str, Any]]) -> None:
    parser = OpenVASParser()
    scan_result = parser.parse(openvas_missing_fields_sample)
    
    asset = scan_result.assets[0]
    assert isinstance(asset, Asset)
    assert asset.hostname == "webserver-01.example.com"
    
    vuln = asset.findings[0]
    assert isinstance(vuln.cves, list) and (not vuln.cves or vuln.cves[0] in ["N/A", "Unknown"])
    assert isinstance(vuln.description, str) and (vuln.description in ["N/A", "Unknown", "Not Available"])
    assert isinstance(vuln.protocol, str) and (vuln.protocol in ["N/A", "Unknown", "unavailable"])
    assert isinstance(vuln.references, list) and (not vuln.references or vuln.references[0] in ["N/A", "Unknown", "Not Available"])

@pytest.fixture
def openvas_empty_vuln():
    return {
        "report": {
            "results": [
                {}
            ]
        }
    }
    
def test_openvas_allmissing_fields(openvas_empty_vuln: dict[str, dict[str, Any]]) -> None:
    parser = OpenVASParser()
    scan_result = parser.parse(openvas_empty_vuln)
    vuln = scan_result.assets[0].findings[0]
    assert isinstance(vuln.vuln_id, str)
    assert re.match(r"^[a-fA-F0-9]{12}$", vuln.vuln_id), "Fallback ID is not a valid SHA256 Hash"
    
@pytest.fixture
# Not necessary since standard openvas json host info is all one dictionary obj.
def openvas_mssing_asset_fields():
    pass
    
def test_asset_missing_metadata(openvas_mssing_asset_fields ):
    pass
#####################################################################
@pytest.fixture
def openvas_bad_cvss_score():
    return {
            "report": {
            "scan_start": "N/A",
            "scan_end": "N/A",
            "results": [
                {
                    "host": "webserver-01.example.com",
                    "port": "443/tcp",
                    "nvt": {
                        "cve": ["CVE-2024-1234", "CVE-2024-5678"],
                        "cvss_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "tags": "cvss_base_vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H;cvss_base_score=not;solution=Update Apache;see_also=https://httpd.apache.org/security/vulnerabilities_24.html"
                    }
                }
            ]
        }
    }
    
def test_invalid_cvss_score(openvas_bad_cvss_score):
    parser = OpenVASParser()
    result = parser.parse(openvas_bad_cvss_score)
    vuln = result.assets[0].findings[0]
    assert isinstance(vuln.cvss_score, float)
    assert vuln.cvss_score == 0.0
    
@pytest.fixture
def openvas_mixed_severity():
    return {
            "report": {
            "scan_start": "N/A",
            "scan_end": "N/A",
            "results": [
                {
                    "host": "webserver-01.example.com",
                    "port": "443/tcp",
                    "threat": "HiGh",
                    "severity": "7.5",
                    "description": None,
                    "result": None,
                    "solution": "Update Apache HTTPD to the latest available version.",
                    "creation_time": "2025-06-13T14:05:00Z",
                    "modification_time": "2025-06-13T14:10:00Z",
                    "scan_nvt_version": "2025061301",
                    "port": None,
                    "protocol": "tcp",
                    "nvt": {
                        "oid": "",
                        "name": None,
                        "cve": [],
                        "cvss_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "tags": None
                    }
                }
            ]
        }
    }
    
def test_severity_normalization(openvas_mixed_severity):
    parser = OpenVASParser()
    result = parser.parse(openvas_mixed_severity)
    vuln = result.assets[0].findings[0]
    assert vuln.severity.lower() == "high"
    
@pytest.fixture
def openvas_multi_cves():
    return {
            "report": {
            "scan_start": "N/A",
            "scan_end": "N/A",
            "results": [
                {
                    "host": "webserver-01.example.com",
                    "port": "443/tcp",
                    "threat": "High",
                    "severity": "7.5",
                    "description": "The remote web server is running an outdated version of Apache HTTPD.",
                    "result": "Vulnerable version detected.",
                    "solution": "Update Apache HTTPD to the latest available version.",
                    "creation_time": "2025-06-13T14:05:00Z",
                    "modification_time": "2025-06-13T14:10:00Z",
                    "scan_nvt_version": "2025061301",
                    "nvt": {
                    "oid": "1.3.6.1.4.1.25623.1.0.12345",
                    "name": "Apache HTTPD Version Detection",
                    "cve": "CVE-2024-1234,CVE-2024-5678",
                    "cvss_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "tags": "cvss_base_vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H;cvss_base_score=9.8;solution=Update Apache;see_also=https://httpd.apache.org/security/vulnerabilities_24.html"
                    }
                }
            ]
        }
    }
    
def test_multiple_cves(openvas_multi_cves):
    parser = OpenVASParser()
    result = parser.parse(openvas_multi_cves)
    vuln = result.assets[0].findings[0]
    assert isinstance(vuln.cves, list)
    expected_cves = {"CVE-2024-1234", "CVE-2024-5678"}
    assert expected_cves.issubset(set(vuln.cves))
    