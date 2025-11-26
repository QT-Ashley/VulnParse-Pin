import pytest
from parsers.nessus_parser import NessusParser
from classes.dataclass import ScanResult, Asset
from utils.logger import LoggerWrapper
from typing import Any

pytestmark = pytest.mark.xfail(reason="JSON parsers deferred; tests outdated after parser architecture refactor.")

@pytest.fixture(scope='session', autouse=True)
def setup_logging():
    import utils.logger_instance as log
    if not getattr(log, 'log', None):
        log.log = LoggerWrapper(log_file='logs/pytest.log')
        log.log.print_info("Pytest logging initialized.")

@pytest.fixture
def nessus_sample_report():
    return {
        "scan": {
            "info": {
                "name": "Internal Scan",
                "start_time": "2025-07-03T12:00:00Z",
                "end time": "2025-07--03T16:00:00Z"
            },
            "hosts": [
                {
                    "hostname": "test-host",
                    "ip": "192.168.1.1",
                    "vulnerabilities": [
                        {
                            "plugin_id": "1000",
                            "plugin_name": "test-vuln",
                            "severity": "High",
                            "cvss_base_score": 7.5,
                            "cve": ["CVE-2023-12345"]
                        }
                    ]
                }
            ]
        }
    }
    
def test_nessus_parser_basic(nessus_sample_report):
    parser = NessusParser()
    scan_result = parser.parse(nessus_sample_report)
    
    assert isinstance(scan_result, ScanResult)
    assert len(scan_result.assets) == 1
    asset = scan_result.assets[0]
    assert isinstance(asset, Asset)
    assert asset.hostname == "test-host"
    assert asset.ip_address == "192.168.1.1"
    assert len(asset.findings) == 1
    vuln = asset.findings[0]
    assert vuln.cves == ["CVE-2023-12345"]
    assert isinstance(vuln.cvss_score, float)

@pytest.fixture
def nessus_missing_fields_sample() -> dict[str, dict[str, Any]]:
    return {
        "scan": {
            "info": {
                "name": "Internal Scan",
                "start_time": "2025-07-03T12:00:00Z",
                "end time": "2025-07--03T16:00:00Z"
            },
            "hosts": [
                {
                    "hostname": "test-host",
                    "ip": "192.168.1.1",
                    "vulnerabilities": [
                        {
                            "plugin_id": "1000",
                            "plugin_name": "test-vuln",
                            "severity": "High",
                            "cvss_base_score": 7.5,
                            "cve": None,
                            "see also": [],
                            "description": "",
                            "protocol": None
                        }
                    ]
                }
            ]
        }
    }
    
def test_nessus_missing_fields(nessus_missing_fields_sample: dict[str, dict[str, Any]]) -> None:
    parser = NessusParser()
    scan_result = parser.parse(nessus_missing_fields_sample)
    
    assert isinstance(scan_result, ScanResult)
    assert len(scan_result.assets) == 1
    
    asset = scan_result.assets[0]
    assert isinstance(asset, Asset)
    assert asset.hostname == "test-host"
    assert asset.ip_address == "192.168.1.1"
    assert len(asset.findings) == 1
    vuln = asset.findings[0]
    assert isinstance(vuln.cves, list) and (not vuln.cves or vuln.cves[0] in ["N/A", "Unknown"])
    assert isinstance(vuln.description, str) and (vuln.description in ["N/A", "Unknown", "Not Available"])
    assert isinstance(vuln.protocol, str) and (vuln.protocol in ["N/A", "Unknown", "unavailable"])
    assert isinstance(vuln.references, list) and (not vuln.references or vuln.references[0] in ["N/A", "Unknown", "Not Available"])

@pytest.fixture
def nessus_empty_vuln():
    return {
        "scan": {
            "info": {
                
            },
            "hosts": [
                {
                    "vulnerabilities": [{}]
                }
            ]
        }
    }
    
def test_nessus_allmissing_fields(nessus_empty_vuln: dict[str, dict[str, Any]]) -> None:
    parser = NessusParser()
    scan_result = parser.parse(nessus_empty_vuln)
    vuln = scan_result.assets[0].findings[0]
    assert vuln.vuln_id == "unknown"
    
@pytest.fixture
def nessus_mssing_asset_fields():
    return {
        "scan": {
            "info": {
                
            },
            "hosts": [
                {
                    "vulnerabilities": [
                        {
                            "vuln_id": "1001",
                            "title": "Test Plugin"
                        }
                    ]
                }
            ]
        }
    }
    
def test_asset_missing_metadata(nessus_mssing_asset_fields ):
    parser = NessusParser()
    result = parser.parse(nessus_mssing_asset_fields)
    asset = result.assets[0]
    assert asset.hostname in ["N/A", "Unknown"]
    assert asset.ip_address in ["N/A", "Unknown"]
    
@pytest.fixture
def nessus_bad_cvss_score():
    return {
        "scan": {
            "info": {
                
            },
            "hosts": [
                {
                    "hostname": "host",
                    "ip": "10.10.10.10",
                    "vulnerabilities": [
                        {
                            "vuln_id": "1001",
                            "cvss_base_score": "not_a_score"
                        }
                    ]
                }
            ]
        }
    }
    
def test_invalid_cvss_score(nessus_bad_cvss_score):
    parser = NessusParser()
    result = parser.parse(nessus_bad_cvss_score)
    vuln = result.assets[0].findings[0]
    assert isinstance(vuln.cvss_score, float)
    assert vuln.cvss_score == 0.0
    
@pytest.fixture
def nessus_mixed_severity():
    return {
        "scan": {
            "info": {
                
            },
            "hosts": [
                {
                    "hostname": "host",
                    "ip": "0.0.0.0",
                    "vulnerabilities": [
                        {
                            "vuln_id": "3000",
                            "severity": "hIgH"
                        }
                    ]
                }
            ]
        }
    }
    
def test_severity_normalization(nessus_mixed_severity):
    parser = NessusParser()
    result = parser.parse(nessus_mixed_severity)
    vuln = result.assets[0].findings[0]
    assert vuln.severity.lower() == "high"
    
@pytest.fixture
def nessus_multi_cves():
    return {
        "scan": {
            "info": {
                
            },
            "hosts": [
                {
                    "hostname": "host",
                    "ip": "2.2.2.2",
                    "vulnerabilities": [
                        {
                            "vuln_id": "5000",
                            "cve": ["CVE-2023-0001", "CVE-2023-0002"]
                        }
                    ]
                }
            ]
        }
    }
    
def test_multiple_cves(nessus_multi_cves):
    parser = NessusParser()
    result = parser.parse(nessus_multi_cves)
    vuln = result.assets[0].findings[0]
    assert vuln.cves == ["CVE-2023-0001", "CVE-2023-0002"]