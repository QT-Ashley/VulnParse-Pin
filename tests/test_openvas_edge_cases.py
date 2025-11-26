import pytest
from parsers.openvas_parser import OpenVASParser
from utils.logger import LoggerWrapper

pytestmark = pytest.mark.xfail(reason="JSON parsers deferred; tests outdated after parser architecture refactor.")

@pytest.fixture(scope='session', autouse=True)
def setup_logging():
    import utils.logger_instance as log
    if not getattr(log, 'log', None):
        log.log = LoggerWrapper(log_file='logs/pytest.log')
        log.log.print_info("PyTest logging initialized")

@pytest.mark.parametrize("input_json, expected_hostname_fragment", [
    # Malformed port field
    ({
        "report": {
            "results": [{
                "port": "invalid_format",
                "host": "192.168.1.100",
                "name": "Example Plugin",
                "cve": "CVE-2022-0001"
            }]
        }
    }, "192.168.1.100"),

    # Missing hostname and port, fallback to hash
    ({
        "report": {
            "results": [{
                "name": "Missing fields plugin",
                "cve": "CVE-2021-9999"
            }]
        }
    }, "unknown_"),

    # Empty results array
    ({
        "report": {
            "results": []
        }
    }, None),

    # Missing results key
    ({
        "report": {}
    }, None),

    # Malformed CVSS vector
    ({
        "report": {
            "results": [{
                "port": "80/tcp",
                "host": "10.0.0.1",
                "name": "Bad CVSS Plugin",
                "cve": "CVE-2023-1111",
                "cvss_base": "not_a_score"
            }]
        }
    }, "10.0.0.1"),

    # Multiple CVEs
    ({
        "report": {
            "results": [{
                "port": "443/tcp",
                "host": "10.10.10.10",
                "name": "Multi-CVE Plugin",
                "cve": "CVE-2021-1234, CVE-2022-9999"
            }]
        }
    }, "10.10.10.10"),

    # Missing port and host completely
    ({
        "report": {
            "results": [{
                "name": "No Port or Host",
                "cve": "CVE-2000-0001"
            }]
        }
    }, "unknown_"),
])
def test_openvas_edge_cases(input_json, expected_hostname_fragment):
    parser = OpenVASParser()
    try:
        scan_result = parser.parse(input_json)
        
        if not scan_result or not scan_result.assets:
            assert expected_hostname_fragment is None
        else:
            actual_hostname = scan_result.assets[0].hostname
            assert expected_hostname_fragment in actual_hostname

    except Exception as e:
        if expected_hostname_fragment is None:
            assert True  # Expected failure
        else:
            pytest.fail(f"Unexpected failure: {e}")
