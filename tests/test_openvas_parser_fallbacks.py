
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

@pytest.mark.parametrize("input_json, expected_fields", [
    # Plugin with missing CVSS, severity, or description
    ({
        "report": {
            "results": [{
                "host": "192.168.1.50",
                "port": "443/tcp",
                "name": "Incomplete Plugin",
                "cve": "CVE-2022-1111"
            }]
        }
    }, {
        "title": "Incomplete Plugin",
        "vuln_id": "CVE-2022-1111",
        "severity": "Unknown",
        "cvss_score": 0.0,
        "description": "Unknown"
    }),

    # Plugin with invalid CVSS base string
    ({
        "report": {
            "results": [{
                "host": "192.168.1.51",
                "port": "80/tcp",
                "name": "Bad CVSS Plugin",
                "cve": "CVE-2022-2222",
                "cvss_base": "nonsense_score"
            }]
        }
    }, {
        "cvss_score": 0.0,
        "vuln_id": "CVE-2022-2222"
    }),

    # Plugin with missing CVE, should fallback to plugin name hash
    ({
        "report": {
            "results": [{
                "host": "192.168.1.52",
                "port": "22/tcp",
                "name": "No CVE Plugin",
                "nvt": {
                    "oid": "1.3.6.1.4.1.25623.1.0.123456"
                }
            }]
        }
    }, {
        "vuln_id": "1.3.6.1.4.1.25623.1.0.123456"
    })
])
def test_parser_field_fallbacks(input_json, expected_fields):
    parser = OpenVASParser()
    result = parser.parse(input_json)
    assert result.assets, "No assets returned"
    asset = result.assets[0]
    assert asset.findings, "No findings parsed"
    finding = asset.findings[0]

    for field, expected_value in expected_fields.items():
        actual = getattr(finding, field, None)
        assert actual == expected_value, f"Field '{field}' mismatch: expected {expected_value}, got {actual}"
