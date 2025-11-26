
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

@pytest.mark.parametrize("input_json, expected_port, expected_protocol", [
    # Normal case: "80/tcp"
    ({
        "report": {
            "results": [{
                "host": "192.168.1.100",
                "port": "80/tcp",
                "name": "HTTP Service",
                "cve": "CVE-2023-0800"
            }]
        }
    }, 80, "tcp"),

    # Edge case: "general/tcp" (OpenVAS uses this when no port is applicable)
    ({
        "report": {
            "results": [{
                "host": "192.168.1.101",
                "port": "general/tcp",
                "name": "General Plugin",
                "cve": "CVE-2022-0002"
            }]
        }
    }, None, "tcp"),

    # Protocol only: "udp"
    ({
        "report": {
            "results": [{
                "host": "192.168.1.102",
                "port": "123/udp",
                "name": "NTP Service",
                "cve": "CVE-2021-9999"
            }]
        }
    }, 123, "udp"),

    # Completely malformed port
    ({
        "report": {
            "results": [{
                "host": "192.168.1.103",
                "port": "nonsense",
                "name": "Broken Port",
                "cve": "CVE-2099-1234"
            }]
        }
    }, None, "unknown")
])
def test_parser_port_protocol_fallbacks(input_json, expected_port, expected_protocol):
    parser = OpenVASParser()
    result = parser.parse(input_json)

    assert result.assets, "No assets returned"
    asset = result.assets[0]
    assert asset.findings, "No findings parsed"
    finding = asset.findings[0]

    assert finding.affected_port == expected_port, f"Expected port {expected_port}, got {finding.affected_port}"
    assert finding.protocol == expected_protocol, f"Expected protocol {expected_protocol}, got {finding.protocol}"
