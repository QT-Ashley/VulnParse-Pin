
import pytest
from parsers.openvas_parser import OpenVASParser
from utils.logger import LoggerWrapper

@pytest.fixture(scope='session', autouse=True)
def setup_logging():
    import utils.logger_instance as log
    if not getattr(log, 'log', None):
        log.log = LoggerWrapper(log_file='logs/pytest.log')
        log.log.print_info("PyTest logging initialized")

@pytest.mark.parametrize("input_json, expected_title, expected_description", [
    # Normal case: title and description in nvt
    ({
        "report": {
            "results": [{
                "host": "192.168.1.200",
                "port": "443/tcp",
                "nvt": {
                    "name": "TLS Weak Cipher Detected",
                    "description": "This plugin detects weak ciphers in TLS services."
                },
                "cve": "CVE-2022-3333"
            }]
        }
    }, "TLS Weak Cipher Detected", "This plugin detects weak ciphers in TLS services."),

    # Fallback to 'name' field when nvt.name is missing
    ({
        "report": {
            "results": [{
                "host": "192.168.1.201",
                "port": "80/tcp",
                "name": "Fallback Plugin Title",
                "nvt": {
                    "description": "This is a fallback description only."
                },
                "cve": "CVE-2021-4444"
            }]
        }
    }, "Fallback Plugin Title", "This is a fallback description only."),

    # Fallback to 'N/A' when description is missing entirely
    ({
        "report": {
            "results": [{
                "host": "192.168.1.202",
                "port": "22/tcp",
                "name": "Plugin With No Description",
                "nvt": {
                    "name": "NVT Plugin Name"
                },
                "cve": "CVE-2020-5555"
            }]
        }
    }, "NVT Plugin Name", "N/A"),

    # Fallback title and description when everything is missing
    ({
        "report": {
            "results": [{
                "host": "192.168.1.203",
                "port": "53/udp",
                "cve": "CVE-2023-0001"
            }]
        }
    }, "N/A", "N/A")
])
def test_plugin_title_description_fallbacks(input_json, expected_title, expected_description):
    parser = OpenVASParser()
    result = parser.parse(input_json)

    assert result.assets, "No assets returned"
    asset = result.assets[0]
    assert asset.findings, "No findings parsed"
    finding = asset.findings[0]

    assert finding.title == expected_title, f"Expected title '{expected_title}', got '{finding.title}'"
    assert finding.description == expected_description, f"Expected description '{expected_description}', got '{finding.description}'"
