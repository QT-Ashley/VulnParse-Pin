
import pytest
from parsers.openvas_parser import OpenVASParser
from utils.logger import LoggerWrapper

@pytest.fixture(scope='session', autouse=True)
def setup_logging():
    import utils.logger_instance as log
    if not getattr(log, 'log', None):
        log.log = LoggerWrapper(log_file='logs/pytest.log')
        log.log.print_info("PyTest logging initialized")

@pytest.mark.parametrize("raw_input, expected_result_count, expected_keys", [
    # Normal, minimal input
    ({
        "scan": {
            "info": {
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-01-01T01:00:00Z"
            },
            "results": [{
                "host": "192.168.1.10",
                "ip": "192.168.1.10",
                "port": "80",
                "description": "Test vuln",
                "severity": "2",
                "nvt": {
                    "name": "Fake Plugin",
                    "cve": "CVE-2024-0001"
                }
            }]
        }
    }, 1, ["host", "ip", "port", "description", "severity", "nvt"]),

    # Missing keys, should be defaulted
    ({
        "scan": {
            "results": [{}]
        }
    }, 1, ["host", "ip", "port", "description", "severity", "nvt"]),

    # Single object instead of list
    ({
        "scan": {
            "results": {
                "host": "10.0.0.1",
                "port": "443",
                "nvt": {}
            }
        }
    }, 1, ["host", "ip", "port", "description", "severity", "nvt"]),

    # Malformed structure
    ({
        "scan": {
            "results": "not_a_list_or_dict"
        }
    }, 0, [])
])
def test_omp_normalizer(raw_input, expected_result_count, expected_keys):
    normalizer = OpenVASParser()
    result = normalizer.normalize_omp_api_format(raw_input)
    
    #Handke tuple return if structure malformed
    normalized = result[1] if isinstance(result, tuple) else result

    results = normalized["report"]["results"]
    assert isinstance(results, list)
    assert len(results) == expected_result_count

    if expected_result_count > 0:
        for key in expected_keys:
            assert key in results[0], f"Missing key: {key}"
