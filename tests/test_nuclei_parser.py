# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
from pathlib import Path

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import RunContext, Services
from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.parsers.nuclei_jsonl_parser import NucleiJSONLParser
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema
from vulnparse_pin.utils.validations import FileInputValidator


def _ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "nuclei.log"))
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


def test_nuclei_detection_16_lines_and_schema_detector(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    detector = SchemaDetector(PARSER_SPECS)

    lines = []
    for i in range(20):
        lines.append(
            json.dumps(
                {
                    "template-id": f"cve-2024-{1000 + i}",
                    "info": {"name": f"Template {i}", "severity": "high"},
                    "host": "https://app.example.com",
                    "matched-at": f"https://app.example.com/path/{i}",
                }
            )
        )
    f = tmp_path / "nuclei.jsonl"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")

    conf, evidence = NucleiJSONLParser.detect_file(f, ctx=ctx)
    assert conf >= 0.90
    assert any(k == "nuclei_lines" and v == "16/16" for k, v in evidence)
    assert detector.select(ctx, f).parser_cls is NucleiJSONLParser

    non_nuclei = tmp_path / "events.jsonl"
    non_nuclei.write_text('{"event": "login", "user": "alice"}\n', encoding="utf-8")
    conf_bad, _ = NucleiJSONLParser.detect_file(non_nuclei, ctx=ctx)
    assert conf_bad == 0.0


def test_nuclei_jsonl_full_field_extraction_and_safe_excerpt(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    long_curl = "curl -X POST https://api.example.com:8443/login -d '" + ("A" * 1200) + "'"

    row1 = {
        "template-id": "CVE-2021-44228",
        "info": {
            "name": "Apache Log4j2 Remote Code Execution",
            "severity": "critical",
            "description": "Log4j2 JNDI lookup allows RCE.",
            "tags": ["cve", "cve2021", "rce", "jndi"],
            "reference": [
                "https://logging.apache.org/log4j/2.x/security.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            ],
            "remediation": "Upgrade Log4j to 2.17.1 or later.",
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cwe-id": ["CWE-502", "CWE-917"],
                "cvss-score": 10.0,
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
        },
        "type": "http",
        "scheme": "https",
        "host": "https://api.example.com:8443",
        "ip": "203.0.113.25",
        "port": "8443",
        "matched-at": "https://api.example.com:8443/v1/auth",
        "matcher-name": "dns-callback",
        "extracted-results": ["log4j-2.14.1"],
        "curl-command": long_curl,
        "timestamp": "2026-10-15T08:30:00Z",
    }
    row2 = {
        "template-id": "exposed-env",
        "info": {
            "name": "Exposed .env File",
            "severity": "medium",
            "tags": "exposure,config,env",
            "reference": "https://owasp.org/",
            "classification": {
                "cwe-id": "CWE-200",
            },
        },
        "type": "http",
        "host": "http://198.51.100.10:8080",
        "matched-at": "http://198.51.100.10:8080/.env",
    }

    f_valid = tmp_path / "valid_results.jsonl"
    f_valid.write_bytes(
        b"\xef\xbb\xbf"
        + (json.dumps(row1) + "\n\n" + json.dumps(row2) + "\n").encode("utf-8")
    )
    assert FileInputValidator(ctx, f_valid).validate() == f_valid

    f = tmp_path / "results.jsonl"
    f.write_bytes(
        b"\xef\xbb\xbf"
        + (json.dumps(row1) + "\n\n" + json.dumps(row2) + "\n{bad-json-line\n").encode("utf-8")
    )

    parser = NucleiJSONLParser(ctx, f)
    batches = list(parser.iter_batches(batch_size=1))
    assert len(batches) == 2

    r1, r2 = batches[0][0], batches[1][0]
    assert r1["source_format"] == "nuclei-jsonl"
    assert r1["detection_mode"] == "active_dast"
    assert r1["fidelity_tier"] == "high"
    assert r1["ingestion_confidence"] == 0.95
    assert r1["degraded_input"] is False
    assert r1["scanner_sig"] == "nuclei:CVE-2021-44228"
    assert r1["ip_address"] == "203.0.113.25"
    assert r1["hostname"] == "api.example.com"
    assert r1["affected_port"] == 8443
    assert r1["protocol"] == "tcp"
    assert r1["service_name"] == "https"
    assert r1["target_uri"] == "https://api.example.com:8443/v1/auth"
    assert r1["cves"] == ["CVE-2021-44228"]
    assert r1["cwes"] == ["CWE-502", "CWE-917"]
    assert r1["scanner_cvss_score"] == 10.0
    assert r1["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert r1["severity"] == "Critical"
    assert r1["tags"] == ["cve", "cve2021", "rce", "jndi"]
    assert len(r1["references"]) == 2
    assert len(r1["raw_evidence_excerpt"]) <= 503
    assert "dns-callback" in r1["plugin_output"]

    assert r2["ip_address"] == "198.51.100.10"
    assert r2["affected_port"] == 8080
    assert r2["cves"] == []
    assert r2["cwes"] == ["CWE-200"]
    assert r2["tags"] == ["exposure", "config", "env"]
    assert r2["references"] == ["https://owasp.org/"]
    assert r2["severity"] == "Medium"

    # Malformed line recorded on ledger
    entries = ctx.services.ledger.snapshot().entries
    assert any(
        e.why.reason_code == DecisionReasonCodes.INGESTION_MALFORMED_ROWS_SKIPPED
        for e in entries
    )

    scan = parser.parse()
    validate_scan_result_schema(scan)
    assert scan.scan_metadata.vulnerability_count == 2
