# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import RunContext, Services
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.parsers.sarif_parser import SarifParser
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema
from vulnparse_pin.utils.validations import FileInputValidator


def _ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "sarif.log"))
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
        services=Services(),
    )


def test_sarif_detection_for_sarif_and_json_extensions(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    detector = SchemaDetector(PARSER_SPECS)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy", "rules": []}},
                "results": [],
            }
        ],
    }

    f_sarif = tmp_path / "report.sarif"
    f_sarif.write_text(json.dumps(payload), encoding="utf-8")
    f_json = tmp_path / "report.json"
    f_json.write_text(json.dumps(payload), encoding="utf-8")
    f_other = tmp_path / "other.json"
    f_other.write_text('{"unrelated": true}', encoding="utf-8")

    conf_s, _ = SarifParser.detect_file(f_sarif, ctx=ctx)
    conf_j, _ = SarifParser.detect_file(f_json, ctx=ctx)
    conf_o, _ = SarifParser.detect_file(f_other, ctx=ctx)

    assert conf_s >= 0.90
    assert conf_j >= 0.80
    assert conf_o == 0.0
    assert detector.select(ctx, f_sarif).parser_cls is SarifParser
    assert detector.select(ctx, f_json).parser_cls is SarifParser


def test_sarif_sca_container_trivy_and_grype_extraction(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "semanticVersion": "0.55.0",
                        "rules": [
                            {
                                "id": "CVE-2021-44228",
                                "name": "Log4j JNDI RCE",
                                "shortDescription": {"text": "Apache Log4j2 RCE"},
                                "fullDescription": {"text": "Remote code execution in log4j-core."},
                                "helpUri": "https://avd.aquasec.com/nvd/cve-2021-44228",
                                "properties": {
                                    "tags": ["vulnerability", "security", "CWE-502"],
                                    "security-severity": "10.0",
                                },
                            }
                        ],
                    }
                },
                "properties": {"imageName": "ghcr.io/acme/api:1.4.2"},
                "results": [
                    {
                        "ruleId": "CVE-2021-44228",
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {"text": "Package log4j-core 2.14.1 is vulnerable (GHSA-jfh8-c2jp-5v3q)"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "usr/local/lib/log4j-core-2.14.1.jar"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                        "properties": {
                            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                            "cvss": {
                                "nvd": {
                                    "V3Score": 10.0,
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                }
                            },
                        },
                    }
                ],
            },
            {
                "tool": {"driver": {"name": "Grype", "rules": []}},
                "results": [
                    {
                        "ruleId": "GHSA-3333-4444-5555",
                        "level": "warning",
                        "message": {"text": "Vulnerable dependency pkg:pypi/urllib3@1.26.4 (CVE-2021-33503)"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "python:3.11-slim"}}}
                        ],
                    }
                ],
            },
        ],
    }

    f = tmp_path / "container.sarif"
    f.write_text(json.dumps(sarif), encoding="utf-8")

    assert FileInputValidator(ctx, f).validate() == f

    parser = SarifParser(ctx, f)
    batches = list(parser.iter_batches(batch_size=1))
    assert len(batches) == 2
    r0, r1 = batches[0][0], batches[1][0]

    assert r0["source_format"] == "sarif-2.1.0"
    assert r0["detection_mode"] == "sca_container"
    assert r0["scanner_sig"] == "trivy:CVE-2021-44228"
    assert r0["image_or_repo"] == "ghcr.io/acme/api:1.4.2"
    assert r0["location_uri"] == "usr/local/lib/log4j-core-2.14.1.jar"
    assert r0["line_number"] == 1
    assert r0["package_purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert r0["cves"] == ["CVE-2021-44228"]
    assert r0["cwes"] == ["CWE-502"]
    assert r0["ghsa_ids"] == ["GHSA-jfh8-c2jp-5v3q"]
    assert r0["scanner_cvss_score"] == 10.0
    assert r0["scanner_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert r0["severity"] == "Critical"
    assert r0["asset_metadata"]["partial_fingerprints"] == {"primaryLocationLineHash": "abc123"}

    assert r1["detection_mode"] == "sca_container"
    assert r1["scanner_sig"] == "grype:GHSA-3333-4444-5555"
    assert r1["image_or_repo"] == "python:3.11-slim"
    assert r1["package_purl"] == "pkg:pypi/urllib3@1.26.4"
    assert r1["cves"] == ["CVE-2021-33503"]
    assert r1["ghsa_ids"] == ["GHSA-3333-4444-5555"]
    assert r1["severity"] == "Medium"

    scan = parser.parse()
    validate_scan_result_schema(scan)


def test_sarif_static_sast_semgrep_codeql_and_out_of_order_keys(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    # Place "results" BEFORE "tool" inside run to verify out-of-order SARIF streaming
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "versionControlProvenance": [
                    {"repositoryUri": "https://github.com/acme/webapp"}
                ],
                "results": [
                    {
                        "ruleIndex": 0,
                        "level": "error",
                        "message": {"text": "User input flows into SQL query"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "js/xss",
                        "level": "note",
                        "message": {"text": "Minor DOM sink"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/ui.js"},
                                    "region": {"startLine": 9},
                                }
                            }
                        ],
                    },
                ],
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "shortDescription": {"text": "SQL query built from user-controlled sources"},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-089"],
                                    "security-severity": "8.6",
                                },
                            }
                        ],
                    }
                },
            }
        ],
    }

    f = tmp_path / "codeql.sarif"
    f.write_bytes(b"\xef\xbb\xbf" + json.dumps(sarif).encode("utf-8"))

    records = [r for b in SarifParser(ctx, f).iter_batches(batch_size=10) for r in b]
    assert len(records) == 2

    sqli, xss = records[0], records[1]
    assert sqli["detection_mode"] == "static_sast"
    assert sqli["scanner_sig"] == "codeql:py/sql-injection"
    assert sqli["title"] == "SQL query built from user-controlled sources"
    assert sqli["cwes"] == ["CWE-89"]
    assert sqli["scanner_cvss_score"] == 8.6
    assert sqli["severity"] == "High"
    assert sqli["location_uri"] == "src/db.py"
    assert sqli["line_number"] == 42
    assert sqli["image_or_repo"] == "https://github.com/acme/webapp"

    assert xss["detection_mode"] == "static_sast"
    assert xss["severity"] == "Low"
    assert xss["line_number"] == 9
