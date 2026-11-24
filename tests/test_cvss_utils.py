# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import Mock

import pytest

from vulnparse_pin.utils import cvss_utils
from vulnparse_pin.utils.cvss_utils import (
    compute_cvss_base_score,
    detect_cvss_exact_version,
    detect_cvss_version,
    extract_cvss_metrics,
    is_valid_cvss_vector,
    parse_cvss_vector,
)


def test_cvss_utils_has_no_lgpl_cvss_package_dependency() -> None:
    src_path = Path(cvss_utils.__file__)
    tree = ast.parse(src_path.read_text(encoding="utf-8"))
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])
    assert "cvss" not in imported_modules


@pytest.mark.parametrize(
    ("vector", "expected_major", "expected_exact", "expected_score"),
    [
        # CVSS v2.0 official vectors
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "v2", "2.0", 7.5),
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "v2", "2.0", 10.0),
        ("AV:L/AC:H/Au:M/C:N/I:N/A:N", "v2", "2.0", 0.0),
        ("AV:N/AC:M/Au:N/C:N/I:P/A:N", "v2", "2.0", 4.3),
        ("AV:L/AC:L/Au:N/C:P/I:P/A:P", "v2", "2.0", 4.6),
        ("AV:L/AC:L/Au:S/C:P/I:P/A:P", "v2", "2.0", 4.3),
        ("AV:A/AC:L/Au:N/C:C/I:C/A:C", "v2", "2.0", 8.3),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C", "v2", "2.0", 7.5),
        # CVSS v3.0 official vectors
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "v3", "3.0", 10.0),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", "v3", "3.0", 6.4),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", "v3", "3.0", 7.5),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "v3", "3.0", 0.0),
        # CVSS v3.1 official vectors
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "v3", "3.1", 10.0),  # Log4Shell
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", "v3", "3.1", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "v3", "3.1", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "v3", "3.1", 7.1),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H", "v3", "3.1", 8.3),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", "v3", "3.1", 4.4),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", "v3", "3.1", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C", "v3", "3.1", 9.8),
        # CVSS v4.0 official vectors
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "v4", "4.0", 9.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "v4", "4.0", 10.0),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "v4", "4.0", 4.6),
        ("CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:L/SI:H/SA:N", "v4", "4.0", 7.0),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "v4", "4.0", 1.0),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N", "v4", "4.0", 8.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "v4", "4.0", 0.0),
        # CVSS v4.0 with optional Threat / Environmental / Supplemental metrics keeps Base Score
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:L/MAV:P/S:P/AU:Y/U:Red", "v4", "4.0", 9.3),
    ],
)
def test_cvss_detection_validation_and_base_score(
    vector: str,
    expected_major: str,
    expected_exact: str,
    expected_score: float,
) -> None:
    assert detect_cvss_version(vector) == expected_major
    assert detect_cvss_exact_version(vector) == expected_exact
    assert is_valid_cvss_vector(vector) is True
    assert compute_cvss_base_score(vector) == expected_score
    assert parse_cvss_vector(None, vector) == (expected_score, expected_score, expected_score)


def test_cvss_v30_vs_v31_roundup_edge_cases() -> None:
    # CVSS v3.1 integer-scaled roundup treats 4.000001 (1e-6) as exact 4.0 boundary, while v3.0 rounds up
    assert cvss_utils._roundup_v31(4.00) == 4.0
    assert cvss_utils._roundup_v31(4.02) == 4.1
    assert cvss_utils._roundup_v31(4.000001) == 4.0
    assert cvss_utils._roundup_v30(4.000001) == 4.1
    # Both tolerate microscopic IEEE-754 float noise (~1e-15)
    assert cvss_utils._roundup_v30(4.000000000000001) == 4.0
    assert cvss_utils._roundup_v31(4.000000000000001) == 4.0
    # Zero / negative safety
    assert cvss_utils._roundup_v30(0.0) == 0.0
    assert cvss_utils._roundup_v31(0.0) == 0.0


@pytest.mark.parametrize(
    "bad_vector",
    [
        None,
        "",
        "   ",
        "SENTINEL:NoCVE",
        "SENTINEL:ScoreOnly:7.5",
        "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",  # wrong order
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",  # trailing slash
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:P/S:U/C:H/I:H/A:H",  # v4 UI:P in v3.1
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # v3 UI:R in v4.0
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",  # missing SA
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:X",  # X forbidden on base
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/SA:H",  # duplicate
        "AV:P/AC:L/Au:N/C:P/I:P/A:P",  # invalid AV:P in v2
        "AV:N/AC:L/Au:H/C:P/I:P/A:P",  # invalid Au:H in v2
        "AV:N/AC:L/Au:N/C:H/I:P/A:P",  # invalid C:H in v2
    ],
)
def test_invalid_cvss_vectors_are_rejected(bad_vector) -> None:
    assert detect_cvss_version(bad_vector) is None
    assert detect_cvss_exact_version(bad_vector) is None
    assert is_valid_cvss_vector(bad_vector) is False
    assert compute_cvss_base_score(bad_vector) is None  # type: ignore[arg-type]
    assert extract_cvss_metrics(bad_vector) == {}

    ctx = Mock()
    ctx.logger = Mock()
    assert parse_cvss_vector(ctx, bad_vector) is None  # type: ignore[arg-type]
    ctx.logger.debug.assert_called_once()


def test_extract_cvss_metrics_returns_normalized_base_metrics() -> None:
    assert extract_cvss_metrics("AV:N/AC:L/Au:N/C:P/I:P/A:P") == {
        "AV": "N",
        "AC": "L",
        "Au": "N",
        "C": "P",
        "I": "P",
        "A": "P",
    }
    assert extract_cvss_metrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "S": "C",
        "C": "H",
        "I": "H",
        "A": "H",
    }
    assert extract_cvss_metrics(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"
    ) == {
        "AV": "N",
        "AC": "L",
        "AT": "N",
        "PR": "N",
        "UI": "N",
        "VC": "H",
        "VI": "H",
        "VA": "H",
        "SC": "N",
        "SI": "N",
        "SA": "N",
    }


def test_cvss4_lookup_table_covers_all_270_macrovectors() -> None:
    assert len(cvss_utils._CVSS4_LOOKUP) == 270
    assert cvss_utils._CVSS4_LOOKUP["000000"] == 10.0
    assert cvss_utils._CVSS4_LOOKUP["000200"] == 9.3
    assert cvss_utils._CVSS4_LOOKUP["212221"] == 0.1
