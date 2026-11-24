# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley
"""
Clean-room Apache-2.0 CVSS v2.0, v3.0, v3.1, and v4.0 validation, metric
extraction, and base-score calculation engine.

Implements official FIRST specifications for CVSS v2.0, v3.0, v3.1, and v4.0
using Python standard library modules only (zero LGPL runtime dependencies).
"""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction
import math
import re
from typing import Any, Dict, Literal, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


CVSSExactVersion = Literal["2.0", "3.0", "3.1", "4.0"]
CVSSMajorVersion = Literal["v2", "v3", "v4"]
CVSSKIND = Literal["cvss2", "cvss3", "cvss4", "unknown"]

# Backward-compatible regex constants (base vectors)
CVSS3_REGEX = r"^CVSS:3\.[01]/AV:(N|A|L|P)/AC:(L|H)/PR:(N|L|H)/UI:(N|R)/S:(U|C)/C:(N|L|H)/I:(N|L|H)/A:(N|L|H)$"
CVSS3_REGEX_L = r"CVSS:3\.[0-1]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
CVSS2_REGEX = r"^AV:(L|A|N)/AC:(L|M|H)/Au:(N|S|M)/C:(N|P|C)/I:(N|P|C)/A:(N|P|C)$"

CVSS3_RE = re.compile(CVSS3_REGEX)
CVSS2_RE = re.compile(CVSS2_REGEX)

# -------------------------
# CVSS v2.0 specification
# -------------------------

_CVSS2_BASE_METRICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("AV", ("L", "A", "N")),
    ("AC", ("H", "M", "L")),
    ("Au", ("M", "S", "N")),
    ("C", ("N", "P", "C")),
    ("I", ("N", "P", "C")),
    ("A", ("N", "P", "C")),
)

_CVSS2_TEMPORAL_METRICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("E", ("U", "POC", "F", "H", "ND")),
    ("RL", ("OF", "TF", "W", "U", "ND")),
    ("RC", ("UC", "UR", "C", "ND")),
)

_CVSS2_AV_WEIGHTS = {"L": Decimal("0.395"), "A": Decimal("0.646"), "N": Decimal("1.0")}
_CVSS2_AC_WEIGHTS = {"H": Decimal("0.35"), "M": Decimal("0.61"), "L": Decimal("0.71")}
_CVSS2_AU_WEIGHTS = {"M": Decimal("0.45"), "S": Decimal("0.56"), "N": Decimal("0.704")}
_CVSS2_CIA_WEIGHTS = {"N": Decimal("0.0"), "P": Decimal("0.275"), "C": Decimal("0.660")}


# -------------------------
# CVSS v3.0 / v3.1 specification
# -------------------------

_CVSS3_BASE_METRICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("AV", ("N", "A", "L", "P")),
    ("AC", ("L", "H")),
    ("PR", ("N", "L", "H")),
    ("UI", ("N", "R")),
    ("S", ("U", "C")),
    ("C", ("N", "L", "H")),
    ("I", ("N", "L", "H")),
    ("A", ("N", "L", "H")),
)

_CVSS3_OPTIONAL_METRICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("E", ("X", "U", "P", "F", "H")),
    ("RL", ("X", "O", "T", "W", "U")),
    ("RC", ("X", "U", "R", "C")),
    ("CR", ("X", "L", "M", "H")),
    ("IR", ("X", "L", "M", "H")),
    ("AR", ("X", "L", "M", "H")),
    ("MAV", ("X", "N", "A", "L", "P")),
    ("MAC", ("X", "L", "H")),
    ("MPR", ("X", "N", "L", "H")),
    ("MUI", ("X", "N", "R")),
    ("MS", ("X", "U", "C")),
    ("MC", ("X", "N", "L", "H")),
    ("MI", ("X", "N", "L", "H")),
    ("MA", ("X", "N", "L", "H")),
)

_CVSS3_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_CVSS3_PR_UNCHANGED_WEIGHTS = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_CHANGED_WEIGHTS = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS3_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CVSS3_CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}


# -------------------------
# CVSS v4.0 specification
# -------------------------

_CVSS4_BASE_METRICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("AV", ("N", "A", "L", "P")),
    ("AC", ("L", "H")),
    ("AT", ("N", "P")),
    ("PR", ("N", "L", "H")),
    ("UI", ("N", "P", "A")),
    ("VC", ("H", "L", "N")),
    ("VI", ("H", "L", "N")),
    ("VA", ("H", "L", "N")),
    ("SC", ("H", "L", "N")),
    ("SI", ("H", "L", "N")),
    ("SA", ("H", "L", "N")),
)

_CVSS4_OPTIONAL_METRICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Threat
    ("E", ("X", "A", "P", "U")),
    # Environmental
    ("CR", ("X", "H", "M", "L")),
    ("IR", ("X", "H", "M", "L")),
    ("AR", ("X", "H", "M", "L")),
    ("MAV", ("X", "N", "A", "L", "P")),
    ("MAC", ("X", "L", "H")),
    ("MAT", ("X", "N", "P")),
    ("MPR", ("X", "N", "L", "H")),
    ("MUI", ("X", "N", "P", "A")),
    ("MVC", ("X", "H", "L", "N")),
    ("MVI", ("X", "H", "L", "N")),
    ("MVA", ("X", "H", "L", "N")),
    ("MSC", ("X", "H", "L", "N")),
    ("MSI", ("X", "S", "H", "L", "N")),
    ("MSA", ("X", "S", "H", "L", "N")),
    # Supplemental
    ("S", ("X", "N", "P")),
    ("AU", ("X", "N", "Y")),
    ("R", ("X", "A", "U", "I")),
    ("V", ("X", "D", "C")),
    ("RE", ("X", "L", "M", "H")),
    ("U", ("X", "Clear", "Green", "Amber", "Red")),
)

# Official FIRST CVSS v4.0 MacroVector lookup table (all 270 valid EQ1-EQ6 macrovectors)
_CVSS4_LOOKUP: dict[str, float] = {
    "000000": 10.0,
    "000001": 9.9,
    "000010": 9.8,
    "000011": 9.5,
    "000020": 9.5,
    "000021": 9.2,
    "000100": 10.0,
    "000101": 9.6,
    "000110": 9.3,
    "000111": 8.7,
    "000120": 9.1,
    "000121": 8.1,
    "000200": 9.3,
    "000201": 9.0,
    "000210": 8.9,
    "000211": 8.0,
    "000220": 8.1,
    "000221": 6.8,
    "001000": 9.8,
    "001001": 9.5,
    "001010": 9.5,
    "001011": 9.2,
    "001020": 9.0,
    "001021": 8.4,
    "001100": 9.3,
    "001101": 9.2,
    "001110": 8.9,
    "001111": 8.1,
    "001120": 8.1,
    "001121": 6.5,
    "001200": 8.8,
    "001201": 8.0,
    "001210": 7.8,
    "001211": 7.0,
    "001220": 6.9,
    "001221": 4.8,
    "002001": 9.2,
    "002011": 8.2,
    "002021": 7.2,
    "002101": 7.9,
    "002111": 6.9,
    "002121": 5.0,
    "002201": 6.9,
    "002211": 5.5,
    "002221": 2.7,
    "010000": 9.9,
    "010001": 9.7,
    "010010": 9.5,
    "010011": 9.2,
    "010020": 9.2,
    "010021": 8.5,
    "010100": 9.5,
    "010101": 9.1,
    "010110": 9.0,
    "010111": 8.3,
    "010120": 8.4,
    "010121": 7.1,
    "010200": 9.2,
    "010201": 8.1,
    "010210": 8.2,
    "010211": 7.1,
    "010220": 7.2,
    "010221": 5.3,
    "011000": 9.5,
    "011001": 9.3,
    "011010": 9.2,
    "011011": 8.5,
    "011020": 8.5,
    "011021": 7.3,
    "011100": 9.2,
    "011101": 8.2,
    "011110": 8.0,
    "011111": 7.2,
    "011120": 7.0,
    "011121": 5.9,
    "011200": 8.4,
    "011201": 7.0,
    "011210": 7.1,
    "011211": 5.2,
    "011220": 5.0,
    "011221": 3.0,
    "012001": 8.6,
    "012011": 7.5,
    "012021": 5.2,
    "012101": 7.1,
    "012111": 5.2,
    "012121": 2.9,
    "012201": 6.3,
    "012211": 2.9,
    "012221": 1.7,
    "100000": 9.8,
    "100001": 9.5,
    "100010": 9.4,
    "100011": 8.7,
    "100020": 9.1,
    "100021": 8.1,
    "100100": 9.4,
    "100101": 8.9,
    "100110": 8.6,
    "100111": 7.4,
    "100120": 7.7,
    "100121": 6.4,
    "100200": 8.7,
    "100201": 7.5,
    "100210": 7.4,
    "100211": 6.3,
    "100220": 6.3,
    "100221": 4.9,
    "101000": 9.4,
    "101001": 8.9,
    "101010": 8.8,
    "101011": 7.7,
    "101020": 7.6,
    "101021": 6.7,
    "101100": 8.6,
    "101101": 7.6,
    "101110": 7.4,
    "101111": 5.8,
    "101120": 5.9,
    "101121": 5.0,
    "101200": 7.2,
    "101201": 5.7,
    "101210": 5.7,
    "101211": 5.2,
    "101220": 5.2,
    "101221": 2.5,
    "102001": 8.3,
    "102011": 7.0,
    "102021": 5.4,
    "102101": 6.5,
    "102111": 5.8,
    "102121": 2.6,
    "102201": 5.3,
    "102211": 2.1,
    "102221": 1.3,
    "110000": 9.5,
    "110001": 9.0,
    "110010": 8.8,
    "110011": 7.6,
    "110020": 7.6,
    "110021": 7.0,
    "110100": 9.0,
    "110101": 7.7,
    "110110": 7.5,
    "110111": 6.2,
    "110120": 6.1,
    "110121": 5.3,
    "110200": 7.7,
    "110201": 6.6,
    "110210": 6.8,
    "110211": 5.9,
    "110220": 5.2,
    "110221": 3.0,
    "111000": 8.9,
    "111001": 7.8,
    "111010": 7.6,
    "111011": 6.7,
    "111020": 6.2,
    "111021": 5.8,
    "111100": 7.4,
    "111101": 5.9,
    "111110": 5.7,
    "111111": 5.7,
    "111120": 4.7,
    "111121": 2.3,
    "111200": 6.1,
    "111201": 5.2,
    "111210": 5.7,
    "111211": 2.9,
    "111220": 2.4,
    "111221": 1.6,
    "112001": 7.1,
    "112011": 5.9,
    "112021": 3.0,
    "112101": 5.8,
    "112111": 2.6,
    "112121": 1.5,
    "112201": 2.3,
    "112211": 1.3,
    "112221": 0.6,
    "200000": 9.3,
    "200001": 8.7,
    "200010": 8.6,
    "200011": 7.2,
    "200020": 7.5,
    "200021": 5.8,
    "200100": 8.6,
    "200101": 7.4,
    "200110": 7.4,
    "200111": 6.1,
    "200120": 5.6,
    "200121": 3.4,
    "200200": 7.0,
    "200201": 5.4,
    "200210": 5.2,
    "200211": 4.0,
    "200220": 4.0,
    "200221": 2.2,
    "201000": 8.5,
    "201001": 7.5,
    "201010": 7.4,
    "201011": 5.5,
    "201020": 6.2,
    "201021": 5.1,
    "201100": 7.2,
    "201101": 5.7,
    "201110": 5.5,
    "201111": 4.1,
    "201120": 4.6,
    "201121": 1.9,
    "201200": 5.3,
    "201201": 3.6,
    "201210": 3.4,
    "201211": 1.9,
    "201220": 1.9,
    "201221": 0.8,
    "202001": 6.4,
    "202011": 5.1,
    "202021": 2.0,
    "202101": 4.7,
    "202111": 2.1,
    "202121": 1.1,
    "202201": 2.4,
    "202211": 0.9,
    "202221": 0.4,
    "210000": 8.8,
    "210001": 7.5,
    "210010": 7.3,
    "210011": 5.3,
    "210020": 6.0,
    "210021": 5.0,
    "210100": 7.3,
    "210101": 5.5,
    "210110": 5.9,
    "210111": 4.0,
    "210120": 4.1,
    "210121": 2.0,
    "210200": 5.4,
    "210201": 4.3,
    "210210": 4.5,
    "210211": 2.2,
    "210220": 2.0,
    "210221": 1.1,
    "211000": 7.5,
    "211001": 5.5,
    "211010": 5.8,
    "211011": 4.5,
    "211020": 4.0,
    "211021": 2.1,
    "211100": 6.1,
    "211101": 5.1,
    "211110": 4.8,
    "211111": 1.8,
    "211120": 2.0,
    "211121": 0.9,
    "211200": 4.6,
    "211201": 1.8,
    "211210": 1.7,
    "211211": 0.7,
    "211220": 0.8,
    "211221": 0.2,
    "212001": 5.3,
    "212011": 2.4,
    "212021": 1.4,
    "212101": 2.4,
    "212111": 1.2,
    "212121": 0.5,
    "212201": 1.0,
    "212211": 0.3,
    "212221": 0.1,
}

_CVSS4_MAX_COMPOSED = {
    "eq1": {
        0: ("AV:N/PR:N/UI:N/",),
        1: ("AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"),
        2: ("AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"),
    },
    "eq2": {
        0: ("AC:L/AT:N/",),
        1: ("AC:H/AT:N/", "AC:L/AT:P/"),
    },
    "eq3": {
        0: {
            0: ("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/",),
            1: ("VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"),
        },
        1: {
            0: ("VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"),
            1: (
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ),
        },
        2: {
            1: ("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/",),
        },
    },
    "eq4": {
        0: ("SC:H/SI:S/SA:S/",),
        1: ("SC:H/SI:H/SA:H/",),
        2: ("SC:L/SI:L/SA:L/",),
    },
    "eq5": {
        0: ("E:A/",),
        1: ("E:P/",),
        2: ("E:U/",),
    },
}

_CVSS4_MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

_CVSS4_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}


def _parse_max_vector_fragment(fragment: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for token in fragment.strip("/").split("/"):
        if token:
            key, val = token.split(":", 1)
            parsed[key] = val
    return parsed


def _build_cvss4_max_candidates() -> dict[tuple[int, int, int, int, int, int], tuple[dict[str, str], ...]]:
    candidates: dict[tuple[int, int, int, int, int, int], tuple[dict[str, str], ...]] = {}
    for eq1 in (0, 1, 2):
        for eq2 in (0, 1):
            for eq3 in (0, 1, 2):
                eq6_vals = (0, 1) if eq3 < 2 else (1,)
                for eq6 in eq6_vals:
                    for eq4 in (0, 1, 2):
                        for eq5 in (0, 1, 2):
                            combo_list: list[dict[str, str]] = []
                            for f1 in _CVSS4_MAX_COMPOSED["eq1"][eq1]:
                                for f2 in _CVSS4_MAX_COMPOSED["eq2"][eq2]:
                                    for f3 in _CVSS4_MAX_COMPOSED["eq3"][eq3][eq6]:
                                        for f4 in _CVSS4_MAX_COMPOSED["eq4"][eq4]:
                                            for f5 in _CVSS4_MAX_COMPOSED["eq5"][eq5]:
                                                combo_list.append(_parse_max_vector_fragment(f1 + f2 + f3 + f4 + f5))
                            candidates[(eq1, eq2, eq3, eq4, eq5, eq6)] = tuple(combo_list)
    return candidates


_CVSS4_MAX_CANDIDATES = _build_cvss4_max_candidates()


def _clean_vector_string(vector: Optional[str]) -> Optional[str]:
    if not vector or not isinstance(vector, str):
        return None
    cleaned = re.sub(r"\s+", "", vector.strip())
    if not cleaned or cleaned.startswith("SENTINEL:"):
        return None
    return cleaned


def _parse_ordered_metrics(
    tokens: list[str],
    mandatory: tuple[tuple[str, tuple[str, ...]], ...],
    optional: tuple[tuple[str, tuple[str, ...]], ...],
) -> Optional[tuple[dict[str, str], dict[str, str]]]:
    """
    Validate and parse metric tokens in exact FIRST specification order.
    Returns (base_metrics, all_metrics) or None if invalid.
    """
    if len(tokens) < len(mandatory):
        return None

    base_metrics: dict[str, str] = {}
    all_metrics: dict[str, str] = {}

    for idx, (expected_key, allowed_vals) in enumerate(mandatory):
        token = tokens[idx]
        if ":" not in token:
            return None
        key, val = token.split(":", 1)
        if key != expected_key or val not in allowed_vals:
            return None
        base_metrics[key] = val
        all_metrics[key] = val

    opt_idx = 0
    for token in tokens[len(mandatory):]:
        if ":" not in token:
            return None
        key, val = token.split(":", 1)
        while opt_idx < len(optional) and optional[opt_idx][0] != key:
            opt_idx += 1
        if opt_idx >= len(optional):
            return None
        if val not in optional[opt_idx][1]:
            return None
        all_metrics[key] = val
        opt_idx += 1

    return base_metrics, all_metrics


def _parse_vector_internal(
    vector: Optional[str],
) -> Optional[tuple[CVSSExactVersion, dict[str, str], dict[str, str]]]:
    cleaned = _clean_vector_string(vector)
    if cleaned is None:
        return None

    parts = cleaned.split("/")
    if any(not part for part in parts):
        return None

    prefix = parts[0]
    if prefix == "CVSS:4.0":
        parsed = _parse_ordered_metrics(parts[1:], _CVSS4_BASE_METRICS, _CVSS4_OPTIONAL_METRICS)
        if parsed is None:
            return None
        return "4.0", parsed[0], parsed[1]

    if prefix in ("CVSS:3.1", "CVSS:3.0"):
        version: CVSSExactVersion = "3.1" if prefix == "CVSS:3.1" else "3.0"
        parsed = _parse_ordered_metrics(parts[1:], _CVSS3_BASE_METRICS, _CVSS3_OPTIONAL_METRICS)
        if parsed is None:
            return None
        return version, parsed[0], parsed[1]

    parsed_v2 = _parse_ordered_metrics(parts, _CVSS2_BASE_METRICS, _CVSS2_TEMPORAL_METRICS)
    if parsed_v2 is not None:
        return "2.0", parsed_v2[0], parsed_v2[1]

    return None


def _roundup_v30(x: float) -> float:
    """CVSS v3.0 Roundup (1-decimal ceiling with IEEE-754 noise protection)."""
    if x <= 0.0:
        return 0.0
    return math.ceil((x - 1e-12) * 10.0) / 10.0


def _roundup_v31(x: float) -> float:
    """Official FIRST CVSS v3.1 Roundup specification."""
    if x <= 0.0:
        return 0.0
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _compute_v2_base_score(base: dict[str, str]) -> float:
    av = _CVSS2_AV_WEIGHTS[base["AV"]]
    ac = _CVSS2_AC_WEIGHTS[base["AC"]]
    au = _CVSS2_AU_WEIGHTS[base["Au"]]
    c = _CVSS2_CIA_WEIGHTS[base["C"]]
    i = _CVSS2_CIA_WEIGHTS[base["I"]]
    a = _CVSS2_CIA_WEIGHTS[base["A"]]

    impact = Decimal("10.41") * (Decimal("1") - (Decimal("1") - c) * (Decimal("1") - i) * (Decimal("1") - a))
    if impact == Decimal("0"):
        return 0.0

    exploitability = Decimal("20") * av * ac * au
    raw_base = ((Decimal("0.6") * impact) + (Decimal("0.4") * exploitability) - Decimal("1.5")) * Decimal("1.176")
    rounded = raw_base.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    return float(max(Decimal("0.0"), min(Decimal("10.0"), rounded)))


def _compute_v3_base_score(version: Literal["3.0", "3.1"], base: dict[str, str]) -> float:
    scope = base["S"]
    av = _CVSS3_AV_WEIGHTS[base["AV"]]
    ac = _CVSS3_AC_WEIGHTS[base["AC"]]
    pr = _CVSS3_PR_CHANGED_WEIGHTS[base["PR"]] if scope == "C" else _CVSS3_PR_UNCHANGED_WEIGHTS[base["PR"]]
    ui = _CVSS3_UI_WEIGHTS[base["UI"]]
    c = _CVSS3_CIA_WEIGHTS[base["C"]]
    i = _CVSS3_CIA_WEIGHTS[base["I"]]
    a = _CVSS3_CIA_WEIGHTS[base["A"]]

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0.0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    roundup = _roundup_v31 if version == "3.1" else _roundup_v30
    return roundup(raw)


def _cvss4_effective_metric(selected: dict[str, str], metric: str) -> str:
    if metric == "E":
        val = selected.get("E", "X")
        return "A" if val == "X" else val
    if metric in ("CR", "IR", "AR"):
        val = selected.get(metric, "X")
        return "H" if val == "X" else val
    mod_val = selected.get(f"M{metric}", "X")
    if mod_val != "X":
        return mod_val
    return selected.get(metric, "X")


def _cvss4_macrovector(selected: dict[str, str]) -> tuple[int, int, int, int, int, int]:
    av = _cvss4_effective_metric(selected, "AV")
    pr = _cvss4_effective_metric(selected, "PR")
    ui = _cvss4_effective_metric(selected, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2

    ac = _cvss4_effective_metric(selected, "AC")
    at = _cvss4_effective_metric(selected, "AT")
    eq2 = 0 if (ac == "L" and at == "N") else 1

    vc = _cvss4_effective_metric(selected, "VC")
    vi = _cvss4_effective_metric(selected, "VI")
    va = _cvss4_effective_metric(selected, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    sc = _cvss4_effective_metric(selected, "SC")
    si = _cvss4_effective_metric(selected, "SI")
    sa = _cvss4_effective_metric(selected, "SA")
    msi = _cvss4_effective_metric(selected, "MSI")
    msa = _cvss4_effective_metric(selected, "MSA")
    if msi == "S" or msa == "S":
        eq4 = 0
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = 1
    else:
        eq4 = 2

    e = _cvss4_effective_metric(selected, "E")
    if e == "A":
        eq5 = 0
    elif e == "P":
        eq5 = 1
    else:
        eq5 = 2

    cr = _cvss4_effective_metric(selected, "CR")
    ir = _cvss4_effective_metric(selected, "IR")
    ar = _cvss4_effective_metric(selected, "AR")
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = 0
    else:
        eq6 = 1

    return eq1, eq2, eq3, eq4, eq5, eq6


_CVSS4_LOOKUP_FRAC: dict[str, Fraction] = {
    key: Fraction(str(val)) for key, val in _CVSS4_LOOKUP.items()
}
_CVSS4_LEVELS_FRAC: dict[str, dict[str, Fraction]] = {
    metric: {level_key: Fraction(str(level_val)) for level_key, level_val in levels.items()}
    for metric, levels in _CVSS4_LEVELS.items()
}


def _compute_v4_score(selected: dict[str, str]) -> float:
    if all(_cvss4_effective_metric(selected, m) == "N" for m in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    eq1, eq2, eq3, eq4, eq5, eq6 = _cvss4_macrovector(selected)
    macro_key = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    value = _CVSS4_LOOKUP_FRAC[macro_key]

    score_eq1_next = _CVSS4_LOOKUP_FRAC.get(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}")
    score_eq2_next = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}")

    if eq3 == 0 and eq6 == 0:
        left = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        right = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        if left is not None and right is not None:
            score_eq36_next: Optional[Fraction] = left if left > right else right
        else:
            score_eq36_next = left if left is not None else right
    elif (eq3 == 1 and eq6 == 1) or (eq3 == 0 and eq6 == 1):
        score_eq36_next = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 1 and eq6 == 0:
        score_eq36_next = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    else:
        score_eq36_next = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")

    score_eq4_next = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
    score_eq5_next = _CVSS4_LOOKUP_FRAC.get(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

    effective_values = {m: _cvss4_effective_metric(selected, m) for m in _CVSS4_LEVELS_FRAC}
    chosen_distances: Optional[dict[str, Fraction]] = None
    for max_candidate in _CVSS4_MAX_CANDIDATES[(eq1, eq2, eq3, eq4, eq5, eq6)]:
        distances = {
            metric: _CVSS4_LEVELS_FRAC[metric][effective_values[metric]]
            - _CVSS4_LEVELS_FRAC[metric][max_candidate[metric]]
            for metric in _CVSS4_LEVELS_FRAC
        }
        if any(dist < 0 for dist in distances.values()):
            continue
        chosen_distances = distances
        break

    if chosen_distances is None:
        raise ValueError(f"Unable to locate max composed vector for CVSS v4.0 macrovector {macro_key}")

    dist_eq1 = chosen_distances["AV"] + chosen_distances["PR"] + chosen_distances["UI"]
    dist_eq2 = chosen_distances["AC"] + chosen_distances["AT"]
    dist_eq36 = (
        chosen_distances["VC"]
        + chosen_distances["VI"]
        + chosen_distances["VA"]
        + chosen_distances["CR"]
        + chosen_distances["IR"]
        + chosen_distances["AR"]
    )
    dist_eq4 = chosen_distances["SC"] + chosen_distances["SI"] + chosen_distances["SA"]

    step = Fraction(1, 10)
    max_sev_eq1 = Fraction(_CVSS4_MAX_SEVERITY["eq1"][eq1]) * step
    max_sev_eq2 = Fraction(_CVSS4_MAX_SEVERITY["eq2"][eq2]) * step
    max_sev_eq36 = Fraction(_CVSS4_MAX_SEVERITY["eq3eq6"][eq3][eq6]) * step
    max_sev_eq4 = Fraction(_CVSS4_MAX_SEVERITY["eq4"][eq4]) * step

    n_existing_lower = 0
    total_normalized = Fraction(0)

    if score_eq1_next is not None:
        n_existing_lower += 1
        total_normalized += (value - score_eq1_next) * dist_eq1 / max_sev_eq1
    if score_eq2_next is not None:
        n_existing_lower += 1
        total_normalized += (value - score_eq2_next) * dist_eq2 / max_sev_eq2
    if score_eq36_next is not None:
        n_existing_lower += 1
        total_normalized += (value - score_eq36_next) * dist_eq36 / max_sev_eq36
    if score_eq4_next is not None:
        n_existing_lower += 1
        total_normalized += (value - score_eq4_next) * dist_eq4 / max_sev_eq4
    if score_eq5_next is not None:
        n_existing_lower += 1

    mean_distance = Fraction(0) if n_existing_lower == 0 else (total_normalized / n_existing_lower)
    final = value - mean_distance
    if final <= 0:
        return 0.0
    if final >= 10:
        return 10.0
    final_dec = Decimal(final.numerator) / Decimal(final.denominator)
    return float(final_dec.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


# -------------------------
# Public API
# -------------------------


def detect_cvss_exact_version(vector: Optional[str]) -> Optional[CVSSExactVersion]:
    """Return exact CVSS version ('2.0', '3.0', '3.1', '4.0') if valid, else None."""
    parsed = _parse_vector_internal(vector)
    if parsed is None:
        return None
    return parsed[0]


def detect_cvss_version(vector: Optional[str]) -> Optional[CVSSMajorVersion]:
    """Return 'v4', 'v3', 'v2', or None based on syntax."""
    exact = detect_cvss_exact_version(vector)
    if exact is None:
        return None
    if exact == "4.0":
        return "v4"
    if exact in ("3.0", "3.1"):
        return "v3"
    return "v2"


def is_valid_cvss_vector(vector: Optional[str]) -> bool:
    """Validate if a given string is a well-formed CVSS v2.0, v3.0, v3.1, or v4.0 vector."""
    return detect_cvss_exact_version(vector) is not None


def extract_cvss_metrics(vector: Optional[str]) -> Dict[str, str]:
    """
    Parse normalized base metric key-values from a valid CVSS v2.0, v3.x, or v4.0 vector.
    Returns an empty dict if the vector is invalid.
    """
    parsed = _parse_vector_internal(vector)
    if parsed is None:
        return {}
    return dict(parsed[1])


def compute_cvss_base_score(vector: Optional[str]) -> Optional[float]:
    """
    Compute the exact FIRST specification CVSS Base Score (v2.0, v3.0, v3.1, or v4.0).
    Returns None if the vector is invalid.
    """
    parsed = _parse_vector_internal(vector)
    if parsed is None:
        return None

    version, base_metrics, _ = parsed
    if version == "2.0":
        return _compute_v2_base_score(base_metrics)
    if version in ("3.0", "3.1"):
        return _compute_v3_base_score(version, base_metrics)
    return _compute_v4_score(base_metrics)


def parse_cvss_vector(
    ctx: Optional["RunContext"],
    vector: str,
) -> Optional[Tuple[float, float, float]]:
    """
    Parse a CVSS v2.0, v3.x, or v4.0 vector string and return (base, base, base)
    for backward compatibility with legacy CVSS3/CVSS2 .scores() callers.
    """
    score = compute_cvss_base_score(vector)
    if score is None:
        if ctx is not None and getattr(ctx, "logger", None) is not None:
            ctx.logger.debug(f"[cvss_util] Invalid CVSS Vector: {vector}")
        return None
    return (score, score, score)


def _safe_cvss_float(val: Any) -> Optional[float]:
    if val is None or isinstance(val, bool) or val == "":
        return None
    try:
        num = float(val)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(num):
        return None
    return num


def _normalize_cvss_prov(prov: Optional[str]) -> str:
    return str(prov or "").strip()


def _is_missing_prov(prov_str: str) -> bool:
    return prov_str.lower() == "missing"


def _is_unset_or_missing_prov(prov_str: str) -> bool:
    return not prov_str or _is_missing_prov(prov_str)


def resolve_effective_cvss_fields(
    snap_cvss: Any = None,
    snap_prov: Optional[str] = None,
    snap_ver: Optional[str] = None,
    snap_vec: Optional[str] = None,
    scanner_cvss: Any = None,
    scanner_vec: Optional[str] = None,
    score_trace: Optional[Dict[str, Any]] = None,
    *,
    treat_bare_zero_trace_as_score: bool = False,
) -> Tuple[Optional[float], str, Optional[str], Optional[str]]:
    """
    Resolve effective (cvss_score, cvss_provenance, cvss_version, cvss_vector) across
    enrichment snapshot, score_trace, and scanner fields without letting `"Missing"`
    overwrite `"Scanner-Supplied"` or leaking synthetic `0.0` for missing CVSS.
    """
    trace = score_trace if isinstance(score_trace, dict) else {}
    s_prov = _normalize_cvss_prov(snap_prov)
    t_prov = _normalize_cvss_prov(trace.get("cvss_provenance"))
    s_score = _safe_cvss_float(snap_cvss)
    t_score = _safe_cvss_float(trace.get("cvss_score"))
    scan_score = _safe_cvss_float(scanner_cvss)

    eff_vec_raw = snap_vec or trace.get("cvss_vector") or scanner_vec
    eff_vec = str(eff_vec_raw).strip() if eff_vec_raw else None
    eff_ver_raw = snap_ver or trace.get("cvss_version") or (detect_cvss_exact_version(eff_vec) if eff_vec else None)
    eff_ver = str(eff_ver_raw).strip() if eff_ver_raw else None

    if not _is_unset_or_missing_prov(s_prov):
        eff_prov = s_prov
        eff_cvss = s_score
        if eff_cvss is None:
            if not _is_unset_or_missing_prov(t_prov):
                eff_cvss = t_score
            elif not t_prov and t_score is not None and (t_score > 0.0 or treat_bare_zero_trace_as_score):
                eff_cvss = t_score
            elif scan_score is not None:
                eff_cvss = scan_score
            elif eff_vec:
                eff_cvss = compute_cvss_base_score(eff_vec)
        return eff_cvss, eff_prov, eff_ver, eff_vec

    if not s_prov and s_score is not None:
        if not _is_unset_or_missing_prov(t_prov):
            eff_prov = t_prov
        elif scan_score is not None or scanner_vec:
            eff_prov = "Scanner-Supplied"
        else:
            eff_prov = "Enriched"
        return s_score, eff_prov, eff_ver, eff_vec

    if not _is_unset_or_missing_prov(t_prov):
        eff_prov = t_prov
        eff_cvss = t_score
        if eff_cvss is None:
            if scan_score is not None:
                eff_cvss = scan_score
            elif eff_vec:
                eff_cvss = compute_cvss_base_score(eff_vec)
        return eff_cvss, eff_prov, eff_ver, eff_vec

    if scan_score is not None:
        scan_vec_str = str(scanner_vec).strip() if scanner_vec else eff_vec
        scan_ver_str = eff_ver or (detect_cvss_exact_version(scan_vec_str) if scan_vec_str else None)
        return scan_score, "Scanner-Supplied", scan_ver_str, scan_vec_str

    if scanner_vec:
        computed_scan = compute_cvss_base_score(str(scanner_vec))
        if computed_scan is not None:
            scan_vec_str = str(scanner_vec).strip()
            return computed_scan, "Scanner-Supplied", detect_cvss_exact_version(scan_vec_str) or eff_ver, scan_vec_str

    if eff_vec:
        computed = compute_cvss_base_score(eff_vec)
        if computed is not None:
            return computed, "Enriched", detect_cvss_exact_version(eff_vec) or eff_ver, eff_vec

    if not t_prov and not _is_missing_prov(s_prov) and t_score is not None:
        if t_score > 0.0 or treat_bare_zero_trace_as_score:
            return t_score, "Missing", eff_ver, eff_vec

    return None, "Missing", eff_ver, eff_vec
