# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations
import re
from typing import Literal, Optional, TYPE_CHECKING

try:
    from cvss import CVSS3, CVSS2
except ImportError:
    CVSS3 = None #Fallback if module isn't installed

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


CVSS3_REGEX = r'^CVSS:3\.[01]/AV:(N|A|L|P)/AC:(L|H)/PR:(N|L|H)/UI:(N|R)/S:(U|C)/C:(N|L|H)/I:(N|L|H)/A:(N|L|H)$'
CVSS3_REGEX_L = r'CVSS:3\.[0-1]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
CVSS2_REGEX = r'^AV:(L|A|N)/AC:(L|M|H)/Au:(N|S|M)/C:(N|P|C)/I:(N|P|C)/A:(N|P|C)$'
CVSSKIND = Literal["cvss2", "cvss3", "unknown"] # TODO: Use these as Tags

CVSS3_RE = re.compile(CVSS3_REGEX)
CVSS2_RE = re.compile(CVSS2_REGEX)

def detect_cvss_version(vector: Optional[str]) -> Optional[str]:
    """Return 'v3', 'v2', or None based on syntax."""
    if not vector:
        return None

    v = re.sub(r'\s+', '', vector.strip())
    if v.startswith("SENTINEL:"):
        return None

    if CVSS3_RE.match(v):
        return "v3"
    if CVSS2_RE.match(v):
        return "v2"
    return None

def is_valid_cvss_vector(vector: Optional[str]) -> bool:
    '''
    Validate if a given string is well-formed CVSS V3.x or V2 vector.

    Args:
        vector (str): CVSS vector string.

    Returns:
        bool: True if valid, False otherwise.
    '''
    return detect_cvss_version(vector) in ("v2", "v3")


def parse_cvss_vector(ctx: "RunContext", vector: str):
    '''
    Parse a CVSS v3.X or V2 vector string into its base score components.

    Args:
        vector (str): CVSS vector string.

    Returns:
        dict or None: Dictionary of CVSS score or None if invalid or supported.
    '''
    if not is_valid_cvss_vector(vector):
        ctx.logger.debug(f"[cvss_util] Invalid CVSS Vector: {vector}")
        return None

    if CVSS3 is None or CVSS2 is None:
        raise ImportError("cvss package is not installed. Install it with 'pip install cvss'.")

    try:
        if detect_cvss_version(vector) == "v3":
            cvss_obj = CVSS3(vector)
            return cvss_obj.scores()
        elif detect_cvss_version(vector) == "v2":
            cvss_obj = CVSS2(vector)
            return cvss_obj.scores()
    except Exception as e:
        ctx.logger.debug("Error parsing CVSS vector: %s", e)
        return None
