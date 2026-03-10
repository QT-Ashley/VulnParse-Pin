# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from typing import Dict, List, Optional


def select_authoritative_cve(cve_list: List[str], m: Dict[str, Dict]) -> Optional[str]:
    def f(x) -> float:
        return float(x) if isinstance(x, (int, float)) else -1.0

    candidates = [c for c in cve_list if c in m]
    if not candidates:
        return None

    return max(
        candidates,
        key=lambda c: (
            bool(m[c].get("cisa_kev", False)),
            f(m[c].get("epss_score")),
            f(m[c].get("cvss_score")),
            c,
        ),
    )