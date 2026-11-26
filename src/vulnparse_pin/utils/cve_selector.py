# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

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