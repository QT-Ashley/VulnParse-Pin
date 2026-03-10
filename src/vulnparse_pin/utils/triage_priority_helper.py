# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from vulnparse_pin.core.classes.dataclass import TriageConfig


def determine_triage_priority(
    raw_score: float,
    severity: str,
    epss_score: float,
    cisa_kev: bool,
    exploit_available: bool,
    cfg: TriageConfig
) -> str:
    """
    Compute triage priorty based on:
    - raw_scoreL numeric base (e.g CVSS or fallback)
    - severity: original severity level
    - epss_score: EPSS probability
    - cisa_kev: on CISA Known Exploited Vuln List
    - exploit_available: any exploit detected
    - cfg: thresholds/toggles for profiles
    """
    # 1) Override to Critical on KEV
    if cisa_kev:
        return "Critical"

    # 2) Use exploit to bump raw_score if missing CVSS
    if raw_score == 0 and exploit_available:
        raw_score = max(cfg.exploit_floor_score, raw_score)

    # 3) Critical by raw score
    if raw_score >= cfg.critical_score:
        return "Critical"

    # 4) Critical by High severity + EPSS
    if severity == "High" and epss_score >= cfg.high_epss_score:
        return "Critical"

    # 5) Warning Level
    if raw_score >= 7.0 or (exploit_available and raw_score >= cfg.exploit_floor_score):
        return "High"

    # 6) Everything else is Medium or below
    if raw_score >= 4.0:
        return "Medium"

    return "Low"