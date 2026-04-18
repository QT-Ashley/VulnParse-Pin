# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from vulnparse_pin.core.classes.dataclass import FeedCachePolicy
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.io.pfhandler import PathLike

NVD_MIN_YEAR = 2002


def format_runtime(seconds: float) -> str:
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes > 0:
        return f"{minutes}m {secs:.2f}s"
    else:
        return f"{secs:2f}s"


def build_run_log(input_path: PathLike) -> Path:
    """
    Helper to create a log filename with timestamp.
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(input_path).stem
    return f"vulnparse-{stem}-{ts}.log"


def _require(condition: bool, msg: str) -> None:
    if not condition:
        raise ValueError(msg)


def extract_cve_years(ctx, scan_result) -> set[int]:
    _CVE_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)
    years: set[int] = set()
    for asset in scan_result.assets:
        for f in asset.findings:
            for cve in (f.cves or []):
                m = _CVE_RE.match(str(cve).strip())
                if m:
                    years.add(int(m.group(1)))
    if len(years) < 1:
        ctx.logger.debug("No CVEs could properly be extracted from the input file. Years is None; Years: %s", years, extra={"vp_label": "CVE Year Extraction"})
    else:
        ctx.logger.debug("Years seen: %s", years, extra={"vp_label": "CVE Year Extraction"})
    return years


def select_years(ctx, years_seen: set[int]) -> set[int]:
    normalized_years: set[int] = set()

    for y in years_seen:
        if y < NVD_MIN_YEAR:
            y = NVD_MIN_YEAR
            normalized_years.add(y)
        normalized_years.add(y)
    # dedup the years
    if normalized_years:
        ctx.logger.debug("Normalized years: %s", normalized_years, extra={"vp_label": "CVE Year Normalization"})
        return normalized_years
    else:
        raise RuntimeError("Unable to normalize years. Killswitching for failure mode.")


def load_score_policy(config: dict, nmap_port_bonus: float = 0.0) -> ScoringPolicyV1:
    epss = config.get("epss", {})
    evp = config.get("evidence_points", {})
    bands = config.get("bands", {})
    agg = config.get("aggregation", {})
    weights = config.get("weights", {})
    risk_ceiling = config.get("risk_ceiling", {})

    return ScoringPolicyV1(
        epss_scale = float(epss.get("scale", 10.0)),
        epss_min = float(epss.get("min", 0.0)),
        epss_max = float(epss.get("max", 1.0)),
        kev_evd = float(evp.get("kev", 9.5)),
        exploit_evd = float(evp.get("exploit", 9.0)),
        band_critical = float(bands.get("critical", 8.9)),
        band_high = float(bands.get("high", 7.9)),
        band_medium = float(bands.get("medium", 4.0)),
        band_low = float(bands.get("low", 2.0)),
        asset_aggregation = str(agg.get("asset_score", "max")),
        w_epss_high = float(weights.get("epss_high", 2.0)),
        w_epss_medium = float(weights.get("epss_medium", 1.0)),
        w_kev = float(weights.get("kev", 1.25)),
        w_exploit = float(weights.get("exploit", 2)),
        max_raw_risk = float(risk_ceiling.get("max_raw_risk", 15)),
        max_op_risk = float(risk_ceiling.get("max_operational_risk", 10.0)),
        cve_aggregation_mode = str(agg.get("finding_cve_score", "stacked_decay")),
        cve_aggregation_decay = float(agg.get("finding_cve_decay", 0.35)),
        cve_aggregation_max_contributors = int(agg.get("finding_cve_max_contributors", 8)),
        nmap_port_bonus = float(nmap_port_bonus),
    )


# Resolve feed sources.
def resolve_feed_path(arg_val, offline_mode: bool, default_online: PathLike, default_offline: PathLike) -> Any | str:
    """
    Used to determine how the feeds should be resolved based on user input.

    :param arg_val: User input from flag
    :param offline_mode: Whethere or not offline mode flag is specified.
    :type offline_mode: bool
    :param default_online: Resolves online feed cache url.
    :type default_online: str
    :param default_offline: Resolve offline feed cache path.
    :type default_offline: str | Path
    :return: Feed Source
    :rtype: Any | str
    """
    if arg_val:
        return arg_val
    elif offline_mode:
        return default_offline
    else:
        return default_online


def build_feed_cache_policy(config: dict) -> FeedCachePolicy:
    fc = config.get("feed_cache", {}) or {}
    defaults = fc.get("defaults", {}) or {}
    default_ttl = int(defaults.get("ttl_hours", 24))

    ttl_map = fc.get("ttl_hours", {}) or {}
    ttl_map = {str(k): int(v) for k, v in ttl_map.items()}

    return FeedCachePolicy(default_ttl_hours = default_ttl, ttl_hours = ttl_map)
