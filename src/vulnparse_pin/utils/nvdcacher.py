# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.
from __future__ import annotations
import gzip
import json
from datetime import datetime
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

class NVDFeedCache:
    '''
    Feed-based NVD Cache.
    - Pulls feed list + TTL policy from config.yaml
    - Uses FeedCacheManager for caching/integrity/refresh/offline
    - Parses cached raw .json.gz feeds into in-memory lookup for O(1) enrichment
    '''

    def __init__(self, ctx: "RunContext") -> None:
        self.ctx = ctx
        self.lookup: Dict[str, Dict[str, Any]] = {}

    def refresh(self, *, config: dict, feed_cache, refresh_cache: bool, offline: bool) -> None:
        feeds = nvd_feed_plan(config)
        if not feeds:
            self.ctx.logger.print_info("NVD disabled via config.")
            return

        missing: List[str] = []

        for f in feeds:
            try:
                path = feed_cache.resolve_nvd_feed(
                    key=f["key"],
                    ttl_hours=int(f["ttl_hours"]),
                    refresh_cache=refresh_cache,
                    offline=offline,
                )
            except FileNotFoundError:
                missing.append(f["fname"])
                continue

            self._parse_feed(path)

        if offline and missing:
            self.ctx.logger.warning(
                f"Offline mode: {len(missing)} feed(s) missing: {', '.join(missing)}."
            )
    # NOTE(perf): NVD feed parse builds in-mem O(1) index at startup (~2-4s).
    # Deferred until GA+: SQLite-backed indexing (persistent db, incremental refresh)
    def _parse_feed(self, path: str) -> None:
        """Parse NVD 2.0 feed into lookup dict."""
        ctx = self.ctx
        path = ctx.pfh.ensure_readable_file(path, label = "NVD Feed (.json.gz)")
        with ctx.pfh.open_for_read(path, mode="rb", label = "NVD Feed (.json.gz)") as raw:
            with gzip.open(raw, mode="rt", encoding="utf-8") as f:
                data = json.load(f)

        # Parse pertinent information from feeds.
        for item in data.get("vulnerabilities", []):
            cve = (item or {}).get("cve", {}) or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            # Description
            desc = ""
            descs = cve.get("descriptions") or []
            if descs:
                desc = (descs[0] or {}).get("value", "") or ""
            # Published/lastMod
            published = cve.get("published")
            last_mod = cve.get("lastModified")
            # CVSS Metrics
            metrics = cve.get("metrics", {}) or {}
            cvss, vector = None, None
            # Break out CVSS Version Prioritization
            if "cvssMetricV31" in metrics:
                cvss, vector = self._choose_cvss(metrics["cvssMetricV31"])
            elif "cvssMetricV30" in metrics:
                cvss, vector = self._choose_cvss(metrics["cvssMetricV30"])
            elif "cvssMetricV2" in metrics:
                cvss, vector = self._choose_cvss(metrics["cvssMetricV2"])

            # Create O1 Lookup
            self.lookup[cve_id] = {
                "id": cve_id,
                "description": desc,
                "cvss_score": cvss,
                "cvss_vector": vector,
                "published": published,
                "last_modiifed": last_mod,
            }

    def _choose_cvss(self, metrics_list) -> tuple | tuple[None, None]:
        """Pick Primary cvss first, fallback to Secondary."""
        primary = next((m for m in metrics_list if m.get("type") == "Primary"), None)
        if not primary and metrics_list:
            primary = metrics_list[0]
        if primary and "cvssData" in primary:
            d = primary["cvssData"]
            return d.get("baseScore"), d.get("vectorString")
        return None, None

    def get(self, cve_id: str) -> dict[str, Any]:
        """Lookup CVE from cache.
        Always return a normalized dict with expected keys, even if the CVE is missing
        (values default to None).
        """

        default_record = {
        "id": cve_id,
        "description": "",
        "cvss_score": None,
        "cvss_vector": None,
        "published": None,
        "last_Modified": None,
        "found": False,
        }

        record = self.lookup.get(cve_id, {})
        if record is None:
            return default_record

        merged = {**default_record, **record}
        merged["found"] = True
        return merged

def _cfg_get(config: Dict[str, Any], path: List[str], default = None):
    cur = config
    for k in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur

def _cfg_int(config: Dict[str, Any], path: List[str], default: int) -> int:
    v = _cfg_get(config, path, default)
    try:
        return int(v)
    except Exception:
        return default

def _cfg_bool(config: Dict[str, Any], path: List[str], default: bool) -> bool:
    v = _cfg_get(config, path, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return default

def nvd_policy_from_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pulls NVD policy config values from the config.
    """
    enabled = _cfg_bool(config, ["feed_cache", "nvd", "enabled"], True)

    ttl_default = _cfg_int(config, ["feed_cache", "defaults", "ttl_hours"], 24)
    ttl_yearly = _cfg_int(config, ["feed_cache", "ttl_hours", "nvd_yearly"], ttl_default)
    ttl_modified = _cfg_int(config, ["feed_cache", "ttl_hours", "nvd_modified"], min(2, ttl_default))


    now_year = datetime.now().year
    start_year = _cfg_int(config, ["feed_cache", "nvd", "start_year"], now_year)
    end_year = _cfg_int(config, ["feed_cache", "nvd", "end_year"], now_year)


    if start_year > end_year:
        start_year, end_year = end_year, start_year
    if end_year > now_year:
        end_year = now_year

    return {
        "enabled": enabled,
        "ttl_default": ttl_default,
        "ttl_yearly": ttl_yearly,
        "ttl_modified": ttl_modified,
        "start_year": start_year,
        "end_year": end_year,
    }

def nvd_feed_plan(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Returns the NVD Feed plan based off the YAML config parameters.
    
    :param config: Global config YAML
    :type config: Dict[str, Any]
    :return: A list of nvd feed params based on YAML config.
    :rtype: List[Dict[str, Any]]
    """
    p = nvd_policy_from_config(config)
    if not p["enabled"]:
        return []

    feeds = [{
        "key": "nvd.modified",
        "fname": "modified.json.gz",
        "ttl_hours": p["ttl_modified"],
    }]

    for y in range(p["start_year"], p["end_year"] + 1):
        feeds.append({
            "key": f"nvd.year.{y}",
            "fname": f"{y}.json.gz",
            "ttl_hours": p["ttl_yearly"],
        })

    return feeds
