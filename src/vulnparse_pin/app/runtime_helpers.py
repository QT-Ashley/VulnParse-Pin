# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from vulnparse_pin.core.classes.dataclass import FeedCachePolicy
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.io.pfhandler import _UMASK_LOCK, FilePathError, PathLike

NVD_MIN_YEAR = 2002


def format_runtime(seconds: float) -> str:
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes > 0:
        return f"{minutes}m {secs:.2f}s"
    return f"{secs:.2f}s"


def build_run_log(input_path: PathLike) -> str:
    """Helper to create a log filename with timestamp."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(input_path).stem
    return f"vulnparse-{stem}-{ts}.log"


def _require(condition: bool, msg: str) -> None:
    if not condition:
        raise ValueError(msg)


def _to_unresolved_abs(pfh: Any, raw_path: PathLike) -> Path:
    if hasattr(pfh, "_to_unresolved_abs_path"):
        return pfh._to_unresolved_abs_path(raw_path)
    p = raw_path if isinstance(raw_path, Path) else Path(raw_path)
    p = p.expanduser()
    if not p.is_absolute():
        p = Path(os.getcwd()) / p
    return p


def _nearest_existing_ancestor(path: Path) -> Path:
    cur = Path(os.path.normpath(str(path)))
    while not cur.exists():
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return cur


def authorize_output_path(
    pfh: Any,
    raw_path: PathLike,
    *,
    label: str = "Output File",
    overwrite: bool = True,
) -> Path:
    """
    Validate and authorize an explicit user-supplied output path via
    ``pfh.allow_workspace_root(...)`` without stripping parent directories,
    while preserving symlink and filesystem-root escape checks.
    """
    if raw_path is None or (isinstance(raw_path, str) and not raw_path.strip()):
        raise FilePathError(f"{label} path must not be empty.")

    unresolved = _to_unresolved_abs(pfh, raw_path)

    if getattr(pfh, "forbid_symlinks_write", True) and hasattr(pfh, "_inspect_raw_symlinks"):
        pfh._inspect_raw_symlinks(unresolved, label=label, op="write", raise_on_error=True)

    if hasattr(pfh, "allow_workspace_root"):
        anc = _nearest_existing_ancestor(unresolved.parent)
        if anc.parent == anc:
            raise FilePathError(
                f"{label} parent directory cannot be authorized at filesystem root: {unresolved}"
            )
        pfh.allow_workspace_root(anc)

    return pfh.ensure_writable_file(
        unresolved,
        label=label,
        create_parents=True,
        overwrite=overwrite,
    )


def authorize_output_dir(pfh: Any, raw_dir: PathLike, *, label: str = "Output Directory") -> Path:
    """Validate, create if needed, and authorize an explicit directory via ``pfh.allow_workspace_root``."""
    if raw_dir is None or (isinstance(raw_dir, str) and not raw_dir.strip()):
        raise FilePathError(f"{label} path must not be empty.")

    unresolved = _to_unresolved_abs(pfh, raw_dir)

    if getattr(pfh, "forbid_symlinks_write", True) and hasattr(pfh, "_inspect_raw_symlinks"):
        pfh._inspect_raw_symlinks(unresolved, label=label, op="write", raise_on_error=True)

    if hasattr(pfh, "allow_workspace_root"):
        anc = _nearest_existing_ancestor(unresolved)
        if anc.parent == anc:
            raise FilePathError(
                f"{label} cannot be authorized at filesystem root: {unresolved}"
            )
        pfh.allow_workspace_root(anc)

    if not unresolved.exists():
        dir_mode = getattr(pfh, "dir_mode", None)
        if os.name == "posix" and dir_mode is not None:
            dmode = int(dir_mode)
            with _UMASK_LOCK:
                old_umask = os.umask(0o777 & ~dmode)
                try:
                    unresolved.mkdir(mode=dmode, parents=True, exist_ok=True)
                finally:
                    os.umask(old_umask)
        else:
            unresolved.mkdir(parents=True, exist_ok=True)
        if hasattr(pfh, "_apply_dir_mode"):
            pfh._apply_dir_mode(unresolved)

    if hasattr(pfh, "allow_workspace_root"):
        return pfh.allow_workspace_root(unresolved)
    return unresolved.resolve()


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
    if normalized_years:
        ctx.logger.debug("Normalized years: %s", normalized_years, extra={"vp_label": "CVE Year Normalization"})
        return normalized_years
    raise RuntimeError("Unable to normalize years. Killswitching for failure mode.")


def load_score_policy(config: dict, nmap_port_bonus: float = 0.0) -> ScoringPolicyV1:
    epss = config.get("epss", {})
    evp = config.get("evidence_points", {})
    bands = config.get("bands", {})
    agg = config.get("aggregation", {})
    weights = config.get("weights", {})
    risk_ceiling = config.get("risk_ceiling", {})

    return ScoringPolicyV1(
        epss_scale=float(epss.get("scale", 10.0)),
        epss_min=float(epss.get("min", 0.0)),
        epss_max=float(epss.get("max", 1.0)),
        kev_evd=float(evp.get("kev", 9.5)),
        exploit_evd=float(evp.get("exploit", 9.0)),
        band_critical=float(bands.get("critical", 8.9)),
        band_high=float(bands.get("high", 7.9)),
        band_medium=float(bands.get("medium", 4.0)),
        band_low=float(bands.get("low", 2.0)),
        asset_aggregation=str(agg.get("asset_score", "max")),
        w_epss_high=float(weights.get("epss_high", 2.0)),
        w_epss_medium=float(weights.get("epss_medium", 1.0)),
        w_kev=float(weights.get("kev", 1.25)),
        w_exploit=float(weights.get("exploit", 2)),
        max_raw_risk=float(risk_ceiling.get("max_raw_risk", 15)),
        max_op_risk=float(risk_ceiling.get("max_operational_risk", 10.0)),
        cve_aggregation_mode=str(agg.get("finding_cve_score", "stacked_decay")),
        cve_aggregation_decay=float(agg.get("finding_cve_decay", 0.35)),
        cve_aggregation_max_contributors=int(agg.get("finding_cve_max_contributors", 8)),
        nmap_port_bonus=float(nmap_port_bonus),
    )


def resolve_feed_path(arg_val, offline_mode: bool, default_online: PathLike, default_offline: PathLike) -> Any | str:
    """Resolve feed source based on explicit override and online/offline mode."""
    if arg_val:
        return arg_val
    if offline_mode:
        return default_offline
    return default_online


def build_feed_cache_policy(config: dict) -> FeedCachePolicy:
    fc = config.get("feed_cache", {}) or {}
    defaults = fc.get("defaults", {}) or {}
    default_ttl = int(defaults.get("ttl_hours", 24))

    ttl_map = fc.get("ttl_hours", {}) or {}
    ttl_map = {str(k): int(v) for k, v in ttl_map.items()}

    return FeedCachePolicy(default_ttl_hours=default_ttl, ttl_hours=ttl_map)
