# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from multiprocessing import Value
from typing import Dict, Any, Optional, Tuple

def _parse_version_tuple(v: str) -> Tuple[int, ...]:
    """
    Semantic version parser for sorting versions.
    Non-numeric parts ignored.
    
    :param v: Version string
    :type v: str
    :rtype: Tuple[int, ...]
    """
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)

def _chosen_scoring_pass_key(derived_passes: Dict[str, Any], preferred_key: Optional[str]) -> Optional[str]:
    """
    Selects scoring pass key.
        - If preferred_key exists, use it.
        - Otherwise, pick the highest version among keys.
    
    :param derived_passes: DerivedContext obj -> asdict
    :type derived_passes: Dict[str, Any]
    :param preferred_key: Preferred pass key to retrieve.
    :type preferred_key: Optional[str]
    :return: Pass Key
    :rtype: str | None
    """
    if not derived_passes:
        return None

    if preferred_key and preferred_key in derived_passes:
        return preferred_key

    candidates = []
    for k in derived_passes.keys():
        if k.startswith("Scoring@"):
            _, _, ver = k.partition("@")
            candidates.append((k, _parse_version_tuple(ver)))

    if not candidates:
        return None

    # Resolve highest version wins
    candidates.sort(key=lambda t: t[1], reverse=True)
    return candidates[0][0]

def _ensure_dict(obj: Any) -> Dict[str, Any]:
    """
    Ensure obj is a dictionary suitable for JSON serialization:
      - dataclass -> asdict
      -  already dict -> returns
      - Other -> {}
    
    :param obj: Object
    :type obj: Any(Class obj or Dict Works)
    :return: Dict
    :rtype: Dict[str, Any]
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if is_dataclass(obj):
        return asdict(obj)
    # Best-effort mode
    to_dict = getattr(obj, "dict", None)
    if callable(to_dict):
        return to_dict()
    return {}

def materialize_presentation(
    scan_result: Any,
    *,
    scoring_pass_key: Optional[str] = None,
    overlay_mode: str = "flatten", # 'flatten' or 'namespaced'
    include_meta: bool = True,
) -> Dict[str, Any]:
    """
    Produces a JSON-ready presentation object by overlaying derived scoring back onto findings.
    
    Does NOT mutate ScanResult object.
    
    overlay_mode:
      - 'flatten': writes scoring fields onto finding root keys (UX-friendly)
      - 'namespaced': writes scoring data under finding["derived"][scoring_key] (architecture-friendly)
    
    :param scan_result: ScanResult Object(Processed report object)
    :type scan_result: Any
    :param scoring_pass_key: Scoring Pass key string to search(Optional)
    :type scoring_pass_key: Optional[str]
    :param overlay_mode: 'flatten' or 'namespace'
    :type overlay_mode: str
    :param include_meta: Includes pass meta data. Default true.
    :type include_meta: bool
    :return: Report output with UX friendly data overlay presentation.
    :rtype: Dict[str, Any]
    """
    # Let's first convert the whole ScanResult to a dictionary first.
    base = asdict(scan_result) if is_dataclass(scan_result) else _ensure_dict(scan_result)
    
    # Defensive gates - Errors shall NOT pass
    assets = base.get("assets") if isinstance(base, dict) else None
    if not isinstance(assets, list):
        return base

    # Retrieve necessary data
    derived = base.get("derived", {}) if isinstance(base, dict) else {}
    derived = _ensure_dict(derived)
    passes = _ensure_dict(derived.get("passes", {}))

    chosen_key = _chosen_scoring_pass_key(passes, scoring_pass_key)
    scoring_pass = _ensure_dict(passes.get(chosen_key)) if chosen_key else {}
    scoring_data = _ensure_dict(scoring_pass.get("data"))
    scored_findings = _ensure_dict(scoring_data.get("scored_findings"))
    scored_asset_criticality = _ensure_dict(scoring_data.get("asset_criticality"))
    scored_asset_band_counts = _ensure_dict(scoring_data.get("asset_band_counts"))

    # Lookup build: fid -> scoring record 
    sf_map: Dict[str, Dict[str, Any]] = {}
    for fid, rec in scored_findings.items():
        if isinstance(fid, str):
            sf_map[fid] = _ensure_dict(rec)

    # Overlay onto assets (derived asset-level characteristics)
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        aid = asset.get("asset_id")
        if not isinstance(aid, str):
            continue

        asset_crit = scored_asset_criticality.get(aid)
        asset_counts = scored_asset_band_counts.get(aid)

        if overlay_mode == "namespace":
            a_derived = asset.get("derived")
            if not isinstance(a_derived, dict):
                a_derived = {}
                asset["derived"] = a_derived
            pass_key = chosen_key or "Scoring@?"
            scoped = a_derived.get(pass_key)
            if not isinstance(scoped, dict):
                scoped = {}
                a_derived[pass_key] = scoped
            if asset_crit is not None:
                scoped["asset_criticality"] = asset_crit
            if isinstance(asset_counts, dict):
                scoped["asset_band_counts"] = asset_counts
        elif overlay_mode == "flatten":
            if asset_crit is not None:
                asset["criticality"] = asset_crit
            if isinstance(asset_counts, dict):
                asset["asset_band_counts"] = asset_counts

    # Overlay onto each finding
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        findings = asset.get("findings")
        if not isinstance(findings, list):
            continue

        for f in findings:
            if not isinstance(f, dict):
                continue

            fid = f.get("finding_id")
            if not isinstance(fid, str):
                continue

            sf = sf_map.get(fid)
            if not sf:
                continue # No scoring available

            # Normalize expected key from scoring output
            raw = sf.get("raw_score")
            op = sf.get("operational_score")
            band = sf.get("risk_band")
            reason = sf.get("reason")

            if overlay_mode == "namespace":
                f_derived = f.get("derived")
                if not isinstance(f_derived, dict):
                    f_derived = {}
                    f["derived"] = f_derived
                f_derived[chosen_key or "Scoring@?"] = sf
                f_derived[chosen_key or "Scoring@?"]["raw_score"] = round(f_derived[chosen_key or "Scoring@?"]["raw_score"], 2)
                f_derived[chosen_key or "Scoring@?"]["operational_score"] = round(f_derived[chosen_key or "Scoring@?"]["operational_score"], 2)

            elif overlay_mode == "flatten":
                # UX Friendly
                f["raw_risk_score"] = round(raw, 2)
                f["operational_score"] = round(op, 2)
                f["risk_score"] = round(op, 2)
                f["risk_band"] = band
                f["reason"] = reason

            else:
                raise ValueError(f"Unknown overlay_mode={overlay_mode}")

    if overlay_mode:
        base.pop("derived")


    if include_meta and isinstance(base, dict):
        pres = base.get("presentation")
        if not isinstance(pres, dict):
            pres = {}
            base["presentation"] = pres

        pres["scoring_pass"] = chosen_key
        pres["band_source"] = "raw_score"
        pres["operational_scale"] = "0-10"
        pres["overlay_mode"] = overlay_mode
        cov = _ensure_dict(scoring_data.get("coverage"))
        if cov:
            pres["scoring_coverage"] = cov

    return base