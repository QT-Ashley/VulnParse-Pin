# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, time, timezone
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import duckdb

from vulnparse_pin.core.assets_context import DecisionEvaluation, DecisionsRegistry
from vulnparse_pin.storage.repositories import insert_diff_events
from vulnparse_pin.utils.cvss_utils import resolve_effective_cvss_fields


VALID_FAIL_ON_VALUES = frozenset({"none", "p1", "p2", "kev", "stale-assumption"})
EPSS_SCORE_THRESHOLDS: Tuple[float, ...] = (0.04, 0.10)
EPSS_PERCENTILE_THRESHOLDS: Tuple[float, ...] = (0.90, 0.95)
CVSS_DELTA_THRESHOLD: float = 1.0

_P1_TIERS = frozenset({"P1", "P1B"})
_P1_SLA_BUCKETS = frozenset({"3-day + forensic triage", "3-day", "14-day"})
_P2_TIERS = frozenset({"P2"})
_P2_SLA_BUCKETS = frozenset({"60-day"})
_BASELINE_TIERS = frozenset({"P3", "P4"})
_BASELINE_SLA_BUCKETS = frozenset({"fix on upgrade", "60-day"})
_KNOWN_TIERS = _P1_TIERS | _P2_TIERS | _BASELINE_TIERS
_KNOWN_OALS = frozenset({"OAL-1", "OAL-2", "OAL-3"})
_KNOWN_SSVC = frozenset({"act", "attend", "track*", "track"})

_VALID_SUPPRESSED_STATUSES = frozenset(
    {"deferred_valid", "accepted_valid", "mitigated", "deferred", "accepted"}
)
_EXPLICIT_INVALIDATED_STATUSES = frozenset(
    {"deferred_invalidated", "accepted_invalidated", "mitigated_invalidated"}
)

_CORE_INTEL_METADATA_KEYS: Tuple[str, ...] = (
    "epss_model_version",
    "epss_score_date",
    "epss_date",
    "epss_sha256",
    "kev_catalog_version",
    "kev_version",
    "kev_date_released",
    "kev_date",
    "kev_sha256",
    "nvd_status",
    "nvd_version",
    "nvd_date",
    "ghsa_enabled",
    "osv_enabled",
)

_FINDING_RUN_CTE_SQL = """
    SELECT
        f.asset_id,
        f.finding_id,
        f.scoring_track,
        COALESCE(
            UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')),
            f.primary_cve
        ) AS primary_cve,
        f.cves_json,
        f.title,
        f.scanner_severity,
        f.scanner_cvss_score,
        f.scanner_cvss_vector,
        a.canonical_key,
        a.hostname,
        a.ip_address,
        a.target_uri,
        a.image_or_repo,
        a.internet_facing,
        a.inventory_status,
        a.matched_rule_id,
        e.cvss_score,
        e.cvss_provenance,
        e.epss_score,
        e.epss_percentile,
        (
            COALESCE(e.in_kev, FALSE)
            OR COALESCE(fc_agg.fc_in_kev, FALSE)
            OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
        ) AS in_kev,
        (
            COALESCE(e.verified_exploit, FALSE)
            OR COALESCE(fc_agg.fc_verified_exploit, FALSE)
            OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.verified_exploit') AS BOOLEAN), FALSE)
        ) AS verified_exploit,
        s.raw_risk_score,
        s.operational_score,
        s.risk_band,
        s.score_trace_json,
        td.priority_tier,
        td.oal_compat,
        td.ssvc_action,
        td.sla_bucket,
        td.sla_days,
        td.decision_status,
        td.decision_id,
        td.assumed_state_json,
        td.rationale_summary
    FROM findings f
    LEFT JOIN assets a
        ON a.run_id = f.run_id AND a.asset_id = f.asset_id
    LEFT JOIN scores s
        ON s.run_id = f.run_id AND s.finding_id = f.finding_id
    LEFT JOIN enrichment_snapshots e
        ON e.run_id = f.run_id
       AND UPPER(e.cve_id) = COALESCE(
           UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')),
           UPPER(f.primary_cve)
       )
    LEFT JOIN (
        SELECT
            fc.finding_id,
            BOOL_OR(COALESCE(es.in_kev, FALSE)) AS fc_in_kev,
            BOOL_OR(COALESCE(es.verified_exploit, FALSE)) AS fc_verified_exploit
        FROM finding_cves fc
        JOIN enrichment_snapshots es
            ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id)
        WHERE fc.run_id = ?
        GROUP BY fc.finding_id
    ) fc_agg
        ON fc_agg.finding_id = f.finding_id
    LEFT JOIN triage_decisions td
        ON td.run_id = f.run_id AND td.finding_id = f.finding_id
    WHERE f.run_id = ?
"""

_ASSET_RUN_CTE_SQL = """
    SELECT
        a.asset_id,
        a.canonical_key,
        a.hostname,
        a.ip_address,
        a.target_uri,
        a.image_or_repo,
        a.internet_facing,
        a.inventory_status,
        a.matched_rule_id,
        COUNT(f.finding_id) AS finding_count,
        MAX(s.operational_score) AS max_operational_score,
        SUM(
            CASE
                WHEN (
                    COALESCE(e.in_kev, FALSE)
                    OR COALESCE(fc_agg.fc_in_kev, FALSE)
                    OR COALESCE(TRY_CAST(json_extract(s.score_trace_json, '$.in_kev') AS BOOLEAN), FALSE)
                ) THEN 1
                ELSE 0
            END
        ) AS kev_count
    FROM assets a
    LEFT JOIN findings f ON f.run_id = a.run_id AND f.asset_id = a.asset_id
    LEFT JOIN scores s ON s.run_id = f.run_id AND s.finding_id = f.finding_id
    LEFT JOIN enrichment_snapshots e
        ON e.run_id = f.run_id
       AND UPPER(e.cve_id) = COALESCE(
           UPPER(NULLIF(json_extract_string(s.score_trace_json, '$.primary_cve'), '')),
           UPPER(f.primary_cve)
       )
    LEFT JOIN (
        SELECT
            fc.finding_id,
            BOOL_OR(COALESCE(es.in_kev, FALSE)) AS fc_in_kev
        FROM finding_cves fc
        JOIN enrichment_snapshots es
            ON es.run_id = fc.run_id AND UPPER(es.cve_id) = UPPER(fc.cve_id)
        WHERE fc.run_id = ?
        GROUP BY fc.finding_id
    ) fc_agg
        ON fc_agg.finding_id = f.finding_id
    WHERE a.run_id = ?
    GROUP BY
        a.asset_id, a.canonical_key, a.hostname, a.ip_address,
        a.target_uri, a.image_or_repo, a.internet_facing,
        a.inventory_status, a.matched_rule_id
"""


def _get_conn(db: Any) -> duckdb.DuckDBPyConnection:
    if isinstance(db, duckdb.DuckDBPyConnection):
        return db
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    raise TypeError(f"Expected VppDatabase or DuckDBPyConnection, got {type(db).__name__}")


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_loads_safe(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        loaded = json.loads(raw)
        return loaded if loaded is not None else default
    except Exception:
        return default


def _safe_float(val: Any) -> Optional[float]:
    if val is None or val == "":
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _safe_int(val: Any) -> Optional[int]:
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _parse_iso_datetime(
    value: Union[datetime, date, str],
    *,
    end_of_day_for_date: bool = False,
) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        t = time(23, 59, 59, 999999) if end_of_day_for_date else time(0, 0, 0)
        return datetime.combine(value, t, tzinfo=timezone.utc)
    raw = str(value).strip()
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        d = date.fromisoformat(raw)
        t = time(23, 59, 59, 999999) if end_of_day_for_date else time(0, 0, 0)
        return datetime.combine(d, t, tzinfo=timezone.utc)
    iso = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    dt = datetime.fromisoformat(iso)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def compute_diff_id(base_run_id: str, target_run_id: str) -> str:
    """Compute a deterministic diff identifier for a (base_run_id, target_run_id) pair."""
    digest = hashlib.sha256(
        f"vpp:diff:v2|base={base_run_id}|target={target_run_id}".encode("utf-8")
    ).hexdigest()[:20]
    return f"diff_v2_{digest}"


def _is_p1(
    priority_tier: Optional[str],
    sla_bucket: Optional[str],
    oal_compat: Optional[str] = None,
    ssvc_action: Optional[str] = None,
) -> bool:
    tier = (priority_tier or "").strip().upper()
    sla = (sla_bucket or "").strip().lower()
    oal = (oal_compat or "").strip().upper()
    ssvc = (ssvc_action or "").strip().lower()
    if sla in {"3-day + forensic triage", "3-day"} or sla.startswith("3-day"):
        return True
    if tier in _KNOWN_TIERS:
        return tier in _P1_TIERS
    if oal in _KNOWN_OALS:
        return oal == "OAL-1"
    if ssvc in _KNOWN_SSVC:
        return ssvc == "act"
    return sla in _P1_SLA_BUCKETS or sla.startswith("14-day")


def _is_p2(
    priority_tier: Optional[str],
    sla_bucket: Optional[str],
    oal_compat: Optional[str] = None,
    ssvc_action: Optional[str] = None,
) -> bool:
    if _is_p1(priority_tier, sla_bucket, oal_compat, ssvc_action):
        return False
    tier = (priority_tier or "").strip().upper()
    sla = (sla_bucket or "").strip().lower()
    oal = (oal_compat or "").strip().upper()
    ssvc = (ssvc_action or "").strip().lower()
    if tier in _KNOWN_TIERS:
        return tier in _P2_TIERS
    if oal in _KNOWN_OALS:
        return oal == "OAL-2"
    if ssvc in _KNOWN_SSVC:
        return ssvc == "attend"
    return sla in _P2_SLA_BUCKETS or sla.startswith("60-day")


def _is_p1_or_p2(
    priority_tier: Optional[str],
    sla_bucket: Optional[str],
    oal_compat: Optional[str] = None,
    ssvc_action: Optional[str] = None,
) -> bool:
    return _is_p1(priority_tier, sla_bucket, oal_compat, ssvc_action) or _is_p2(
        priority_tier, sla_bucket, oal_compat, ssvc_action
    )


def _urgency_rank(
    priority_tier: Optional[str],
    sla_bucket: Optional[str],
    oal_compat: Optional[str] = None,
    ssvc_action: Optional[str] = None,
) -> int:
    if _is_p1(priority_tier, sla_bucket, oal_compat, ssvc_action):
        return 1
    if _is_p2(priority_tier, sla_bucket, oal_compat, ssvc_action):
        return 2
    tier = (priority_tier or "").strip().upper()
    sla = (sla_bucket or "").strip().lower()
    oal = (oal_compat or "").strip().upper()
    ssvc = (ssvc_action or "").strip().lower()
    if tier in _BASELINE_TIERS or "fix on upgrade" in sla or oal == "OAL-3" or ssvc in ("track", "track*"):
        return 3
    return 99


def _is_baseline_for_implicit_drift(
    priority_tier: Optional[str],
    sla_bucket: Optional[str],
    oal_compat: Optional[str] = None,
    ssvc_action: Optional[str] = None,
) -> bool:
    tier = (priority_tier or "").strip().upper()
    sla = (sla_bucket or "").strip().lower()
    oal = (oal_compat or "").strip().upper()
    ssvc = (ssvc_action or "").strip().lower()
    return (
        tier in _BASELINE_TIERS
        or sla in _BASELINE_SLA_BUCKETS
        or "fix on upgrade" in sla
        or sla.startswith("60-day")
        or oal == "OAL-3"
        or ssvc in ("track", "track*")
    )


def _is_validly_suppressed_status(decision_status: Optional[str]) -> bool:
    if not decision_status:
        return False
    return decision_status.strip().lower() in _VALID_SUPPRESSED_STATUSES


def _effective_cvss(
    snapshot_cvss: Optional[float],
    scanner_cvss: Optional[float],
    score_trace: Optional[Dict[str, Any]],
    *,
    snapshot_prov: Optional[str] = None,
    scanner_vec: Optional[str] = None,
) -> Optional[float]:
    eff_cvss, _, _, _ = resolve_effective_cvss_fields(
        snap_cvss=snapshot_cvss,
        snap_prov=snapshot_prov,
        scanner_cvss=scanner_cvss,
        scanner_vec=scanner_vec,
        score_trace=score_trace,
    )
    return eff_cvss


def _effective_cvss_provenance(
    snapshot_prov: Optional[str],
    snapshot_cvss: Optional[float],
    scanner_cvss: Optional[float],
    score_trace: Optional[Dict[str, Any]],
    *,
    scanner_vec: Optional[str] = None,
) -> str:
    _, eff_prov, _, _ = resolve_effective_cvss_fields(
        snap_cvss=snapshot_cvss,
        snap_prov=snapshot_prov,
        scanner_cvss=scanner_cvss,
        scanner_vec=scanner_vec,
        score_trace=score_trace,
    )
    return eff_prov


def _evaluate_assumed_state_predicates(
    assumed_state: Dict[str, Any],
    *,
    target_in_kev: bool,
    target_epss: Optional[float],
    target_epss_pct: Optional[float],
    target_facing: Optional[bool],
    target_cvss: Optional[float],
    now_dt: datetime,
) -> Tuple[List[str], List[str]]:
    """Evaluate raw assumed_state dict predicates against target run state."""
    violated: List[str] = []
    reasons: List[str] = []

    exp_raw = assumed_state.get("expires_at")
    if exp_raw:
        try:
            exp_dt = _parse_iso_datetime(exp_raw, end_of_day_for_date=True)
            if now_dt > exp_dt:
                violated.append("expired")
                reasons.append(f"expired: decision expired at {exp_raw}")
        except Exception:
            pass

    if assumed_state.get("in_kev") is not None:
        expected_kev = bool(assumed_state["in_kev"])
        if bool(target_in_kev) != expected_kev:
            violated.append("kev_flipped")
            reasons.append(f"kev_flipped: expected in_kev={expected_kev}, actual={bool(target_in_kev)}")

    if assumed_state.get("max_epss") is not None and target_epss is not None:
        max_epss = float(assumed_state["max_epss"])
        if target_epss > max_epss:
            violated.append("epss_exceeded")
            reasons.append(f"epss_exceeded: epss={target_epss:.4f} > max_epss={max_epss:.4f}")

    if assumed_state.get("max_epss_percentile") is not None and target_epss_pct is not None:
        max_pct = float(assumed_state["max_epss_percentile"])
        if target_epss_pct > max_pct:
            violated.append("epss_percentile_exceeded")
            reasons.append(
                f"epss_percentile_exceeded: percentile={target_epss_pct:.4f} > max_epss_percentile={max_pct:.4f}"
            )

    if assumed_state.get("internet_facing") is not None and target_facing is not None:
        expected_facing = bool(assumed_state["internet_facing"])
        if bool(target_facing) != expected_facing:
            violated.append("exposure_flipped")
            reasons.append(
                f"exposure_flipped: expected internet_facing={expected_facing}, actual={bool(target_facing)}"
            )

    if assumed_state.get("max_cvss") is not None and target_cvss is not None:
        max_cvss = float(assumed_state["max_cvss"])
        if target_cvss > max_cvss:
            violated.append("cvss_exceeded")
            reasons.append(f"cvss_exceeded: cvss={target_cvss:.1f} > max_cvss={max_cvss:.1f}")

    for key in ("violated_predicates", "violations"):
        extra = assumed_state.get(key)
        if isinstance(extra, (list, tuple)):
            for item in extra:
                s = str(item).strip()
                if s and s not in violated:
                    violated.append(s)

    return violated, reasons


def _coerce_decisions_registry(
    decisions_registry: Optional[Union[DecisionsRegistry, Path, str, Dict[str, Any], Sequence[Dict[str, Any]]]],
) -> Optional[DecisionsRegistry]:
    if decisions_registry is None:
        return None
    if isinstance(decisions_registry, DecisionsRegistry):
        return decisions_registry
    if isinstance(decisions_registry, (Path, str)):
        return DecisionsRegistry.from_file(decisions_registry)
    if isinstance(decisions_registry, dict):
        return DecisionsRegistry.from_dict(decisions_registry)
    if isinstance(decisions_registry, (list, tuple)):
        return DecisionsRegistry(decisions_registry)
    raise TypeError(f"Unsupported decisions_registry type: {type(decisions_registry).__name__}")


def _resolve_target_decision_state(
    *,
    r: Dict[str, Any],
    asset_id: str,
    finding_id: str,
    registry: Optional[DecisionsRegistry],
    target_aliases_by_asset: Dict[str, List[str]],
    target_sigs_by_finding: Dict[str, List[str]],
    t_cves: List[str],
    t_in_kev: bool,
    t_epss: Optional[float],
    t_epss_pct: Optional[float],
    t_cvss: Optional[float],
    t_facing: Optional[bool],
    now_dt: datetime,
) -> Tuple[Optional[str], Optional[str], bool, bool, List[str], List[str], Dict[str, Any]]:
    """
    Resolve effective decision status, active flag, and any explicit invalidation details
    from DecisionsRegistry (if supplied) or DuckDB triage_decisions.
    """
    t_assumed_state_db = _json_loads_safe(r["t_assumed_state_json"], {})
    if not isinstance(t_assumed_state_db, dict):
        t_assumed_state_db = {}

    inner_assumed = t_assumed_state_db.get("assumed_state")
    if isinstance(inner_assumed, dict):
        eval_assumed: Dict[str, Any] = dict(inner_assumed)
        if "expires_at" not in eval_assumed and t_assumed_state_db.get("expires_at"):
            eval_assumed["expires_at"] = t_assumed_state_db.get("expires_at")
        for key in ("violated_predicates", "violations"):
            if key not in eval_assumed and t_assumed_state_db.get(key):
                eval_assumed[key] = t_assumed_state_db.get(key)
    else:
        eval_assumed = dict(t_assumed_state_db)

    reg_eval: Optional[DecisionEvaluation] = None
    if registry is not None and registry.entries:
        asset_ctx = {
            "asset_id": asset_id,
            "matched_rule_id": r["t_matched_rule_id"],
            "canonical_key": r["t_canonical_key"],
            "hostname": r["t_hostname"],
            "ip_address": r["t_ip_address"],
            "ip": r["t_ip_address"],
            "target_uri": r["t_target_uri"],
            "image_or_repo": r["t_image_or_repo"],
            "internet_facing": t_facing,
            "aliases": tuple(target_aliases_by_asset.get(asset_id, ())),
        }
        sigs = target_sigs_by_finding.get(finding_id) or []
        finding_facts = {
            "primary_cve": r["t_primary_cve"],
            "cves": t_cves,
            "scanner_sig": sigs[0] if sigs else None,
            "scanner_sigs": sigs,
            "rule_id": sigs[0] if sigs else None,
            "rule_ids": sigs,
            "vuln_id": finding_id,
            "in_kev": t_in_kev,
            "epss_score": t_epss,
            "epss_percentile": t_epss_pct,
            "cvss_score": t_cvss,
            "internet_facing": t_facing,
        }
        cand_eval = registry.evaluate(asset_ctx, finding_facts, now_utc=now_dt)
        if cand_eval.matched:
            reg_eval = cand_eval

    db_decision_status = (r["t_decision_status"] or "").strip() or None
    effective_status: Optional[str] = db_decision_status
    effective_id: Optional[str] = r["t_decision_id"] or (
        str(t_assumed_state_db["decision_id"]).strip()
        if t_assumed_state_db.get("decision_id")
        else None
    )
    explicit_violated: List[str] = []
    explicit_reasons: List[str] = []
    explicit_assumed: Dict[str, Any] = dict(eval_assumed)
    is_explicit_invalidated = False

    if reg_eval is not None and reg_eval.matched:
        effective_id = reg_eval.decision_id
        explicit_assumed = dict(reg_eval.assumed_state)
        if reg_eval.expires_at is not None:
            explicit_assumed.setdefault("expires_at", reg_eval.expires_at)
        base_stat = (reg_eval.decision_status or "deferred").strip().lower()
        if reg_eval.status == "invalidated":
            effective_status = f"{base_stat}_invalidated"
            explicit_violated = list(reg_eval.violated_predicates)
            explicit_reasons = list(reg_eval.reasons)
            is_explicit_invalidated = True
        else:
            effective_status = "mitigated" if base_stat == "mitigated" else f"{base_stat}_valid"
    else:
        db_stat_low = (db_decision_status or "").lower()
        if db_stat_low in _EXPLICIT_INVALIDATED_STATUSES:
            is_explicit_invalidated = True
            v_preds, v_reasons = _evaluate_assumed_state_predicates(
                eval_assumed,
                target_in_kev=t_in_kev,
                target_epss=t_epss,
                target_epss_pct=t_epss_pct,
                target_facing=t_facing,
                target_cvss=t_cvss,
                now_dt=now_dt,
            )
            explicit_violated = v_preds or ["decision_invalidated"]
            explicit_reasons = v_reasons or (
                [str(r["t_rationale_summary"])]
                if r["t_rationale_summary"]
                else [f"Decision status is {db_decision_status}"]
            )
        elif db_stat_low in _VALID_SUPPRESSED_STATUSES and eval_assumed:
            v_preds, v_reasons = _evaluate_assumed_state_predicates(
                eval_assumed,
                target_in_kev=t_in_kev,
                target_epss=t_epss,
                target_epss_pct=t_epss_pct,
                target_facing=t_facing,
                target_cvss=t_cvss,
                now_dt=now_dt,
            )
            if v_preds:
                is_explicit_invalidated = True
                base_stat = db_stat_low.removesuffix("_valid")
                effective_status = f"{base_stat}_invalidated"
                explicit_violated = v_preds
                explicit_reasons = v_reasons

    is_valid_suppressed = (not is_explicit_invalidated) and _is_validly_suppressed_status(effective_status)
    return (
        effective_status,
        effective_id,
        not is_valid_suppressed,
        is_explicit_invalidated,
        explicit_violated,
        explicit_reasons,
        explicit_assumed,
    )


def _detect_threat_intel_escalations(
    *,
    b_in_kev: bool,
    t_in_kev: bool,
    b_epss: Optional[float],
    t_epss: Optional[float],
    b_epss_pct: Optional[float],
    t_epss_pct: Optional[float],
    b_cvss: Optional[float],
    t_cvss: Optional[float],
    b_cvss_prov: str,
    t_cvss_prov: str,
    b_facing: Optional[bool],
    t_facing: Optional[bool],
) -> Tuple[List[str], bool, bool]:
    """Return (escalation_reasons, prov_upgraded, exposure_flipped) for persisting findings."""
    reasons: List[str] = []
    if (not b_in_kev) and t_in_kev:
        reasons.append("in_kev_added")

    if t_epss is not None:
        for thresh in EPSS_SCORE_THRESHOLDS:
            if (b_epss is None or b_epss < thresh) and t_epss >= thresh:
                reasons.append(f"epss_score_crossed_{thresh:.2f}")

    if t_epss_pct is not None:
        for thresh in EPSS_PERCENTILE_THRESHOLDS:
            if (b_epss_pct is None or b_epss_pct < thresh) and t_epss_pct >= thresh:
                reasons.append(f"epss_percentile_crossed_{thresh:.2f}")

    if b_cvss is not None and t_cvss is not None and round(t_cvss - b_cvss, 6) >= CVSS_DELTA_THRESHOLD:
        reasons.append(f"cvss_increased_{b_cvss:.1f}_to_{t_cvss:.1f}")

    prov_upgraded = (
        b_cvss_prov.lower() == "missing"
        and t_cvss_prov.lower() != "missing"
        and t_cvss is not None
    )
    if prov_upgraded:
        reasons.append(f"cvss_provenance_upgraded_Missing_to_{t_cvss_prov}")

    exposure_flipped = (not bool(b_facing)) and (t_facing is True)
    if exposure_flipped:
        reasons.append("internet_facing_flipped_true")

    return reasons, prov_upgraded, exposure_flipped


def _detect_implicit_baseline_drift(
    *,
    r: Dict[str, Any],
    b_in_kev: bool,
    t_in_kev: bool,
    b_epss: Optional[float],
    t_epss: Optional[float],
    b_epss_pct: Optional[float],
    t_epss_pct: Optional[float],
    b_cvss: Optional[float],
    t_cvss: Optional[float],
    b_cvss_prov: str,
    t_cvss_prov: str,
    prov_upgraded: bool,
    exposure_flipped: bool,
    b_verified_exploit: bool,
    t_verified_exploit: bool,
) -> Tuple[List[str], List[str]]:
    """Detect implicit P3/P4 (or Fix on Upgrade / 60-day) -> P1/P2 baseline drift."""
    b_rank = _urgency_rank(
        r["b_priority_tier"],
        r["b_sla_bucket"],
        oal_compat=r["b_oal_compat"],
        ssvc_action=r["b_ssvc_action"],
    )
    t_rank = _urgency_rank(
        r["t_priority_tier"],
        r["t_sla_bucket"],
        oal_compat=r["t_oal_compat"],
        ssvc_action=r["t_ssvc_action"],
    )
    base_was_baseline = _is_baseline_for_implicit_drift(
        r["b_priority_tier"],
        r["b_sla_bucket"],
        oal_compat=r["b_oal_compat"],
        ssvc_action=r["b_ssvc_action"],
    )
    target_is_urgent = _is_p1_or_p2(
        r["t_priority_tier"],
        r["t_sla_bucket"],
        oal_compat=r["t_oal_compat"],
        ssvc_action=r["t_ssvc_action"],
    )
    if not (base_was_baseline and target_is_urgent and t_rank < b_rank):
        return [], []

    drivers: List[str] = []
    texts: List[str] = []
    if (not b_in_kev) and t_in_kev:
        drivers.append("kev_flipped")
        texts.append("in_kev changed False -> True")
    if t_epss is not None and (b_epss is None or t_epss > b_epss):
        drivers.append("epss_increased")
        texts.append(f"epss_score increased {b_epss} -> {t_epss}")
    if t_epss_pct is not None and (b_epss_pct is None or t_epss_pct > b_epss_pct):
        drivers.append("epss_percentile_increased")
        texts.append(f"epss_percentile increased {b_epss_pct} -> {t_epss_pct}")
    if (t_cvss is not None and b_cvss is not None and t_cvss > b_cvss) or prov_upgraded:
        drivers.append("cvss_increased")
        texts.append(f"cvss changed {b_cvss} ({b_cvss_prov}) -> {t_cvss} ({t_cvss_prov})")
    if exposure_flipped:
        drivers.append("exposure_flipped")
        texts.append("internet_facing changed False -> True")
    if (not b_verified_exploit) and t_verified_exploit:
        drivers.append("verified_exploit_added")
        texts.append("verified_exploit changed False -> True")

    if not drivers:
        return [], []

    reason = (
        f"Implicit baseline drift ({r['b_priority_tier'] or r['b_sla_bucket']} -> "
        f"{r['t_priority_tier'] or r['t_sla_bucket']}): " + "; ".join(texts)
    )
    return drivers, [reason]


@dataclass(frozen=True)
class NewlyIntroducedFinding:
    """Finding newly observed in the target run and absent from the base run."""

    asset_id: str
    finding_id: str
    primary_cve: Optional[str]
    title: str
    scoring_track: str
    hostname: Optional[str]
    ip_address: Optional[str]
    inventory_status: Optional[str]
    internet_facing: Optional[bool]
    priority_tier: Optional[str]
    sla_bucket: Optional[str]
    sla_days: Optional[int]
    ssvc_action: Optional[str]
    operational_score: Optional[float]
    raw_risk_score: Optional[float]
    risk_band: Optional[str]
    cvss_score: Optional[float]
    cvss_provenance: Optional[str]
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    in_kev: bool
    decision_status: Optional[str]
    decision_id: Optional[str]
    is_active: bool
    oal_compat: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ThreatIntelEscalatedFinding:
    """Persisting finding whose threat-intel or exposure posture escalated."""

    asset_id: str
    finding_id: str
    primary_cve: Optional[str]
    title: str
    hostname: Optional[str]
    ip_address: Optional[str]
    escalation_reasons: List[str]
    base_in_kev: bool
    target_in_kev: bool
    base_epss_score: Optional[float]
    target_epss_score: Optional[float]
    base_epss_percentile: Optional[float]
    target_epss_percentile: Optional[float]
    base_cvss_score: Optional[float]
    target_cvss_score: Optional[float]
    base_cvss_provenance: Optional[str]
    target_cvss_provenance: Optional[str]
    base_internet_facing: Optional[bool]
    target_internet_facing: Optional[bool]
    base_priority_tier: Optional[str]
    target_priority_tier: Optional[str]
    base_sla_bucket: Optional[str]
    target_sla_bucket: Optional[str]
    base_operational_score: Optional[float]
    target_operational_score: Optional[float]
    decision_status: Optional[str]
    decision_id: Optional[str]
    is_active: bool
    base_oal_compat: Optional[str] = None
    target_oal_compat: Optional[str] = None
    base_ssvc_action: Optional[str] = None
    target_ssvc_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerifiedRemediatedFinding:
    """Finding present in base run and absent in target run, annotated by host presence."""

    asset_id: str
    finding_id: str
    primary_cve: Optional[str]
    title: str
    hostname: Optional[str]
    ip_address: Optional[str]
    asset_still_present: bool
    remediation_status: str
    base_priority_tier: Optional[str]
    base_sla_bucket: Optional[str]
    base_operational_score: Optional[float]
    base_in_kev: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InvalidatedAssumptionFinding:
    """Finding with explicit deferral/acceptance invalidation or implicit baseline drift."""

    asset_id: str
    finding_id: str
    primary_cve: Optional[str]
    title: str
    hostname: Optional[str]
    ip_address: Optional[str]
    invalidation_kind: str
    decision_id: Optional[str]
    decision_status: Optional[str]
    violated_predicates: List[str]
    reasons: List[str]
    assumed_state: Dict[str, Any]
    target_state: Dict[str, Any]
    base_priority_tier: Optional[str]
    target_priority_tier: Optional[str]
    base_sla_bucket: Optional[str]
    target_sla_bucket: Optional[str]
    base_oal_compat: Optional[str] = None
    target_oal_compat: Optional[str] = None
    base_ssvc_action: Optional[str] = None
    target_ssvc_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ShadowAssetDeltaItem:
    """Asset-level shadow inventory transition between base and target runs."""

    asset_id: str
    canonical_key: Optional[str]
    hostname: Optional[str]
    ip_address: Optional[str]
    target_uri: Optional[str]
    image_or_repo: Optional[str]
    delta_kind: str
    base_inventory_status: Optional[str]
    target_inventory_status: Optional[str]
    matched_rule_id: Optional[str]
    internet_facing: Optional[bool]
    finding_count: int
    kev_count: int
    max_operational_score: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ShadowAssetsDelta:
    """Grouped shadow asset changes across runs."""

    newly_observed: List[ShadowAssetDeltaItem] = field(default_factory=list)
    resolved: List[ShadowAssetDeltaItem] = field(default_factory=list)
    became_shadow: List[ShadowAssetDeltaItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "newly_observed": [x.to_dict() for x in self.newly_observed],
            "resolved": [x.to_dict() for x in self.resolved],
            "became_shadow": [x.to_dict() for x in self.became_shadow],
        }


@dataclass(frozen=True)
class RunMetadataDelta:
    """Config, asset/decision registry, and threat-intel metadata changes between runs."""

    base_run_id: str
    target_run_id: str
    base_created_at_utc: Optional[str]
    target_created_at_utc: Optional[str]
    vpp_version_changed: bool
    profile_changed: bool
    config_changed: bool
    assets_changed: bool
    decisions_changed: bool
    manifest_changed: bool
    intel_changed: bool
    field_changes: Dict[str, Dict[str, Any]]
    intel_changes: Dict[str, Dict[str, Any]]
    base_intel_metadata: Dict[str, Any]
    target_intel_metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DiffSummary:
    """Aggregate summary counts for a DiffReport."""

    base_run_id: str
    target_run_id: str
    base_total_findings: int
    target_total_findings: int
    persisting_findings: int
    newly_introduced_all: int
    newly_introduced_high_risk: int
    threat_intel_escalated: int
    verified_remediated: int
    verified_remediated_confirmed: int
    verified_remediated_asset_missing: int
    invalidated_assumptions: int
    shadow_assets_new: int
    shadow_assets_resolved: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DiffReport:
    """Complete structured cross-run diff report."""

    diff_id: str
    base_run_id: str
    target_run_id: str
    generated_at_utc: str
    newly_introduced_high_risk: List[NewlyIntroducedFinding]
    newly_introduced_all: int
    newly_introduced_active_kev_count: int
    threat_intel_escalated: List[ThreatIntelEscalatedFinding]
    verified_remediated: List[VerifiedRemediatedFinding]
    invalidated_assumptions: List[InvalidatedAssumptionFinding]
    shadow_assets_delta: ShadowAssetsDelta
    metadata_delta: RunMetadataDelta
    summary: DiffSummary
    persisted_events_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "diff_id": self.diff_id,
            "base_run_id": self.base_run_id,
            "target_run_id": self.target_run_id,
            "generated_at_utc": self.generated_at_utc,
            "summary": self.summary.to_dict(),
            "metadata_delta": self.metadata_delta.to_dict(),
            "newly_introduced_all": self.newly_introduced_all,
            "newly_introduced_active_kev_count": self.newly_introduced_active_kev_count,
            "newly_introduced_high_risk": [x.to_dict() for x in self.newly_introduced_high_risk],
            "threat_intel_escalated": [x.to_dict() for x in self.threat_intel_escalated],
            "verified_remediated": [x.to_dict() for x in self.verified_remediated],
            "invalidated_assumptions": [x.to_dict() for x in self.invalidated_assumptions],
            "shadow_assets_delta": self.shadow_assets_delta.to_dict(),
            "persisted_events_count": self.persisted_events_count,
        }


def resolve_run_ids(
    db: Any,
    base_run_id: Optional[str] = None,
    target_run_id: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Resolve `(base_run_id, target_run_id)`.

    If either `base_run_id` or `target_run_id` is omitted, resolves against runs
    ordered by `created_at_utc DESC`, failing with `ValueError` if fewer than 2
    runs exist or if an explicitly named run is missing.
    """
    conn = _get_conn(db)
    rows = conn.execute(
        """
        SELECT run_id, created_at_utc, baseline_run_id
        FROM runs
        ORDER BY created_at_utc DESC, run_id DESC
        """
    ).fetchall()
    run_map = {str(r[0]): (idx, r[1], r[2]) for idx, r in enumerate(rows)}

    if base_run_id is not None and base_run_id not in run_map:
        raise ValueError(f"Base run_id '{base_run_id}' does not exist in runs.")
    if target_run_id is not None and target_run_id not in run_map:
        raise ValueError(f"Target run_id '{target_run_id}' does not exist in runs.")

    if base_run_id is not None and target_run_id is not None:
        return str(base_run_id), str(target_run_id)

    if len(rows) < 2:
        raise ValueError(
            f"At least 2 runs are required to resolve default diff runs (found {len(rows)})."
        )

    if base_run_id is None and target_run_id is None:
        return str(rows[1][0]), str(rows[0][0])

    if base_run_id is None and target_run_id is not None:
        target_idx, _, explicit_baseline = run_map[str(target_run_id)]
        if explicit_baseline and explicit_baseline in run_map and explicit_baseline != target_run_id:
            return str(explicit_baseline), str(target_run_id)
        if target_idx + 1 < len(rows):
            return str(rows[target_idx + 1][0]), str(target_run_id)
        return str(rows[0][0]), str(target_run_id)

    assert base_run_id is not None
    for r in rows:
        cand = str(r[0])
        if cand != base_run_id:
            return str(base_run_id), cand
    raise ValueError("Unable to resolve a distinct target_run_id.")


def resolve_re_enrich_run_ids(
    db: Any,
    base_run_id: Optional[str] = None,
    target_run_id: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Resolve `(base_run_id, target_source_run_id)` for `--re-enrich` across both
    1-run and multi-run DuckDB workspaces without mutating historical runs.
    """
    conn = _get_conn(db)
    rows = conn.execute(
        """
        SELECT run_id, created_at_utc, baseline_run_id
        FROM runs
        ORDER BY created_at_utc DESC, run_id DESC
        """
    ).fetchall()
    if not rows:
        raise ValueError("No runs recorded in DuckDB workspace.")

    run_ids = {str(r[0]) for r in rows}
    if base_run_id is not None and str(base_run_id) not in run_ids:
        raise ValueError(f"Base run_id '{base_run_id}' does not exist in runs.")
    if target_run_id is not None and str(target_run_id) not in run_ids:
        raise ValueError(f"Target run_id '{target_run_id}' does not exist in runs.")

    if base_run_id is not None and target_run_id is not None:
        return str(base_run_id), str(target_run_id)

    if len(rows) == 1:
        only_id = str(rows[0][0])
        return only_id, only_id

    return resolve_run_ids(conn, base_run_id=base_run_id, target_run_id=target_run_id)


def clone_run_for_re_enrichment(
    db: Any,
    source_run_id: str,
    new_run_id: str,
    *,
    baseline_run_id: Optional[str] = None,
    decisions_sha256: Optional[str] = None,
    profile: Optional[str] = None,
) -> str:
    """
    Clone a stored run's metadata, assets, aliases, findings, evidence, and CVEs
    into an ephemeral target run ID so enrichment and scoring/triage passes can
    be re-evaluated cleanly without mutating the source run.
    """
    conn = _get_conn(db)
    row = conn.execute(
        """
        SELECT vpp_version, profile, config_sha256, assets_sha256,
               decisions_sha256, input_files_json
        FROM runs
        WHERE run_id = ?
        """,
        [str(source_run_id)],
    ).fetchone()
    if row is None:
        raise ValueError(f"Target run_id '{source_run_id}' does not exist in runs.")

    vpp_version, stored_profile, cfg_sha, assets_sha, stored_dec_sha, input_files_json = row
    eff_profile = profile or stored_profile or "default"
    eff_dec_sha = decisions_sha256 or stored_dec_sha

    conn.execute("BEGIN TRANSACTION")
    try:
        conn.execute(
            """
            INSERT INTO runs (
                run_id, created_at_utc, vpp_version, profile,
                config_sha256, assets_sha256, decisions_sha256,
                intel_metadata_json, manifest_digest, input_files_json, baseline_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
            """,
            [
                str(new_run_id),
                _utc_now_z(),
                vpp_version,
                eff_profile,
                cfg_sha,
                assets_sha,
                eff_dec_sha,
                input_files_json,
                baseline_run_id,
            ],
        )
        conn.execute(
            """
            INSERT INTO assets (
                run_id, asset_id, canonical_key, hostname, ip_address, target_uri,
                image_or_repo, os, declared_criticality, derived_criticality,
                internet_facing, owner, env_tags_json, inventory_status,
                matched_rule_id, open_ports_json
            )
            SELECT
                ?, asset_id, canonical_key, hostname, ip_address, target_uri,
                image_or_repo, os, declared_criticality, derived_criticality,
                internet_facing, owner, env_tags_json, inventory_status,
                matched_rule_id, open_ports_json
            FROM assets
            WHERE run_id = ?
            """,
            [str(new_run_id), str(source_run_id)],
        )
        conn.execute(
            """
            INSERT INTO asset_aliases (run_id, asset_id, alias_type, alias_value)
            SELECT ?, asset_id, alias_type, alias_value
            FROM asset_aliases
            WHERE run_id = ?
            """,
            [str(new_run_id), str(source_run_id)],
        )
        conn.execute(
            """
            INSERT INTO findings (
                run_id, finding_id, asset_id, scoring_track, primary_cve, cves_json,
                cwes_json, ghsa_ids_json, title, description, solution, plugin_output,
                affected_port, protocol, service_name, location_uri, line_number,
                package_purl, scanner_severity, scanner_cvss_score, scanner_cvss_vector,
                detection_mode, signal_reliability, ingestion_confidence, fidelity_tier,
                source_format, references_json, tags_json, exploit_evidence,
                is_deduplicated, source_count
            )
            SELECT
                ?, finding_id, asset_id, scoring_track, primary_cve, cves_json,
                cwes_json, ghsa_ids_json, title, description, solution, plugin_output,
                affected_port, protocol, service_name, location_uri, line_number,
                package_purl, scanner_severity, scanner_cvss_score, scanner_cvss_vector,
                detection_mode, signal_reliability, ingestion_confidence, fidelity_tier,
                source_format, references_json, tags_json, exploit_evidence,
                is_deduplicated, source_count
            FROM findings
            WHERE run_id = ?
            """,
            [str(new_run_id), str(source_run_id)],
        )
        conn.execute(
            """
            INSERT INTO finding_evidence (
                run_id, finding_id, evidence_idx, source_format, scanner_sig,
                raw_severity, raw_cvss, raw_location, evidence_excerpt
            )
            SELECT
                ?, finding_id, evidence_idx, source_format, scanner_sig,
                raw_severity, raw_cvss, raw_location, evidence_excerpt
            FROM finding_evidence
            WHERE run_id = ?
            """,
            [str(new_run_id), str(source_run_id)],
        )
        conn.execute(
            """
            INSERT INTO finding_cves (run_id, finding_id, cve_id)
            SELECT ?, finding_id, cve_id
            FROM finding_cves
            WHERE run_id = ?
            """,
            [str(new_run_id), str(source_run_id)],
        )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    return str(new_run_id)


def compare_run_metadata(db: Any, base_run_id: str, target_run_id: str) -> RunMetadataDelta:
    """Compare config/assets/decisions hashes and threat-intel metadata between two runs."""
    conn = _get_conn(db)
    base_id = str(base_run_id)
    target_id = str(target_run_id)

    def _fetch_run(rid: str) -> Dict[str, Any]:
        cur = conn.execute(
            """
            SELECT
                run_id, created_at_utc, vpp_version, profile,
                config_sha256, assets_sha256, decisions_sha256,
                intel_metadata_json, manifest_digest, input_files_json
            FROM runs
            WHERE run_id = ?
            """,
            [rid],
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"Run '{rid}' does not exist in runs.")
        cols = [d[0] for d in cur.description]
        rec = dict(zip(cols, row))
        rec["intel_metadata"] = _json_loads_safe(rec.pop("intel_metadata_json", None), {})
        rec["input_files"] = _json_loads_safe(rec.pop("input_files_json", None), [])

        if not isinstance(rec["intel_metadata"], dict):
            rec["intel_metadata"] = {}

        if "epss_model_version" not in rec["intel_metadata"] or "epss_score_date" not in rec["intel_metadata"]:
            snap_row = conn.execute(
                """
                SELECT MAX(epss_model_version), MAX(epss_date)
                FROM enrichment_snapshots
                WHERE run_id = ?
                """,
                [rid],
            ).fetchone()
            if snap_row is not None:
                if snap_row[0] and "epss_model_version" not in rec["intel_metadata"]:
                    rec["intel_metadata"]["epss_model_version"] = snap_row[0]
                if snap_row[1] and "epss_score_date" not in rec["intel_metadata"]:
                    rec["intel_metadata"]["epss_score_date"] = snap_row[1]
        return rec

    base_rec = _fetch_run(base_id)
    target_rec = _fetch_run(target_id)

    tracked_fields = (
        "vpp_version",
        "profile",
        "config_sha256",
        "assets_sha256",
        "decisions_sha256",
        "manifest_digest",
        "input_files",
    )
    field_changes: Dict[str, Dict[str, Any]] = {}
    for fname in tracked_fields:
        bval = base_rec.get(fname)
        tval = target_rec.get(fname)
        if bval != tval:
            field_changes[fname] = {"base": bval, "target": tval}

    base_intel = dict(base_rec["intel_metadata"])
    target_intel = dict(target_rec["intel_metadata"])
    intel_changes: Dict[str, Dict[str, Any]] = {}

    all_intel_keys = sorted(
        (set(base_intel.keys()) | set(target_intel.keys()) | set(_CORE_INTEL_METADATA_KEYS))
        - {"updated_at_utc", "populated_cves"}
    )
    for key in all_intel_keys:
        bval = base_intel.get(key)
        tval = target_intel.get(key)
        if bval != tval and (bval is not None or tval is not None):
            intel_changes[key] = {"base": bval, "target": tval}

    return RunMetadataDelta(
        base_run_id=base_id,
        target_run_id=target_id,
        base_created_at_utc=base_rec.get("created_at_utc"),
        target_created_at_utc=target_rec.get("created_at_utc"),
        vpp_version_changed="vpp_version" in field_changes,
        profile_changed="profile" in field_changes,
        config_changed="config_sha256" in field_changes,
        assets_changed="assets_sha256" in field_changes,
        decisions_changed="decisions_sha256" in field_changes,
        manifest_changed="manifest_digest" in field_changes,
        intel_changed=len(intel_changes) > 0,
        field_changes=field_changes,
        intel_changes=intel_changes,
        base_intel_metadata=base_intel,
        target_intel_metadata=target_intel,
    )


def _escalated_to_p1(item: Union[ThreatIntelEscalatedFinding, InvalidatedAssumptionFinding]) -> bool:
    return _is_p1(
        item.target_priority_tier,
        item.target_sla_bucket,
        oal_compat=item.target_oal_compat,
        ssvc_action=item.target_ssvc_action,
    ) and not _is_p1(
        item.base_priority_tier,
        item.base_sla_bucket,
        oal_compat=item.base_oal_compat,
        ssvc_action=item.base_ssvc_action,
    )


def _escalated_into_p2(item: Union[ThreatIntelEscalatedFinding, InvalidatedAssumptionFinding]) -> bool:
    if not _is_p1_or_p2(
        item.target_priority_tier,
        item.target_sla_bucket,
        oal_compat=item.target_oal_compat,
        ssvc_action=item.target_ssvc_action,
    ):
        return False
    t_rank = _urgency_rank(
        item.target_priority_tier,
        item.target_sla_bucket,
        oal_compat=item.target_oal_compat,
        ssvc_action=item.target_ssvc_action,
    )
    b_rank = _urgency_rank(
        item.base_priority_tier,
        item.base_sla_bucket,
        oal_compat=item.base_oal_compat,
        ssvc_action=item.base_ssvc_action,
    )
    return t_rank < b_rank


def evaluate_fail_gate(report: DiffReport, fail_on: Optional[str]) -> int:
    """
    Evaluate CI exit gate against a DiffReport.

    Returns 0 on pass, 2 on policy breach, and raises ValueError on unknown fail_on mode.
    """
    if fail_on is None:
        return 0
    mode = str(fail_on).strip().lower()
    if mode not in VALID_FAIL_ON_VALUES:
        allowed = ", ".join(sorted(VALID_FAIL_ON_VALUES))
        raise ValueError(f"Unknown fail_on mode '{fail_on}'. Expected one of: {allowed}")

    if mode == "none":
        return 0

    if mode == "stale-assumption":
        return 2 if len(report.invalidated_assumptions) > 0 else 0

    if mode == "p1":
        if any(
            item.is_active
            and _is_p1(
                item.priority_tier,
                item.sla_bucket,
                oal_compat=item.oal_compat,
                ssvc_action=item.ssvc_action,
            )
            for item in report.newly_introduced_high_risk
        ):
            return 2
        if any(item.is_active and _escalated_to_p1(item) for item in report.threat_intel_escalated):
            return 2
        if any(_escalated_to_p1(item) for item in report.invalidated_assumptions):
            return 2
        return 0

    if mode == "p2":
        if any(
            item.is_active
            and _is_p1_or_p2(
                item.priority_tier,
                item.sla_bucket,
                oal_compat=item.oal_compat,
                ssvc_action=item.ssvc_action,
            )
            for item in report.newly_introduced_high_risk
        ):
            return 2
        if any(item.is_active and _escalated_into_p2(item) for item in report.threat_intel_escalated):
            return 2
        if any(_escalated_into_p2(item) for item in report.invalidated_assumptions):
            return 2
        return 0

    if mode == "kev":
        if report.newly_introduced_active_kev_count > 0:
            return 2
        if any(item.is_active and item.in_kev for item in report.newly_introduced_high_risk):
            return 2
        if any(
            item.is_active and (not item.base_in_kev) and item.target_in_kev
            for item in report.threat_intel_escalated
        ):
            return 2
        return 0

    raise ValueError(f"Unhandled fail_on mode: {fail_on}")


class DiffEngine:
    """
    Cross-run DuckDB diff engine computing the 4 Playbook delta categories +
    shadow asset deltas, assumption invalidations, run metadata deltas, and CI gates.
    """

    def __init__(
        self,
        db: Any,
        *,
        decisions_registry: Optional[
            Union[DecisionsRegistry, Path, str, Dict[str, Any], Sequence[Dict[str, Any]]]
        ] = None,
        now_utc: Optional[Union[datetime, date, str]] = None,
    ) -> None:
        self.db = db
        self.conn = _get_conn(db)
        self.decisions_registry = _coerce_decisions_registry(decisions_registry)
        self.now_utc = now_utc

    def resolve_run_ids(
        self,
        base_run_id: Optional[str] = None,
        target_run_id: Optional[str] = None,
    ) -> Tuple[str, str]:
        return resolve_run_ids(self.conn, base_run_id=base_run_id, target_run_id=target_run_id)

    def compare_run_metadata(self, base_run_id: str, target_run_id: str) -> RunMetadataDelta:
        return compare_run_metadata(self.conn, base_run_id, target_run_id)

    @staticmethod
    def evaluate_fail_gate(report: DiffReport, fail_on: Optional[str]) -> int:
        return evaluate_fail_gate(report, fail_on)

    def _load_target_decision_lookups(
        self,
        target_run_id: str,
        registry: Optional[DecisionsRegistry],
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        aliases_by_asset: Dict[str, List[str]] = {}
        sigs_by_finding: Dict[str, List[str]] = {}
        if registry is None or not registry.entries:
            return aliases_by_asset, sigs_by_finding
        for aid, aval in self.conn.execute(
            "SELECT asset_id, alias_value FROM asset_aliases WHERE run_id = ? ORDER BY asset_id, alias_value",
            [target_run_id],
        ).fetchall():
            if aid and aval:
                aliases_by_asset.setdefault(str(aid), []).append(str(aval))
        for fid, sig in self.conn.execute(
            """
            SELECT DISTINCT finding_id, scanner_sig
            FROM finding_evidence
            WHERE run_id = ? AND scanner_sig IS NOT NULL AND scanner_sig <> ''
            ORDER BY finding_id, scanner_sig
            """,
            [target_run_id],
        ).fetchall():
            if fid and sig:
                sigs_by_finding.setdefault(str(fid), []).append(str(sig))
        return aliases_by_asset, sigs_by_finding

    def _query_joined_findings(self, base_run_id: str, target_run_id: str) -> List[Dict[str, Any]]:
        query = (
            f"WITH base_rows AS ({_FINDING_RUN_CTE_SQL}),\n"
            f"target_rows AS ({_FINDING_RUN_CTE_SQL})\n"
            """
            SELECT
                COALESCE(t.asset_id, b.asset_id) AS asset_id,
                COALESCE(t.finding_id, b.finding_id) AS finding_id,
                (b.finding_id IS NOT NULL) AS in_base,
                (t.finding_id IS NOT NULL) AS in_target,
                (ta.asset_id IS NOT NULL) AS target_asset_still_present,
                b.scoring_track AS b_scoring_track,
                b.primary_cve AS b_primary_cve,
                b.cves_json AS b_cves_json,
                b.title AS b_title,
                b.scanner_cvss_score AS b_scanner_cvss_score,
                b.scanner_cvss_vector AS b_scanner_cvss_vector,
                b.canonical_key AS b_canonical_key,
                b.hostname AS b_hostname,
                b.ip_address AS b_ip_address,
                b.target_uri AS b_target_uri,
                b.image_or_repo AS b_image_or_repo,
                b.internet_facing AS b_internet_facing,
                b.inventory_status AS b_inventory_status,
                b.matched_rule_id AS b_matched_rule_id,
                b.cvss_score AS b_cvss_score,
                b.cvss_provenance AS b_cvss_provenance,
                b.epss_score AS b_epss_score,
                b.epss_percentile AS b_epss_percentile,
                b.in_kev AS b_in_kev,
                b.verified_exploit AS b_verified_exploit,
                b.raw_risk_score AS b_raw_risk_score,
                b.operational_score AS b_operational_score,
                b.risk_band AS b_risk_band,
                b.score_trace_json AS b_score_trace_json,
                b.priority_tier AS b_priority_tier,
                b.oal_compat AS b_oal_compat,
                b.ssvc_action AS b_ssvc_action,
                b.sla_bucket AS b_sla_bucket,
                b.sla_days AS b_sla_days,
                b.decision_status AS b_decision_status,
                b.decision_id AS b_decision_id,
                t.scoring_track AS t_scoring_track,
                t.primary_cve AS t_primary_cve,
                t.cves_json AS t_cves_json,
                t.title AS t_title,
                t.scanner_cvss_score AS t_scanner_cvss_score,
                t.scanner_cvss_vector AS t_scanner_cvss_vector,
                t.canonical_key AS t_canonical_key,
                t.hostname AS t_hostname,
                t.ip_address AS t_ip_address,
                t.target_uri AS t_target_uri,
                t.image_or_repo AS t_image_or_repo,
                t.internet_facing AS t_internet_facing,
                t.inventory_status AS t_inventory_status,
                t.matched_rule_id AS t_matched_rule_id,
                t.cvss_score AS t_cvss_score,
                t.cvss_provenance AS t_cvss_provenance,
                t.epss_score AS t_epss_score,
                t.epss_percentile AS t_epss_percentile,
                t.in_kev AS t_in_kev,
                t.verified_exploit AS t_verified_exploit,
                t.raw_risk_score AS t_raw_risk_score,
                t.operational_score AS t_operational_score,
                t.risk_band AS t_risk_band,
                t.score_trace_json AS t_score_trace_json,
                t.priority_tier AS t_priority_tier,
                t.oal_compat AS t_oal_compat,
                t.ssvc_action AS t_ssvc_action,
                t.sla_bucket AS t_sla_bucket,
                t.sla_days AS t_sla_days,
                t.decision_status AS t_decision_status,
                t.decision_id AS t_decision_id,
                t.assumed_state_json AS t_assumed_state_json,
                t.rationale_summary AS t_rationale_summary
            FROM base_rows b
            FULL OUTER JOIN target_rows t
                ON b.asset_id = t.asset_id AND b.finding_id = t.finding_id
            LEFT JOIN assets ta
                ON ta.run_id = ? AND ta.asset_id = COALESCE(t.asset_id, b.asset_id)
            ORDER BY asset_id ASC, finding_id ASC
            """
        )
        cursor = self.conn.execute(query, [base_run_id, base_run_id, target_run_id, target_run_id, target_run_id])
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, raw)) for raw in cursor.fetchall()]

    def compare(
        self,
        base_run_id: Optional[str] = None,
        target_run_id: Optional[str] = None,
        *,
        persist: bool = False,
        decisions_registry: Optional[
            Union[DecisionsRegistry, Path, str, Dict[str, Any], Sequence[Dict[str, Any]]]
        ] = None,
        now_utc: Optional[Union[datetime, date, str]] = None,
    ) -> DiffReport:
        """
        Execute cross-run comparison across all 4 Playbook delta categories +
        shadow assets delta, optionally persisting events into `diff_events`.
        """
        resolved_base, resolved_target = self.resolve_run_ids(base_run_id, target_run_id)
        metadata_delta = compare_run_metadata(self.conn, resolved_base, resolved_target)
        registry = (
            _coerce_decisions_registry(decisions_registry)
            if decisions_registry is not None
            else self.decisions_registry
        )
        effective_now = now_utc if now_utc is not None else self.now_utc
        now_dt = (
            _parse_iso_datetime(effective_now, end_of_day_for_date=False)
            if effective_now is not None
            else datetime.now(timezone.utc)
        )

        target_aliases_by_asset, target_sigs_by_finding = self._load_target_decision_lookups(
            resolved_target, registry
        )
        joined_rows = self._query_joined_findings(resolved_base, resolved_target)

        newly_introduced_high_risk: List[NewlyIntroducedFinding] = []
        newly_introduced_all = 0
        newly_introduced_active_kev_count = 0
        threat_intel_escalated: List[ThreatIntelEscalatedFinding] = []
        verified_remediated: List[VerifiedRemediatedFinding] = []
        invalidated_assumptions: List[InvalidatedAssumptionFinding] = []

        base_total_findings = 0
        target_total_findings = 0
        persisting_findings = 0

        for r in joined_rows:
            asset_id = str(r["asset_id"])
            finding_id = str(r["finding_id"])
            in_base = bool(r["in_base"])
            in_target = bool(r["in_target"])

            if in_base:
                base_total_findings += 1
            if in_target:
                target_total_findings += 1

            # Category 3: verified_remediated (in base, absent in target)
            if in_base and not in_target:
                b_trace_rem = _json_loads_safe(r["b_score_trace_json"], {})
                if not isinstance(b_trace_rem, dict):
                    b_trace_rem = {}
                still_present = bool(r["target_asset_still_present"])
                verified_remediated.append(
                    VerifiedRemediatedFinding(
                        asset_id=asset_id,
                        finding_id=finding_id,
                        primary_cve=r["b_primary_cve"],
                        title=str(r["b_title"] or ""),
                        hostname=r["b_hostname"],
                        ip_address=r["b_ip_address"],
                        asset_still_present=still_present,
                        remediation_status="verified_patched" if still_present else "asset_missing",
                        base_priority_tier=r["b_priority_tier"],
                        base_sla_bucket=r["b_sla_bucket"],
                        base_operational_score=_safe_float(r["b_operational_score"]),
                        base_in_kev=bool(r["b_in_kev"]) or bool(b_trace_rem.get("in_kev")),
                    )
                )
                continue

            t_score_trace = _json_loads_safe(r["t_score_trace_json"], {})
            if not isinstance(t_score_trace, dict):
                t_score_trace = {}
            t_cves = _json_loads_safe(r["t_cves_json"], [])
            if not isinstance(t_cves, list):
                t_cves = []
            if r["t_primary_cve"] and r["t_primary_cve"] not in t_cves:
                t_cves = [r["t_primary_cve"], *t_cves]

            t_cvss = _effective_cvss(
                r["t_cvss_score"],
                r["t_scanner_cvss_score"],
                t_score_trace,
                snapshot_prov=r["t_cvss_provenance"],
                scanner_vec=r["t_scanner_cvss_vector"],
            )
            t_cvss_prov = _effective_cvss_provenance(
                r["t_cvss_provenance"],
                r["t_cvss_score"],
                r["t_scanner_cvss_score"],
                t_score_trace,
                scanner_vec=r["t_scanner_cvss_vector"],
            )
            t_epss = _safe_float(r["t_epss_score"])
            t_epss_pct = _safe_float(r["t_epss_percentile"])
            t_in_kev = bool(r["t_in_kev"]) or bool(t_score_trace.get("in_kev"))
            t_facing: Optional[bool] = (
                bool(r["t_internet_facing"]) if r["t_internet_facing"] is not None else None
            )

            (
                effective_decision_status,
                effective_decision_id,
                is_active,
                is_explicit_invalidated,
                explicit_violated,
                explicit_reasons,
                explicit_assumed,
            ) = _resolve_target_decision_state(
                r=r,
                asset_id=asset_id,
                finding_id=finding_id,
                registry=registry,
                target_aliases_by_asset=target_aliases_by_asset,
                target_sigs_by_finding=target_sigs_by_finding,
                t_cves=t_cves,
                t_in_kev=t_in_kev,
                t_epss=t_epss,
                t_epss_pct=t_epss_pct,
                t_cvss=t_cvss,
                t_facing=t_facing,
                now_dt=now_dt,
            )

            # Category 1: newly_introduced_high_risk (absent in base)
            if not in_base and in_target:
                newly_introduced_all += 1
                if is_active and t_in_kev:
                    newly_introduced_active_kev_count += 1

                if _is_p1_or_p2(
                    r["t_priority_tier"],
                    r["t_sla_bucket"],
                    oal_compat=r["t_oal_compat"],
                    ssvc_action=r["t_ssvc_action"],
                ):
                    newly_introduced_high_risk.append(
                        NewlyIntroducedFinding(
                            asset_id=asset_id,
                            finding_id=finding_id,
                            primary_cve=r["t_primary_cve"],
                            title=str(r["t_title"] or ""),
                            scoring_track=str(r["t_scoring_track"] or ""),
                            hostname=r["t_hostname"],
                            ip_address=r["t_ip_address"],
                            inventory_status=r["t_inventory_status"],
                            internet_facing=t_facing,
                            priority_tier=r["t_priority_tier"],
                            sla_bucket=r["t_sla_bucket"],
                            sla_days=_safe_int(r["t_sla_days"]),
                            ssvc_action=r["t_ssvc_action"],
                            operational_score=_safe_float(r["t_operational_score"]),
                            raw_risk_score=_safe_float(r["t_raw_risk_score"]),
                            risk_band=r["t_risk_band"],
                            cvss_score=t_cvss,
                            cvss_provenance=t_cvss_prov,
                            epss_score=t_epss,
                            epss_percentile=t_epss_pct,
                            in_kev=t_in_kev,
                            decision_status=effective_decision_status,
                            decision_id=effective_decision_id,
                            is_active=is_active,
                            oal_compat=r["t_oal_compat"],
                        )
                    )

                if is_explicit_invalidated:
                    invalidated_assumptions.append(
                        InvalidatedAssumptionFinding(
                            asset_id=asset_id,
                            finding_id=finding_id,
                            primary_cve=r["t_primary_cve"],
                            title=str(r["t_title"] or ""),
                            hostname=r["t_hostname"],
                            ip_address=r["t_ip_address"],
                            invalidation_kind="explicit",
                            decision_id=effective_decision_id,
                            decision_status=effective_decision_status,
                            violated_predicates=explicit_violated,
                            reasons=explicit_reasons,
                            assumed_state=explicit_assumed,
                            target_state={
                                "in_kev": t_in_kev,
                                "epss_score": t_epss,
                                "epss_percentile": t_epss_pct,
                                "cvss_score": t_cvss,
                                "cvss_provenance": t_cvss_prov,
                                "internet_facing": t_facing,
                            },
                            base_priority_tier=None,
                            target_priority_tier=r["t_priority_tier"],
                            base_sla_bucket=None,
                            target_sla_bucket=r["t_sla_bucket"],
                            base_oal_compat=None,
                            target_oal_compat=r["t_oal_compat"],
                            base_ssvc_action=None,
                            target_ssvc_action=r["t_ssvc_action"],
                        )
                    )
                continue

            # Persisting findings (in_base and in_target)
            persisting_findings += 1
            b_score_trace = _json_loads_safe(r["b_score_trace_json"], {})
            if not isinstance(b_score_trace, dict):
                b_score_trace = {}

            b_cvss = _effective_cvss(
                r["b_cvss_score"],
                r["b_scanner_cvss_score"],
                b_score_trace,
                snapshot_prov=r["b_cvss_provenance"],
                scanner_vec=r["b_scanner_cvss_vector"],
            )
            b_cvss_prov = _effective_cvss_provenance(
                r["b_cvss_provenance"],
                r["b_cvss_score"],
                r["b_scanner_cvss_score"],
                b_score_trace,
                scanner_vec=r["b_scanner_cvss_vector"],
            )
            b_epss = _safe_float(r["b_epss_score"])
            b_epss_pct = _safe_float(r["b_epss_percentile"])
            b_in_kev = bool(r["b_in_kev"]) or bool(b_score_trace.get("in_kev"))
            b_facing: Optional[bool] = (
                bool(r["b_internet_facing"]) if r["b_internet_facing"] is not None else None
            )

            # Category 2: threat_intel_escalated
            escalation_reasons, prov_upgraded, exposure_flipped = _detect_threat_intel_escalations(
                b_in_kev=b_in_kev,
                t_in_kev=t_in_kev,
                b_epss=b_epss,
                t_epss=t_epss,
                b_epss_pct=b_epss_pct,
                t_epss_pct=t_epss_pct,
                b_cvss=b_cvss,
                t_cvss=t_cvss,
                b_cvss_prov=b_cvss_prov,
                t_cvss_prov=t_cvss_prov,
                b_facing=b_facing,
                t_facing=t_facing,
            )
            if escalation_reasons:
                threat_intel_escalated.append(
                    ThreatIntelEscalatedFinding(
                        asset_id=asset_id,
                        finding_id=finding_id,
                        primary_cve=r["t_primary_cve"] or r["b_primary_cve"],
                        title=str(r["t_title"] or r["b_title"] or ""),
                        hostname=r["t_hostname"] or r["b_hostname"],
                        ip_address=r["t_ip_address"] or r["b_ip_address"],
                        escalation_reasons=escalation_reasons,
                        base_in_kev=b_in_kev,
                        target_in_kev=t_in_kev,
                        base_epss_score=b_epss,
                        target_epss_score=t_epss,
                        base_epss_percentile=b_epss_pct,
                        target_epss_percentile=t_epss_pct,
                        base_cvss_score=b_cvss,
                        target_cvss_score=t_cvss,
                        base_cvss_provenance=b_cvss_prov,
                        target_cvss_provenance=t_cvss_prov,
                        base_internet_facing=b_facing,
                        target_internet_facing=t_facing,
                        base_priority_tier=r["b_priority_tier"],
                        target_priority_tier=r["t_priority_tier"],
                        base_sla_bucket=r["b_sla_bucket"],
                        target_sla_bucket=r["t_sla_bucket"],
                        base_operational_score=_safe_float(r["b_operational_score"]),
                        target_operational_score=_safe_float(r["t_operational_score"]),
                        decision_status=effective_decision_status,
                        decision_id=effective_decision_id,
                        is_active=is_active,
                        base_oal_compat=r["b_oal_compat"],
                        target_oal_compat=r["t_oal_compat"],
                        base_ssvc_action=r["b_ssvc_action"],
                        target_ssvc_action=r["t_ssvc_action"],
                    )
                )

            # Category 4: invalidated_assumptions (explicit OR implicit baseline drift)
            implicit_violated: List[str] = []
            implicit_reasons: List[str] = []
            if is_active:
                implicit_violated, implicit_reasons = _detect_implicit_baseline_drift(
                    r=r,
                    b_in_kev=b_in_kev,
                    t_in_kev=t_in_kev,
                    b_epss=b_epss,
                    t_epss=t_epss,
                    b_epss_pct=b_epss_pct,
                    t_epss_pct=t_epss_pct,
                    b_cvss=b_cvss,
                    t_cvss=t_cvss,
                    b_cvss_prov=b_cvss_prov,
                    t_cvss_prov=t_cvss_prov,
                    prov_upgraded=prov_upgraded,
                    exposure_flipped=exposure_flipped,
                    b_verified_exploit=bool(r["b_verified_exploit"]) or bool(b_score_trace.get("verified_exploit")),
                    t_verified_exploit=bool(r["t_verified_exploit"]) or bool(t_score_trace.get("verified_exploit")),
                )

            is_implicit_drift = len(implicit_violated) > 0
            if is_explicit_invalidated or is_implicit_drift:
                if is_explicit_invalidated and is_implicit_drift:
                    inv_kind = "explicit+implicit"
                elif is_explicit_invalidated:
                    inv_kind = "explicit"
                else:
                    inv_kind = "implicit"

                assumed_payload = (
                    dict(explicit_assumed)
                    if is_explicit_invalidated
                    else {
                        "priority_tier": r["b_priority_tier"],
                        "sla_bucket": r["b_sla_bucket"],
                        "in_kev": b_in_kev,
                        "epss_score": b_epss,
                        "epss_percentile": b_epss_pct,
                        "cvss_score": b_cvss,
                        "internet_facing": b_facing,
                    }
                )
                invalidated_assumptions.append(
                    InvalidatedAssumptionFinding(
                        asset_id=asset_id,
                        finding_id=finding_id,
                        primary_cve=r["t_primary_cve"] or r["b_primary_cve"],
                        title=str(r["t_title"] or r["b_title"] or ""),
                        hostname=r["t_hostname"] or r["b_hostname"],
                        ip_address=r["t_ip_address"] or r["b_ip_address"],
                        invalidation_kind=inv_kind,
                        decision_id=effective_decision_id,
                        decision_status=effective_decision_status,
                        violated_predicates=list(dict.fromkeys([*explicit_violated, *implicit_violated])),
                        reasons=list(dict.fromkeys([*explicit_reasons, *implicit_reasons])),
                        assumed_state=assumed_payload,
                        target_state={
                            "priority_tier": r["t_priority_tier"],
                            "sla_bucket": r["t_sla_bucket"],
                            "in_kev": t_in_kev,
                            "epss_score": t_epss,
                            "epss_percentile": t_epss_pct,
                            "cvss_score": t_cvss,
                            "cvss_provenance": t_cvss_prov,
                            "internet_facing": t_facing,
                        },
                        base_priority_tier=r["b_priority_tier"],
                        target_priority_tier=r["t_priority_tier"],
                        base_sla_bucket=r["b_sla_bucket"],
                        target_sla_bucket=r["t_sla_bucket"],
                        base_oal_compat=r["b_oal_compat"],
                        target_oal_compat=r["t_oal_compat"],
                        base_ssvc_action=r["b_ssvc_action"],
                        target_ssvc_action=r["t_ssvc_action"],
                    )
                )

        # Category 5: shadow_assets_delta
        shadow_delta = self._compute_shadow_assets_delta(resolved_base, resolved_target)

        diff_id = compute_diff_id(resolved_base, resolved_target)
        summary = DiffSummary(
            base_run_id=resolved_base,
            target_run_id=resolved_target,
            base_total_findings=base_total_findings,
            target_total_findings=target_total_findings,
            persisting_findings=persisting_findings,
            newly_introduced_all=newly_introduced_all,
            newly_introduced_high_risk=len(newly_introduced_high_risk),
            threat_intel_escalated=len(threat_intel_escalated),
            verified_remediated=len(verified_remediated),
            verified_remediated_confirmed=sum(1 for x in verified_remediated if x.asset_still_present),
            verified_remediated_asset_missing=sum(
                1 for x in verified_remediated if not x.asset_still_present
            ),
            invalidated_assumptions=len(invalidated_assumptions),
            shadow_assets_new=len(shadow_delta.newly_observed),
            shadow_assets_resolved=len(shadow_delta.resolved),
        )

        persisted_count = 0
        if persist:
            persisted_count = self._persist_diff_events(
                diff_id=diff_id,
                base_run_id=resolved_base,
                target_run_id=resolved_target,
                newly_introduced_high_risk=newly_introduced_high_risk,
                threat_intel_escalated=threat_intel_escalated,
                verified_remediated=verified_remediated,
                invalidated_assumptions=invalidated_assumptions,
                shadow_assets_delta=shadow_delta,
            )

        return DiffReport(
            diff_id=diff_id,
            base_run_id=resolved_base,
            target_run_id=resolved_target,
            generated_at_utc=_utc_now_z(),
            newly_introduced_high_risk=newly_introduced_high_risk,
            newly_introduced_all=newly_introduced_all,
            newly_introduced_active_kev_count=newly_introduced_active_kev_count,
            threat_intel_escalated=threat_intel_escalated,
            verified_remediated=verified_remediated,
            invalidated_assumptions=invalidated_assumptions,
            shadow_assets_delta=shadow_delta,
            metadata_delta=metadata_delta,
            summary=summary,
            persisted_events_count=persisted_count,
        )

    def _compute_shadow_assets_delta(self, base_run_id: str, target_run_id: str) -> ShadowAssetsDelta:
        query = (
            f"WITH base_assets AS ({_ASSET_RUN_CTE_SQL}),\n"
            f"target_assets AS ({_ASSET_RUN_CTE_SQL})\n"
            """
            SELECT
                COALESCE(t.asset_id, b.asset_id) AS asset_id,
                (b.asset_id IS NOT NULL) AS in_base,
                (t.asset_id IS NOT NULL) AS in_target,
                b.canonical_key AS b_canonical_key,
                b.hostname AS b_hostname,
                b.ip_address AS b_ip_address,
                b.target_uri AS b_target_uri,
                b.image_or_repo AS b_image_or_repo,
                b.internet_facing AS b_internet_facing,
                b.inventory_status AS b_inventory_status,
                b.matched_rule_id AS b_matched_rule_id,
                b.finding_count AS b_finding_count,
                b.max_operational_score AS b_max_operational_score,
                b.kev_count AS b_kev_count,
                t.canonical_key AS t_canonical_key,
                t.hostname AS t_hostname,
                t.ip_address AS t_ip_address,
                t.target_uri AS t_target_uri,
                t.image_or_repo AS t_image_or_repo,
                t.internet_facing AS t_internet_facing,
                t.inventory_status AS t_inventory_status,
                t.matched_rule_id AS t_matched_rule_id,
                t.finding_count AS t_finding_count,
                t.max_operational_score AS t_max_operational_score,
                t.kev_count AS t_kev_count
            FROM base_assets b
            FULL OUTER JOIN target_assets t ON b.asset_id = t.asset_id
            ORDER BY asset_id ASC
            """
        )
        cursor = self.conn.execute(query, [base_run_id, base_run_id, target_run_id, target_run_id])
        cols = [d[0] for d in cursor.description]

        newly_observed: List[ShadowAssetDeltaItem] = []
        resolved: List[ShadowAssetDeltaItem] = []
        became_shadow: List[ShadowAssetDeltaItem] = []

        for raw in cursor.fetchall():
            r = dict(zip(cols, raw))
            in_base = bool(r["in_base"])
            in_target = bool(r["in_target"])
            b_status = r["b_inventory_status"]
            t_status = r["t_inventory_status"]

            if (not in_base) and in_target and t_status == "unmatched_shadow":
                newly_observed.append(self._make_shadow_item(r, "new_shadow", use_target=True))
            elif in_base and b_status == "unmatched_shadow" and (
                (not in_target) or t_status != "unmatched_shadow"
            ):
                kind = "resolved_matched" if in_target else "resolved_absent"
                resolved.append(self._make_shadow_item(r, kind, use_target=in_target))
            elif in_base and b_status != "unmatched_shadow" and in_target and t_status == "unmatched_shadow":
                became_shadow.append(self._make_shadow_item(r, "became_shadow", use_target=True))

        return ShadowAssetsDelta(
            newly_observed=newly_observed,
            resolved=resolved,
            became_shadow=became_shadow,
        )

    @staticmethod
    def _make_shadow_item(
        r: Dict[str, Any],
        delta_kind: str,
        *,
        use_target: bool,
    ) -> ShadowAssetDeltaItem:
        in_target = bool(r["in_target"])
        facing_raw = r["t_internet_facing"] if use_target else r["b_internet_facing"]
        if facing_raw is None and in_target:
            facing_raw = r["b_internet_facing"]
        return ShadowAssetDeltaItem(
            asset_id=str(r["asset_id"]),
            canonical_key=r["t_canonical_key"] or r["b_canonical_key"],
            hostname=r["t_hostname"] or r["b_hostname"],
            ip_address=r["t_ip_address"] or r["b_ip_address"],
            target_uri=r["t_target_uri"] or r["b_target_uri"],
            image_or_repo=r["t_image_or_repo"] or r["b_image_or_repo"],
            delta_kind=delta_kind,
            base_inventory_status=r["b_inventory_status"],
            target_inventory_status=r["t_inventory_status"],
            matched_rule_id=r["t_matched_rule_id"],
            internet_facing=bool(facing_raw) if facing_raw is not None else None,
            finding_count=int((r["t_finding_count"] if use_target else r["b_finding_count"]) or 0),
            kev_count=int((r["t_kev_count"] if use_target else r["b_kev_count"]) or 0),
            max_operational_score=_safe_float(
                r["t_max_operational_score"] if use_target else r["b_max_operational_score"]
            ),
        )

    def _persist_diff_events(
        self,
        *,
        diff_id: str,
        base_run_id: str,
        target_run_id: str,
        newly_introduced_high_risk: Sequence[NewlyIntroducedFinding],
        threat_intel_escalated: Sequence[ThreatIntelEscalatedFinding],
        verified_remediated: Sequence[VerifiedRemediatedFinding],
        invalidated_assumptions: Sequence[InvalidatedAssumptionFinding],
        shadow_assets_delta: ShadowAssetsDelta,
    ) -> int:
        events: List[Dict[str, Any]] = []
        finding_groups: Tuple[Tuple[str, Sequence[Any]], ...] = (
            ("newly_introduced_high_risk", newly_introduced_high_risk),
            ("threat_intel_escalated", threat_intel_escalated),
            ("verified_remediated", verified_remediated),
            ("invalidated_assumptions", invalidated_assumptions),
        )
        for category, items in finding_groups:
            for item in items:
                events.append(
                    {
                        "category": category,
                        "finding_id": item.finding_id,
                        "asset_id": item.asset_id,
                        "cve_id": item.primary_cve,
                        "details": item.to_dict(),
                    }
                )

        for item in (
            *shadow_assets_delta.newly_observed,
            *shadow_assets_delta.resolved,
            *shadow_assets_delta.became_shadow,
        ):
            events.append(
                {
                    "category": "shadow_assets_delta",
                    "finding_id": None,
                    "asset_id": item.asset_id,
                    "cve_id": None,
                    "details": item.to_dict(),
                }
            )

        events.sort(
            key=lambda ev: (
                str(ev["category"]),
                str(ev.get("asset_id") or ""),
                str(ev.get("finding_id") or ""),
                str(ev.get("cve_id") or ""),
                str((ev.get("details") or {}).get("delta_kind") or ""),
            )
        )

        self.conn.execute(
            "DELETE FROM diff_events WHERE diff_id = ? AND base_run_id = ? AND target_run_id = ?",
            [diff_id, base_run_id, target_run_id],
        )
        if not events:
            return 0
        return insert_diff_events(self.conn, diff_id, base_run_id, target_run_id, events)
