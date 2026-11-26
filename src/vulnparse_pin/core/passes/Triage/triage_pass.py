# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
import math
import re
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING

from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta
from vulnparse_pin.core.config_projector import (
    ConfigProjector,
    RuntimeConfigBundle,
    TriagePolicyV2,
    VppConfigV2,
    _build_triage_policy_v2,
)
from vulnparse_pin.core.config_validator import normalize_triage_profile
from vulnparse_pin.utils.cvss_utils import extract_cvss_metrics

if TYPE_CHECKING:
    from vulnparse_pin.core.assets_context import DecisionsRegistry
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult


_HIGH_IMPACT_ACI_CAPS = frozenset({
    "remote_execution",
    "command_execution",
    "auth_bypass",
    "sql_injection",
    "privilege_escalation",
    "initial_access",
    "deserialization",
    "ssrf",
})

_HIGH_CONF_SAST_CWES = frozenset({
    "CWE-78",
    "CWE-89",
    "CWE-94",
    "CWE-287",
    "CWE-306",
    "CWE-434",
    "CWE-502",
    "CWE-798",
    "CWE-918",
})

_HIGH_CONF_SAST_RULE_KEYWORDS = (
    "rce",
    "remote-code-execution",
    "remote_code_execution",
    "command-injection",
    "command_injection",
    "cmd-injection",
    "sqli",
    "sql-injection",
    "sql_injection",
    "auth-bypass",
    "auth_bypass",
    "deserialization",
    "hardcoded-secret",
    "hardcoded-credential",
    "ssrf",
)

_HIGH_CONF_SAST_KW_RE = re.compile(
    r"(?<![a-z0-9])(?:" + "|".join(re.escape(kw) for kw in _HIGH_CONF_SAST_RULE_KEYWORDS) + r")(?![a-z0-9])",
    re.IGNORECASE,
)

_ACTIVE_EXPOSURE_CAPS = frozenset({"remote_execution", "command_execution", "auth_bypass"})
_ACTIVE_EXPOSURE_TOKENS = frozenset({
    "default-login",
    "default_login",
    "default credential",
    "rce",
    "auth-bypass",
    "auth_bypass",
    "auth bypass",
})

_AUTOMATABLE_ACI_CAPS = frozenset({"remote_execution", "command_execution", "auth_bypass"})
_AUTOMATABLE_TOKENS = frozenset({
    "default-login",
    "default_login",
    "default credential",
    "rce",
    "auth-bypass",
    "auth_bypass",
    "auth bypass",
})

_TOTAL_IMPACT_ACI_CAPS = frozenset({
    "remote_execution",
    "command_execution",
    "auth_bypass",
    "privilege_escalation",
    "sql_injection",
})

_CWE_NUM_RE = re.compile(r"CWE[-_:\s]*0*([0-9]+)", re.IGNORECASE)


def _norm_cwe(val: Any) -> Optional[str]:
    if not val:
        return None
    m = _CWE_NUM_RE.search(str(val))
    if not m:
        return None
    return f"CWE-{int(m.group(1))}"


def _norm_prob(val: Any) -> float:
    if val is None:
        return 0.0
    try:
        f = float(val)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(f) or math.isinf(f):
        return 0.0
    if f > 1.0:
        f = f / 100.0
    return max(0.0, min(1.0, f))


def _norm_float(val: Any, default: float = 0.0) -> float:
    if val is None:
        return default
    try:
        f = float(val)
    except (TypeError, ValueError):
        return default
    if math.isnan(f) or math.isinf(f):
        return default
    return f


def _parse_json_obj(raw_s: Optional[str]) -> Dict[str, Any]:
    if not raw_s:
        return {}
    try:
        parsed = json.loads(raw_s)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _parse_json_list(raw_s: Optional[str]) -> Tuple[str, ...]:
    if not raw_s or raw_s == "[]":
        return ()
    try:
        parsed = json.loads(raw_s)
        return tuple(str(x) for x in parsed if x) if isinstance(parsed, list) else ()
    except Exception:
        return ()


def _coerce_triage_policy(policy: Any) -> TriagePolicyV2:
    if policy is None:
        return ConfigProjector.load_packaged_default_bundle().v2.triage
    if isinstance(policy, RuntimeConfigBundle):
        return policy.v2.triage
    if isinstance(policy, VppConfigV2):
        return policy.triage
    if isinstance(policy, TriagePolicyV2):
        return policy
    if isinstance(policy, dict):
        return _build_triage_policy_v2(policy, {})
    raise TypeError(f"Unsupported triage policy type: {type(policy).__name__}")


def _resolve_duckdb_conn(db_obj: Any) -> Any:
    if db_obj is None:
        return None
    inner = getattr(db_obj, "conn", None)
    if inner is not None and hasattr(inner, "execute"):
        return inner
    if hasattr(db_obj, "execute"):
        return db_obj
    return None


def _is_high_conf_sast_corroborated(
    *,
    internet_facing: bool,
    cwes: Sequence[str],
    scanner_sig: Optional[str] = None,
    scanner_sigs: Sequence[str] = (),
    scanner_severity: Optional[str] = None,
    high_impact_aci: bool = False,
) -> bool:
    if not internet_facing:
        return False
    sev = str(scanner_severity or "").strip().lower()
    if sev not in ("high", "critical"):
        return False
    if any(c in _HIGH_CONF_SAST_CWES for c in cwes):
        return True
    if high_impact_aci:
        return True
    sigs: List[str] = []
    for s in scanner_sigs:
        st = str(s or "").strip()
        if st and st not in sigs:
            sigs.append(st)
    if scanner_sig:
        st = str(scanner_sig).strip()
        if st and st not in sigs:
            sigs.append(st)
    return any(_HIGH_CONF_SAST_KW_RE.search(sig) for sig in sigs)


def _compute_ssvc_inputs(
    *,
    internet_facing: bool,
    in_kev: bool,
    verified_exploit: bool,
    epss: float,
    epss_pct: float,
    scoring_track: str,
    signal_reliability: float,
    cvss_vector: Optional[str],
    cvss_version: Optional[str],
    aci_capabilities: Sequence[str],
    matched_tokens: Sequence[str],
) -> Dict[str, Any]:
    caps_set = {str(c).strip().lower() for c in aci_capabilities if c}
    toks_set = {str(t).strip().lower() for t in matched_tokens if t}

    publicly_exposed = bool(internet_facing)

    # 2. exploitation: active | poc | none
    is_active_exposure = (
        scoring_track == "exposure_weakness"
        and signal_reliability >= 0.90
        and (bool(caps_set & _ACTIVE_EXPOSURE_CAPS) or bool(toks_set & _ACTIVE_EXPOSURE_TOKENS))
    )
    if in_kev or is_active_exposure:
        exploitation = "active"
    elif verified_exploit or epss >= 0.10 or epss_pct >= 0.95:
        exploitation = "poc"
    else:
        exploitation = "none"

    # Extract CVSS base metrics when vector is available
    metrics = extract_cvss_metrics(cvss_vector) if cvss_vector else {}
    av = metrics.get("AV")
    ac = metrics.get("AC")
    pr = metrics.get("PR")
    ui = metrics.get("UI")
    au = metrics.get("Au")

    # 3. automatable: network vector + low complexity + no/low auth + no user interaction OR RCE/default-login/auth-bypass
    cvss_auto = False
    if av == "N" and ac == "L":
        if "PR" in metrics:
            cvss_auto = pr in ("N", "L") and ui == "N"
        elif "Au" in metrics:
            cvss_auto = au in ("N", "S")
    aci_auto = bool(caps_set & _AUTOMATABLE_ACI_CAPS) or bool(toks_set & _AUTOMATABLE_TOKENS)
    automatable = bool(cvss_auto or aci_auto)

    # 4. technical_impact: total | partial
    ver_str = str(cvss_version or "").strip()
    is_v3 = ver_str in ("3.0", "3.1") or ("PR" in metrics and "VC" not in metrics)
    cvss_total = (
        (metrics.get("C") == "H" and metrics.get("I") == "H" and metrics.get("A") == "H")
        or (metrics.get("C") == "C" and metrics.get("I") == "C" and metrics.get("A") == "C")
        or (is_v3 and metrics.get("S") == "C")
        or (metrics.get("VC") == "H" and metrics.get("VI") == "H")
        or (metrics.get("SC") == "H" and metrics.get("SI") == "H")
    )
    aci_total = bool(caps_set & _TOTAL_IMPACT_ACI_CAPS)
    technical_impact = "total" if (cvss_total or aci_total) else "partial"

    ssvc_path = (
        f"exposed={publicly_exposed}|exp={exploitation}|"
        f"auto={automatable}|impact={technical_impact}"
    )
    return {
        "publicly_exposed": publicly_exposed,
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "ssvc_path": ssvc_path,
    }


def _evaluate_bod_26_04_decision(
    *,
    ssvc: Dict[str, Any],
    epss: float,
    epss_pct: float,
    operational_score: float,
    scoring_track: str,
    signal_reliability: float,
    aci_chains: Sequence[str],
    detection_mode: str,
    policy: Optional[TriagePolicyV2] = None,
    cwes: Sequence[str] = (),
    scanner_sig: Optional[str] = None,
    scanner_sigs: Sequence[str] = (),
    scanner_severity: Optional[str] = None,
    aci_capabilities: Sequence[str] = (),
) -> Tuple[str, str, str, str, Optional[int], List[str], bool]:
    exposed = bool(ssvc["publicly_exposed"])
    exp = ssvc["exploitation"]
    auto = bool(ssvc["automatable"])
    impact = ssvc["technical_impact"]
    reasons: List[str] = [ssvc["ssvc_path"]]

    p1_3day = exposed and exp == "active"
    p1_14day = (not p1_3day) and (
        exp == "active"
        or (
            exposed
            and (
                (auto and impact == "total")
                or epss_pct >= 0.95
                or (scoring_track == "exposure_weakness" and signal_reliability >= 0.85 and impact == "total")
            )
        )
    )

    if p1_3day or p1_14day:
        sast_cap_enabled = bool(policy.static_sast_p1_cap) if policy is not None else True
        if detection_mode == "static_sast" and sast_cap_enabled:
            caps_set = {str(c).strip().lower() for c in aci_capabilities if c}
            high_impact_aci = bool(caps_set & _HIGH_IMPACT_ACI_CAPS) or bool(aci_chains)
            corroborated = _is_high_conf_sast_corroborated(
                internet_facing=exposed,
                cwes=cwes,
                scanner_sig=scanner_sig,
                scanner_sigs=scanner_sigs,
                scanner_severity=scanner_severity,
                high_impact_aci=high_impact_aci,
            )
            if not corroborated:
                reasons.append("BOD-26-04: SAST P1-cap guardrail applied -> capped at P2 (60-day)")
                return "P2", "OAL-2", "Attend", "60-day", 60, reasons, True
            reasons.append("BOD-26-04: SAST corroborated high-confidence finding on internet-facing asset -> P1")

        if p1_3day:
            reasons.append("BOD-26-04: publicly_exposed + active exploitation -> 3-day + Forensic Triage")
            return "P1", "OAL-1", "Act", "3-day + Forensic Triage", 3, reasons, False

        reasons.append("BOD-26-04: active(internal) or exposed+(auto&total|epss>=95th|reliable_total) -> 14-day")
        return "P1", "OAL-1", "Act", "14-day", 14, reasons, False

    if (
        epss_pct >= 0.90
        or epss >= 0.04
        or (auto and impact == "total")
        or bool(aci_chains)
        or (detection_mode == "static_sast" and impact == "total")
    ):
        reasons.append("BOD-26-04: epss>=90th/4% or auto&total or chains or sast+total -> 60-day")
        return "P2", "OAL-2", "Attend", "60-day", 60, reasons, False

    reasons.append("BOD-26-04: remainder -> Fix on Upgrade")
    tier = "P3" if operational_score >= 3.5 else "P4"
    return tier, "OAL-3", "Track", "Fix on Upgrade", None, reasons, False


def _evaluate_default_decision(
    *,
    policy: TriagePolicyV2,
    in_kev: bool,
    internet_facing: bool,
    declared_crit: str,
    epss: float,
    epss_pct: float,
    scoring_track: str,
    signal_reliability: float,
    operational_score: float,
    aci_capabilities: Sequence[str],
    aci_chains: Sequence[str],
    detection_mode: str,
    cwes: Sequence[str],
    scanner_sig: Optional[str],
    scanner_sigs: Sequence[str] = (),
    scanner_severity: Optional[str],
) -> Tuple[str, str, str, str, Optional[int], List[str], bool]:
    caps_set = {str(c).strip().lower() for c in aci_capabilities if c}
    high_impact_aci = bool(caps_set & _HIGH_IMPACT_ACI_CAPS) or bool(aci_chains)
    reasons: List[str] = []

    p1_match = (
        (in_kev and (internet_facing or declared_crit in ("critical", "high")))
        or ((epss >= 0.10 or epss_pct >= 0.95) and internet_facing)
        or (
            scoring_track == "exposure_weakness"
            and signal_reliability >= 0.85
            and (internet_facing or declared_crit == "critical")
            and (high_impact_aci or operational_score >= 8.5)
        )
        or (operational_score >= 9.0 and signal_reliability >= 0.85)
    )

    if p1_match:
        if detection_mode == "static_sast" and policy.static_sast_p1_cap:
            corroborated = _is_high_conf_sast_corroborated(
                internet_facing=internet_facing,
                cwes=cwes,
                scanner_sig=scanner_sig,
                scanner_sigs=scanner_sigs,
                scanner_severity=scanner_severity,
                high_impact_aci=high_impact_aci,
            )
            if not corroborated:
                reasons.append("SAST P1-cap guardrail applied -> capped at P2")
                return "P2", "OAL-2", "Attend", "14-day", 14, reasons, True
            reasons.append("SAST corroborated critical finding on internet-facing asset -> P1")
        if in_kev and internet_facing:
            reasons.append("KEV on internet-facing asset -> P1")
            return "P1", "OAL-1", "Act", "3-day + Forensic Triage", 3, reasons, False
        reasons.append("Default P1 threshold met")
        return "P1", "OAL-1", "Act", "14-day", 14, reasons, False

    if (
        in_kev
        or epss >= 0.04
        or epss_pct >= 0.90
        or bool(aci_chains)
        or operational_score >= 6.5
    ):
        reasons.append("Default P2 threshold met")
        return "P2", "OAL-2", "Attend", "14-day", 14, reasons, False

    if operational_score >= 3.5:
        reasons.append("Default P3 threshold met")
        return "P3", "OAL-3", "Track*", "60-day", 60, reasons, False

    reasons.append("Default P4 remainder")
    return "P4", "OAL-3", "Track", "Fix on Upgrade", None, reasons, False


def _reconcile_decision_registry(
    registry: Optional["DecisionsRegistry"],
    *,
    asset_context: Dict[str, Any],
    finding_facts: Dict[str, Any],
    now_utc: Optional[Any] = None,
) -> Tuple[str, Optional[str], Dict[str, Any], List[str]]:
    if registry is None:
        return "active", None, {}, []

    ev = registry.evaluate(asset_context, finding_facts, now_utc=now_utc)
    if not ev.matched:
        return "active", None, {}, []

    notes: List[str] = []
    if ev.decision_status == "deferred":
        status = "deferred_valid" if ev.status == "valid" else "deferred_invalidated"
    elif ev.decision_status == "accepted":
        status = "accepted_valid" if ev.status == "valid" else "accepted_invalidated"
    elif ev.decision_status == "mitigated":
        status = "mitigated"
    else:
        status = "active"

    state = {
        "decision_id": ev.decision_id,
        "registry_status": ev.decision_status,
        "validity": ev.status,
        "assumed_state": dict(ev.assumed_state),
        "violated_predicates": list(ev.violated_predicates),
        "reasons": list(ev.reasons),
        "owner": ev.owner,
        "expires_at": ev.expires_at,
    }
    if ev.status == "invalidated":
        preds = ", ".join(ev.violated_predicates) or "assumption_violated"
        notes.append(f"invalidated({ev.decision_id}: {preds})")
    else:
        notes.append(f"{status}({ev.decision_id})")
    return status, ev.decision_id, state, notes


class TriageDecisionPass(Pass):
    """First-class Triage@2.0 pass supporting default and BOD 26-04 SSVC profiles."""

    name: str = "Triage"
    version: str = "2.0"
    requires_passes: tuple[str, ...] = ("Scoring@3.0", "ACI@2.0")

    def __init__(
        self,
        policy: Optional[Any] = None,
        *,
        profile: Optional[str] = None,
        decisions_registry: Optional["DecisionsRegistry"] = None,
        now_utc: Optional[Any] = None,
    ) -> None:
        self.policy = _coerce_triage_policy(policy)
        self._explicit_profile = profile
        self._explicit_decisions_registry = decisions_registry
        self._now_utc = now_utc

    def _resolve_profile(self, ctx: "RunContext", conn: Any, run_id: Optional[str]) -> str:
        raw_profile = self._explicit_profile
        if not raw_profile:
            services = getattr(ctx, "services", None)
            raw_profile = getattr(ctx, "profile", None) or getattr(services, "profile", None)
        if not raw_profile and conn is not None and run_id is not None:
            row = conn.execute("SELECT profile FROM runs WHERE run_id = ?", [run_id]).fetchone()
            if row and row[0]:
                raw_profile = row[0]
        if not raw_profile:
            raw_profile = self.policy.default_profile
        return normalize_triage_profile(raw_profile)

    def _resolve_decisions_registry(self, ctx: "RunContext") -> Optional["DecisionsRegistry"]:
        if self._explicit_decisions_registry is not None:
            return self._explicit_decisions_registry
        services = getattr(ctx, "services", None)
        return getattr(ctx, "decisions_registry", None) or getattr(services, "decisions_registry", None)

    def run(self, ctx: "RunContext", scan: Optional["ScanResult"] = None) -> DerivedPassResult:
        services = getattr(ctx, "services", None)
        db = getattr(ctx, "db", None) or getattr(services, "db", None)
        run_id = getattr(ctx, "run_id", None) or getattr(services, "run_id", None)
        conn = _resolve_duckdb_conn(db) if (db is not None and run_id is not None) else None

        if conn is not None and run_id is not None:
            return self._run_duckdb(ctx, conn, str(run_id))

        if scan is None:
            raise ValueError("TriageDecisionPass requires either DuckDB (ctx.db + ctx.run_id) or ScanResult.")
        return self._run_scan_result(ctx, scan)

    def _run_duckdb(self, ctx: "RunContext", conn: Any, run_id: str) -> DerivedPassResult:
        profile = self._resolve_profile(ctx, conn, run_id)
        registry = self._resolve_decisions_registry(ctx)
        has_registry = bool(registry is not None and getattr(registry, "entries", None))

        # Load CVSS vectors by CVE from enrichment_snapshots once (needed for SSVC CVSS metric rules)
        cvss_vec_by_cve: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
        for cve_id, vec, ver in conn.execute(
            "SELECT cve_id, cvss_vector, cvss_version FROM enrichment_snapshots WHERE run_id = ?",
            [run_id],
        ).fetchall():
            if cve_id:
                cvss_vec_by_cve[str(cve_id).strip().upper()] = (vec, ver)

        aliases_by_asset: Dict[str, Tuple[str, ...]] = {}
        sigs_by_finding: Dict[str, Tuple[str, ...]] = {}
        exact_dec_ids: FrozenSet[str] = getattr(registry, "exact_finding_ids", frozenset()) if has_registry else frozenset()
        wildcard_dec = bool(getattr(registry, "has_wildcard_finding_ids", True)) if has_registry else False

        if has_registry:
            for fid, sig_list in conn.execute(
                """
                SELECT finding_id, LIST(DISTINCT scanner_sig ORDER BY scanner_sig)
                FROM finding_evidence
                WHERE run_id = ? AND scanner_sig IS NOT NULL AND scanner_sig <> ''
                GROUP BY finding_id
                """,
                [run_id],
            ).fetchall():
                sigs = tuple(str(s) for s in (sig_list or ()) if s)
                if sigs:
                    sigs_by_finding[str(fid)] = sigs
        else:
            for fid, sig_list in conn.execute(
                """
                SELECT fe.finding_id, LIST(DISTINCT fe.scanner_sig ORDER BY fe.scanner_sig)
                FROM finding_evidence fe
                JOIN findings f
                  ON f.run_id = fe.run_id AND f.finding_id = fe.finding_id
                WHERE fe.run_id = ?
                  AND LOWER(TRIM(COALESCE(f.detection_mode, ''))) = 'static_sast'
                  AND fe.scanner_sig IS NOT NULL
                  AND fe.scanner_sig <> ''
                GROUP BY fe.finding_id
                """,
                [run_id],
            ).fetchall():
                sigs = tuple(str(s) for s in (sig_list or ()) if s)
                if sigs:
                    sigs_by_finding[str(fid)] = sigs

        if has_registry:
            tmp_aliases: Dict[str, List[str]] = {}
            for aid, aval in conn.execute(
                "SELECT asset_id, alias_value FROM asset_aliases WHERE run_id = ?",
                [run_id],
            ).fetchall():
                if aid and aval:
                    tmp_aliases.setdefault(aid, []).append(str(aval))
            aliases_by_asset = {k: tuple(v) for k, v in tmp_aliases.items()}

        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                s.finding_id,
                s.asset_id,
                s.scoring_track,
                s.operational_score,
                s.risk_band,
                s.score_trace_json,
                f.primary_cve,
                f.cves_json,
                f.cwes_json,
                f.scanner_severity,
                f.scanner_cvss_vector,
                f.detection_mode,
                f.signal_reliability,
                a.matched_rule_id,
                a.canonical_key,
                a.hostname,
                a.ip_address,
                a.target_uri,
                a.image_or_repo,
                a.internet_facing,
                a.declared_criticality,
                aci.capabilities_json,
                aci.chains_json,
                aci.matched_tokens_json
            FROM scores s
            JOIN findings f
              ON f.run_id = s.run_id AND f.finding_id = s.finding_id
            LEFT JOIN assets a
              ON a.run_id = s.run_id AND a.asset_id = s.asset_id
            LEFT JOIN aci_signals aci
              ON aci.run_id = s.run_id AND aci.finding_id = s.finding_id
            WHERE s.run_id = ?
            """,
            [run_id],
        )

        total_triaged = 0
        tier_counts: Dict[str, int] = {}
        sla_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}
        sast_capped_count = 0
        decisions_sample: Dict[str, Dict[str, Any]] = {}
        trace_cache: Dict[str, Dict[str, Any]] = {}
        json_list_cache: Dict[str, Tuple[str, ...]] = {}
        cwe_tuple_cache: Dict[str, Tuple[str, ...]] = {}
        triage_memo: Dict[
            Tuple[Any, ...],
            Tuple[str, str, str, str, Optional[int], bool, Optional[str], str, str],
        ] = {}

        def _cached_list(raw_s: Optional[str]) -> Tuple[str, ...]:
            if not raw_s or raw_s == "[]":
                return ()
            hit = json_list_cache.get(raw_s)
            if hit is not None:
                return hit
            val = _parse_json_list(raw_s)
            if len(json_list_cache) < 50_000:
                json_list_cache[raw_s] = val
            return val

        def _cached_cwes(raw_s: Optional[str]) -> Tuple[str, ...]:
            if not raw_s or raw_s == "[]":
                return ()
            hit = cwe_tuple_cache.get(raw_s)
            if hit is not None:
                return hit
            val = tuple(c for c in (_norm_cwe(x) for x in _cached_list(raw_s)) if c)
            if len(cwe_tuple_cache) < 50_000:
                cwe_tuple_cache[raw_s] = val
            return val

        is_bod = profile == "bod-26-04"
        sast_p1_cap = bool(self.policy.static_sast_p1_cap)
        populate_sample = (
            int((conn.execute("SELECT COUNT(*) FROM scores WHERE run_id = ?", [run_id]).fetchone() or (0,))[0] or 0)
            <= 10_000
        )

        conn.execute("BEGIN TRANSACTION")
        try:
            conn.execute("DELETE FROM triage_decisions WHERE run_id = ?", [run_id])
            with conn.appender("triage_decisions") as appender:
                batch_rows: List[Tuple[Any, ...]] = []
                while True:
                    chunk = cursor.fetchmany(25_000)
                    if not chunk:
                        break
                    for (
                        finding_id,
                        asset_id,
                        scoring_track,
                        operational_score,
                        risk_band,
                        score_trace_json,
                        primary_cve,
                        cves_json,
                        cwes_json,
                        scanner_sev,
                        scanner_cvss_vec,
                        detection_mode,
                        f_sig_rel,
                        matched_rule_id,
                        canonical_key,
                        hostname,
                        ip_address,
                        target_uri,
                        image_or_repo,
                        a_internet_facing,
                        a_declared_crit,
                        caps_json,
                        chains_json,
                        toks_json,
                    ) in chunk:
                        total_triaged += 1
                        if score_trace_json:
                            trace = trace_cache.get(score_trace_json)
                            if trace is None:
                                trace = _parse_json_obj(score_trace_json)
                                if len(trace_cache) < 100_000:
                                    trace_cache[score_trace_json] = trace
                        else:
                            trace = {}

                        caps_override = trace.get("aci_capabilities")
                        chains_override = trace.get("aci_chains")
                        caps_key = tuple(caps_override) if caps_override else (caps_json or "[]")
                        chains_key = tuple(chains_override) if chains_override else (chains_json or "[]")
                        toks_key = toks_json or "[]"

                        in_kev = bool(trace.get("in_kev", False))
                        verified_exploit = bool(trace.get("verified_exploit", False))
                        epss = _norm_prob(trace.get("epss_score"))
                        epss_pct = _norm_prob(trace.get("epss_percentile"))
                        internet_facing = bool(
                            trace.get("internet_facing")
                            if trace.get("internet_facing") is not None
                            else a_internet_facing
                        )
                        declared_crit = str(
                            trace.get("declared_criticality") or a_declared_crit or ""
                        ).strip().lower()
                        track = str(scoring_track or trace.get("scoring_track") or "exposure_weakness").strip().lower()
                        sig_rel = _norm_float(
                            trace.get("signal_reliability"),
                            default=_norm_float(f_sig_rel, 0.70),
                        )
                        op_score = _norm_float(operational_score, 0.0)
                        det_mode = str(detection_mode or trace.get("detection_mode") or "").strip().lower()
                        scanner_sigs = sigs_by_finding.get(finding_id, ())
                        scanner_sig = scanner_sigs[0] if scanner_sigs else None
                        trace_cve = trace.get("primary_cve") or primary_cve
                        cvss_score_val = _norm_float(trace.get("cvss_score"), 0.0)

                        # Resolve CVSS vector preferring winning CVE snapshot, fallback to scanner vector
                        cvss_vec: Optional[str] = None
                        cvss_ver: Optional[str] = trace.get("cvss_version")
                        if trace_cve:
                            snap_vec, snap_ver = cvss_vec_by_cve.get(str(trace_cve).strip().upper(), (None, None))
                            if snap_vec:
                                cvss_vec = snap_vec
                                if not cvss_ver:
                                    cvss_ver = snap_ver
                        if not cvss_vec and scanner_cvss_vec:
                            cvss_vec = scanner_cvss_vec

                        # Fast-skip DecisionsRegistry when wildcard-free and no finding ID matches index
                        may_match_decision = False
                        if has_registry:
                            if wildcard_dec:
                                may_match_decision = True
                            else:
                                if (trace_cve and str(trace_cve).strip().lower() in exact_dec_ids) or (
                                    finding_id and finding_id.strip().lower() in exact_dec_ids
                                ) or any(s.strip().lower() in exact_dec_ids for s in scanner_sigs):
                                    may_match_decision = True
                                elif cves_json and cves_json != "[]" and (not trace_cve or "," in cves_json):
                                    for c_item in _cached_list(cves_json):
                                        if c_item.strip().lower() in exact_dec_ids:
                                            may_match_decision = True
                                            break

                        need_sast_fields = det_mode == "static_sast" and sast_p1_cap
                        if not may_match_decision:
                            if is_bod:
                                tm_key = (
                                    1,
                                    internet_facing,
                                    in_kev,
                                    verified_exploit,
                                    epss >= 0.10,
                                    epss >= 0.04,
                                    epss_pct >= 0.95,
                                    epss_pct >= 0.90,
                                    track,
                                    sig_rel >= 0.90,
                                    sig_rel >= 0.85,
                                    op_score >= 3.5,
                                    cvss_vec,
                                    cvss_ver,
                                    caps_key,
                                    bool(chains_override) if chains_override else (bool(chains_json) and chains_json != "[]"),
                                    toks_key,
                                    det_mode == "static_sast",
                                    cwes_json if need_sast_fields else None,
                                    scanner_sigs if need_sast_fields else None,
                                    str(scanner_sev or "").strip().lower() if need_sast_fields else None,
                                )
                            else:
                                crit_bucket = (
                                    "critical"
                                    if declared_crit == "critical"
                                    else ("high" if declared_crit == "high" else "")
                                )
                                tm_key = (
                                    0,
                                    in_kev,
                                    internet_facing,
                                    crit_bucket,
                                    epss >= 0.10,
                                    epss >= 0.04,
                                    epss_pct >= 0.95,
                                    epss_pct >= 0.90,
                                    track,
                                    sig_rel >= 0.85,
                                    op_score >= 9.0,
                                    op_score >= 8.5,
                                    op_score >= 6.5,
                                    op_score >= 3.5,
                                    caps_key,
                                    bool(chains_override) if chains_override else (bool(chains_json) and chains_json != "[]"),
                                    det_mode == "static_sast",
                                    cwes_json if need_sast_fields else None,
                                    scanner_sigs if need_sast_fields else None,
                                    str(scanner_sev or "").strip().lower() if need_sast_fields else None,
                                )

                            tm_hit = triage_memo.get(tm_key)
                            if tm_hit is None:
                                caps = tuple(caps_override) if caps_override else _cached_list(caps_json)
                                chains = tuple(chains_override) if chains_override else _cached_list(chains_json)
                                matched_tokens = _cached_list(toks_json)
                                cwes = _cached_cwes(cwes_json)
                                ssvc_info: Optional[Dict[str, Any]] = None
                                capped = False
                                if is_bod:
                                    ssvc_info = _compute_ssvc_inputs(
                                        internet_facing=internet_facing,
                                        in_kev=in_kev,
                                        verified_exploit=verified_exploit,
                                        epss=epss,
                                        epss_pct=epss_pct,
                                        scoring_track=track,
                                        signal_reliability=sig_rel,
                                        cvss_vector=cvss_vec,
                                        cvss_version=cvss_ver,
                                        aci_capabilities=caps,
                                        matched_tokens=matched_tokens,
                                    )
                                    tier, oal, ssvc_act, sla_bucket, sla_days, rationale_parts, capped = _evaluate_bod_26_04_decision(
                                        ssvc=ssvc_info,
                                        epss=epss,
                                        epss_pct=epss_pct,
                                        operational_score=op_score,
                                        scoring_track=track,
                                        signal_reliability=sig_rel,
                                        aci_chains=chains,
                                        detection_mode=det_mode,
                                        policy=self.policy,
                                        cwes=cwes,
                                        scanner_sig=scanner_sig,
                                        scanner_sigs=scanner_sigs,
                                        scanner_severity=scanner_sev,
                                        aci_capabilities=caps,
                                    )
                                else:
                                    tier, oal, ssvc_act, sla_bucket, sla_days, rationale_parts, capped = _evaluate_default_decision(
                                        policy=self.policy,
                                        in_kev=in_kev,
                                        internet_facing=internet_facing,
                                        declared_crit=declared_crit,
                                        epss=epss,
                                        epss_pct=epss_pct,
                                        scoring_track=track,
                                        signal_reliability=sig_rel,
                                        operational_score=op_score,
                                        aci_capabilities=caps,
                                        aci_chains=chains,
                                        detection_mode=det_mode,
                                        cwes=cwes,
                                        scanner_sig=scanner_sig,
                                        scanner_sigs=scanner_sigs,
                                        scanner_severity=scanner_sev,
                                    )

                                assumed_payload: Dict[str, Any] = {}
                                if ssvc_info is not None:
                                    assumed_payload["ssvc_path"] = ssvc_info["ssvc_path"]
                                    assumed_payload["ssvc_inputs"] = {
                                        "publicly_exposed": ssvc_info["publicly_exposed"],
                                        "exploitation": ssvc_info["exploitation"],
                                        "automatable": ssvc_info["automatable"],
                                        "technical_impact": ssvc_info["technical_impact"],
                                    }
                                if capped:
                                    assumed_payload["sast_p1_capped"] = True
                                assumed_payload["decision_status"] = "active"
                                assumed_json = json.dumps(assumed_payload, ensure_ascii=True, separators=(",", ":"))
                                rationale_str = "; ".join(rationale_parts)
                                ssvc_path_val = ssvc_info["ssvc_path"] if ssvc_info is not None else None
                                tm_hit = (tier, oal, ssvc_act, sla_bucket, sla_days, capped, ssvc_path_val, assumed_json, rationale_str)
                                if len(triage_memo) < 50_000:
                                    triage_memo[tm_key] = tm_hit

                            tier, oal, ssvc_act, sla_bucket, sla_days, capped, ssvc_path_val, assumed_json, rationale_str = tm_hit
                            if capped:
                                sast_capped_count += 1
                            dec_status = "active"
                            dec_id: Optional[str] = None
                        else:
                            caps = tuple(caps_override) if caps_override else _cached_list(caps_json)
                            chains = tuple(chains_override) if chains_override else _cached_list(chains_json)
                            matched_tokens = _cached_list(toks_json)
                            cwes = _cached_cwes(cwes_json)
                            cves = _cached_list(cves_json)

                            ssvc_info = None
                            capped = False
                            if is_bod:
                                ssvc_info = _compute_ssvc_inputs(
                                    internet_facing=internet_facing,
                                    in_kev=in_kev,
                                    verified_exploit=verified_exploit,
                                    epss=epss,
                                    epss_pct=epss_pct,
                                    scoring_track=track,
                                    signal_reliability=sig_rel,
                                    cvss_vector=cvss_vec,
                                    cvss_version=cvss_ver,
                                    aci_capabilities=caps,
                                    matched_tokens=matched_tokens,
                                )
                                tier, oal, ssvc_act, sla_bucket, sla_days, rationale_parts, capped = _evaluate_bod_26_04_decision(
                                    ssvc=ssvc_info,
                                    epss=epss,
                                    epss_pct=epss_pct,
                                    operational_score=op_score,
                                    scoring_track=track,
                                    signal_reliability=sig_rel,
                                    aci_chains=chains,
                                    detection_mode=det_mode,
                                    policy=self.policy,
                                    cwes=cwes,
                                    scanner_sig=scanner_sig,
                                    scanner_sigs=scanner_sigs,
                                    scanner_severity=scanner_sev,
                                    aci_capabilities=caps,
                                )
                                if capped:
                                    sast_capped_count += 1
                            else:
                                tier, oal, ssvc_act, sla_bucket, sla_days, rationale_parts, capped = _evaluate_default_decision(
                                    policy=self.policy,
                                    in_kev=in_kev,
                                    internet_facing=internet_facing,
                                    declared_crit=declared_crit,
                                    epss=epss,
                                    epss_pct=epss_pct,
                                    scoring_track=track,
                                    signal_reliability=sig_rel,
                                    operational_score=op_score,
                                    aci_capabilities=caps,
                                    aci_chains=chains,
                                    detection_mode=det_mode,
                                    cwes=cwes,
                                    scanner_sig=scanner_sig,
                                    scanner_sigs=scanner_sigs,
                                    scanner_severity=scanner_sev,
                                )
                                if capped:
                                    sast_capped_count += 1

                            dec_status, dec_id, dec_state, dec_notes = _reconcile_decision_registry(
                                registry,
                                asset_context={
                                    "asset_id": asset_id,
                                    "matched_rule_id": matched_rule_id,
                                    "canonical_key": canonical_key,
                                    "hostname": hostname,
                                    "ip_address": ip_address,
                                    "target_uri": target_uri,
                                    "image_or_repo": image_or_repo,
                                    "internet_facing": internet_facing,
                                    "aliases": aliases_by_asset.get(asset_id, ()),
                                },
                                finding_facts={
                                    "primary_cve": trace_cve,
                                    "cves": list(cves) if cves else ([trace_cve] if trace_cve else []),
                                    "scanner_sig": scanner_sig,
                                    "scanner_sigs": list(scanner_sigs),
                                    "rule_id": scanner_sig,
                                    "rule_ids": list(scanner_sigs),
                                    "vuln_id": finding_id,
                                    "in_kev": in_kev,
                                    "epss_score": trace.get("epss_score"),
                                    "epss_percentile": epss_pct if trace.get("epss_percentile") is not None else None,
                                    "internet_facing": internet_facing,
                                    "cvss_score": cvss_score_val if trace.get("cvss_score") is not None else None,
                                },
                                now_utc=self._now_utc,
                            )
                            rationale_parts.extend(dec_notes)

                            assumed_payload = dict(dec_state)
                            if ssvc_info is not None:
                                assumed_payload["ssvc_path"] = ssvc_info["ssvc_path"]
                                assumed_payload["ssvc_inputs"] = {
                                    "publicly_exposed": ssvc_info["publicly_exposed"],
                                    "exploitation": ssvc_info["exploitation"],
                                    "automatable": ssvc_info["automatable"],
                                    "technical_impact": ssvc_info["technical_impact"],
                                }
                            if capped:
                                assumed_payload["sast_p1_capped"] = True
                            assumed_payload["decision_status"] = dec_status
                            assumed_json = json.dumps(assumed_payload, ensure_ascii=True, separators=(",", ":"))
                            rationale_str = "; ".join(rationale_parts)
                            ssvc_path_val = ssvc_info["ssvc_path"] if ssvc_info is not None else None

                        batch_rows.append(
                            (
                                run_id,
                                finding_id,
                                asset_id,
                                profile,
                                tier,
                                oal,
                                ssvc_act,
                                sla_bucket,
                                sla_days,
                                dec_status,
                                dec_id,
                                assumed_json,
                                rationale_str,
                            )
                        )
                        if len(batch_rows) >= 25_000:
                            appender.append_rows(batch_rows)
                            batch_rows.clear()

                        tier_counts[tier] = tier_counts.get(tier, 0) + 1
                        sla_counts[sla_bucket] = sla_counts.get(sla_bucket, 0) + 1
                        status_counts[dec_status] = status_counts.get(dec_status, 0) + 1

                        if populate_sample:
                            decisions_sample[finding_id] = {
                                "finding_id": finding_id,
                                "asset_id": asset_id,
                                "profile": profile,
                                "priority_tier": tier,
                                "oal_compat": oal,
                                "ssvc_action": ssvc_act,
                                "sla_bucket": sla_bucket,
                                "sla_days": sla_days,
                                "decision_status": dec_status,
                                "decision_id": dec_id,
                                "ssvc_path": ssvc_path_val,
                                "rationale_summary": rationale_str,
                            }

                if batch_rows:
                    appender.append_rows(batch_rows)
                    batch_rows.clear()
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            trace_cache.clear()
            triage_memo.clear()
            json_list_cache.clear()
            cwe_tuple_cache.clear()
            try:
                cursor.close()
            except Exception:
                pass

        ctx.logger.info(
            "[pass:triage@2.0] profile=%s | triaged=%d | tiers=%s | sast_capped=%d",
            profile,
            total_triaged,
            tier_counts,
            sast_capped_count,
            extra={"vp_label": "TriageDecisionPass"},
        )
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes=f"Triage@2.0 policy evaluation (profile={profile}).",
        )
        return DerivedPassResult(
            meta=meta,
            data={
                "profile": profile,
                "total_triaged": total_triaged,
                "by_priority_tier": tier_counts,
                "by_sla_bucket": sla_counts,
                "by_decision_status": status_counts,
                "sast_p1_capped": sast_capped_count,
                "decisions": decisions_sample,
            },
        )

    def _run_scan_result(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        """In-memory ScanResult fallback when DuckDB is not attached."""
        profile = self._resolve_profile(ctx, None, None)
        registry = self._resolve_decisions_registry(ctx)
        scoring_res = scan.derived.get("Scoring@3.0") or scan.derived.get("Scoring@2.0")
        aci_res = scan.derived.get("ACI@2.0") or scan.derived.get("ACI@1.0")
        scored_map = (scoring_res.data or {}).get("scored_findings", {}) if scoring_res else {}
        aci_map = (aci_res.data or {}).get("finding_semantics", {}) if aci_res else {}

        tier_counts: Dict[str, int] = {}
        sla_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}
        decisions_out: Dict[str, Dict[str, Any]] = {}
        total_triaged = 0
        sast_capped = 0

        for asset in scan.assets:
            aid = str(getattr(asset, "asset_id", None) or getattr(asset, "ip_address", "") or "")
            a_facing = bool(getattr(asset, "internet_facing", False))
            a_crit = str(getattr(asset, "declared_criticality", None) or getattr(asset, "criticality", None) or "").strip().lower()
            for f in asset.findings:
                total_triaged += 1
                fid = str(getattr(f, "finding_id", ""))
                sf = scored_map.get(fid) or {}
                trace = sf.get("score_trace", {}) if isinstance(sf, dict) else (getattr(f, "score_trace", None) or {})
                aci_item = aci_map.get(fid) or {}

                op_score = _norm_float(sf.get("operational_score") if isinstance(sf, dict) else getattr(f, "operational_score", 0.0))
                caps = tuple(aci_item.get("capabilities") or ()) if isinstance(aci_item, dict) else tuple(getattr(aci_item, "capabilities", ()) or ())
                chains = tuple(aci_item.get("chain_candidates") or ()) if isinstance(aci_item, dict) else tuple(getattr(aci_item, "chain_candidates", ()) or ())
                tokens = tuple(aci_item.get("evidence") or ()) if isinstance(aci_item, dict) else ()

                in_kev = bool(trace.get("in_kev", getattr(f, "cisa_kev", False)))
                ver_exp = bool(trace.get("verified_exploit", getattr(f, "verified_exploit", False)))
                epss = _norm_prob(trace.get("epss_score", getattr(f, "epss_score", None)))
                epss_pct = _norm_prob(trace.get("epss_percentile", getattr(f, "epss_percentile", None)))
                facing = bool(trace.get("internet_facing") if trace.get("internet_facing") is not None else a_facing)
                track = str(trace.get("scoring_track") or ("cve_threat" if getattr(f, "cves", None) else "exposure_weakness")).lower()
                sig_rel = _norm_float(trace.get("signal_reliability"), 0.70)
                det_mode = str(getattr(f, "detection_mode", None) or trace.get("detection_mode") or "").strip().lower()
                cwes = tuple(c for c in (_norm_cwe(x) for x in (getattr(f, "cwes", None) or ())) if c)
                cvss_vec = getattr(f, "cvss_vector", None)
                cvss_ver = trace.get("cvss_version")
                sig = getattr(f, "detection_plugin", None) or getattr(f, "scanner_sig", None)
                scanner_sigs = tuple(str(s) for s in (getattr(f, "scanner_sigs", None) or ()) if s)
                if not scanner_sigs and sig:
                    scanner_sigs = (str(sig),)

                ssvc_info: Optional[Dict[str, Any]] = None
                capped = False
                if profile == "bod-26-04":
                    ssvc_info = _compute_ssvc_inputs(
                        internet_facing=facing,
                        in_kev=in_kev,
                        verified_exploit=ver_exp,
                        epss=epss,
                        epss_pct=epss_pct,
                        scoring_track=track,
                        signal_reliability=sig_rel,
                        cvss_vector=cvss_vec,
                        cvss_version=cvss_ver,
                        aci_capabilities=caps,
                        matched_tokens=tokens,
                    )
                    tier, oal, ssvc_act, sla_bucket, sla_days, rparts, capped = _evaluate_bod_26_04_decision(
                        ssvc=ssvc_info,
                        epss=epss,
                        epss_pct=epss_pct,
                        operational_score=op_score,
                        scoring_track=track,
                        signal_reliability=sig_rel,
                        aci_chains=chains,
                        detection_mode=det_mode,
                        policy=self.policy,
                        cwes=cwes,
                        scanner_sig=sig,
                        scanner_sigs=scanner_sigs,
                        scanner_severity=getattr(f, "severity", None),
                        aci_capabilities=caps,
                    )
                    if capped:
                        sast_capped += 1
                else:
                    tier, oal, ssvc_act, sla_bucket, sla_days, rparts, capped = _evaluate_default_decision(
                        policy=self.policy,
                        in_kev=in_kev,
                        internet_facing=facing,
                        declared_crit=a_crit,
                        epss=epss,
                        epss_pct=epss_pct,
                        scoring_track=track,
                        signal_reliability=sig_rel,
                        operational_score=op_score,
                        aci_capabilities=caps,
                        aci_chains=chains,
                        detection_mode=det_mode,
                        cwes=cwes,
                        scanner_sig=sig,
                        scanner_sigs=scanner_sigs,
                        scanner_severity=getattr(f, "severity", None),
                    )
                    if capped:
                        sast_capped += 1

                dec_status, dec_id, _, dec_notes = _reconcile_decision_registry(
                    registry,
                    asset_context={
                        "asset_id": aid,
                        "hostname": getattr(asset, "hostname", None),
                        "ip_address": getattr(asset, "ip_address", None),
                        "internet_facing": facing,
                    },
                    finding_facts={
                        "primary_cve": (getattr(f, "cves", None) or [None])[0],
                        "cves": list(getattr(f, "cves", None) or ()),
                        "scanner_sig": sig,
                        "scanner_sigs": list(scanner_sigs),
                        "rule_id": sig,
                        "rule_ids": list(scanner_sigs),
                        "vuln_id": fid,
                        "in_kev": in_kev,
                        "epss_score": epss if trace.get("epss_score") is not None else None,
                        "epss_percentile": epss_pct if trace.get("epss_percentile") is not None else None,
                        "internet_facing": facing,
                        "cvss_score": trace.get("cvss_score"),
                    },
                    now_utc=self._now_utc,
                )
                rparts.extend(dec_notes)
                tier_counts[tier] = tier_counts.get(tier, 0) + 1
                sla_counts[sla_bucket] = sla_counts.get(sla_bucket, 0) + 1
                status_counts[dec_status] = status_counts.get(dec_status, 0) + 1
                decisions_out[fid] = {
                    "finding_id": fid,
                    "asset_id": aid,
                    "profile": profile,
                    "priority_tier": tier,
                    "oal_compat": oal,
                    "ssvc_action": ssvc_act,
                    "sla_bucket": sla_bucket,
                    "sla_days": sla_days,
                    "decision_status": dec_status,
                    "decision_id": dec_id,
                    "ssvc_path": ssvc_info["ssvc_path"] if ssvc_info is not None else None,
                    "rationale_summary": "; ".join(rparts),
                }

        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes=f"Triage@2.0 policy evaluation (ScanResult fallback, profile={profile}).",
        )
        return DerivedPassResult(
            meta=meta,
            data={
                "profile": profile,
                "total_triaged": total_triaged,
                "by_priority_tier": tier_counts,
                "by_sla_bucket": sla_counts,
                "by_decision_status": status_counts,
                "sast_p1_capped": sast_capped,
                "decisions": decisions_out,
            },
        )


TriagePass = TriageDecisionPass
