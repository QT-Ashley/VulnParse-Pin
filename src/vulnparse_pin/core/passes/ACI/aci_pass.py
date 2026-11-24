# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta
from vulnparse_pin.core.config_source import ConfigSource
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import ACIConfig, validate_and_normalize_semantics
from vulnparse_pin.core.passes.types import (
    ACIAssetSemantic,
    ACIFindingSemantic,
    ACIPassMetrics,
    ACIPassOutput,
)

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import Finding, RunContext, ScanResult

_REMOTE_PORT_SIGNALS = frozenset({
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3389, 5900, 8080, 8443
})

_REMOTE_SERVICE_ONLY_GUARDRAIL_CAPS = frozenset({"remote_execution", "initial_access"})
_PROTOCOL_ONLY_LATERAL_SIGNALS = frozenset({"smb", "ssh", "rdp", "rpc"})

_LATERAL_CONTEXT_SIGNALS = frozenset({
    "exploit",
    "kev",
    "credential",
    "password",
    "hash",
    "hardcoded credential",
    "default credential",
    "auth bypass",
    "authentication bypass",
    "bypass login",
    "rce",
    "command injection",
    "cmd injection",
    "os command",
    "command execution",
    "privilege escalation",
    "privesc",
    "persistence",
    "deserialization",
})

_LATERAL_CONTEXT_KEYWORDS = (
    "lateral",
    "pivot",
    "relay",
    "pass-the-hash",
    "pass the hash",
    "psexec",
    "wmiexec",
    "smbexec",
    "winrm",
    "dcom",
    "credential",
    "password",
    "hash",
    "brute",
    "auth bypass",
    "authentication bypass",
    "remote execution",
    "code execution",
    "command execution",
    "command injection",
    "rce",
    "exploit",
    "tunnel",
    "port forwarding",
    "hijack",
    "impersonat",
    "eternalblue",
    "bluekeep",
    "zerologon",
)

_CORE_TEXT_TOKENS: Dict[str, str] = {
    "initial access": "initial_access",
    "auth bypass": "auth bypass",
    "authentication bypass": "authentication bypass",
    "bypass login": "bypass login",
    "default credential": "default credential",
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "command injection",
    "cmd injection": "cmd injection",
    "os command": "os command",
    "command execution": "command execution",
    "privesc": "privesc",
    "privilege escalation": "privilege escalation",
    "sudo": "sudo",
    "setuid": "setuid",
    "kernel": "kernel",
    "credential": "credential",
    "password": "password",
    "hash": "hash",
    "info disclosure": "info disclosure",
    "information disclosure": "information disclosure",
    "sensitive data": "sensitive data",
    "leak": "leak",
    "persistence": "persistence",
    "startup": "startup",
    "autorun": "autorun",
    "scheduled task": "scheduled task",
    "service install": "service install",
    "lfi": "lfi",
    "local file inclusion": "local file inclusion",
    "path traversal": "path traversal",
    "file read": "file read",
    "etc/passwd": "etc/passwd",
    "sqli": "sqli",
    "sql injection": "sql injection",
    "union select": "union select",
    "database": "database",
    "query": "query",
    "api key": "api key",
    "token": "token",
    "secret": "secret",
    "private key": "private key",
    "hardcoded credential": "hardcoded credential",
    "smb": "smb",
    "ssh": "ssh",
    "rdp": "rdp",
    "rpc": "rpc",
    "exploit": "exploit",
}

_EXTENDED_TEXT_TOKENS: Dict[str, Tuple[str, ...]] = {
    "deserialization": ("deserialization", "rce"),
    "unsafe deserialization": ("deserialization", "rce"),
    "ssrf": ("ssrf",),
    "server-side request forgery": ("ssrf",),
    "server side request forgery": ("ssrf",),
    "default-login": ("default-login", "default credential", "auth bypass"),
    "auth-bypass": ("auth-bypass", "auth bypass"),
    "misconfig": ("misconfig",),
    "misconfiguration": ("misconfig",),
    "admin panel": ("panel",),
    "login panel": ("panel",),
}

_STRUCTURED_TAG_SIGNALS: Dict[str, Tuple[str, ...]] = {
    "default-login": ("default-login", "default credential", "auth bypass"),
    "default_login": ("default-login", "default credential", "auth bypass"),
    "panel": ("panel", "exposure"),
    "rce": ("rce",),
    "auth-bypass": ("auth-bypass", "auth bypass"),
    "auth_bypass": ("auth-bypass", "auth bypass"),
    "sqli": ("sqli", "sql injection"),
    "sql-injection": ("sqli", "sql injection"),
    "lfi": ("lfi", "local file inclusion"),
    "traversal": ("path traversal", "lfi"),
    "path-traversal": ("path traversal", "lfi"),
    "ssrf": ("ssrf",),
    "exposure": ("exposure", "info disclosure"),
    "misconfig": ("misconfig",),
    "misconfiguration": ("misconfig",),
    "deserialization": ("deserialization", "rce"),
    "privesc": ("privesc", "privilege escalation"),
    "privilege-escalation": ("privesc", "privilege escalation"),
    "xss": ("xss",),
    "command-injection": ("command injection", "command execution"),
    "cmd-injection": ("cmd injection", "command execution"),
    "hardcoded-credential": ("hardcoded credential", "credential"),
    "hardcoded-secret": ("hardcoded credential", "secret"),
    "secret": ("secret",),
    "secrets": ("secret",),
}

_CWE_SIGNAL_MAP: Dict[str, Tuple[str, ...]] = {
    "CWE-22": ("lfi", "path traversal"),
    "CWE-77": ("command injection", "command execution"),
    "CWE-78": ("command injection", "os command", "command execution"),
    "CWE-79": ("xss",),
    "CWE-89": ("sqli", "sql injection"),
    "CWE-94": ("rce", "command execution"),
    "CWE-200": ("info disclosure", "information disclosure"),
    "CWE-250": ("privilege escalation", "privesc"),
    "CWE-269": ("privilege escalation", "privesc"),
    "CWE-287": ("auth bypass", "authentication bypass"),
    "CWE-306": ("auth bypass", "authentication bypass"),
    "CWE-434": ("rce",),
    "CWE-502": ("deserialization", "rce"),
    "CWE-522": ("credential", "password"),
    "CWE-798": ("hardcoded credential", "default credential", "credential"),
    "CWE-918": ("ssrf",),
}

_EXTRA_CAPABILITY_SIGNALS: Tuple[Tuple[str, Tuple[str, ...], float], ...] = (
    ("deserialization", ("deserialization",), 0.80),
    ("ssrf", ("ssrf",), 0.70),
    ("initial_access", ("ssrf", "deserialization"), 0.70),
    ("panel", ("panel",), 0.50),
    ("misconfig", ("misconfig",), 0.50),
    ("exposure", ("exposure",), 0.50),
    ("xss", ("xss",), 0.55),
)

_CWE_TOKEN_RE = re.compile(r"cwe-(\d+)", re.IGNORECASE)
_CWE_NUM_RE = re.compile(r"CWE[-_:\s]*0*([0-9]+)", re.IGNORECASE)
_SHORT_BOUNDED_TOKEN_RES: Dict[str, re.Pattern[str]] = {
    tok: re.compile(rf"(?<![a-z0-9]){re.escape(tok)}(?![a-z0-9])")
    for tok in ("rce", "sqli", "lfi", "smb", "ssh", "rdp", "rpc", "xss")
}


def _needle_matches_lower(needle: str, text_low: str) -> bool:
    pat = _SHORT_BOUNDED_TOKEN_RES.get(needle)
    if pat is not None:
        return pat.search(text_low) is not None
    return needle in text_low


def _default_aci_config() -> ACIConfig:
    defaults = ConfigSource.load_packaged_defaults()
    normalized, issues = validate_and_normalize_semantics(defaults.topn_config)
    if normalized is not None and not issues:
        return normalized.aci
    raise RuntimeError("Packaged tn_triage.json failed ACI semantic validation.")


def _get_duckdb_conn(db: Any) -> Any:
    conn = getattr(db, "conn", None)
    if conn is not None:
        return conn
    if hasattr(db, "execute") and hasattr(db, "appender"):
        return db
    return None


def _effective_text_tokens(cfg: ACIConfig) -> Dict[str, str]:
    mode = str(getattr(cfg, "token_mode", "merge") or "merge").strip().lower()
    disabled = {
        str(token).strip().lower()
        for token in (getattr(cfg, "disabled_core_tokens", ()) or ())
        if str(token).strip()
    }

    if mode == "replace":
        tokens: Dict[str, str] = {}
    else:
        tokens = {
            token: signal
            for token, signal in _CORE_TEXT_TOKENS.items()
            if token not in disabled
        }

    aliases = getattr(cfg, "signal_aliases", ()) or ()
    for item in aliases:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        token = str(item[0]).strip().lower()
        signal = str(item[1]).strip().lower()
        if token and signal:
            tokens[token] = signal

    return tokens


def _bucket_confidence(value: float) -> str:
    if value >= 0.8:
        return "high"
    if value >= 0.5:
        return "medium"
    return "low"


def _normalize_cwe(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return f"CWE-{int(text)}"
    m = _CWE_NUM_RE.search(text)
    if m:
        return f"CWE-{int(m.group(1))}"
    return None


def _extract_cwe_ids_from_scan_finding(finding: "Finding") -> Tuple[str, ...]:
    cwes: Set[str] = set()
    raw_cwes = getattr(finding, "cwes", None)
    if isinstance(raw_cwes, (list, tuple, set)):
        for item in raw_cwes:
            norm = _normalize_cwe(item)
            if norm:
                cwes.add(norm)

    cve_analysis = getattr(finding, "cve_analysis", [])
    if isinstance(cve_analysis, list):
        for entry in cve_analysis:
            if not isinstance(entry, dict):
                continue
            cwe_ids = entry.get("cwe_ids", [])
            if isinstance(cwe_ids, list):
                for item in cwe_ids:
                    normalized = _normalize_cwe(item)
                    if normalized:
                        cwes.add(normalized)
            normalized_single = _normalize_cwe(entry.get("cwe_id"))
            if normalized_single:
                cwes.add(normalized_single)

    return tuple(sorted(cwes))


def _has_exploit_for_confidence(finding: "Finding") -> bool:
    if bool(getattr(finding, "exploit_available", False)):
        return True
    cve_analysis = getattr(finding, "cve_analysis", [])
    if isinstance(cve_analysis, list):
        for entry in cve_analysis:
            if isinstance(entry, dict) and bool(entry.get("exploit_available", False)):
                return True
    return False


_EMPTY_FS: FrozenSet[str] = frozenset()


def _evaluate_aci_signals_to_result(
    *,
    cfg: ACIConfig,
    signals: Set[str],
    matched_tokens: Set[str],
    cwe_ids: Tuple[str, ...],
    has_exploit: bool,
    in_kev: bool,
    has_lateral_kw: bool,
    mode: str,
) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], float, float, Tuple[str, ...], Tuple[str, ...], float]:
    matched_caps: List[str] = []
    confidence_factors: List[str] = []
    capability_weight_max: Dict[str, float] = {}

    lateral_has_context = (
        has_exploit
        or in_kev
        or bool(signals.intersection(_LATERAL_CONTEXT_SIGNALS))
        or has_lateral_kw
    )

    for rule in cfg.capability_rules:
        if not rule.enabled:
            continue
        matched_rule_signals = {sig for sig in rule.signals if sig in signals}
        if not matched_rule_signals:
            continue
        if (
            rule.capability in _REMOTE_SERVICE_ONLY_GUARDRAIL_CAPS
            and matched_rule_signals == {"remote_service"}
        ):
            continue
        if (
            rule.capability == "lateral_movement"
            and matched_rule_signals.issubset(_PROTOCOL_ONLY_LATERAL_SIGNALS)
            and not lateral_has_context
        ):
            continue
        matched_caps.append(rule.capability)
        current = capability_weight_max.get(rule.capability, 0.0)
        capability_weight_max[rule.capability] = max(current, float(rule.weight))
        confidence_factors.append(f"capability_rule:{rule.rule_id}")

    if mode != "replace":
        for cap_name, req_sigs, weight in _EXTRA_CAPABILITY_SIGNALS:
            if any(sig in signals for sig in req_sigs):
                matched_caps.append(cap_name)
                capability_weight_max[cap_name] = max(capability_weight_max.get(cap_name, 0.0), weight)
                confidence_factors.append(f"capability_signal:{cap_name}")

    confidence_base = min(1.0, sum(capability_weight_max.values()))
    exploit_bonus = 0.0
    if cfg.exploit_boost.enabled and has_exploit:
        exploit_bonus = min(
            float(cfg.exploit_boost.max_bonus),
            float(cfg.exploit_boost.weight) * max(0.0, confidence_base),
        )
        if exploit_bonus > 0.0:
            confidence_factors.append("exploit_boost")

    confidence = min(1.0, confidence_base + exploit_bonus)

    matched_set = set(matched_caps)
    chains: List[str] = []
    for rule in cfg.chain_rules:
        if not rule.enabled:
            continue
        if set(rule.requires_all).issubset(matched_set):
            chains.append(rule.label)

    if confidence >= float(cfg.min_confidence):
        denom = max(0.000001, 1.0 - float(cfg.min_confidence))
        rank_uplift = float(cfg.max_uplift) * ((confidence - float(cfg.min_confidence)) / denom)
    else:
        rank_uplift = 0.0
    rank_uplift = max(0.0, min(float(cfg.max_uplift), rank_uplift))

    evidence: List[str] = []
    for cap in sorted(matched_set):
        evidence.append(f"capability:{cap}")
    for chain in chains:
        evidence.append(f"chain:{chain}")
    for signal in sorted(signals):
        evidence.append(f"signal:{signal}")
    for cwe in cwe_ids:
        evidence.append(f"cwe:{cwe}")

    return (
        tuple(sorted(matched_set)),
        tuple(sorted(set(chains))),
        tuple(sorted(matched_tokens | signals)),
        round(confidence, 4),
        round(rank_uplift, 4),
        tuple(sorted(set(confidence_factors))),
        tuple(sorted(set(evidence))),
        round(exploit_bonus, 4),
    )


def _infer_single_record(
    *,
    cfg: ACIConfig,
    text_tokens: Dict[str, str],
    disabled_tokens: Set[str],
    title: str,
    description: str,
    plugin_output: str,
    references: Sequence[str],
    tags: Sequence[str],
    scanner_sig: str,
    affected_port: Optional[int],
    cwe_ids: Tuple[str, ...],
    has_exploit: bool,
    in_kev: bool,
    extra_texts: Sequence[str] = (),
    scanner_sigs: Sequence[str] = (),
) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], float, float, Tuple[str, ...], Tuple[str, ...], float]:
    """
    Core deterministic ACI inference for a single finding.
    Returns (capabilities, chains, matched_tokens, confidence, rank_uplift,
             confidence_factors, evidence, exploit_bonus).
    """
    signals: Set[str] = set()
    matched_tokens: Set[str] = set()
    mode = str(getattr(cfg, "token_mode", "merge") or "merge").strip().lower()

    if has_exploit:
        signals.add("exploit")
    if in_kev:
        signals.add("kev")
    if isinstance(affected_port, int) and affected_port in _REMOTE_PORT_SIGNALS:
        signals.add("remote_service")

    text_parts = [p for p in (title, description, plugin_output, *extra_texts, *references) if p]
    combined_lower = "\n".join(text_parts).lower()

    if combined_lower:
        for needle, signal in text_tokens.items():
            if _needle_matches_lower(needle, combined_lower):
                signals.add(signal)
                matched_tokens.add(needle)
        if mode != "replace":
            for needle, ext_sigs in _EXTENDED_TEXT_TOKENS.items():
                if needle not in disabled_tokens and _needle_matches_lower(needle, combined_lower):
                    signals.update(ext_sigs)
                    matched_tokens.add(needle)

    if mode != "replace":
        # Structured tags (Nuclei tags, SARIF tags, etc.)
        for tag in tags:
            t_low = str(tag or "").strip().lower()
            if not t_low:
                continue
            if t_low in _STRUCTURED_TAG_SIGNALS:
                signals.update(_STRUCTURED_TAG_SIGNALS[t_low])
                matched_tokens.add(t_low)
            elif t_low in text_tokens:
                signals.add(text_tokens[t_low])
                matched_tokens.add(t_low)
            for m in _CWE_TOKEN_RE.finditer(t_low):
                cwe_norm = f"CWE-{int(m.group(1))}"
                if cwe_norm in _CWE_SIGNAL_MAP:
                    signals.update(_CWE_SIGNAL_MAP[cwe_norm])
                    matched_tokens.add(cwe_norm.lower())

        # SARIF / scanner rule signature hints across all contributing signatures
        all_sigs: List[str] = []
        for s_item in scanner_sigs:
            st = str(s_item or "").strip()
            if st and st not in all_sigs:
                all_sigs.append(st)
        if scanner_sig:
            st = str(scanner_sig).strip()
            if st and st not in all_sigs:
                all_sigs.append(st)
        for sig_item in all_sigs:
            sig_low = sig_item.lower()
            sig_spaced = re.sub(r"[/._:-]+", " ", sig_low)
            sig_tokens = set(sig_spaced.split())
            for tag_key, mapped_sigs in _STRUCTURED_TAG_SIGNALS.items():
                if tag_key in {"exposure", "secret", "secrets"}:
                    continue
                spaced_key = tag_key.replace("-", " ")
                if (" " not in spaced_key and spaced_key in sig_tokens) or (
                    " " in spaced_key and spaced_key in sig_spaced
                ):
                    signals.update(mapped_sigs)
                    matched_tokens.add(tag_key)
            for needle, signal in text_tokens.items():
                if _needle_matches_lower(needle, sig_spaced):
                    signals.add(signal)
                    matched_tokens.add(needle)

        # CWE signal enrichment
        for cwe in cwe_ids:
            mapped = _CWE_SIGNAL_MAP.get(cwe)
            if mapped:
                signals.update(mapped)
                matched_tokens.add(cwe.lower())

    has_lateral_kw = any(_needle_matches_lower(kw, combined_lower) for kw in _LATERAL_CONTEXT_KEYWORDS) if combined_lower else False
    return _evaluate_aci_signals_to_result(
        cfg=cfg,
        signals=signals,
        matched_tokens=matched_tokens,
        cwe_ids=cwe_ids,
        has_exploit=has_exploit,
        in_kev=in_kev,
        has_lateral_kw=has_lateral_kw,
        mode=mode,
    )


class AttackCapabilityInferencePass(Pass):
    """
    Attack Capability Inference pass.
    - Legacy ScanResult path: emits ACI@1.0 DerivedPassResult for backward compatibility.
    - DuckDB path (when ctx.db and ctx.run_id are set): batch-streams findings and persists `aci_signals`.
    """

    name = "ACI"
    version = "1.0"
    requires_passes: tuple[str, ...] = ("Scoring@2.0",)

    def __init__(self, aci_config: Optional[Any] = None) -> None:
        if isinstance(aci_config, ACIConfig):
            self.cfg = aci_config
        elif isinstance(aci_config, dict):
            defaults = ConfigSource.load_packaged_defaults()
            merged_topn = dict(defaults.topn_config)
            merged_aci = dict(merged_topn.get("aci") or {})
            if "aci" in aci_config and isinstance(aci_config.get("aci"), dict):
                for key, val in aci_config.items():
                    if key != "aci":
                        merged_topn[key] = val
                merged_aci.update(aci_config["aci"])
            else:
                merged_aci.update(aci_config)
            merged_topn["aci"] = merged_aci
            normalized, issues = validate_and_normalize_semantics(merged_topn)
            if normalized is not None and not issues:
                self.cfg = normalized.aci
            else:
                raise ValueError(f"Invalid ACI config dict: {issues}")
        elif aci_config is None:
            self.cfg = _default_aci_config()
        else:
            raise TypeError(f"Unsupported ACI config type: {type(aci_config).__name__}")

    def _iter_findings(self, scan: "ScanResult") -> Iterable[Tuple[str, "Finding"]]:
        for asset in scan.assets:
            asset_id = getattr(asset, "asset_id", None)
            for finding in asset.findings:
                fid = getattr(finding, "finding_id", None)
                if not fid:
                    continue
                resolved_asset_id = str(getattr(finding, "asset_id", None) or asset_id or "")
                if not resolved_asset_id:
                    continue
                yield resolved_asset_id, finding

    def run(self, ctx: "RunContext", scan: Optional["ScanResult"] = None) -> DerivedPassResult:
        services = getattr(ctx, "services", None)
        db = getattr(ctx, "db", None) or getattr(services, "db", None)
        run_id = getattr(ctx, "run_id", None) or getattr(services, "run_id", None)
        conn = _get_duckdb_conn(db) if (db is not None and run_id is not None) else None

        if conn is not None and run_id is not None:
            return self._run_duckdb(ctx, conn, str(run_id))

        if scan is None:
            raise ValueError("AttackCapabilityInferencePass requires either DuckDB (ctx.db + ctx.run_id) or ScanResult.")

        return self._run_scan_result(ctx, scan)

    def _run_duckdb(self, ctx: "RunContext", conn: Any, run_id: str) -> DerivedPassResult:
        text_tokens = _effective_text_tokens(self.cfg)
        disabled_tokens = {
            str(t).strip().lower()
            for t in (getattr(self.cfg, "disabled_core_tokens", ()) or ())
            if str(t).strip()
        }
        mode = str(getattr(self.cfg, "token_mode", "merge") or "merge").strip().lower()
        text_token_items = tuple(text_tokens.items())
        scanner_prefix_or_digit_tokens = tuple(
            t
            for t, _ in text_token_items
            if any(ch.isdigit() for ch in t)
            or any(_needle_matches_lower(t, prefix) for prefix in ("nessus", "qualys", "openvas"))
        )
        active_ext_items = (
            ()
            if mode == "replace"
            else tuple((k, v) for k, v in _EXTENDED_TEXT_TOKENS.items() if k not in disabled_tokens)
        )
        all_needles_single_line = (
            all("\n" not in k for k, _ in text_token_items)
            and all("\n" not in k for k, _ in active_ext_items)
            and all("\n" not in kw for kw in _LATERAL_CONTEXT_KEYWORDS)
        )

        row_cnt = int((conn.execute("SELECT COUNT(*) FROM findings WHERE run_id = ?", [run_id]).fetchone() or (0,))[0] or 0)
        populate_derived = row_cnt <= 10_000

        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                f.finding_id,
                f.asset_id,
                f.cwes_json,
                f.title,
                f.description,
                f.plugin_output,
                f.affected_port,
                f.tags_json,
                f.exploit_evidence,
                f.references_json,
                COALESCE(e_prim.in_kev, FALSE) OR COALESCE(fc_agg.fc_kev, FALSE) AS in_kev_flag,
                COALESCE(e_prim.verified_exploit, FALSE) OR COALESCE(fc_agg.fc_exp, FALSE) AS ver_exp_flag,
                fe_sig.sig_list AS scanner_sigs
            FROM findings f
            LEFT JOIN enrichment_snapshots e_prim
              ON e_prim.run_id = f.run_id AND e_prim.cve_id = UPPER(f.primary_cve)
            LEFT JOIN (
                SELECT fc.finding_id,
                       BOOL_OR(COALESCE(e.in_kev, FALSE)) AS fc_kev,
                       BOOL_OR(COALESCE(e.verified_exploit, FALSE)) AS fc_exp
                FROM finding_cves fc
                JOIN enrichment_snapshots e
                  ON e.run_id = fc.run_id AND e.cve_id = UPPER(fc.cve_id)
                WHERE fc.run_id = ?
                GROUP BY fc.finding_id
            ) fc_agg
              ON fc_agg.finding_id = f.finding_id
            LEFT JOIN (
                SELECT finding_id, LIST(DISTINCT scanner_sig ORDER BY scanner_sig) AS sig_list
                FROM finding_evidence
                WHERE run_id = ? AND scanner_sig IS NOT NULL AND scanner_sig <> ''
                GROUP BY finding_id
            ) fe_sig
              ON fe_sig.finding_id = f.finding_id
            WHERE f.run_id = ?
            """,
            [run_id, run_id, run_id],
        )

        total_findings = 0
        inferred_findings = 0
        uplifted_findings = 0
        capability_counts: Dict[str, int] = {}
        chain_counts: Dict[str, int] = {}
        confidence_buckets: Dict[str, int] = {"low": 0, "medium": 0, "high": 0}
        finding_semantics: Dict[str, ACIFindingSemantic] = {}
        asset_rollups: Dict[str, Tuple[float, float, int, Set[str], int, float]] = {}

        chain_label_to_id = {r.label: r.rule_id for r in self.cfg.chain_rules}
        json_cache: Dict[Tuple[str, ...], str] = {}
        text_field_memo: Dict[str, Tuple[FrozenSet[str], FrozenSet[str], bool]] = {}
        cwes_memo: Dict[str, Tuple[Tuple[str, ...], FrozenSet[str], FrozenSet[str]]] = {}
        tags_memo: Dict[str, Tuple[FrozenSet[str], FrozenSet[str]]] = {}
        sig_memo: Dict[str, Tuple[FrozenSet[str], FrozenSet[str]]] = {}
        refs_memo: Dict[str, Tuple[str, ...]] = {}
        eval_memo: Dict[
            Tuple[Any, ...],
            Tuple[
                Tuple[str, ...],
                Tuple[str, ...],
                Tuple[str, ...],
                float,
                float,
                Tuple[str, ...],
                Tuple[str, ...],
                float,
                str,
                str,
                str,
            ],
        ] = {}
        legacy_memo: Dict[
            Tuple[Any, ...],
            Tuple[
                Tuple[str, ...],
                Tuple[str, ...],
                Tuple[str, ...],
                float,
                float,
                Tuple[str, ...],
                Tuple[str, ...],
                float,
                Tuple[str, ...],
                str,
                str,
                str,
            ],
        ] = {}

        def _dump_tuple(items: Tuple[str, ...]) -> str:
            if not items:
                return "[]"
            cached = json_cache.get(items)
            if cached is not None:
                return cached
            encoded = json.dumps(list(items), ensure_ascii=True)
            if len(json_cache) < 50_000:
                json_cache[items] = encoded
            return encoded

        def _scan_single_text(raw_s: str) -> Tuple[FrozenSet[str], FrozenSet[str], bool]:
            hit = text_field_memo.get(raw_s)
            if hit is not None:
                return hit
            low = raw_s.lower()
            sigs: Set[str] = set()
            toks: Set[str] = set()
            for needle, signal in text_token_items:
                if _needle_matches_lower(needle, low):
                    sigs.add(signal)
                    toks.add(needle)
            if active_ext_items:
                for needle, ext_sigs in active_ext_items:
                    if _needle_matches_lower(needle, low):
                        sigs.update(ext_sigs)
                        toks.add(needle)
            lat_kw = any(_needle_matches_lower(kw, low) for kw in _LATERAL_CONTEXT_KEYWORDS)
            res = (frozenset(sigs), frozenset(toks), lat_kw)
            if len(text_field_memo) < 100_000:
                text_field_memo[raw_s] = res
            return res

        def _scan_cwes(raw_json: str) -> Tuple[Tuple[str, ...], FrozenSet[str], FrozenSet[str]]:
            hit = cwes_memo.get(raw_json)
            if hit is not None:
                return hit
            try:
                raw_cwes = json.loads(raw_json)
            except Exception:
                raw_cwes = []
            cwe_ids = tuple(
                sorted({c for c in (_normalize_cwe(x) for x in raw_cwes) if c is not None})
            ) if isinstance(raw_cwes, list) else ()
            sigs: Set[str] = set()
            toks: Set[str] = set()
            if mode != "replace":
                for cwe in cwe_ids:
                    mapped = _CWE_SIGNAL_MAP.get(cwe)
                    if mapped:
                        sigs.update(mapped)
                        toks.add(cwe.lower())
            res = (cwe_ids, frozenset(sigs), frozenset(toks))
            if len(cwes_memo) < 50_000:
                cwes_memo[raw_json] = res
            return res

        def _scan_tags(raw_json: str) -> Tuple[FrozenSet[str], FrozenSet[str]]:
            hit = tags_memo.get(raw_json)
            if hit is not None:
                return hit
            sigs: Set[str] = set()
            toks: Set[str] = set()
            if mode != "replace":
                try:
                    raw_tags = json.loads(raw_json)
                except Exception:
                    raw_tags = []
                if isinstance(raw_tags, list):
                    for tag in raw_tags:
                        t_low = str(tag or "").strip().lower()
                        if not t_low:
                            continue
                        if t_low in _STRUCTURED_TAG_SIGNALS:
                            sigs.update(_STRUCTURED_TAG_SIGNALS[t_low])
                            toks.add(t_low)
                        elif t_low in text_tokens:
                            sigs.add(text_tokens[t_low])
                            toks.add(t_low)
                        for m in _CWE_TOKEN_RE.finditer(t_low):
                            cwe_norm = f"CWE-{int(m.group(1))}"
                            if cwe_norm in _CWE_SIGNAL_MAP:
                                sigs.update(_CWE_SIGNAL_MAP[cwe_norm])
                                toks.add(cwe_norm.lower())
            res = (frozenset(sigs), frozenset(toks))
            if len(tags_memo) < 50_000:
                tags_memo[raw_json] = res
            return res

        def _scan_sig(scanner_sig: str) -> Tuple[FrozenSet[str], FrozenSet[str]]:
            hit = sig_memo.get(scanner_sig)
            if hit is not None:
                return hit
            if mode != "replace" and ":" in scanner_sig:
                sig_prefix, sig_rest = scanner_sig.split(":", 1)
                sig_prefix_low = sig_prefix.strip().lower()
                if sig_prefix_low in ("nessus", "qualys", "openvas"):
                    rest_clean = sig_rest.strip().replace(".", "").replace("-", "")
                    if rest_clean.isdigit() and sig_prefix_low not in _STRUCTURED_TAG_SIGNALS:
                        sig_spaced_fast = re.sub(r"[/._:-]+", " ", scanner_sig.strip().lower())
                        if not any(
                            _needle_matches_lower(t, sig_spaced_fast)
                            for t in scanner_prefix_or_digit_tokens
                        ):
                            res_empty = (_EMPTY_FS, _EMPTY_FS)
                            if len(sig_memo) < 50_000:
                                sig_memo[scanner_sig] = res_empty
                            return res_empty
            sigs: Set[str] = set()
            toks: Set[str] = set()
            if mode != "replace" and scanner_sig:
                sig_low = scanner_sig.strip().lower()
                sig_spaced = re.sub(r"[/._:-]+", " ", sig_low)
                sig_tokens = set(sig_spaced.split())
                for tag_key, mapped_sigs in _STRUCTURED_TAG_SIGNALS.items():
                    if tag_key in {"exposure", "secret", "secrets"}:
                        continue
                    spaced_key = tag_key.replace("-", " ")
                    if (" " not in spaced_key and spaced_key in sig_tokens) or (
                        " " in spaced_key and spaced_key in sig_spaced
                    ):
                        sigs.update(mapped_sigs)
                        toks.add(tag_key)
                for needle, signal in text_token_items:
                    if _needle_matches_lower(needle, sig_spaced):
                        sigs.add(signal)
                        toks.add(needle)
            res = (frozenset(sigs), frozenset(toks))
            if len(sig_memo) < 50_000:
                sig_memo[scanner_sig] = res
            return res

        min_conf_f = float(self.cfg.min_confidence)

        conn.execute("BEGIN TRANSACTION")
        try:
            conn.execute("DELETE FROM aci_signals WHERE run_id = ?", [run_id])
            with conn.appender("aci_signals") as appender:
                batch_rows: List[Tuple[Any, ...]] = []
                while True:
                    chunk = cursor.fetchmany(25_000)
                    if not chunk:
                        break
                    for (
                        finding_id,
                        asset_id,
                        cwes_json,
                        title,
                        description,
                        plugin_output,
                        affected_port,
                        tags_json,
                        exploit_evidence,
                        references_json,
                        in_kev_flag,
                        ver_exp_flag,
                        scanner_sigs_col,
                    ) in chunk:
                        total_findings += 1
                        has_exploit = bool(exploit_evidence) or bool(ver_exp_flag)
                        in_kev = bool(in_kev_flag)
                        cwes_s = cwes_json or "[]"
                        tags_s = tags_json or "[]"
                        refs_s = references_json or "[]"
                        sigs_tuple = tuple(str(s) for s in (scanner_sigs_col or ()) if s)

                        if all_needles_single_line:
                            if cwes_s == "[]":
                                cwe_ids: Tuple[str, ...] = ()
                                cwe_sigs, cwe_toks = _EMPTY_FS, _EMPTY_FS
                            else:
                                cwe_ids, cwe_sigs, cwe_toks = _scan_cwes(cwes_s)

                            if tags_s == "[]" or mode == "replace":
                                tag_sigs, tag_toks = _EMPTY_FS, _EMPTY_FS
                            else:
                                tag_sigs, tag_toks = _scan_tags(tags_s)

                            if not sigs_tuple or mode == "replace":
                                sig_sigs, sig_toks = _EMPTY_FS, _EMPTY_FS
                            elif len(sigs_tuple) == 1:
                                sig_sigs, sig_toks = _scan_sig(sigs_tuple[0])
                            else:
                                sig_acc: Set[str] = set()
                                tok_acc: Set[str] = set()
                                for s_item in sigs_tuple:
                                    ss, st = _scan_sig(s_item)
                                    if ss:
                                        sig_acc.update(ss)
                                    if st:
                                        tok_acc.update(st)
                                sig_sigs, sig_toks = frozenset(sig_acc), frozenset(tok_acc)

                            has_remote_port = isinstance(affected_port, int) and affected_port in _REMOTE_PORT_SIGNALS

                            t_sigs, t_toks, t_lat = _scan_single_text(title) if title else (_EMPTY_FS, _EMPTY_FS, False)
                            d_sigs, d_toks, d_lat = _scan_single_text(description) if description else (_EMPTY_FS, _EMPTY_FS, False)
                            p_sigs, p_toks, p_lat = _scan_single_text(plugin_output) if plugin_output else (_EMPTY_FS, _EMPTY_FS, False)

                            has_lat_kw = t_lat or d_lat or p_lat
                            sigs_fs = cwe_sigs | tag_sigs | sig_sigs | t_sigs | d_sigs | p_sigs
                            toks_fs = cwe_toks | tag_toks | sig_toks | t_toks | d_toks | p_toks

                            if refs_s != "[]":
                                ref_tuple = refs_memo.get(refs_s)
                                if ref_tuple is None:
                                    try:
                                        parsed_r = json.loads(refs_s)
                                        ref_tuple = tuple(str(r) for r in parsed_r if r) if isinstance(parsed_r, list) else ()
                                    except Exception:
                                        ref_tuple = ()
                                    if len(refs_memo) < 50_000:
                                        refs_memo[refs_s] = ref_tuple
                                for ref_item in ref_tuple:
                                    r_sigs, r_toks, r_lat = _scan_single_text(ref_item)
                                    if r_sigs:
                                        sigs_fs = sigs_fs | r_sigs
                                    if r_toks:
                                        toks_fs = toks_fs | r_toks
                                    if r_lat:
                                        has_lat_kw = True

                            if has_exploit or in_kev or has_remote_port:
                                extra_sigs: Set[str] = set()
                                if has_exploit:
                                    extra_sigs.add("exploit")
                                if in_kev:
                                    extra_sigs.add("kev")
                                if has_remote_port:
                                    extra_sigs.add("remote_service")
                                sigs_fs = sigs_fs | frozenset(extra_sigs)

                            eval_key = (sigs_fs, toks_fs, cwe_ids, has_exploit, in_kev, has_lat_kw)
                            ev_hit = eval_memo.get(eval_key)
                            if ev_hit is None:
                                inferred = _evaluate_aci_signals_to_result(
                                    cfg=self.cfg,
                                    signals=set(sigs_fs),
                                    matched_tokens=set(toks_fs),
                                    cwe_ids=cwe_ids,
                                    has_exploit=has_exploit,
                                    in_kev=in_kev,
                                    has_lateral_kw=has_lat_kw,
                                    mode=mode,
                                )
                                ev_hit = (
                                    *inferred,
                                    _dump_tuple(inferred[0]),
                                    _dump_tuple(inferred[1]),
                                    _dump_tuple(inferred[2]),
                                )
                                if len(eval_memo) < 100_000:
                                    eval_memo[eval_key] = ev_hit
                            (
                                caps,
                                chains,
                                matched_toks,
                                confidence,
                                rank_uplift,
                                conf_factors,
                                evidence,
                                exp_bonus,
                                caps_json_str,
                                chains_json_str,
                                toks_json_str,
                            ) = ev_hit
                        else:
                            memo_key = (
                                sigs_tuple,
                                title or "",
                                description or "",
                                plugin_output or "",
                                cwes_s,
                                tags_s,
                                refs_s,
                                affected_port,
                                has_exploit,
                                in_kev,
                            )
                            cached_res = legacy_memo.get(memo_key)
                            if cached_res is None:
                                try:
                                    raw_cwes = json.loads(cwes_s) if cwes_s != "[]" else []
                                except Exception:
                                    raw_cwes = []
                                cwe_ids = tuple(
                                    sorted({c for c in (_normalize_cwe(x) for x in raw_cwes) if c is not None})
                                )
                                try:
                                    raw_tags = json.loads(tags_s) if tags_s != "[]" else []
                                except Exception:
                                    raw_tags = []
                                try:
                                    raw_refs = json.loads(refs_s) if refs_s != "[]" else []
                                except Exception:
                                    raw_refs = []

                                inferred = _infer_single_record(
                                    cfg=self.cfg,
                                    text_tokens=text_tokens,
                                    disabled_tokens=disabled_tokens,
                                    title=title or "",
                                    description=description or "",
                                    plugin_output=plugin_output or "",
                                    references=[str(r) for r in raw_refs if r],
                                    tags=[str(t) for t in raw_tags if t],
                                    scanner_sig=sigs_tuple[0] if sigs_tuple else "",
                                    scanner_sigs=sigs_tuple,
                                    affected_port=int(affected_port) if affected_port is not None else None,
                                    cwe_ids=cwe_ids,
                                    has_exploit=has_exploit,
                                    in_kev=in_kev,
                                )
                                cached_res = (
                                    *inferred,
                                    cwe_ids,
                                    _dump_tuple(inferred[0]),
                                    _dump_tuple(inferred[1]),
                                    _dump_tuple(inferred[2]),
                                )
                                if len(legacy_memo) < 100_000:
                                    legacy_memo[memo_key] = cached_res
                            (
                                caps,
                                chains,
                                matched_toks,
                                confidence,
                                rank_uplift,
                                conf_factors,
                                evidence,
                                exp_bonus,
                                cwe_ids,
                                caps_json_str,
                                chains_json_str,
                                toks_json_str,
                            ) = cached_res

                        batch_rows.append(
                            (
                                run_id,
                                finding_id,
                                asset_id,
                                caps_json_str,
                                chains_json_str,
                                toks_json_str,
                                confidence,
                                rank_uplift,
                            )
                        )
                        if len(batch_rows) >= 25_000:
                            appender.append_rows(batch_rows)
                            batch_rows.clear()

                        for cap in caps:
                            capability_counts[cap] = capability_counts.get(cap, 0) + 1
                        for ch in chains:
                            rid = chain_label_to_id.get(ch, ch)
                            chain_counts[rid] = chain_counts.get(rid, 0) + 1

                        if caps and confidence >= min_conf_f:
                            inferred_findings += 1
                        if rank_uplift > 0.0:
                            uplifted_findings += 1
                        bucket = _bucket_confidence(confidence)
                        confidence_buckets[bucket] = confidence_buckets.get(bucket, 0) + 1

                        prev_r = asset_rollups.get(asset_id)
                        if prev_r is None:
                            asset_rollups[asset_id] = (
                                confidence,
                                confidence,
                                1,
                                set(caps),
                                len(chains),
                                rank_uplift,
                            )
                        else:
                            prev_r[3].update(caps)
                            asset_rollups[asset_id] = (
                                prev_r[0] + confidence,
                                max(prev_r[1], confidence),
                                prev_r[2] + 1,
                                prev_r[3],
                                prev_r[4] + len(chains),
                                prev_r[5] + rank_uplift,
                            )

                        if populate_derived:
                            finding_semantics[finding_id] = ACIFindingSemantic(
                                finding_id=finding_id,
                                asset_id=asset_id,
                                confidence=confidence,
                                confidence_factors=conf_factors,
                                capabilities=caps,
                                chain_candidates=chains,
                                cwe_ids=cwe_ids,
                                evidence=evidence,
                                exploit_boost_applied=exp_bonus,
                                rank_uplift=rank_uplift,
                            )
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
            try:
                cursor.close()
            except Exception:
                pass

        asset_semantics: Dict[str, ACIAssetSemantic] = {}
        if len(asset_rollups) <= 50_000:
            for aid, (sum_c, max_c, cnt, cap_u, ch_cnt, sum_up) in asset_rollups.items():
                asset_uplift = min(float(self.cfg.max_uplift), sum_up * float(self.cfg.asset_uplift_weight))
                asset_semantics[aid] = ACIAssetSemantic(
                    asset_id=aid,
                    weighted_confidence=round(sum_c / cnt, 4),
                    max_confidence=round(max_c, 4),
                    capability_count=len(cap_u),
                    chain_candidate_count=ch_cnt,
                    ranked_finding_count=cnt,
                    rank_uplift=round(asset_uplift, 4),
                )

        coverage_ratio = (float(inferred_findings) / float(total_findings)) if total_findings else 0.0
        output = ACIPassOutput(
            finding_semantics=finding_semantics,
            asset_semantics=asset_semantics,
            metrics=ACIPassMetrics(
                total_findings=total_findings,
                inferred_findings=inferred_findings,
                coverage_ratio=round(coverage_ratio, 4),
                capabilities_detected=dict(sorted(capability_counts.items())),
                chain_candidates_detected=dict(sorted(chain_counts.items())),
                confidence_buckets=confidence_buckets,
                uplifted_findings=uplifted_findings,
            ),
        )
        self._emit_ledger(ctx, output)
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived DuckDB Attack Capability Inference output.",
        )
        return DerivedPassResult(meta=meta, data=asdict(output))

    def _run_scan_result(self, ctx: "RunContext", scan: "ScanResult") -> DerivedPassResult:
        text_tokens = _effective_text_tokens(self.cfg)
        disabled_tokens = {
            str(t).strip().lower()
            for t in (getattr(self.cfg, "disabled_core_tokens", ()) or ())
            if str(t).strip()
        }

        finding_semantics: Dict[str, ACIFindingSemantic] = {}
        asset_rollups: Dict[str, List[ACIFindingSemantic]] = {}
        capability_counts: Dict[str, int] = {}
        chain_counts: Dict[str, int] = {}
        confidence_buckets = {"low": 0, "medium": 0, "high": 0}
        chain_label_to_id = {r.label: r.rule_id for r in self.cfg.chain_rules}

        total_findings = 0
        inferred_findings = 0
        uplifted_findings = 0

        for asset_id, finding in self._iter_findings(scan):
            total_findings += 1
            finding_id = str(getattr(finding, "finding_id", ""))
            cwe_ids = _extract_cwe_ids_from_scan_finding(finding)
            has_exploit = _has_exploit_for_confidence(finding)
            in_kev = bool(getattr(finding, "cisa_kev", False))

            extra_texts: List[str] = []
            cve_analysis = getattr(finding, "cve_analysis", [])
            if isinstance(cve_analysis, list):
                for entry in cve_analysis:
                    if isinstance(entry, dict):
                        for fld in ("description", "summary", "vector"):
                            val = entry.get(fld)
                            if isinstance(val, str) and val:
                                extra_texts.append(val)

            raw_refs = getattr(finding, "references", []) or []
            raw_tags = getattr(finding, "tags", []) or []
            scanner_sig = str(getattr(finding, "detection_plugin", None) or getattr(finding, "scanner_sig", None) or "")

            caps, chains, _matched_toks, confidence, rank_uplift, conf_factors, evidence, exp_bonus = _infer_single_record(
                cfg=self.cfg,
                text_tokens=text_tokens,
                disabled_tokens=disabled_tokens,
                title=str(getattr(finding, "title", None) or ""),
                description=str(getattr(finding, "description", None) or ""),
                plugin_output=str(getattr(finding, "plugin_output", None) or ""),
                references=[str(r) for r in raw_refs if isinstance(r, str)],
                tags=[str(t) for t in raw_tags if isinstance(t, str)],
                scanner_sig=scanner_sig,
                affected_port=getattr(finding, "affected_port", None),
                cwe_ids=cwe_ids,
                has_exploit=has_exploit,
                in_kev=in_kev,
                extra_texts=extra_texts,
            )

            for cap in caps:
                capability_counts[cap] = capability_counts.get(cap, 0) + 1
            for ch in chains:
                rid = chain_label_to_id.get(ch, ch)
                chain_counts[rid] = chain_counts.get(rid, 0) + 1

            if caps and confidence >= float(self.cfg.min_confidence):
                inferred_findings += 1
            if rank_uplift > 0.0:
                uplifted_findings += 1

            bucket = _bucket_confidence(confidence)
            confidence_buckets[bucket] = confidence_buckets.get(bucket, 0) + 1

            semantic = ACIFindingSemantic(
                finding_id=finding_id,
                asset_id=asset_id,
                confidence=confidence,
                confidence_factors=conf_factors,
                capabilities=caps,
                chain_candidates=chains,
                cwe_ids=cwe_ids,
                evidence=evidence,
                exploit_boost_applied=exp_bonus,
                rank_uplift=rank_uplift,
            )
            finding_semantics[finding_id] = semantic
            asset_rollups.setdefault(asset_id, []).append(semantic)

        asset_semantics: Dict[str, ACIAssetSemantic] = {}
        for asset_id, rows in asset_rollups.items():
            if not rows:
                continue
            total_confidence = sum(r.confidence for r in rows)
            max_conf = max(r.confidence for r in rows)
            avg_conf = total_confidence / len(rows)
            capability_union: Set[str] = set()
            chain_total = 0
            total_uplift = 0.0
            for row in rows:
                capability_union.update(row.capabilities)
                chain_total += len(row.chain_candidates)
                total_uplift += row.rank_uplift

            rank_uplift = min(
                float(self.cfg.max_uplift),
                total_uplift * float(self.cfg.asset_uplift_weight),
            )

            asset_semantics[asset_id] = ACIAssetSemantic(
                asset_id=asset_id,
                weighted_confidence=round(avg_conf, 4),
                max_confidence=round(max_conf, 4),
                capability_count=len(capability_union),
                chain_candidate_count=chain_total,
                ranked_finding_count=len(rows),
                rank_uplift=round(rank_uplift, 4),
            )

        coverage_ratio = (float(inferred_findings) / float(total_findings)) if total_findings else 0.0
        output = ACIPassOutput(
            finding_semantics=finding_semantics,
            asset_semantics=asset_semantics,
            metrics=ACIPassMetrics(
                total_findings=total_findings,
                inferred_findings=inferred_findings,
                coverage_ratio=round(coverage_ratio, 4),
                capabilities_detected=dict(sorted(capability_counts.items())),
                chain_candidates_detected=dict(sorted(chain_counts.items())),
                confidence_buckets=confidence_buckets,
                uplifted_findings=uplifted_findings,
            ),
        )
        self._emit_ledger(ctx, output)
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived Attack Capability Inference output.",
        )
        return DerivedPassResult(meta=meta, data=asdict(output))

    def _emit_ledger(self, ctx: "RunContext", output: ACIPassOutput) -> None:
        ledger = getattr(getattr(ctx, "services", None), "ledger", None)
        if ledger is None:
            return
        ledger.append_event(
            component="ACI",
            event_type="decision",
            subject_ref="aci:summary",
            reason_code=DecisionReasonCodes.ACI_INFERENCE_SUMMARY,
            reason_text="Attack capability inference summary computed.",
            factor_refs=["aci.enabled", "aci.min_confidence", "aci.max_uplift"],
            evidence={
                "enabled": bool(self.cfg.enabled),
                "total_findings": output.metrics.total_findings,
                "inferred_findings": output.metrics.inferred_findings,
                "uplifted_findings": output.metrics.uplifted_findings,
            },
        )
        for semantic in list(output.finding_semantics.values())[:10]:
            if not semantic.capabilities:
                continue
            ledger.append_event(
                component="ACI",
                event_type="decision",
                subject_ref=f"finding:{semantic.finding_id}",
                reason_code=DecisionReasonCodes.ACI_FINDING_INFERRED,
                reason_text="Attack capability inferred for finding.",
                factor_refs=["aci.capability_rules", "aci.chain_rules", "aci.exploit_boost"],
                confidence=_bucket_confidence(semantic.confidence),
                evidence={
                    "asset_id": semantic.asset_id,
                    "confidence": semantic.confidence,
                    "capabilities": list(semantic.capabilities),
                    "chain_candidates": list(semantic.chain_candidates),
                    "rank_uplift": semantic.rank_uplift,
                },
            )


class ACIV2Pass(AttackCapabilityInferencePass):
    """DuckDB-first ACI@2.0 pass (default-enabled, CWE/Nuclei/SARIF-aware)."""

    name = "ACI"
    version = "2.0"
    requires_passes: tuple[str, ...] = ()
