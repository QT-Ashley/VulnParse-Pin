# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# -----------------------------------------------
# Issue Collection
# -----------------------------------------------

@dataclass(frozen=True)
class SemanticIssue:
    """
    Semantic validation issue object.
    """
    path: str
    message: str
    code: str
    detail: str = ""

class SemanticValidationError(ValueError):
    def __init__(self, issues: Sequence[SemanticIssue]) -> None:
        self.issues = issues
        super().__init__(f"TopN config failed semantic validation ({len(self.issues)} issue(s)).")


# -----------------------------------------------
# Config Normalization
# -----------------------------------------------

@dataclass(frozen=True)
class TopNConfig:
    """
    TopN Ranking Config
    """
    rank_basis: str
    decay: Tuple[float, ...]
    k: int
    max_assets: int
    max_findings_per_asset: int
    include_global_top_findings: bool
    global_top_findings: int

@dataclass(frozen=True)
class ConfidenceThreshold:
    """
    Confidence Thresholds
    """
    low: int
    medium: int
    high: int

@dataclass(frozen=True)
class ParsedPredicate:
    """
    Canonical predicate representation.
    """
    name: str
    ports: Tuple[int, ...] = ()
    tokens: Tuple[str, ...] = ()

@dataclass(frozen=True)
class ParsedRule:
    rule_id: str
    enabled: bool
    tag: str
    weight: int
    predicate: ParsedPredicate
    evidence: str

@dataclass(frozen=True)
class InferenceConfig:
    confidence_thresholds: ConfidenceThreshold
    public_service_ports: Tuple[int, ...]
    public_service_ports_set: frozenset[int]
    allow_predicates: frozenset[str]
    finding_text_min_token_matches: int
    finding_text_title_weight: int
    finding_text_description_weight: int
    finding_text_plugin_output_weight: int
    finding_text_max_weighted_hits: int
    finding_text_conflict_tokens: Tuple[str, ...]
    finding_text_conflict_penalty: int
    finding_text_diminishing_factors: Tuple[float, ...]
    rules: Tuple[ParsedRule, ...]


@dataclass(frozen=True)
class ACIExploitBoost:
    enabled: bool
    weight: float
    max_bonus: float


@dataclass(frozen=True)
class ACICapabilityRule:
    rule_id: str
    enabled: bool
    capability: str
    signals: Tuple[str, ...]
    weight: float


@dataclass(frozen=True)
class ACIChainRule:
    rule_id: str
    enabled: bool
    requires_all: Tuple[str, ...]
    label: str


@dataclass(frozen=True)
class ACIConfig:
    enabled: bool
    min_confidence: float
    max_uplift: float
    asset_uplift_weight: float
    exploit_boost: ACIExploitBoost
    capability_rules: Tuple[ACICapabilityRule, ...]
    chain_rules: Tuple[ACIChainRule, ...]
    token_mode: str = "merge"
    signal_aliases: Tuple[Tuple[str, str], ...] = ()
    disabled_core_tokens: Tuple[str, ...] = ()


@dataclass(frozen=True)
class TriagePolicyConfig:
    enabled: bool
    oal1_risk_bands: Tuple[str, ...]
    oal1_require_public_exposure: bool
    oal1_require_exploit_or_kev: bool
    oal2_risk_bands: Tuple[str, ...]
    oal2_min_aci_confidence: float
    oal2_require_chain_candidate: bool
    oal2_require_public_exposure: bool
    preserve_oal1_precedence: bool

@dataclass(frozen=True)
class TNTriageConfig:
    topn: TopNConfig
    inference: InferenceConfig
    aci: ACIConfig
    triage_policy: TriagePolicyConfig


# -----------------------------------------------
# API
# -----------------------------------------------

def validate_and_normalize_semantics(raw: Dict[str, Any]) -> Tuple[Optional[TNTriageConfig], List[SemanticIssue]]:
    """
    Semantic validation and normalization for TopN config.
    
    :returns: (topn_config or None, issues)
    """
    issues: List[SemanticIssue] = []

    topn_raw = raw.get("topn", {})
    inf_raw = raw.get("inference", {})
    aci_raw = raw.get("aci", {})
    triage_policy_raw = raw.get("triage_policy", {})


    # ---- topn semantics
    topn_cfg = _parse_topn(topn_raw, issues)

    # ---- inference semantics
    inf_cfg = _parse_inference(inf_raw, issues)
    aci_cfg = _parse_aci(aci_raw, issues)
    triage_policy_cfg = _parse_triage_policy(triage_policy_raw, issues)

    if issues:
        return None, issues

    assert topn_cfg is not None and inf_cfg is not None and aci_cfg is not None and triage_policy_cfg is not None
    return TNTriageConfig(topn=topn_cfg, inference=inf_cfg, aci=aci_cfg, triage_policy=triage_policy_cfg), issues


def _parse_triage_policy(raw: Dict[str, Any], issues: List[SemanticIssue]) -> Optional[TriagePolicyConfig]:
    if not isinstance(raw, dict):
        issues.append(SemanticIssue("/triage_policy", "triage_policy must be an object", "TRIAGE_POLICY_TYPE"))
        return None

    enabled = bool(raw.get("enabled", True))
    allowed_bands = {"critical", "high", "medium", "low", "informational"}

    def _parse_band_list(path: str, value: Any, default: Tuple[str, ...]) -> Tuple[str, ...]:
        if value is None:
            return default
        if not isinstance(value, list):
            issues.append(SemanticIssue(path, "risk band list must be an array", "TRIAGE_BANDS_TYPE"))
            return default
        normalized: List[str] = []
        seen: Set[str] = set()
        for idx, item in enumerate(value):
            band = str(item).strip().lower()
            if band not in allowed_bands:
                issues.append(SemanticIssue(f"{path}/{idx}", f"invalid risk band: {band}", "TRIAGE_BAND_INVALID"))
                continue
            if band in seen:
                continue
            seen.add(band)
            normalized.append(band)
        if not normalized:
            issues.append(SemanticIssue(path, "risk band list cannot be empty", "TRIAGE_BANDS_EMPTY"))
            return default
        return tuple(normalized)

    def _pick(primary: str, legacy: str, default: Any) -> Any:
        if primary in raw:
            return raw.get(primary)
        if legacy in raw:
            return raw.get(legacy)
        return default

    oal1_risk_bands = _parse_band_list(
        "/triage_policy/oal1_risk_bands",
        _pick("oal1_risk_bands", "p1_risk_bands", ["critical", "high"]),
        ("critical", "high"),
    )
    oal2_risk_bands = _parse_band_list(
        "/triage_policy/oal2_risk_bands",
        _pick("oal2_risk_bands", "p1b_risk_bands", ["critical", "high", "medium"]),
        ("critical", "high", "medium"),
    )

    oal1_require_public_exposure = bool(_pick("oal1_require_public_exposure", "p1_require_public_exposure", True))
    oal1_require_exploit_or_kev = bool(_pick("oal1_require_exploit_or_kev", "p1_require_exploit_or_kev", True))

    try:
        oal2_min_aci_confidence = float(_pick("oal2_min_aci_confidence", "p1b_min_aci_confidence", 0.8))
    except (TypeError, ValueError):
        issues.append(SemanticIssue("/triage_policy/oal2_min_aci_confidence", "oal2_min_aci_confidence must be a number", "TRIAGE_OAL2_CONF_TYPE"))
        oal2_min_aci_confidence = 0.8
    if oal2_min_aci_confidence < 0.0 or oal2_min_aci_confidence > 1.0:
        issues.append(SemanticIssue("/triage_policy/oal2_min_aci_confidence", "oal2_min_aci_confidence must be between 0.0 and 1.0", "TRIAGE_OAL2_CONF_RANGE"))
        oal2_min_aci_confidence = min(1.0, max(0.0, oal2_min_aci_confidence))

    oal2_require_chain_candidate = bool(_pick("oal2_require_chain_candidate", "p1b_require_chain_candidate", True))
    oal2_require_public_exposure = bool(_pick("oal2_require_public_exposure", "p1b_require_public_exposure", True))
    preserve_oal1_precedence = bool(_pick("preserve_oal1_precedence", "preserve_p1_precedence", True))

    return TriagePolicyConfig(
        enabled=enabled,
        oal1_risk_bands=oal1_risk_bands,
        oal1_require_public_exposure=oal1_require_public_exposure,
        oal1_require_exploit_or_kev=oal1_require_exploit_or_kev,
        oal2_risk_bands=oal2_risk_bands,
        oal2_min_aci_confidence=oal2_min_aci_confidence,
        oal2_require_chain_candidate=oal2_require_chain_candidate,
        oal2_require_public_exposure=oal2_require_public_exposure,
        preserve_oal1_precedence=preserve_oal1_precedence,
    )


def _parse_aci(aci_raw: Dict[str, Any], issues: List[SemanticIssue]) -> Optional[ACIConfig]:
    if not isinstance(aci_raw, dict):
        issues.append(SemanticIssue("/aci", "aci must be an object", "ACI_TYPE"))
        return None

    enabled = bool(aci_raw.get("enabled", False))

    min_confidence_raw = aci_raw.get("min_confidence", 0.6)
    max_uplift_raw = aci_raw.get("max_uplift", 2.0)
    asset_uplift_weight_raw = aci_raw.get("asset_uplift_weight", 0.5)

    try:
        min_confidence = float(min_confidence_raw)
    except (TypeError, ValueError):
        issues.append(SemanticIssue("/aci/min_confidence", "min_confidence must be a number", "ACI_MIN_CONF_TYPE"))
        min_confidence = 0.6
    try:
        max_uplift = float(max_uplift_raw)
    except (TypeError, ValueError):
        issues.append(SemanticIssue("/aci/max_uplift", "max_uplift must be a number", "ACI_MAX_UPLIFT_TYPE"))
        max_uplift = 2.0
    try:
        asset_uplift_weight = float(asset_uplift_weight_raw)
    except (TypeError, ValueError):
        issues.append(SemanticIssue("/aci/asset_uplift_weight", "asset_uplift_weight must be a number", "ACI_ASSET_UPLIFT_WEIGHT_TYPE"))
        asset_uplift_weight = 0.5

    if min_confidence < 0.0 or min_confidence > 1.0:
        issues.append(SemanticIssue("/aci/min_confidence", "min_confidence must be between 0.0 and 1.0", "ACI_MIN_CONF_RANGE"))
        min_confidence = min(1.0, max(0.0, min_confidence))
    if max_uplift < 0.0:
        issues.append(SemanticIssue("/aci/max_uplift", "max_uplift must be >= 0.0", "ACI_MAX_UPLIFT_RANGE"))
        max_uplift = 0.0
    if asset_uplift_weight < 0.0 or asset_uplift_weight > 1.0:
        issues.append(SemanticIssue("/aci/asset_uplift_weight", "asset_uplift_weight must be between 0.0 and 1.0", "ACI_ASSET_UPLIFT_WEIGHT_RANGE"))
        asset_uplift_weight = min(1.0, max(0.0, asset_uplift_weight))

    token_mode = str(aci_raw.get("token_mode", "merge") or "merge").strip().lower()
    if token_mode not in ("merge", "replace"):
        issues.append(SemanticIssue("/aci/token_mode", "token_mode must be either 'merge' or 'replace'", "ACI_TOKEN_MODE"))
        token_mode = "merge"

    signal_aliases_raw = aci_raw.get("signal_aliases", [])
    if not isinstance(signal_aliases_raw, list):
        issues.append(SemanticIssue("/aci/signal_aliases", "signal_aliases must be an array", "ACI_SIGNAL_ALIASES_TYPE"))
        signal_aliases_raw = []
    signal_aliases: List[Tuple[str, str]] = []
    seen_alias_tokens: Set[str] = set()
    for idx, item in enumerate(signal_aliases_raw):
        if not isinstance(item, dict):
            issues.append(SemanticIssue(f"/aci/signal_aliases/{idx}", "alias entry must be an object", "ACI_SIGNAL_ALIAS_ENTRY_TYPE"))
            continue
        token = str(item.get("token", "")).strip().lower()
        signal = str(item.get("signal", "")).strip().lower()
        if not token:
            issues.append(SemanticIssue(f"/aci/signal_aliases/{idx}/token", "token must be a non-empty string", "ACI_SIGNAL_ALIAS_TOKEN"))
            continue
        if not signal:
            issues.append(SemanticIssue(f"/aci/signal_aliases/{idx}/signal", "signal must be a non-empty string", "ACI_SIGNAL_ALIAS_SIGNAL"))
            continue
        if len(token) > 64:
            issues.append(SemanticIssue(f"/aci/signal_aliases/{idx}/token", "token max length is 64", "ACI_SIGNAL_ALIAS_TOKEN_LEN"))
            continue
        if len(signal) > 64:
            issues.append(SemanticIssue(f"/aci/signal_aliases/{idx}/signal", "signal max length is 64", "ACI_SIGNAL_ALIAS_SIGNAL_LEN"))
            continue
        if token in seen_alias_tokens:
            issues.append(SemanticIssue(f"/aci/signal_aliases/{idx}/token", f"duplicate alias token: {token}", "ACI_SIGNAL_ALIAS_TOKEN_DUP"))
            continue
        seen_alias_tokens.add(token)
        signal_aliases.append((token, signal))

    disabled_core_tokens_raw = aci_raw.get("disabled_core_tokens", [])
    if not isinstance(disabled_core_tokens_raw, list):
        issues.append(SemanticIssue("/aci/disabled_core_tokens", "disabled_core_tokens must be an array", "ACI_DISABLED_CORE_TOKENS_TYPE"))
        disabled_core_tokens_raw = []
    disabled_core_tokens: List[str] = []
    seen_disabled_tokens: Set[str] = set()
    for idx, token_raw in enumerate(disabled_core_tokens_raw):
        token = str(token_raw).strip().lower()
        if not token:
            issues.append(SemanticIssue(f"/aci/disabled_core_tokens/{idx}", "disabled token must be non-empty", "ACI_DISABLED_CORE_TOKEN_EMPTY"))
            continue
        if len(token) > 64:
            issues.append(SemanticIssue(f"/aci/disabled_core_tokens/{idx}", "disabled token max length is 64", "ACI_DISABLED_CORE_TOKEN_LEN"))
            continue
        if token in seen_disabled_tokens:
            issues.append(SemanticIssue(f"/aci/disabled_core_tokens/{idx}", f"duplicate disabled token: {token}", "ACI_DISABLED_CORE_TOKEN_DUP"))
            continue
        seen_disabled_tokens.add(token)
        disabled_core_tokens.append(token)

    exploit_boost_raw = aci_raw.get("exploit_boost", {})
    if not isinstance(exploit_boost_raw, dict):
        issues.append(SemanticIssue("/aci/exploit_boost", "exploit_boost must be an object", "ACI_EXPLOIT_BOOST_TYPE"))
        exploit_boost_raw = {}

    exploit_enabled = bool(exploit_boost_raw.get("enabled", True))
    try:
        exploit_weight = float(exploit_boost_raw.get("weight", 0.25))
    except (TypeError, ValueError):
        issues.append(SemanticIssue("/aci/exploit_boost/weight", "exploit_boost.weight must be a number", "ACI_EXPLOIT_WEIGHT_TYPE"))
        exploit_weight = 0.25
    try:
        exploit_max_bonus = float(exploit_boost_raw.get("max_bonus", 0.2))
    except (TypeError, ValueError):
        issues.append(SemanticIssue("/aci/exploit_boost/max_bonus", "exploit_boost.max_bonus must be a number", "ACI_EXPLOIT_MAX_BONUS_TYPE"))
        exploit_max_bonus = 0.2

    if exploit_weight < 0.0 or exploit_weight > 1.0:
        issues.append(SemanticIssue("/aci/exploit_boost/weight", "exploit_boost.weight must be between 0.0 and 1.0", "ACI_EXPLOIT_WEIGHT_RANGE"))
        exploit_weight = min(1.0, max(0.0, exploit_weight))
    if exploit_max_bonus < 0.0:
        issues.append(SemanticIssue("/aci/exploit_boost/max_bonus", "exploit_boost.max_bonus must be >= 0.0", "ACI_EXPLOIT_MAX_BONUS_RANGE"))
        exploit_max_bonus = 0.0

    capability_rules_raw = aci_raw.get("capability_rules", [])
    if not isinstance(capability_rules_raw, list):
        issues.append(SemanticIssue("/aci/capability_rules", "capability_rules must be an array", "ACI_CAP_RULES_TYPE"))
        capability_rules_raw = []

    capability_rules: List[ACICapabilityRule] = []
    seen_cap_rule_ids: Set[str] = set()
    for idx, rule in enumerate(capability_rules_raw):
        if not isinstance(rule, dict):
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}", "rule must be an object", "ACI_CAP_RULE_TYPE"))
            continue
        rule_id = str(rule.get("id", "")).strip()
        if not rule_id:
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}/id", "id must be a non-empty string", "ACI_CAP_RULE_ID"))
            continue
        if rule_id in seen_cap_rule_ids:
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}/id", f"duplicate rule id: {rule_id}", "ACI_CAP_RULE_ID_DUP"))
            continue
        seen_cap_rule_ids.add(rule_id)

        capability = str(rule.get("capability", "")).strip().lower()
        if not capability:
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}/capability", "capability must be a non-empty string", "ACI_CAP_RULE_CAPABILITY"))
            continue

        signals_raw = rule.get("signals", [])
        if not isinstance(signals_raw, list) or not signals_raw:
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}/signals", "signals must be a non-empty array", "ACI_CAP_RULE_SIGNALS"))
            continue
        signals = tuple(str(s).strip().lower() for s in signals_raw if str(s).strip())
        if not signals:
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}/signals", "signals cannot be empty after normalization", "ACI_CAP_RULE_SIGNALS_EMPTY"))
            continue

        try:
            weight = float(rule.get("weight", 0.0))
        except (TypeError, ValueError):
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}/weight", "weight must be a number", "ACI_CAP_RULE_WEIGHT_TYPE"))
            continue
        if weight < 0.0 or weight > 1.0:
            issues.append(SemanticIssue(f"/aci/capability_rules/{idx}/weight", "weight must be between 0.0 and 1.0", "ACI_CAP_RULE_WEIGHT_RANGE"))
            continue

        capability_rules.append(
            ACICapabilityRule(
                rule_id=rule_id,
                enabled=bool(rule.get("enabled", True)),
                capability=capability,
                signals=signals,
                weight=weight,
            )
        )

    chain_rules_raw = aci_raw.get("chain_rules", [])
    if not isinstance(chain_rules_raw, list):
        issues.append(SemanticIssue("/aci/chain_rules", "chain_rules must be an array", "ACI_CHAIN_RULES_TYPE"))
        chain_rules_raw = []

    chain_rules: List[ACIChainRule] = []
    seen_chain_ids: Set[str] = set()
    for idx, rule in enumerate(chain_rules_raw):
        if not isinstance(rule, dict):
            issues.append(SemanticIssue(f"/aci/chain_rules/{idx}", "rule must be an object", "ACI_CHAIN_RULE_TYPE"))
            continue
        rule_id = str(rule.get("id", "")).strip()
        if not rule_id:
            issues.append(SemanticIssue(f"/aci/chain_rules/{idx}/id", "id must be a non-empty string", "ACI_CHAIN_RULE_ID"))
            continue
        if rule_id in seen_chain_ids:
            issues.append(SemanticIssue(f"/aci/chain_rules/{idx}/id", f"duplicate rule id: {rule_id}", "ACI_CHAIN_RULE_ID_DUP"))
            continue
        seen_chain_ids.add(rule_id)

        requires_all_raw = rule.get("requires_all", [])
        if not isinstance(requires_all_raw, list) or not requires_all_raw:
            issues.append(SemanticIssue(f"/aci/chain_rules/{idx}/requires_all", "requires_all must be a non-empty array", "ACI_CHAIN_REQUIRES"))
            continue
        requires_all = tuple(str(s).strip().lower() for s in requires_all_raw if str(s).strip())
        if not requires_all:
            issues.append(SemanticIssue(f"/aci/chain_rules/{idx}/requires_all", "requires_all cannot be empty after normalization", "ACI_CHAIN_REQUIRES_EMPTY"))
            continue

        label = str(rule.get("label", "")).strip()
        if not label:
            issues.append(SemanticIssue(f"/aci/chain_rules/{idx}/label", "label must be a non-empty string", "ACI_CHAIN_LABEL"))
            continue

        chain_rules.append(
            ACIChainRule(
                rule_id=rule_id,
                enabled=bool(rule.get("enabled", True)),
                requires_all=requires_all,
                label=label,
            )
        )

    return ACIConfig(
        enabled=enabled,
        min_confidence=min_confidence,
        max_uplift=max_uplift,
        asset_uplift_weight=asset_uplift_weight,
        exploit_boost=ACIExploitBoost(
            enabled=exploit_enabled,
            weight=exploit_weight,
            max_bonus=exploit_max_bonus,
        ),
        capability_rules=tuple(capability_rules),
        chain_rules=tuple(chain_rules),
        token_mode=token_mode,
        signal_aliases=tuple(signal_aliases),
        disabled_core_tokens=tuple(disabled_core_tokens),
    )

# -----------------------------------------------
# TopN parsing / semantics
# -----------------------------------------------

def _parse_topn(topn_raw: Dict[str, Any], issues: List[SemanticIssue]) -> Optional[TopNConfig]:
    # Guard fields
    rank_basis = topn_raw.get("rank_basis", "raw")
    if rank_basis not in ("raw", "operational"):
        issues.append(SemanticIssue("/topn/rank_basis", f"Invalid rank_basis: {rank_basis}", "RANK_BASIS_INVALID"))
        rank_basis = "raw"

    decay = topn_raw.get("decay")
    if not isinstance(decay, list) or not decay:
        issues.append(SemanticIssue("/topn/decay", "decay must be a non-empty array", "DECAY_EMPTY"))
        return None

    # decay semantics - monotonic non-increasing
    prev = None
    for i, v in enumerate(decay):
        if not isinstance(v, (int, float)):
            issues.append(SemanticIssue(f"/topn/decay/{i}", f"decay[{i}] must be a number", "DECAY_TYPE_INVALID"))
            continue
        if v < 0.0 or v > 1.0:
            issues.append(SemanticIssue(f"/topn/decay/{i}", f"decay[{i}] must be between 0 and 1.0", "DECAY_RANGE_INVALID"))
        if prev is not None and v > prev:
            issues.append(SemanticIssue("/topn/decay", "decay must be non-increasing", "DECAY_NOT_MONOTONIC", detail=f"decay[{i-1}]={prev}, decay[{i}]={v}"))

        prev = float(v)

    # Enforces hard rule: decay[0] == 1.0
    if isinstance(decay[0], (int, float)) and float(decay[0]) != 1.0:
        issues.append(SemanticIssue("/topn/decay/0", "decay[0] should be 1.0 (top finding weight baseline)", "DECAY_FIRST_NOT_ONE", detail=f"decay[0]={decay[0]}"))

    k = len(decay)

    max_assets = int(topn_raw.get("max_assets", 25))
    max_findings_per_asset = int(topn_raw.get("max_findings_per_asset", 10))
    include_global = bool(topn_raw.get("include_global_top_findings", True))
    global_max = int(topn_raw.get("global_top_findings_max", 50))

    # More guards
    if max_assets < 1:
        issues.append(SemanticIssue("/topn/max_assets", "max_assets must be >= 1", "MAX_ASSETS_RANGE"))
        max_assets = 1
    if max_findings_per_asset < 1:
        issues.append(SemanticIssue("/topn/max_findings_per_asset", "max_findings_per_asset must be >= 1", "MAX_FINDINGS_RANGE"))
        max_findings_per_asset = 1
    if global_max < 1:
        issues.append(SemanticIssue("/topn/global_top_findings_max", "global_top_findings_max must be >= 1", "GLOBAL_MAX_RANGE"))
        global_max = 1

    return TopNConfig(
        rank_basis=rank_basis,
        decay=tuple(float(x) for x in decay),
        k=k,
        max_assets= max_assets,
        max_findings_per_asset=max_findings_per_asset,
        include_global_top_findings=include_global,
        global_top_findings=global_max
    )


# -----------------------------------------------
# Inference Parsing / Semantics
# -----------------------------------------------

def _parse_inference(inf_raw: Dict[str, Any], issues: List[SemanticIssue]) -> Optional[InferenceConfig]:
    ct_raw = inf_raw.get("confidence_thresholds", {})
    low = ct_raw.get("low")
    med = ct_raw.get("medium")
    high = ct_raw.get("high")

    if not all(isinstance(x, int) for x in (low, med, high)):
        issues.append(SemanticIssue("/inference/confidence_thresholds", "thresholds must be contain integers", "CONF_THRES_TYPE_VALUE"))

    if not (low < med < high):
        issues.append(SemanticIssue("/inference/confidence_thresholds", "thresholds must be strictly increasing: low < medium < high", "CONF_THRES_ORDER", detail=f"low={low}, medium={med}, high={high}"))

    conf = ConfidenceThreshold(low=low, medium=med, high=high)

    # Public Service Ports
    psp = inf_raw.get("public_service_ports", [])
    ports_list: List[int] = []
    if not isinstance(psp, list):
        issues.append(SemanticIssue("/inference/public_service_ports", "public_service_ports must be an array of ports", "PUBLIC_PORTS_TYPE"))
        psp = []

    for i, p in enumerate(psp):
        if not isinstance(p, int):
            issues.append(SemanticIssue(f"/inference/public_service_ports/{i}", "port must be an integer.", "PORT_TYPE"))

        if p < 1 or p > 65535:
            issues.append(SemanticIssue(f"/inference/public_service_ports/{i}", "port must be in range of 1-65535.", "PORT_RANGE_ERROR", detail=str(p)))
        ports_list.append(p)

    ports_set = frozenset(ports_list)

    # allow_predicates
    ap = inf_raw.get("allow_predicates", [])
    if not isinstance(ap, list) or not ap:
        issues.append(SemanticIssue("/inference/allow_predicates", "allow_predicates must be a non-empty array", "ALLOW_PRED_EMPTY"))
        return None
    allow_predicates: Set[str] = set()
    for i, name in enumerate(ap):
        if not isinstance(name, str) or not name.strip():
            issues.append(SemanticIssue(f"/inference/allow_predicates/{i}", "predicate name must be a non-empty string.", "ALLOW_PRED_TYPE"))
            continue
        allow_predicates.add(name.strip())

    allow_pred_frozen = frozenset(allow_predicates)

    finding_text_min_token_matches_raw = inf_raw.get("finding_text_min_token_matches", 2)
    if not isinstance(finding_text_min_token_matches_raw, int):
        issues.append(
            SemanticIssue(
                "/inference/finding_text_min_token_matches",
                "finding_text_min_token_matches must be an integer",
                "FINDING_TEXT_MIN_TOKENS_TYPE",
            )
        )
        finding_text_min_token_matches = 2
    else:
        finding_text_min_token_matches = finding_text_min_token_matches_raw
    if finding_text_min_token_matches < 1 or finding_text_min_token_matches > 10:
        issues.append(
            SemanticIssue(
                "/inference/finding_text_min_token_matches",
                "finding_text_min_token_matches must be in range 1..10",
                "FINDING_TEXT_MIN_TOKENS_RANGE",
                detail=str(finding_text_min_token_matches),
            )
        )
        finding_text_min_token_matches = min(10, max(1, finding_text_min_token_matches))

    def _parse_int_with_range(path: str, raw_value: Any, default: int, min_value: int, max_value: int, code_prefix: str) -> int:
        if not isinstance(raw_value, int):
            issues.append(SemanticIssue(path, f"{path.split('/')[-1]} must be an integer", f"{code_prefix}_TYPE"))
            value = default
        else:
            value = raw_value
        if value < min_value or value > max_value:
            issues.append(SemanticIssue(path, f"{path.split('/')[-1]} must be in range {min_value}..{max_value}", f"{code_prefix}_RANGE", detail=str(value)))
            value = min(max_value, max(min_value, value))
        return value

    finding_text_title_weight = _parse_int_with_range(
        "/inference/finding_text_title_weight",
        inf_raw.get("finding_text_title_weight", 3),
        3,
        0,
        10,
        "FINDING_TEXT_TITLE_WEIGHT",
    )
    finding_text_description_weight = _parse_int_with_range(
        "/inference/finding_text_description_weight",
        inf_raw.get("finding_text_description_weight", 2),
        2,
        0,
        10,
        "FINDING_TEXT_DESCRIPTION_WEIGHT",
    )
    finding_text_plugin_output_weight = _parse_int_with_range(
        "/inference/finding_text_plugin_output_weight",
        inf_raw.get("finding_text_plugin_output_weight", 1),
        1,
        0,
        10,
        "FINDING_TEXT_PLUGIN_OUTPUT_WEIGHT",
    )
    finding_text_max_weighted_hits = _parse_int_with_range(
        "/inference/finding_text_max_weighted_hits",
        inf_raw.get("finding_text_max_weighted_hits", 4),
        4,
        1,
        50,
        "FINDING_TEXT_MAX_WEIGHTED_HITS",
    )
    finding_text_conflict_penalty = _parse_int_with_range(
        "/inference/finding_text_conflict_penalty",
        inf_raw.get("finding_text_conflict_penalty", 2),
        2,
        0,
        10,
        "FINDING_TEXT_CONFLICT_PENALTY",
    )

    conflict_tokens_raw = inf_raw.get("finding_text_conflict_tokens", [])
    if not isinstance(conflict_tokens_raw, list):
        issues.append(
            SemanticIssue(
                "/inference/finding_text_conflict_tokens",
                "finding_text_conflict_tokens must be an array",
                "FINDING_TEXT_CONFLICT_TOKENS_TYPE",
            )
        )
        conflict_tokens_raw = []
    conflict_tokens: List[str] = []
    for idx, tok in enumerate(conflict_tokens_raw):
        token = str(tok or "").strip().lower()
        if not token:
            continue
        if len(token) > 64:
            issues.append(
                SemanticIssue(
                    f"/inference/finding_text_conflict_tokens/{idx}",
                    "conflict token too long (max 64)",
                    "FINDING_TEXT_CONFLICT_TOKEN_LEN",
                )
            )
            continue
        conflict_tokens.append(token)
    if len(conflict_tokens) > 50:
        issues.append(
            SemanticIssue(
                "/inference/finding_text_conflict_tokens",
                "finding_text_conflict_tokens max length is 50",
                "FINDING_TEXT_CONFLICT_TOKEN_COUNT",
                detail=str(len(conflict_tokens)),
            )
        )
        conflict_tokens = conflict_tokens[:50]

    diminishing_raw = inf_raw.get("finding_text_diminishing_factors", [1.0, 0.6, 0.4])
    if not isinstance(diminishing_raw, list) or not diminishing_raw:
        issues.append(
            SemanticIssue(
                "/inference/finding_text_diminishing_factors",
                "finding_text_diminishing_factors must be a non-empty array",
                "FINDING_TEXT_DIMINISHING_FACTORS_TYPE",
            )
        )
        diminishing_raw = [1.0, 0.6, 0.4]
    diminishing_factors: List[float] = []
    for idx, value in enumerate(diminishing_raw):
        if not isinstance(value, (int, float)):
            issues.append(
                SemanticIssue(
                    f"/inference/finding_text_diminishing_factors/{idx}",
                    "diminishing factor must be a number",
                    "FINDING_TEXT_DIMINISHING_FACTOR_TYPE",
                )
            )
            continue
        fv = float(value)
        if fv < 0.0 or fv > 1.0:
            issues.append(
                SemanticIssue(
                    f"/inference/finding_text_diminishing_factors/{idx}",
                    "diminishing factor must be in range 0.0..1.0",
                    "FINDING_TEXT_DIMINISHING_FACTOR_RANGE",
                    detail=str(fv),
                )
            )
            fv = min(1.0, max(0.0, fv))
        diminishing_factors.append(fv)
    if not diminishing_factors:
        diminishing_factors = [1.0]

    # Rules
    rules_raw = inf_raw.get("rules", [])
    if not isinstance(rules_raw, list):
        issues.append(SemanticIssue("/inference/rules", "rules must be an array", "RULES_TYPE"))
        return None

    seen_ids: Set[str] = set()
    parsed_rules: List[ParsedRule] = []

    for idx, rule in enumerate(rules_raw):
        if not isinstance(rule, dict):
            issues.append(SemanticIssue(f"/inference/rules/{idx}", "rule must be an object", "RULE_TYPE"))
            continue

        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            issues.append(SemanticIssue(f"/inference/rules/{idx}/id", "rule id must be a non-empty string", "RULE_ID_TYPE"))
            continue
        if rule_id in seen_ids:
            issues.append(SemanticIssue(f"/inference/rules/{idx}/id", f"duplicate rule id: {rule_id}", "RULE_ID_DUP"))
            continue
        seen_ids.add(rule_id)

        enabled = bool(rule.get("enabled", True))
        tag = rule.get("tag")
        if tag not in ("externally_facing", "public_service_ports"):
            issues.append(SemanticIssue(f"/inference/rules/{idx}/tag", f"invalid tag: {tag}", "RULE_TAG_INVALID"))
            continue

        weight = rule.get("weight")
        if not isinstance(weight, int):
            issues.append(SemanticIssue(f"/inference/rules/{idx}/weight", "rule weight must be an integer", "RULE_WEIGHT_TYPE"))
            continue

        when = rule.get("when")
        if not isinstance(when, str) or not when.strip():
            issues.append(SemanticIssue(f"/inference/rules/{idx}/when", "when must be a non-empty string", "RULE_WHEN_TYPE"))
            continue
        when = when.strip()

        evidence = rule.get("evidence")
        if evidence is None:
            evidence = ""
        if not isinstance(evidence, str):
            issues.append(SemanticIssue(f"/inference/rules/{idx}/evidence", "evidence must be a string if present", "RULE_EVIDENCE_TYPE"))
            evidence = ""

        pred = _parse_when_predicate(
            when=when,
            allow_predicates=allow_pred_frozen,
            public_ports_set=ports_set,
            rule_path=f"/inference/rules/{idx}/when",
            issues=issues,
        )
        if pred is None:
            continue

        parsed_rules.append(
            ParsedRule(
                rule_id=rule_id,
                enabled=enabled,
                tag=tag,
                weight=weight,
                predicate=pred,
                evidence=evidence
            )
        )

    return InferenceConfig(
        confidence_thresholds=conf,
        public_service_ports=tuple(ports_list),
        public_service_ports_set=ports_set,
        allow_predicates=allow_pred_frozen,
        finding_text_min_token_matches=finding_text_min_token_matches,
        finding_text_title_weight=finding_text_title_weight,
        finding_text_description_weight=finding_text_description_weight,
        finding_text_plugin_output_weight=finding_text_plugin_output_weight,
        finding_text_max_weighted_hits=finding_text_max_weighted_hits,
        finding_text_conflict_tokens=tuple(conflict_tokens),
        finding_text_conflict_penalty=finding_text_conflict_penalty,
        finding_text_diminishing_factors=tuple(diminishing_factors),
        rules=tuple(parsed_rules)
    )


# -----------------------------------------------
# Token Predicate Parsing
# -----------------------------------------------

_SUPPORTED_FORMS = frozenset({
    "ip_is_public",
    "ip_is_private",
    "ip_is_private_no_public_ports",
    "any_port_in_public_list",
    "port_in",
    "hostname_contains_any",
    "finding_text_contains_any",
    "criticality_is",
})


def _parse_when_predicate(
    *,
    when: str,
    allow_predicates: frozenset[str],
    public_ports_set: frozenset[int],
    rule_path: str,
    issues: List[SemanticIssue],
) -> Optional[ParsedPredicate]:
    """
    Strict token-based grammer:
    
    - ip_is_public
    - ip_is_private
    - any_port_in_public_list
    - port_in:[80,443,...]
    - hostname_contains_any:[dmz,rtr,vpn,...]
    - finding_text_contains_any:[internet,public,exposed,...]
    - criticality_is:[extreme,high,medium,low]
    """
    if ":" in when:
        _ = public_ports_set
        name, rest = when.split(":", 1)
        name = name.strip()
        rest = rest.strip()
    else:
        name, rest = when.strip(), ""

    if name not in allow_predicates:
        issues.append(SemanticIssue(rule_path, f"predicate '{name}' not in allow_predicates", "PRED_NOT_ALLOWED"))
        return None

    if name not in _SUPPORTED_FORMS:
        issues.append(SemanticIssue(rule_path, f"predicate '{name}' is not support by this buld", "PRED_NOT_SUPPORTED"))
        return None

    # No-arg preds
    if name in ("ip_is_public", "ip_is_private", "ip_is_private_no_public_ports", "any_port_in_public_list"):
        if rest:
            issues.append(SemanticIssue(rule_path, f"predicate '{name}' does not take arguments", "PRED_UNEXPECTED_ARGS", detail=rest))
            return None
        return ParsedPredicate(name=name)

    # Arg list predicates
    if not rest.startswith("[") or not rest.endswith("]"):
        issues.append(SemanticIssue(rule_path, f"predicate '{name}' must use bracket list syntax: {name}:[...]", "PRED_ARG_SYNTAX", detail=rest))
        return None

    inner = rest[1:-1].strip()
    if not inner:
        issues.append(SemanticIssue(rule_path, f"predicate '{name}' list cannot be empty", "PRED_LIST_EMPTY"))
        return None

    items = [x.strip() for x in inner.split(",") if x.strip()]
    if not items:
        issues.append(SemanticIssue(rule_path, f"predicate '{name}' list cannot be empty", "PRED_LIST_EMPTY"))
        return None

    if name == "port_in":
        ports: List[int] = []
        for it in items:
            if not it.isdigit():
                issues.append(SemanticIssue(rule_path, "port_in entries must be integers", "PORT_IN_NOT_INT", detail=it))
                return None
            p = int(it)
            if p < 1 or p > 65535:
                issues.append(SemanticIssue(rule_path, "port_in entries must be in range 1...65535", "PORT_IN_RANGE", detail=str(p)))
                return None
            ports.append(p)
        return ParsedPredicate(name=name, ports=tuple(ports))

    if name in ("hostname_contains_any", "finding_text_contains_any"):
        tokens: List[str] = []
        for it in items:
            tok = it.strip().lower()
            if not tok:
                continue
            if len(tok) > 64:
                issues.append(SemanticIssue(rule_path, "predicate token too long (max 64)", "HOST_TOKEN_LENGTH", detail=tok[:80]))
                return None
            tokens.append(tok)
        if not tokens:
            issues.append(SemanticIssue(rule_path, f"{name} tokens cannot be empty", "HOST_TOKEN_EMPTY"))
            return None
        if len(tokens) > 50:
            issues.append(SemanticIssue(rule_path, f"{name} token list too large (max 50)", "HOST_TOKEN_COUNT", detail=str(len(tokens))))
            return None
        return ParsedPredicate(name=name, tokens=tuple(tokens))

    if name == "criticality_is":
        allowed = {"extreme", "high", "medium", "low"}
        values: List[str] = []
        for it in items:
            val = it.strip().lower()
            if val not in allowed:
                issues.append(SemanticIssue(rule_path, "criticality_is only supports [extreme,high,medium,low]", "CRIT_VALUE_INVALID", detail=val))
                return None
            values.append(val)
        if not values:
            issues.append(SemanticIssue(rule_path, "criticality_is cannot be empty", "CRIT_VALUE_EMPTY"))
            return None
        return ParsedPredicate(name=name, tokens=tuple(values))

    # any_port_in_public list uses 0 args: Reaching this point is a catch-all
    issues.append(SemanticIssue(rule_path, f"Unhandled predicate form: {name}", "PRED_INTERNAL"))
    return None
