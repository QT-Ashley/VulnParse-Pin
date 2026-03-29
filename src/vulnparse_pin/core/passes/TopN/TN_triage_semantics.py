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
    rules: Tuple[ParsedRule, ...]

@dataclass(frozen=True)
class TNTriageConfig:
    topn: TopNConfig
    inference: InferenceConfig


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


    # ---- topn semantics
    topn_cfg = _parse_topn(topn_raw, issues)

    # ---- inference semantics
    inf_cfg = _parse_inference(inf_raw, issues)

    if issues:
        return None, issues

    assert topn_cfg is not None and inf_cfg is not None
    return TNTriageConfig(topn=topn_cfg, inference=inf_cfg), issues

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
        rules=tuple(parsed_rules)
    )


# -----------------------------------------------
# Token Predicate Parsing
# -----------------------------------------------

_SUPPORTED_FORMS = frozenset({
    "ip_is_public",
    "ip_is_private",
    "any_port_in_public_list",
    "port_in",
    "hostname_contains_any",
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
    if name in ("ip_is_public", "ip_is_private", "any_port_in_public_list"):
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

    if name == "hostname_contains_any":
        tokens: List[str] = []
        for it in items:
            tok = it.strip().lower()
            if not tok:
                continue
            if len(tok) > 64:
                issues.append(SemanticIssue(rule_path, "hostname token too long (max 64)", "HOST_TOKEN_LENGTH", detail=tok[:80]))
                return None
            tokens.append(tok)
        if not tokens:
            issues.append(SemanticIssue(rule_path, "hostname_contains_any tokens cannot be empty", "HOST_TOKEN_EMPTY"))
            return None
        if len(tokens) > 50:
            issues.append(SemanticIssue(rule_path, "hostname_contains_any token list too large (max 50)", "HOST_TOKEN_COUNT", detail=str(len(tokens))))
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
