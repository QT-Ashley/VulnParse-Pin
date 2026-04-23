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
import json
from pathlib import Path
from typing import Any, Dict, Tuple, Sequence, TYPE_CHECKING

from vulnparse_pin.core.passes.TopN.TN_triage_schema import (
    SchemaIssue,
    TriageSchemaValidationError,
    validate_topn_cfg_schema
)
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import (
    ACIConfig,
    ACIExploitBoost,
    ConfidenceThreshold,
    InferenceConfig,
    SemanticIssue,
    TriagePolicyConfig,
    TNTriageConfig,
    TopNConfig,
    validate_and_normalize_semantics,
)
if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

# ---------------------------------------------------
# Result Container Class
# ---------------------------------------------------

@dataclass(frozen=True)
class TriageConfigLoadResult:
    config: TNTriageConfig
    schema_issues: Tuple[SchemaIssue, ...] = ()
    semantic_issues: Tuple[SemanticIssue, ...] = ()
    used_fallback: bool = False


# ---------------------------------------------------
# API
# ---------------------------------------------------

def load_tn_config(
    ctx: "RunContext",
    raw: Dict[str, Any],
    *,
    strict: bool = True,
) -> TriageConfigLoadResult:
    """
    Orchestrator for validating and normalizing the TopN Triage config data.
    Responsible for:
     - Validating JSON Schema (structural)
     - Semantics + normalizing config settings
    
    Behavior: 
     - strict=True: raise on any schema/semantic issues
     - strict= False: log issues and return a safe fallback config
    """
    schema_issues = validate_topn_cfg_schema(raw)
    if schema_issues:
        _log_schema_issues(ctx, schema_issues)

        if strict:
            raise TriageSchemaValidationError(schema_issues)

        fallback = _safe_fallback_config()
        ctx.logger.print_warning("tn_triage: schema invalid; using SAFE FALLBACK config (inference disabled).", label = "TopN-Config")
        return TriageConfigLoadResult(
            config=fallback,
            schema_issues=tuple(schema_issues),
            semantic_issues=(),
            used_fallback=True
        )

    normalized, semantic_issues = validate_and_normalize_semantics(raw)
    if semantic_issues:
        _log_semantic_issues(ctx, semantic_issues)

        if strict:
            raise TriageSchemaValidationError(semantic_issues)

        fallback = _safe_fallback_config()
        ctx.print_warning("tn_triage: semantics invalid; using SAFE FALLBACK config (inference disabled).", label = "TopN-Config")
        return TriageConfigLoadResult(
            config=fallback,
            schema_issues=(),
            semantic_issues=tuple(semantic_issues),
            used_fallback=True
        )

    assert normalized is not None
    ctx.logger.info(
        "tn_triage loaded OK (rank_basis=%s, K=%d, rules=%d, public_ports=%d)",
        normalized.topn.rank_basis,
        normalized.topn.k,
        len(normalized.inference.rules),
        len(normalized.inference.public_service_ports)
    )
    return TriageConfigLoadResult(config=normalized, used_fallback=False)


# ---------------------------------------------------
# Logging Helpers
# ---------------------------------------------------

def _log_schema_issues(ctx: Any, issues: Sequence[SchemaIssue]) -> None:
    ctx.logger.error("tn_triage schema validation failed with %d issue(s):", len(issues))
    for iss in issues:
        # Stable formatting; caller can adjust verbosity
        if iss.context:
            ctx.logger.error("  [SCHEMA] %s %s: %s (%s)", iss.path, iss.validator, iss.message, iss.context)
        else:
            ctx.logger.error("  [SCHEMA] %s %s: %s", iss.path, iss.validator, iss.message)


def _log_semantic_issues(ctx: Any, issues: Sequence[SemanticIssue]) -> None:
    ctx.logger.error("tn_triage semantic validation failed with %d issue(s):", len(issues))
    for iss in issues:
        if iss.detail:
            ctx.logger.error("  [SEM] %s %s: %s (%s)", iss.path, iss.code, iss.message, iss.detail)
        else:
            ctx.logger.error("  [SEM] %s %s: %s", iss.path, iss.code, iss.message)


# ---------------------------------------------------
# Safe Fallback Config
# ---------------------------------------------------

def _safe_fallback_config() -> TNTriageConfig:
    """
    Fallback config used when tn_triage.json is invalid in non-strict mode.
    Philosophy: ranking still works, inference is disabled.
    """
    topn = TopNConfig(
        rank_basis="raw",
        decay=(1.0,),   # K = 1; only the top finding contributes
        k=1,
        max_assets=25,
        max_findings_per_asset=10,
        include_global_top_findings=True,
        global_top_findings=50,
    )

    inference = InferenceConfig(
        confidence_thresholds=ConfidenceThreshold(low=2, medium=5, high=8),
        public_service_ports=(),
        public_service_ports_set=frozenset(),
        allow_predicates=frozenset({"ip_is_public", "ip_is_private", "any_port_in_public_list", "port_in", "hostname_contains_any", "finding_text_contains_any", "criticality_is"}),
        finding_text_min_token_matches=2,
        finding_text_title_weight=3,
        finding_text_description_weight=2,
        finding_text_plugin_output_weight=1,
        finding_text_max_weighted_hits=4,
        finding_text_conflict_tokens=tuple(),
        finding_text_conflict_penalty=2,
        finding_text_diminishing_factors=(1.0, 0.6, 0.4),
        rules=(),
    )

    aci = _fallback_aci_config()
    triage_policy = _fallback_triage_policy_config()

    return TNTriageConfig(topn=topn, inference=inference, aci=aci, triage_policy=triage_policy)


def _fallback_aci_config() -> ACIConfig:
    """
    Build fallback ACI defaults from packaged tn_triage.json when possible.
    This avoids duplicating every capability/chain rule in code.
    """
    try:
        base_dir = Path(__file__).resolve().parents[3]
        resource_path = base_dir / "resources" / "tn_triage.json"
        raw = json.loads(resource_path.read_text(encoding="utf-8"))
        normalized, issues = validate_and_normalize_semantics(raw)
        if normalized is not None and not issues:
            return normalized.aci
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        pass

    # Last-resort ACI fallback if packaged defaults cannot be loaded/parsed.
    return ACIConfig(
        enabled=False,
        min_confidence=0.6,
        max_uplift=2.0,
        asset_uplift_weight=0.5,
        exploit_boost=ACIExploitBoost(enabled=True, weight=0.25, max_bonus=0.2),
        capability_rules=(),
        chain_rules=(),
    )


def _fallback_triage_policy_config() -> TriagePolicyConfig:
    return TriagePolicyConfig(
        enabled=True,
        oal1_risk_bands=("critical", "high"),
        oal1_require_public_exposure=True,
        oal1_require_exploit_or_kev=True,
        oal2_risk_bands=("critical", "high", "medium"),
        oal2_min_aci_confidence=0.8,
        oal2_require_chain_candidate=True,
        oal2_require_public_exposure=True,
        preserve_oal1_precedence=True,
    )