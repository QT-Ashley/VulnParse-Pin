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
from typing import Any, Dict, Tuple, Sequence, TYPE_CHECKING

from vulnparse_pin.core.passes.TopN.TN_triage_schema import (
    SchemaIssue,
    TriageSchemaValidationError,
    validate_topn_cfg_schema
)
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import (
    ConfidenceThreshold,
    InferenceConfig,
    SemanticIssue,
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
        allow_predicates=frozenset({"ip_is_public", "ip_is_private", "any_port_in_public_list", "port_in", "hostname_contains_any", "criticality_is"}),
        rules=(),
    )

    return TNTriageConfig(topn=topn, inference=inference)