# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

import json
from importlib import resources

try:
    import jsonschema
    from jsonschema import validators
except Exception as exc:
    raise RuntimeError(
        "Missing dependency: jsonschema. Install jsonschema to enable tn_triage.json schema validation."
    ) from exc

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
SCHEMA_PACKAGE = "vulnparse_pin.core.schemas"
SCHEMA_FILENAME = "topN.schema.json"


# ----------------------------------------------------------------
# Errors / Result Types
# ----------------------------------------------------------------

@dataclass(frozen=True)
class SchemaIssue:
    """
    One JSON Schema validation issue in a human-readable form
    """
    path: str
    message: str
    validator: str          # jsonschema validator keyword
    context: str = ""

class TriageSchemaValidationError(ValueError):
    """
    Raised when tn_triage.json fails structural JSON Schema validation.
    """
    def __init__(self, issues: Sequence[SchemaIssue]) -> None:
        self.issues = issues
        super().__init__(f"tn_triage.json failed schema validation ({len(self.issues)} issue(s)).")
        
# ----------------------------------------------------------------
# Schema Loading
# ----------------------------------------------------------------

def load_topn_schema() -> Dict[str, Any]:
    """
    Load triage.schema.json from packaged resources.
    """
    try:
        schema_text = (resources.files(SCHEMA_PACKAGE) / SCHEMA_FILENAME).read_text(encoding="utf-8")
    except Exception as exc:
        raise FileNotFoundError(
            f"Unable to load packaged schema '{SCHEMA_FILENAME}' from '{SCHEMA_PACKAGE}'. "
            "Ensure core/schemas is a Python package and the schema is included as package data."
        ) from exc

    try:
        schema_obj = json.loads(schema_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Packaged schema '{SCHEMA_FILENAME}' is not valid JSON."
        ) from exc

    return schema_obj

# ----------------------------------------------------------------
# Validation
# ----------------------------------------------------------------

def validate_topn_cfg_schema(
    config: Dict[str, Any],
    *,
    schema: Optional[Dict[str, Any]] = None,
) -> List[SchemaIssue]:
    """
    Validate tn_triage.json against triage.schema.json.

    Returns list of SchemaIssue. Empty list = OK.
    Caller decides strict vs warn behavior and logging.
    """
    schema_obj = schema if schema is not None else load_topn_schema()

    # Pick correct validator
    ValidatorCls = validators.validator_for(schema_obj)
    ValidatorCls.check_schema(schema_obj)
    validator = ValidatorCls(schema_obj)

    issues: List[SchemaIssue] = []
    for err in validator.iter_errors(config):
        issues.append(_format_issues(err))

    # Authoritative ordering for stable logs
    issues.sort(key=lambda x: (x.path, x.validator, x.message))
    return issues

def ensure_tn_cfg_schema(
    config: Dict[str, Any],
    *,
    schema: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Raises TriageSchemaValidationError if validation fails.
    """
    issues = validate_topn_cfg_schema(config, schema=schema)
    if issues:
        raise TriageSchemaValidationError(issues)


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _format_issues(err: "jsonschema.ValidationError") -> SchemaIssue:
    path = _format_path(err.absolute_path)
    validator = str(err.validator) if err.validator else "unknown"


    context = ""
    if validator == "required":
        context = err.message
    elif validator == "additionalProperties" and getattr(err, "params", None):
        context = str(err.params)

    return SchemaIssue(
        path=path,
        message=err.message,
        validator=validator,
        context=context
    )

def _format_path(path_parts: Iterable[Any]) -> str:
    parts = list(path_parts)
    if not parts:
        return "/"

    def esc(x: Any) -> str:
        s = str(x)
        return s.replace("~", "~0").replace("/", "~1")

    return "/" + "/".join(esc(p) for p in parts)