from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from functools import lru_cache
from importlib import resources
import json
from typing import Any

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
except ImportError:  # pragma: no cover
    Draft202012Validator = None
    JsonSchemaValidationError = Exception


def _to_json_compatible(value: Any) -> Any:
    if is_dataclass(value):
        return _to_json_compatible(asdict(value))
    if isinstance(value, dict):
        return {k: _to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_json_compatible(v) for v in value]
    if isinstance(value, tuple):
        return [_to_json_compatible(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


@lru_cache(maxsize=1)
def _load_scan_result_schema() -> dict[str, Any]:
    schema_path = resources.files("vulnparse_pin.core.schemas").joinpath("scanResult.schema.json")
    with schema_path.open("r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_runmanifest_schema() -> dict[str, Any]:
    schema_path = resources.files("vulnparse_pin.core.schemas").joinpath("runManifest.schema.json")
    with schema_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_scan_result_schema(scan_result: Any) -> None:
    if Draft202012Validator is None:
        raise RuntimeError("jsonschema is required for ScanResult schema validation. Install with: pip install jsonschema")

    payload = _to_json_compatible(scan_result)
    schema = _load_scan_result_schema()

    validator = Draft202012Validator(schema)
    try:
        validator.validate(payload)
    except JsonSchemaValidationError as exc:
        path = "/".join(str(p) for p in exc.path) if exc.path else "<root>"
        raise ValueError(f"ScanResult schema validation failed at {path}: {exc.message}") from exc


def validate_runmanifest_schema(runmanifest: Any) -> None:
    if Draft202012Validator is None:
        raise RuntimeError("jsonschema is required for RunManifest schema validation. Install with: pip install jsonschema")

    payload = _to_json_compatible(runmanifest)
    schema = _load_runmanifest_schema()

    validator = Draft202012Validator(schema)
    try:
        validator.validate(payload)
    except JsonSchemaValidationError as exc:
        path = "/".join(str(p) for p in exc.path) if exc.path else "<root>"
        raise ValueError(f"RunManifest schema validation failed at {path}: {exc.message}") from exc

