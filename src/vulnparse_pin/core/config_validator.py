# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import TYPE_CHECKING

from jsonschema import validators
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext
    from vulnparse_pin.core.config_source import RawConfigPayloads


@dataclass(frozen=True)
class ConfigValidationResult:
    """
    Represents validation results with normalized payloads and metadata.
    """
    ok: bool
    warnings: tuple[str, ...]
    errors: tuple[str, ...]
    normalized: "RawConfigPayloads"


class ConfigValidator:
    """
    Config validator: handles schema validation and version policy enforcement.
    """

    @staticmethod
    def validate(ctx: "RunContext", payloads: "RawConfigPayloads") -> ConfigValidationResult:
        """
        Validate config payloads against schema and version policy.
        Returns ConfigValidationResult with warnings and errors.
        Raises RuntimeError on validation failures.
        """
        ConfigValidator._validate_schema(payloads.global_config, "config.schema.json", label="Global config")
        ConfigValidator._validate_schema(payloads.scoring_config, "scoring.schema.json", label="Scoring config")
        ConfigValidator._validate_schema(payloads.topn_config, "topN.schema.json", label="TopN config")

        warnings: list[str] = []
        global_version = payloads.global_config.get("version")
        if global_version is None:
            msg = "Global config version is missing; treating as legacy v1. Add 'version: v1' to silence this warning."
            warnings.append(msg)
            ctx.logger.print_warning(msg, label="Global Config")
        elif str(global_version) != "v1":
            raise RuntimeError(f"Unsupported global config version: {global_version}")

        return ConfigValidationResult(
            ok=True,
            warnings=tuple(warnings),
            errors=(),
            normalized=payloads,
        )

    @staticmethod
    def _load_schema(schema_filename: str) -> dict:
        """
        Load schema from package resources.
        """
        schema_path = resources.files("vulnparse_pin.core.schemas").joinpath(schema_filename)
        with schema_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    @staticmethod
    def _validate_schema(payload: dict, schema_filename: str, *, label: str) -> None:
        """
        Validate payload against loaded schema.
        Raises RuntimeError on validation failure.
        """
        schema = ConfigValidator._load_schema(schema_filename)
        validator_cls = validators.validator_for(schema)
        validator_cls.check_schema(schema)
        validator = validator_cls(schema)

        try:
            validator.validate(payload)
        except JsonSchemaValidationError as exc:
            path = "/".join(str(part) for part in exc.path) if exc.path else "<root>"
            raise RuntimeError(f"{label} schema validation failed at {path}: {exc.message}") from exc
