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
from urllib.parse import urlsplit
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
        ConfigValidator._validate_webhook_config(payloads.global_config)

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

    @staticmethod
    def _validate_webhook_config(global_config: dict) -> None:
        webhook_cfg = global_config.get("webhook")
        if webhook_cfg is None:
            return
        if not isinstance(webhook_cfg, dict):
            raise RuntimeError("Global config webhook section must be an object.")

        endpoints = webhook_cfg.get("endpoints", [])
        if not isinstance(endpoints, list):
            raise RuntimeError("Global config webhook endpoints must be a list.")

        enabled = bool(webhook_cfg.get("enabled", False))
        if enabled and not any(bool(endpoint.get("enabled", False)) for endpoint in endpoints if isinstance(endpoint, dict)):
            raise RuntimeError("Webhook config is enabled but no enabled endpoints are configured.")

        connect_timeout = int(webhook_cfg.get("connect_timeout_seconds", 0))
        read_timeout = int(webhook_cfg.get("read_timeout_seconds", 0))
        total_timeout = int(webhook_cfg.get("timeout_seconds", 0))
        if total_timeout < max(connect_timeout, read_timeout):
            raise RuntimeError("Webhook timeout_seconds must be >= connect_timeout_seconds and read_timeout_seconds.")

        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                raise RuntimeError("Webhook endpoints must contain only objects.")
            url = str(endpoint.get("url", "")).strip()
            parts = urlsplit(url)
            if parts.scheme.lower() != "https":
                raise RuntimeError(f"Webhook endpoint must use https: {url}")
            if not parts.netloc:
                raise RuntimeError(f"Webhook endpoint must include a host: {url}")
            if parts.username or parts.password:
                raise RuntimeError(f"Webhook endpoint must not embed credentials: {url}")
