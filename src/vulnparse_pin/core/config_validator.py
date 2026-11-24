# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from importlib import resources
import json
from typing import Any, Dict, TYPE_CHECKING
from urllib.parse import urlsplit

from jsonschema import validators
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from vulnparse_pin.core.config_source import RawConfigPayloads

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

SUPPORTED_CONFIG_VERSIONS = ("v1", "v2")

DEFAULT_SIGNAL_RELIABILITY_WEIGHTS: Dict[str, float] = {
    "active_dast": 1.0,
    "credentialed_host": 1.0,
    "sca_container": 0.90,
    "uncredentialed_banner": 0.85,
    "static_sast": 0.55,
    "network_probe": 0.80,
}

DEFAULT_EPSS_BREAKPOINTS: list[list[float]] = [
    [0.0, 0.0],
    [0.04, 1.8],
    [0.10, 3.0],
    [0.50, 4.2],
    [1.0, 5.0],
]


def normalize_triage_profile(raw_profile: Any) -> str:
    """Normalize profile aliases into canonical v2 profile keys ('default' or 'bod-26-04')."""
    if raw_profile is None:
        return "default"
    token = str(raw_profile).strip().lower()
    if not token or token in ("default", "legacy_oal", "oal"):
        return "default"
    if token in ("bod_26_04", "bod-26-04", "ssvc"):
        return "bod-26-04"
    raise RuntimeError(f"Unsupported triage profile: {raw_profile}")


def _project_global_v1_to_v2(global_cfg: dict) -> dict:
    """Auto-project a validated v1 (or unversioned legacy) global config dict to v2."""
    out = deepcopy(global_cfg)
    out["version"] = "v2"

    raw_profile = out.get("profile")
    canon_profile = normalize_triage_profile(raw_profile)
    if not raw_profile:
        out["profile"] = "default"

    sig_rel = out.get("signal_reliability")
    if not isinstance(sig_rel, dict):
        out["signal_reliability"] = {
            "enabled": True,
            "weights": dict(DEFAULT_SIGNAL_RELIABILITY_WEIGHTS),
        }
    else:
        weights = dict(DEFAULT_SIGNAL_RELIABILITY_WEIGHTS)
        if isinstance(sig_rel.get("weights"), dict):
            weights.update({str(k): float(v) for k, v in sig_rel["weights"].items()})
        out["signal_reliability"] = {
            "enabled": bool(sig_rel.get("enabled", True)),
            "weights": weights,
        }

    triage = out.get("triage")
    if not isinstance(triage, dict):
        out["triage"] = {
            "default_profile": "bod_26_04" if canon_profile == "bod-26-04" else "default",
            "static_sast_p1_cap": True,
        }
    else:
        out["triage"] = {
            "default_profile": triage.get(
                "default_profile",
                "bod_26_04" if canon_profile == "bod-26-04" else "default",
            ),
            "static_sast_p1_cap": bool(triage.get("static_sast_p1_cap", True)),
        }

    feed_cache = out.setdefault("feed_cache", {})
    if isinstance(feed_cache, dict):
        feeds = feed_cache.setdefault("feeds", {})
        if isinstance(feeds, dict) and "osv" not in feeds:
            feeds["osv"] = {"enabled": True, "ttl_hours": 24}

    return out


def _project_scoring_v1_to_v2(scoring_cfg: dict) -> dict:
    """Auto-project a validated v1 scoring config dict to v2 defaults while preserving user overrides."""
    out = deepcopy(scoring_cfg)
    was_v1 = str(out.get("version") or "v1") == "v1"
    out["version"] = "v2"

    epss = out.setdefault("epss", {})
    if isinstance(epss, dict):
        if "breakpoints" not in epss:
            epss["breakpoints"] = deepcopy(DEFAULT_EPSS_BREAKPOINTS)
        epss.setdefault("use_percentile", True)
        epss.setdefault("high_cutoff", 0.10)
        epss.setdefault("medium_cutoff", 0.04)
        epss.setdefault("percentile_high_cutoff", 0.95)
        epss.setdefault("percentile_medium_cutoff", 0.90)

    evp = out.setdefault("evidence_points", {})
    if isinstance(evp, dict):
        if was_v1:
            evp.setdefault("verified_exploit", float(evp.get("exploit", 2.0)))
        else:
            evp.setdefault("verified_exploit", 2.0)
        evp.setdefault("verified_exploit_with_kev", 0.5)
        evp.setdefault("heuristic_exploit", 0.0)

    sig_rel = out.get("signal_reliability")
    if not isinstance(sig_rel, dict):
        out["signal_reliability"] = {
            "enabled": True,
            "weights": dict(DEFAULT_SIGNAL_RELIABILITY_WEIGHTS),
        }

    return out


@dataclass(frozen=True)
class ConfigValidationResult:
    """
    Represents validation results with normalized payloads and metadata.
    """
    ok: bool
    warnings: tuple[str, ...]
    errors: tuple[str, ...]
    normalized: RawConfigPayloads
    source_version: str = "v2"


class ConfigValidator:
    """
    Config validator: handles schema validation and version policy enforcement.
    """

    @staticmethod
    def validate(ctx: "RunContext", payloads: RawConfigPayloads) -> ConfigValidationResult:
        """
        Validate config payloads against schema and version policy.
        Accepts both v1 (auto-projected with structured warning) and v2 configs.
        Raises RuntimeError on validation failures or unsupported versions.
        """
        ConfigValidator._validate_schema(payloads.global_config, "config.schema.json", label="Global config")
        ConfigValidator._validate_schema(payloads.scoring_config, "scoring.schema.json", label="Scoring config")
        ConfigValidator._validate_schema(payloads.topn_config, "topN.schema.json", label="TopN config")
        ConfigValidator._validate_webhook_config(payloads.global_config)
        ConfigValidator._validate_scoring_semantics(payloads.scoring_config)

        warnings: list[str] = []
        global_version = payloads.global_config.get("version")
        if global_version is None:
            msg = (
                "Global config version is missing; treating as legacy v1 and auto-projecting to v2. "
                "Add 'version: v2' to silence this warning."
            )
            warnings.append(msg)
            ctx.logger.print_warning(msg, label="Global Config")
            source_version = "v1"
        elif str(global_version) == "v1":
            msg = (
                "Global config uses legacy version 'v1'; auto-projecting to v2 defaults. "
                "Update to 'version: v2' to silence this warning."
            )
            warnings.append(msg)
            ctx.logger.print_warning(msg, label="Global Config")
            source_version = "v1"
        elif str(global_version) == "v2":
            source_version = "v2"
        else:
            raise RuntimeError(f"Unsupported global config version: {global_version}")

        scoring_version = payloads.scoring_config.get("version")
        if scoring_version is not None and str(scoring_version) not in SUPPORTED_CONFIG_VERSIONS:
            raise RuntimeError(f"Unsupported scoring config version: {scoring_version}")
        if str(scoring_version) == "v1" and source_version == "v2":
            msg = (
                "Scoring config uses legacy version 'v1'; auto-projecting to v2 defaults. "
                "Update to 'version: v2' to silence this warning."
            )
            warnings.append(msg)
            ctx.logger.print_warning(msg, label="Scoring Config")

        normalized_global = _project_global_v1_to_v2(payloads.global_config)
        normalized_scoring = _project_scoring_v1_to_v2(payloads.scoring_config)
        normalized_topn = deepcopy(payloads.topn_config)
        if "version" not in normalized_topn:
            normalized_topn["version"] = "v2"

        normalized = RawConfigPayloads(
            global_config=normalized_global,
            scoring_config=normalized_scoring,
            topn_config=normalized_topn,
        )

        return ConfigValidationResult(
            ok=True,
            warnings=tuple(warnings),
            errors=(),
            normalized=normalized,
            source_version=source_version,
        )

    @staticmethod
    def _validate_scoring_semantics(scoring_config: dict) -> None:
        epss = scoring_config.get("epss") or {}
        if isinstance(epss, dict):
            breakpoints = epss.get("breakpoints")
            if breakpoints is not None:
                if not isinstance(breakpoints, list) or len(breakpoints) < 2:
                    raise RuntimeError("Scoring config epss.breakpoints must contain at least 2 points.")
                prev_x = -1.0
                prev_y = -1.0
                for idx, pair in enumerate(breakpoints):
                    if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                        raise RuntimeError(f"Scoring config epss.breakpoints[{idx}] must be [probability, points].")
                    x = float(pair[0])
                    y = float(pair[1])
                    if x < 0.0 or x > 1.0:
                        raise RuntimeError(f"Scoring config epss.breakpoints[{idx}] probability must be in [0, 1].")
                    if x < prev_x:
                        raise RuntimeError("Scoring config epss.breakpoints probabilities must be non-decreasing.")
                    if y < prev_y:
                        raise RuntimeError("Scoring config epss.breakpoints points must be monotonically non-decreasing.")
                    prev_x, prev_y = x, y

        bands = scoring_config.get("bands") or {}
        if isinstance(bands, dict) and all(k in bands for k in ("critical", "high", "medium", "low")):
            c = float(bands["critical"])
            h = float(bands["high"])
            m = float(bands["medium"])
            low = float(bands["low"])
            if not (c > h > m > low >= 0.0):
                raise RuntimeError("Scoring config bands must satisfy critical > high > medium > low >= 0.")

        ceiling = scoring_config.get("risk_ceiling") or {}
        if isinstance(ceiling, dict):
            max_raw = float(ceiling.get("max_raw_risk", 16.0))
            max_op = float(ceiling.get("max_operational_risk", 10.0))
            if max_raw <= 0.0 or max_op <= 0.0:
                raise RuntimeError("Scoring config risk_ceiling values must be > 0.")

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
