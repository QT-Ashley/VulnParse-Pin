import pytest
import json
from importlib import resources

from ruamel.yaml import YAML

from vulnparse_pin.core.config_source import RawConfigPayloads
from vulnparse_pin.core.config_validator import ConfigValidator


def _load_default_payloads() -> RawConfigPayloads:
    yaml = YAML(typ="safe", pure=True)
    cfg_yaml = yaml.load(resources.files("vulnparse_pin.resources").joinpath("config.yaml").read_text(encoding="utf-8"))
    scoring = json.loads(resources.files("vulnparse_pin.resources").joinpath("scoring.json").read_text(encoding="utf-8"))
    topn = json.loads(resources.files("vulnparse_pin.resources").joinpath("tn_triage.json").read_text(encoding="utf-8"))
    return RawConfigPayloads(global_config=cfg_yaml, scoring_config=scoring, topn_config=topn)


class _DummyLogger:
    def __init__(self) -> None:
        self.warnings = []

    def print_warning(self, message: str, label: str | None = None) -> None:
        self.warnings.append((message, label))


class _DummyCtx:
    def __init__(self) -> None:
        self.logger = _DummyLogger()


def test_scoring_schema_validation_rejects_missing_required_key():
    invalid_scoring = {
        "version": "v1",
        "epss": {"scale": 10.0, "min": 0.0, "max": 1.0},
        "evidence_points": {"kev": 2.5, "exploit": 5.0},
        "bands": {"critical": 13.35, "high": 10.5, "medium": 7.0, "low": 4.0},
        # aggregation missing
        "weights": {"epss_high": 0.6, "epss_medium": 0.4, "kev": 1.0, "exploit": 1.0},
        "risk_ceiling": {"max_raw_risk": 15.0, "max_operational_risk": 10.0},
    }

    with pytest.raises(RuntimeError, match="Scoring config schema validation failed"):
        ConfigValidator._validate_schema(invalid_scoring, "scoring.schema.json", label="Scoring config")


def test_global_config_schema_validation_rejects_unknown_properties():
    invalid_cfg = {
        "feed_cache": {
            "defaults": {"ttl_hours": 24},
            "ttl_hours": {
                "exploit_db": 24,
                "kev": 24,
                "epss": 6,
                "nvd_yearly": 24,
                "nvd_modified": 2,
            },
            "feeds": {
                "exploit_db": {"enabled": True, "ttl_hours": 24},
                "kev": {"enabled": True, "ttl_hours": 24},
                "epss": {"enabled": True, "ttl_hours": 6},
                "nvd": {
                    "enabled": True,
                    "ttl_yearly": 24,
                    "ttl_modified": 2,
                    "start_year": 2023,
                    "end_year": 2025,
                    "sqlite_enforce_permissions": True,
                    "sqlite_file_mode": "0o600",
                    "sqlite_max_age_hours": 336,
                    "sqlite_max_rows": 500000,
                },
            },
        },
        "summary": {"top_n_findings": 20},
        "unknown_key": {"not_allowed": True},
    }

    with pytest.raises(RuntimeError, match="Global config schema validation failed"):
        ConfigValidator._validate_schema(invalid_cfg, "config.schema.json", label="Global config")


def test_topn_schema_validation_rejects_unknown_properties():
    invalid_topn = {
        "topn": {
            "rank_basis": "raw",
            "decay": [1.0, 0.7],
            "unknown": 1,
        },
        "inference": {
            "confidence_thresholds": {"low": 2, "medium": 5, "high": 8},
            "public_service_ports": [80, 443],
            "rules": [],
        },
    }

    with pytest.raises(RuntimeError, match="TopN config schema validation failed"):
        ConfigValidator._validate_schema(invalid_topn, "topN.schema.json", label="TopN config")


def test_config_validation_missing_global_version_warns_and_continues():
    payloads = _load_default_payloads()
    payloads = RawConfigPayloads(
        global_config={k: v for k, v in payloads.global_config.items() if k != "version"},
        scoring_config=payloads.scoring_config,
        topn_config=payloads.topn_config,
    )
    ctx = _DummyCtx()

    result = ConfigValidator.validate(ctx, payloads)

    assert result.ok is True
    assert len(result.warnings) == 1
    assert "version is missing" in result.warnings[0]
    assert len(ctx.logger.warnings) == 1


def test_config_validation_unsupported_global_version_fails():
    payloads = _load_default_payloads()
    payloads = RawConfigPayloads(
        global_config={**payloads.global_config, "version": "v2"},
        scoring_config=payloads.scoring_config,
        topn_config=payloads.topn_config,
    )
    ctx = _DummyCtx()

    with pytest.raises(RuntimeError, match="Global config schema validation failed at version"):
        ConfigValidator.validate(ctx, payloads)
