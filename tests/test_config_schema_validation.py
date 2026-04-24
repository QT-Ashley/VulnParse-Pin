import pytest
import json
from importlib import resources

from ruamel.yaml import YAML

from vulnparse_pin.core.config_source import RawConfigPayloads
from vulnparse_pin.core.config_validator import ConfigValidator
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import validate_and_normalize_semantics


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


def test_topn_semantics_accept_oal_aliases_and_finding_text_predicate() -> None:
    payloads = _load_default_payloads()
    payloads.topn_config["triage_policy"] = {
        "enabled": True,
        "p1_risk_bands": ["critical", "high"],
        "p1_require_public_exposure": True,
        "p1_require_exploit_or_kev": True,
        "p1b_risk_bands": ["critical", "high", "medium"],
        "p1b_min_aci_confidence": 0.75,
        "p1b_require_chain_candidate": True,
        "p1b_require_public_exposure": False,
        "preserve_p1_precedence": True,
    }
    payloads.topn_config["inference"]["allow_predicates"] = [
        "ip_is_public",
        "ip_is_private",
        "any_port_in_public_list",
        "port_in",
        "hostname_contains_any",
        "finding_text_contains_any",
        "criticality_is",
    ]
    payloads.topn_config["inference"]["finding_text_min_token_matches"] = 2
    payloads.topn_config["inference"]["finding_text_title_weight"] = 3
    payloads.topn_config["inference"]["finding_text_description_weight"] = 2
    payloads.topn_config["inference"]["finding_text_plugin_output_weight"] = 1
    payloads.topn_config["inference"]["finding_text_max_weighted_hits"] = 4
    payloads.topn_config["inference"]["finding_text_conflict_tokens"] = ["internal only", "localhost"]
    payloads.topn_config["inference"]["finding_text_conflict_penalty"] = 2
    payloads.topn_config["inference"]["finding_text_diminishing_factors"] = [1.0, 0.6, 0.4]
    payloads.topn_config["inference"]["rules"].append(
        {
            "id": "finding_text_test_hint",
            "enabled": True,
            "tag": "externally_facing",
            "weight": 4,
            "when": "finding_text_contains_any:[internet,public]",
            "evidence": "Finding text suggests exposure (+4)",
        }
    )

    normalized, issues = validate_and_normalize_semantics(payloads.topn_config)

    assert issues == []
    assert normalized is not None
    assert normalized.triage_policy.oal1_risk_bands == ("critical", "high")
    assert normalized.triage_policy.oal2_risk_bands == ("critical", "high", "medium")
    assert normalized.inference.finding_text_min_token_matches == 2
    assert normalized.inference.finding_text_title_weight == 3
    assert normalized.inference.finding_text_description_weight == 2
    assert normalized.inference.finding_text_plugin_output_weight == 1
    assert normalized.inference.finding_text_max_weighted_hits == 4
    assert normalized.inference.finding_text_conflict_tokens == ("internal only", "localhost")
    assert normalized.inference.finding_text_conflict_penalty == 2
    assert normalized.inference.finding_text_diminishing_factors == (1.0, 0.6, 0.4)
    assert any(rule.predicate.name == "finding_text_contains_any" for rule in normalized.inference.rules)


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


def test_global_config_schema_accepts_enrichment_block():
    payloads = _load_default_payloads()
    payloads = RawConfigPayloads(
        global_config={
            **payloads.global_config,
            "enrichment": {
                "ghsa_source": "C:/data/ghsa/advisory-database",
                "ghsa_online_prefetch_budget": 25,
                "ghsa_token_env": "GHSA_PAT",
                "ghsa_cache": {
                    "sqlite_max_age_hours": 336,
                    "sqlite_max_rows": 500000,
                },
                "confidence": {
                    "model_version": "v1",
                    "max_score": 100,
                    "base_scanner": 30,
                    "weights": {
                        "nvd": 25,
                        "kev": 15,
                        "epss": 10,
                        "exploitdb": 10,
                        "ghsa": 20,
                    },
                    "ghsa_signals": {
                        "advisory_confidence_bonus": 3,
                        "max_advisory_confidence_bonus": 9,
                        "exploit_signal_on_high_severity": True,
                        "exploit_signal_confidence_bonus": 5,
                    },
                },
            },
        },
        scoring_config=payloads.scoring_config,
        topn_config=payloads.topn_config,
    )
    ctx = _DummyCtx()

    result = ConfigValidator.validate(ctx, payloads)
    assert result.ok is True


def test_global_config_schema_rejects_invalid_confidence_weight():
    payloads = _load_default_payloads()
    invalid = {
        **payloads.global_config,
        "enrichment": {
            "ghsa_source": None,
            "confidence": {
                "model_version": "v1",
                "max_score": 100,
                "base_scanner": 35,
                "weights": {
                    "nvd": 25,
                    "kev": 15,
                    "epss": 10,
                    "exploitdb": 10,
                    "ghsa": 250,
                },
                "ghsa_signals": {
                    "advisory_confidence_bonus": 3,
                    "max_advisory_confidence_bonus": 9,
                    "exploit_signal_on_high_severity": False,
                    "exploit_signal_confidence_bonus": 5,
                },
            },
        },
    }

    with pytest.raises(RuntimeError, match="Global config schema validation failed"):
        ConfigValidator._validate_schema(invalid, "config.schema.json", label="Global config")


def test_global_config_schema_rejects_invalid_ghsa_cache_settings():
    payloads = _load_default_payloads()
    invalid = {
        **payloads.global_config,
        "enrichment": {
            "ghsa_source": None,
            "ghsa_cache": {
                "sqlite_max_age_hours": 0,
                "sqlite_max_rows": 500000,
            },
            "confidence": {
                "model_version": "v1",
                "max_score": 100,
                "base_scanner": 35,
                "weights": {
                    "nvd": 25,
                    "kev": 15,
                    "epss": 10,
                    "exploitdb": 10,
                    "ghsa": 15,
                },
                "ghsa_signals": {
                    "advisory_confidence_bonus": 3,
                    "max_advisory_confidence_bonus": 9,
                    "exploit_signal_on_high_severity": False,
                    "exploit_signal_confidence_bonus": 5,
                },
            },
        },
    }

    with pytest.raises(RuntimeError, match="Global config schema validation failed"):
        ConfigValidator._validate_schema(invalid, "config.schema.json", label="Global config")


def test_global_config_schema_rejects_invalid_ghsa_budget():
    payloads = _load_default_payloads()
    invalid = {
        **payloads.global_config,
        "enrichment": {
            "ghsa_source": None,
            "ghsa_online_prefetch_budget": 0,
            "ghsa_token_env": "GITHUB_TOKEN",
            "confidence": {
                "model_version": "v1",
                "max_score": 100,
                "base_scanner": 35,
                "weights": {
                    "nvd": 25,
                    "kev": 15,
                    "epss": 10,
                    "exploitdb": 10,
                    "ghsa": 15,
                },
                "ghsa_signals": {
                    "advisory_confidence_bonus": 3,
                    "max_advisory_confidence_bonus": 9,
                    "exploit_signal_on_high_severity": False,
                    "exploit_signal_confidence_bonus": 5,
                },
            },
        },
    }

    with pytest.raises(RuntimeError, match="Global config schema validation failed"):
        ConfigValidator._validate_schema(invalid, "config.schema.json", label="Global config")


def test_global_config_schema_accepts_secure_webhook_block():
    payloads = _load_default_payloads()
    payloads = RawConfigPayloads(
        global_config={
            **payloads.global_config,
            "webhook": {
                "enabled": True,
                "signing_key_env": "VP_WEBHOOK_HMAC_KEY",
                "key_id": "primary",
                "timeout_seconds": 5,
                "connect_timeout_seconds": 3,
                "read_timeout_seconds": 5,
                "max_retries": 2,
                "max_payload_bytes": 262144,
                "replay_window_seconds": 300,
                "allow_spool": True,
                "spool_subdir": "webhook_spool",
                "endpoints": [
                    {
                        "url": "https://hooks.example.internal/vpp",
                        "enabled": True,
                        "oal_filter": "P1",
                        "format": "generic",
                    }
                ],
            },
        },
        scoring_config=payloads.scoring_config,
        topn_config=payloads.topn_config,
    )
    ctx = _DummyCtx()

    result = ConfigValidator.validate(ctx, payloads)

    assert result.ok is True


def test_global_config_schema_rejects_insecure_webhook_endpoint_scheme():
    payloads = _load_default_payloads()
    payloads = RawConfigPayloads(
        global_config={
            **payloads.global_config,
            "webhook": {
                "enabled": True,
                "signing_key_env": "VP_WEBHOOK_HMAC_KEY",
                "key_id": "primary",
                "timeout_seconds": 5,
                "connect_timeout_seconds": 3,
                "read_timeout_seconds": 5,
                "max_retries": 2,
                "max_payload_bytes": 262144,
                "replay_window_seconds": 300,
                "allow_spool": True,
                "spool_subdir": "webhook_spool",
                "endpoints": [
                    {
                        "url": "http://hooks.example.internal/vpp",
                        "enabled": True,
                        "oal_filter": "all",
                        "format": "generic",
                    }
                ],
            },
        },
        scoring_config=payloads.scoring_config,
        topn_config=payloads.topn_config,
    )
    ctx = _DummyCtx()

    with pytest.raises(RuntimeError, match="Webhook endpoint must use https"):
        ConfigValidator.validate(ctx, payloads)


def test_global_config_schema_rejects_enabled_webhook_without_enabled_endpoints():
    payloads = _load_default_payloads()
    payloads = RawConfigPayloads(
        global_config={
            **payloads.global_config,
            "webhook": {
                "enabled": True,
                "signing_key_env": "VP_WEBHOOK_HMAC_KEY",
                "key_id": "primary",
                "timeout_seconds": 5,
                "connect_timeout_seconds": 3,
                "read_timeout_seconds": 5,
                "max_retries": 2,
                "max_payload_bytes": 262144,
                "replay_window_seconds": 300,
                "allow_spool": True,
                "spool_subdir": "webhook_spool",
                "endpoints": [
                    {
                        "url": "https://hooks.example.internal/vpp",
                        "enabled": False,
                        "oal_filter": "all",
                        "format": "generic",
                    }
                ],
            },
        },
        scoring_config=payloads.scoring_config,
        topn_config=payloads.topn_config,
    )
    ctx = _DummyCtx()

    with pytest.raises(RuntimeError, match="enabled but no enabled endpoints"):
        ConfigValidator.validate(ctx, payloads)


def test_safe_fallback_aci_rules_track_packaged_topn_defaults() -> None:
    payloads = _load_default_payloads()
    fallback = _safe_fallback_config()

    default_aci = payloads.topn_config.get("aci", {}) if isinstance(payloads.topn_config, dict) else {}
    default_capability_ids = {
        str(rule.get("id", "")).strip()
        for rule in (default_aci.get("capability_rules", []) if isinstance(default_aci, dict) else [])
        if isinstance(rule, dict)
    }
    default_chain_ids = {
        str(rule.get("id", "")).strip()
        for rule in (default_aci.get("chain_rules", []) if isinstance(default_aci, dict) else [])
        if isinstance(rule, dict)
    }

    fallback_capability_ids = {rule.rule_id for rule in fallback.aci.capability_rules}
    fallback_chain_ids = {rule.rule_id for rule in fallback.aci.chain_rules}

    assert default_capability_ids == fallback_capability_ids
    assert default_chain_ids == fallback_chain_ids
