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
from datetime import datetime
from pathlib import Path
import sys
from typing import Any

from vulnparse_pin import __version__
from vulnparse_pin.core.apppaths import AppPaths, ensure_user_configs, load_config
from vulnparse_pin.core.classes.dataclass import FeedSpec, RunContext, Services, WebhookEndpointConfig, WebhookRuntimeConfig
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Nmap.nmap_adapter_pass import NmapAdapterPass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.Summary.summary_pass import SummaryConfig, SummaryPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import TriageConfigLoadResult, load_tn_config
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.utils.banner import print_banner
from vulnparse_pin.utils.feed_cache import FeedCacheManager
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.nvdcacher import NVDFeedCache, nvd_policy_from_config

from vulnparse_pin.app.runtime_helpers import _require, build_feed_cache_policy, build_run_log, load_score_policy


@dataclass(frozen=True)
class RuntimeBootstrapState:
    paths: AppPaths
    pfh: PermFileHandler
    ctx: RunContext
    logger: Any
    cfg_yaml: dict
    scoring_cfg: dict
    topn_cfg: dict
    cfg_yaml_path: Path
    cfg_score_path: Path
    cfg_topn_path: Path
    nvd_cache: NVDFeedCache | None
    nvd_status: str
    nvdpol_start_y: int
    nvdpol_end_y: int
    feed_cache: FeedCacheManager
    detector: SchemaDetector
    passesList: list[Any]
    passOrchestrator: PassRunner


def _build_webhook_runtime_config(cfg_yaml: dict, args: Any) -> WebhookRuntimeConfig:
    webhook_cfg = cfg_yaml.get("webhook", {}) if isinstance(cfg_yaml, dict) else {}
    if not isinstance(webhook_cfg, dict):
        webhook_cfg = {}

    filter_override = getattr(args, "webhook_oal_filter", None)
    cli_endpoint = getattr(args, "webhook_endpoint", None)

    endpoints: list[WebhookEndpointConfig] = []
    if cli_endpoint:
        endpoints.append(
            WebhookEndpointConfig(
                url=str(cli_endpoint),
                enabled=True,
                oal_filter=str(filter_override or "all"),
                format="generic",
            )
        )
    else:
        for raw_endpoint in webhook_cfg.get("endpoints", []):
            if not isinstance(raw_endpoint, dict):
                continue
            endpoints.append(
                WebhookEndpointConfig(
                    url=str(raw_endpoint.get("url", "")).strip(),
                    enabled=bool(raw_endpoint.get("enabled", False)),
                    oal_filter=str(filter_override or raw_endpoint.get("oal_filter", "all")),
                    format=str(raw_endpoint.get("format", "generic")),
                )
            )

    enabled = bool(cli_endpoint) or bool(webhook_cfg.get("enabled", False))
    return WebhookRuntimeConfig(
        enabled=enabled,
        signing_key_env=str(webhook_cfg.get("signing_key_env", "VP_WEBHOOK_HMAC_KEY")),
        key_id=str(webhook_cfg.get("key_id", "primary")),
        timeout_seconds=int(webhook_cfg.get("timeout_seconds", 5)),
        connect_timeout_seconds=int(webhook_cfg.get("connect_timeout_seconds", 3)),
        read_timeout_seconds=int(webhook_cfg.get("read_timeout_seconds", 5)),
        max_retries=int(webhook_cfg.get("max_retries", 2)),
        max_payload_bytes=int(webhook_cfg.get("max_payload_bytes", 262144)),
        replay_window_seconds=int(webhook_cfg.get("replay_window_seconds", 300)),
        allow_spool=bool(webhook_cfg.get("allow_spool", True)),
        spool_subdir=str(webhook_cfg.get("spool_subdir", "webhook_spool")),
        endpoints=tuple(endpoints),
    )


def initialize_runtime(args) -> RuntimeBootstrapState:
    paths = AppPaths.resolve(portable=getattr(args, "portable", None))
    paths.ensure_dirs()

    print_banner()

    bootstrap_log = paths.log_dir / "bootstrap.log"
    logwrap = LoggerWrapper(str(bootstrap_log), log_level=args.log_level)
    logger = logwrap
    logger.print_info("Starting up VulnParse-Pin...", f"VulnParse-Pin {__version__}")

    pfh = PermFileHandler(
        logger=logger,
        root_dir=paths.base_dir,
        allowed_roots=[
            paths.config_dir,
            paths.cache_dir,
            paths.log_dir,
            paths.output_dir,
        ],
        max_log_path_chars=25,
        hide_home=True,
        forbid_symlinks_read=args.forbid_symlinks_read,
        forbid_symlinks_write=args.forbid_symlinks_write,
        enforce_roots_on_read=args.enforce_root_read,
        enforce_roots_on_write=args.enforce_root_write,
        file_mode=args.file_mode,
        dir_mode=args.dir_mode,
    )

    if args.debug_path_policy:
        logger.print_info(f"\n{pfh.describe_policy()}", label="Path Policy")
        sys.exit(0)

    ctx = RunContext(
        paths=paths,
        pfh=pfh,
        logger=logger,
        services=None,
    )

    cfg_yaml_path, cfg_score_path, cfg_topn_path = ensure_user_configs(paths)
    cfg_yaml, scoring_cfg, topn_cfg = load_config(ctx)

    topn_pol: TriageConfigLoadResult = load_tn_config(ctx, topn_cfg)

    nmap_ctx_cfg = cfg_yaml.get("nmap_ctx", {}) or {}
    nmap_port_bonus = float(nmap_ctx_cfg.get("scoring_port_bonus", 0.0))
    score_pol: ScoringPolicyV1 = load_score_policy(scoring_cfg, nmap_port_bonus=nmap_port_bonus)
    try:
        _require(score_pol.w_epss_high >= 0, "w_epss_high must be >= 0")
        _require(score_pol.w_epss_medium >= 0, "w_epss_medium must be >= 0")
        _require(score_pol.w_exploit >= 0, "w_exploit must be >= 0")
        _require(score_pol.w_kev >= 0, "w_kev must be >= 0")
        _require(score_pol.kev_evd >= 0, "kev_evd must be >= 0")
        _require(score_pol.exploit_evd >= 0, "exploit_evd must be >= 0")
        _require(score_pol.band_critical >= 0, "band_critical must be >= 0")
        _require(score_pol.band_high >= 0, "band_high must be >= 0")
        _require(score_pol.band_medium >= 0, "band_medium must be >= 0")
        _require(score_pol.band_low >= 0, "band_low must be >= 0")
        _require(score_pol.epss_scale > 0, "epss.scale must be > 0")
        _require(score_pol.band_critical > score_pol.band_high > score_pol.band_medium > score_pol.band_low >= 0, "Invalid band thresholds")
        _require(score_pol.w_epss_high >= score_pol.w_epss_medium >= 0, "Invalid EPSS weights: epss_high must be >= epss_medium")
    except ValueError as e:
        logger.print_error("Scoring config has invalid values.", label="Scoring Config")
        raise RuntimeError(f"Scoring config has invalid values: {e}") from e

    feed_policy = build_feed_cache_policy(cfg_yaml)

    FEED_SPECS = {
        "epss": FeedSpec(key="epss", filename="epss_cache.csv", label="EPSS"),
        "kev": FeedSpec(key="kev", filename="kev_cache.json", label="CISA KEV"),
        "exploit_db": FeedSpec(key="exploit_db", filename="files_exploit.csv", label="Exploit-DB"),
    }

    feed_cache = FeedCacheManager.from_ctx(ctx, specs=FEED_SPECS, policy=feed_policy)

    # Load NVD Policy
    nvd_policy = nvd_policy_from_config(cfg_yaml)
    nvdpol_start_y = nvd_policy["start_year"]
    nvdpol_end_y = nvd_policy["end_year"]
    if not args.no_nvd:
        nvd_cache = NVDFeedCache(ctx)
        nvd_status = "Enabled"
    else:
        nvd_cache = None
        nvd_status = "Disabled (--no-nvd)"
        logger.print_warning("NVD Cache is disabled. NVD data reconciliation will not be available during enrichment.")
        nvdpol_start_y = cfg_yaml.get("feed_cache", {}).get("nvd", {}).get("start_year", (datetime.now().year - 1))
        nvdpol_end_y = cfg_yaml.get("feed_cache", {}).get("nvd", {}).get("end_year", datetime.now().year)

    services = Services(
        feed_cache=feed_cache,
        nvd_cache=nvd_cache,
        scoring_config=score_pol,
        topn_config=topn_pol.config,
        ledger=LedgerService(),
        runmanifest_mode=getattr(args, "runmanifest_mode", "compact"),
        nmap_ctx_config=nmap_ctx_cfg,
        webhook_config=_build_webhook_runtime_config(cfg_yaml, args),
    )
    ctx = RunContext(paths=paths, pfh=pfh, logger=logger, services=services)

    run_log_name = build_run_log(args.log_file)
    run_log_path = pfh.ensure_writable_file(
        paths.log_dir / Path(run_log_name).name,
        label="Run Log File",
        create_parents=True,
        overwrite=True,
    )

    logwrap = LoggerWrapper(str(run_log_path), log_level=args.log_level)
    logger = logwrap

    pfh.logger = logger
    ctx = RunContext(paths=paths, pfh=pfh, logger=logger, services=services)

    detector = SchemaDetector(PARSER_SPECS)

    logger.phase("Initialization")
    logger.print_info(f"Using config: {cfg_yaml_path.name}", label="Global Config")
    logger.print_info(f"Using scoring config: {cfg_score_path.name}", label="Scoring Weight Config")
    logger.print_info(f"Using TopN Pass Config: {cfg_topn_path.name}", label="TopN Pass Config")
    enrichment_cfg = cfg_yaml.get("enrichment", {}) if isinstance(cfg_yaml, dict) else {}
    ghsa_source = getattr(args, "ghsa", None)
    confidence_cfg = enrichment_cfg.get("confidence") if isinstance(enrichment_cfg, dict) else None
    if isinstance(confidence_cfg, dict):
        model_version = confidence_cfg.get("model_version", "v1")
        base_scanner = confidence_cfg.get("base_scanner", 35)
        max_score = confidence_cfg.get("max_score", 100)
        weights = confidence_cfg.get("weights", {})
        logger.print_info(
            f"Confidence model={model_version}; base_scanner={base_scanner}; max_score={max_score}; "
            f"weights={weights}",
            label="Enrichment Confidence",
        )
    logger.print_info(
        f"GHSA source: {ghsa_source if ghsa_source else 'disabled'}",
        label="GHSA Config",
    )
    logger.debug("\n%s", pfh.describe_policy(), extra={"vp_label": "PFH Policy"})

    summary_cfg = cfg_yaml.get("summary", {}) if isinstance(cfg_yaml, dict) else {}
    summary_top_n = int(summary_cfg.get("top_n_findings", 20))
    if summary_top_n < 1:
        summary_top_n = 1

    passesList = [
        NmapAdapterPass(getattr(args, "nmap_ctx", None)),
        ScoringPass(ctx.services.scoring_config),
        AttackCapabilityInferencePass(ctx.services.topn_config.aci),
        TopNPass(ctx.services.topn_config),
        SummaryPass(SummaryConfig(include_top_risks=summary_top_n)),
    ]
    passOrchestrator = PassRunner(passesList)

    return RuntimeBootstrapState(
        paths=paths,
        pfh=pfh,
        ctx=ctx,
        logger=logger,
        cfg_yaml=cfg_yaml,
        scoring_cfg=scoring_cfg,
        topn_cfg=topn_cfg,
        cfg_yaml_path=cfg_yaml_path,
        cfg_score_path=cfg_score_path,
        cfg_topn_path=cfg_topn_path,
        nvd_cache=nvd_cache,
        nvd_status=nvd_status,
        nvdpol_start_y=nvdpol_start_y,
        nvdpol_end_y=nvdpol_end_y,
        feed_cache=feed_cache,
        detector=detector,
        passesList=passesList,
        passOrchestrator=passOrchestrator,
    )
