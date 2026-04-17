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
import concurrent.futures as cf
from typing import List, Dict

from vulnparse_pin.core.classes.dataclass import ScanResult, RunContext
from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.utils.enricher import enrich_scan_results, update_enrichment_status
from vulnparse_pin.utils.enrichment_stats import stats
from vulnparse_pin.utils.exploit_enrichment_service import (
    apply_heuristic_exploit_tags_batch,
    enrich_exploit_availability,
)
from vulnparse_pin.app.enrichment_source_loader import (
    EnrichmentSourceLoader,
    EnrichmentSourcePlan,
    EnrichmentSourceResult,
)
from vulnparse_pin.app.enrichment_handoff import EnrichmentHandoffBuilder


@dataclass(frozen=True)
class EnrichmentPipelineState:
    scan_result: ScanResult
    sources: dict
    nvd_status: str


@dataclass(frozen=True)
class EnrichmentApplyResult:
    scan_result: ScanResult
    stats_summary: dict


class EnrichmentApplicator:
    """
    Stage 2 seam boundary: applies loaded enrichment sources to findings.
    """

    @staticmethod
    def apply(
        args,
        ctx: RunContext,
        scan_result: ScanResult,
        source_result: EnrichmentSourceResult,
        *,
        nvd_cache,
        confidence_policy: dict | None = None,
    ) -> EnrichmentApplyResult:
        logger = ctx.logger
        kev_data = source_result.kev_data
        epss_data = source_result.epss_data
        exploit_data = source_result.exploit_data
        ghsa_data = source_result.ghsa_data
        ghsa_package_data = source_result.ghsa_package_data

        logger.phase("Exploit Enrichment")
        if (not args.no_exploit) and exploit_data:
            from vulnparse_pin.utils.banner import print_section_header

            print_section_header("Exploit Enrichment Results")

            # Parallel exploit enrichment with batch logging
            asset_stats: List[Dict[str, int]] = []
            num_assets = len(scan_result.assets)

            # Use parallel processing for large asset counts
            if num_assets > 10:
                max_workers = min(8, num_assets)
                logger.print_info(
                    f"Enriching {num_assets:,} assets in parallel (workers={max_workers})...",
                    label="Exploit Enrichment",
                )

                def enrich_asset(asset):
                    enriched, asset_stat = enrich_exploit_availability(ctx, asset.findings, exploit_data, asset.asset_id)
                    return asset, enriched, asset_stat

                with cf.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(enrich_asset, asset): asset for asset in scan_result.assets}

                    for future in cf.as_completed(futures):
                        asset, enriched_findings, asset_stat = future.result()
                        asset.findings = enriched_findings
                        asset_stats.append(asset_stat)
            else:
                # Sequential processing for small asset counts
                for asset in scan_result.assets:
                    enriched_findings, asset_stat = enrich_exploit_availability(ctx, asset.findings, exploit_data, asset.asset_id)
                    asset.findings = enriched_findings
                    asset_stats.append(asset_stat)

            # Aggregate and log summary
            total_exploits = sum(s["exploit_found"] for s in asset_stats)
            total_no_exploit = sum(s["no_exploit"] for s in asset_stats)
            total_no_cves = sum(s["no_cves"] for s in asset_stats)
            total_kev_marked = sum(s["kev_marked"] for s in asset_stats)
            total_findings = sum(s["total_findings"] for s in asset_stats)

            logger.print_success(
                f"Exploit enrichment complete: {total_exploits:,} exploits found, "
                f"{total_no_exploit:,} not found, {total_no_cves:,} no CVEs, "
                f"{total_kev_marked:,} KEV-marked across {num_assets:,} assets ({total_findings:,} findings)",
                label="Enrichment",
            )

        apply_heuristic_exploit_tags_batch(ctx, scan_result)

        logger.phase("Enrichment Pipeline")
        kev_enabled = (not args.no_kev)
        epss_enabled = (not args.no_epss)
        nvd_enabled = (not args.no_nvd)
        if (
            (kev_enabled and kev_data is not None)
            or (epss_enabled and epss_data is not None)
            or (ghsa_data is not None)
            or nvd_enabled
        ):
            enrich_scan_results(
                ctx,
                scan_result,
                kev_data,
                epss_data,
                offline_mode=(args.kev_source == "offline" and args.epss_source == "offline"),
                nvd_cache=nvd_cache,
                ghsa_data=ghsa_data,
                ghsa_package_data=ghsa_package_data,
                confidence_policy=confidence_policy,
            )
            logger.print_success("All enrichments Applied")

        for asset in scan_result.assets:
            for finding in asset.findings:
                update_enrichment_status(finding)

        stats_summary = {
            "kev_hits": stats.kev_hits,
            "kev_total": stats.total_cves,
            "epss_hits": (stats.total_cves - stats.epss_misses),
            "epss_total": stats.total_cves,
            "nvd_vectors": stats.cvss_vectors_assigned,
            "nvd_validated": stats.cvss_vectors_validated,
            "exploit_hits": stats.exploitdb_hits,
            "ghsa_auth_token_rejections": int(source_result.sources.get("ghsa_auth_token_rejections", 0) or 0),
        }

        return EnrichmentApplyResult(scan_result=scan_result, stats_summary=stats_summary)


def run_enrichment_pipeline(
    args,
    ctx,
    scan_result,
    cfg_yaml,
    nvdpol_start_y: int,
    nvdpol_end_y: int,
    feed_cache,
    nvd_cache,
    passes_list,
    pass_orchestrator,
    exploit_db,
    kev_source,
    epss_source,
) -> EnrichmentPipelineState:
    logger = ctx.logger
    ledger = getattr(getattr(ctx, "services", None), "ledger", None)

    if ledger is not None:
        ledger.append_event(
            component="Enrichment",
            event_type="phase_start",
            subject_ref="phase:enrichment",
            reason_code=DecisionReasonCodes.ENRICHMENT_PHASE_STARTED,
            reason_text="Enrichment pipeline started.",
            factor_refs=["kev", "epss", "nvd", "exploit_db"],
        )

    logger.phase("Threat-Intel Enrichment Feeds")
    enrichment_cfg = cfg_yaml.get("enrichment", {}) if isinstance(cfg_yaml, dict) else {}
    ghsa_cfg = enrichment_cfg if isinstance(enrichment_cfg, dict) else {}
    ghsa_source = getattr(args, "ghsa", None)
    ghsa_budget = getattr(args, "ghsa_budget", None)
    ghsa_token_env = ghsa_cfg.get("ghsa_token_env") if isinstance(ghsa_cfg, dict) else None
    if ghsa_budget is None and isinstance(ghsa_cfg, dict):
        ghsa_budget = ghsa_cfg.get("ghsa_online_prefetch_budget")
    confidence_policy = enrichment_cfg.get("confidence") if isinstance(enrichment_cfg, dict) else None

    source_plan = EnrichmentSourcePlan(
        kev_enabled=(not args.no_kev),
        epss_enabled=(not args.no_epss),
        exploit_enabled=(not args.no_exploit),
        nvd_enabled=(not args.no_nvd),
        kev_source=str(kev_source) if kev_source is not None else None,
        epss_source=str(epss_source) if epss_source is not None else None,
        exploit_source=(str(exploit_db) if args.exploit_source == "offline" and exploit_db is not None else args.exploit_source),
        refresh_cache=args.refresh_cache,
        allow_regen=args.allow_regen,
        ghsa_enabled=bool(ghsa_source),
        ghsa_source=str(ghsa_source) if ghsa_source else None,
        ghsa_budget=int(ghsa_budget) if ghsa_budget is not None else None,
        ghsa_token_env=str(ghsa_token_env) if ghsa_token_env else None,
    )
    source_result = EnrichmentSourceLoader.load_sources(
        ctx=ctx,
        scan=scan_result,
        cfg_yaml=cfg_yaml,
        nvd_cache=nvd_cache,
        feed_cache=feed_cache,
        plan=source_plan,
        nvdpol_start_y=nvdpol_start_y,
        nvdpol_end_y=nvdpol_end_y,
    )
    apply_result = EnrichmentApplicator.apply(
        args=args,
        ctx=ctx,
        scan_result=scan_result,
        source_result=source_result,
        nvd_cache=nvd_cache,
        confidence_policy=confidence_policy,
    )
    scan_result = apply_result.scan_result

    handoff = EnrichmentHandoffBuilder.build(ctx=ctx, scan_result=scan_result)
    ctx = handoff.ctx
    scan_result = handoff.scan_result

    logger.phase("Derived Pass Pipeline")
    logger.print_info(
        f"Executing derived passes pipeline — Passes: {[getattr(p, 'name') for p in passes_list] if len(passes_list) > 1 else passes_list[0]}",
        label="Pass Pipeline",
    )
    scan_result = pass_orchestrator.run_all(ctx=ctx, scan=scan_result)
    logger.print_success("Derived Passes Pipeline complete.", label="Pass Pipeline")

    sources = dict(source_result.sources)
    sources["stats"] = dict(apply_result.stats_summary)

    if ledger is not None:
        ledger.append_event(
            component="Enrichment",
            event_type="phase_end",
            subject_ref="phase:enrichment",
            reason_code=DecisionReasonCodes.ENRICHMENT_PHASE_COMPLETED,
            reason_text="Enrichment pipeline completed and index was built.",
            factor_refs=["stats.kev_hits", "stats.epss_hits", "stats.exploit_hits"],
            evidence={"stats": dict(sources.get("stats", {}))},
        )

    return EnrichmentPipelineState(
        scan_result=scan_result,
        sources=sources,
        nvd_status=source_result.nvd_status,
    )
