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
import time
import concurrent.futures as cf
from typing import List, Dict

from colorama import Fore, Style

from vulnparse_pin.core.classes.dataclass import ScanResult, Services, RunContext
from vulnparse_pin.utils.banner import print_section_header
from vulnparse_pin.utils.enricher import enrich_scan_results, load_epss, load_kev, update_enrichment_status
from vulnparse_pin.utils.enrichment_stats import stats
from vulnparse_pin.utils.exploit_enrichment_service import (
    apply_heuristic_exploit_tags_batch,
    enrich_exploit_availability,
    load_exploit_data,
)
from vulnparse_pin.utils.nvdcacher import nvd_policy_from_config

from vulnparse_pin.app.runtime_helpers import extract_cve_years, select_years
from vulnparse_pin.app.index_builder import build_post_enrichment_index


@dataclass(frozen=True)
class EnrichmentPipelineState:
    scan_result: ScanResult
    sources: dict
    nvd_status: str


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

    logger.phase("Threat-Intel Enrichment Feeds")
    kev_data = None
    epss_data = None

    exploit_data = None
    if (not args.no_exploit) and args.exploit_source == "online":
        print_section_header("Exploit-DB")
        logger.print_info(
            f"Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{args.exploit_source.upper()}{Style.RESET_ALL} source...",
            label="Exploit-DB Loader",
        )

        exploit_data = load_exploit_data(ctx, source=args.exploit_source, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)
        logger.print_success(f"Loaded Exploit-DB data ({len(exploit_data)} CVEs with exploits)\n", label="Exploit-DB Loader")
    elif (not args.no_exploit) and args.exploit_source == "offline":
        print_section_header("Exploit-DB")
        logger.print_info(
            f"Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{ctx.pfh.format_for_log(exploit_db)}{Style.RESET_ALL}...",
            label="Local Exploit-DB Cache",
        )

        exploit_data = load_exploit_data(ctx, source=exploit_db, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)

        logger.print_success(f"Loaded Exploit-DB data ({len(exploit_data)} CVEs with expoits)", label="Exploit-DB Loader")

    nvd_status = "Enabled" if not args.no_nvd else "Disabled (--no-nvd)"
    nvd_policy = nvd_policy_from_config(cfg_yaml)
    if not args.no_nvd and nvd_policy.get("enabled", True):
        if ctx.services.nvd_cache is not None:
            print_section_header("National Vulnerability Database (NVD)")
            logger.print_info(f"Policy: {nvd_policy}", label="NVD Cache Policy")
            years_seen = extract_cve_years(ctx, scan_result)
            normalized_years = select_years(ctx, years_seen)
            years_to_load = sorted(y for y in normalized_years if nvdpol_start_y <= y <= nvdpol_end_y)
            include_modified = any(y >= (nvdpol_end_y - 1) for y in years_to_load)
            if not years_to_load:
                ctx.logger.print_info("NVD Enabled, but no CVEs in configured year range; skipping NVD index build.", label="NVD Cache Loader")
                nvd_status = "Enabled (Skipped)"
            else:
                t0 = time.perf_counter()

                cves_in_scan = set()
                for asset in scan_result.assets:
                    for finding in asset.findings:
                        if finding.cves:
                            cves_in_scan.update(finding.cves)

                ctx.logger.debug(
                    "Years seen during normalization: %s, Years Normalized: %s Years Selected: %s",
                    years_seen,
                    normalized_years,
                    years_to_load,
                    extra={"vp_label": "NVD Cache Loader"},
                )
                ctx.logger.print_info(
                    f"Scan contains {len(cves_in_scan)} unique CVEs; filtering NVD index...",
                    label="NVD Optimization",
                )

                ctx.services.nvd_cache.refresh(
                    config=cfg_yaml,
                    feed_cache=feed_cache,
                    refresh_cache=args.refresh_cache,
                    offline=(args.kev_source == "offline" and args.epss_source == "offline"),
                    years=years_to_load,
                    include_modified=include_modified,
                    target_cves=cves_in_scan,
                )
                t1 = time.perf_counter()
                logger.debug(f"NVD Load time: {(t1 - t0)}", extra={"vp_label": "Performance"})
        else:
            raise ValueError("NVD Enrichment is enabled but no O1 Lookup exists. Check flags and try again.")

    if kev_source:
        print_section_header("CISA Known Exploited Vulnerabilities (KEV)")
        kev_data = load_kev(ctx, path_url=kev_source, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)

    if epss_source:
        print_section_header("FIRST Exploit Prediction Scoring System (EPSS)")
        epss_data = load_epss(ctx, path_url=epss_source, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)

    logger.phase("Exploit Enrichment")
    if (not args.no_exploit) and exploit_data:
        print_section_header("Exploit Enrichment Results")
        
        # Parallel exploit enrichment with batch logging
        asset_stats: List[Dict[str, int]] = []
        num_assets = len(scan_result.assets)
        
        # Use parallel processing for large asset counts
        if num_assets > 10:
            max_workers = min(8, num_assets)
            logger.print_info(f"Enriching {num_assets:,} assets in parallel (workers={max_workers})...", label="Exploit Enrichment")
            
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
            label="Enrichment"
        )

    apply_heuristic_exploit_tags_batch(ctx, scan_result)

    logger.phase("Enrichment Pipeline")
    kev_enabled = (not args.no_kev)
    epss_enabled = (not args.no_epss)
    if (kev_enabled and kev_data is not None) or (epss_enabled and epss_data is not None):
        enrich_scan_results(
            ctx,
            scan_result,
            kev_data,
            epss_data,
            offline_mode=(args.kev_source == "offline" and args.epss_source == "offline"),
            nvd_cache=nvd_cache,
        )
        logger.print_success("All enrichments Applied")

    # Build post-enrichment index for pass phase optimization
    logger.phase("Post-Enrichment Indexing")
    logger.print_info("Building post-enrichment index for pass phases...", label="Index Builder")
    post_enrichment_index = build_post_enrichment_index(scan_result)
    logger.debug(
        "Index built: %d findings, %d assets, %d severity groups, %d CVE groups",
        len(post_enrichment_index.finding_by_id),
        len(post_enrichment_index.asset_observations),
        len(post_enrichment_index.findings_by_severity),
        len(post_enrichment_index.findings_by_cve),
        extra={"vp_label": "Index Builder"}
    )
    
    # Update context with indexed services
    updated_services = Services(
        feed_cache=ctx.services.feed_cache,
        nvd_cache=ctx.services.nvd_cache,
        scoring_config=ctx.services.scoring_config,
        topn_config=ctx.services.topn_config,
        post_enrichment_index=post_enrichment_index,
    )
    ctx = RunContext(
        paths=ctx.paths,
        pfh=ctx.pfh,
        logger=ctx.logger,
        services=updated_services,
    )
    logger.print_success("Post-enrichment index built and wired to services")

    logger.phase("Derived Pass Pipeline")
    logger.print_info(
        f"Executing derived passes pipeline — Passes: {[getattr(p, 'name') for p in passes_list] if len(passes_list) > 1 else passes_list[0]}",
        label="Pass Pipeline",
    )
    scan_result = pass_orchestrator.run_all(ctx=ctx, scan=scan_result)
    logger.print_success("Derived Passes Pipeline complete.", label="Pass Pipeline")

    for asset in scan_result.assets:
        for finding in asset.findings:
            update_enrichment_status(finding)

    sources = {
        "exploitdb": True,
        "kev": kev_data is not None,
        "epss": epss_data is not None,
        "nvd": nvd_status,
        "stats": {
            "kev_hits": stats.kev_hits,
            "kev_total": stats.total_cves,
            "epss_hits": (stats.total_cves - stats.epss_misses),
            "epss_total": stats.total_cves,
            "nvd_vectors": stats.cvss_vectors_assigned,
            "nvd_validated": stats.cvss_vectors_validated,
            "exploit_hits": stats.exploitdb_hits,
        },
    }

    return EnrichmentPipelineState(scan_result=scan_result, sources=sources, nvd_status=nvd_status)
