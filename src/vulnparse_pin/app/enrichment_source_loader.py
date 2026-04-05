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
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult


@dataclass(frozen=True)
class EnrichmentSourcePlan:
    """
    Represents the enrichment source loading plan (mode, flags, paths).
    """
    kev_enabled: bool
    epss_enabled: bool
    exploit_enabled: bool
    nvd_enabled: bool
    kev_source: Optional[str]
    epss_source: Optional[str]
    exploit_source: Optional[str]
    refresh_cache: bool
    allow_regen: bool


@dataclass(frozen=True)
class EnrichmentSourceResult:
    """
    Represents loaded enrichment source data and status.
    """
    kev_data: Optional[dict]
    epss_data: Optional[dict]
    exploit_data: Optional[dict]
    nvd_status: str
    sources: dict  # Summary of source availability


class EnrichmentSourceLoader:
    """
    Enrichment source loader: handles discovery and loading of all enrichment sources.
    Orchestrates KEV, EPSS, Exploit-DB, and NVD loading based on configuration and mode.
    """

    @staticmethod
    def load_sources(
        ctx: "RunContext",
        scan: "ScanResult",
        cfg_yaml: dict,
        nvd_cache,
        feed_cache,
        plan: EnrichmentSourcePlan,
        nvdpol_start_y: int,
        nvdpol_end_y: int,
    ) -> EnrichmentSourceResult:
        """
        Load all enrichment sources according to plan.
        Returns EnrichmentSourceResult with loaded data and status summary.
        """
        from vulnparse_pin.utils.enricher import load_epss, load_kev
        from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
        from vulnparse_pin.utils.nvdcacher import nvd_policy_from_config
        from vulnparse_pin.app.runtime_helpers import extract_cve_years, select_years
        import time
        from vulnparse_pin.utils.banner import print_section_header
        from colorama import Fore, Style

        logger = ctx.logger
        kev_data = None
        epss_data = None
        exploit_data = None
        nvd_status = "Enabled" if plan.nvd_enabled else "Disabled (--no-nvd)"

        # Load Exploit-DB
        if plan.exploit_enabled and plan.exploit_source:
            print_section_header("Exploit-DB")
            logger.print_info(
                f"Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{plan.exploit_source.upper()}{Style.RESET_ALL} source...",
                label="Exploit-DB Loader",
            )
            exploit_data = load_exploit_data(
                ctx,
                source=plan.exploit_source,
                force_refresh=plan.refresh_cache,
                allow_regen=plan.allow_regen,
            )
            logger.print_success(
                f"Loaded Exploit-DB data ({len(exploit_data)} CVEs with exploits)\n",
                label="Exploit-DB Loader",
            )

        # Load NVD
        if plan.nvd_enabled and nvd_cache is not None:
            nvd_policy = nvd_policy_from_config(cfg_yaml)
            if nvd_policy.get("enabled", True):
                print_section_header("National Vulnerability Database (NVD)")
                logger.print_info(f"Policy: {nvd_policy}", label="NVD Cache Policy")

                years_seen = extract_cve_years(ctx, scan)
                normalized_years = select_years(ctx, years_seen)
                years_to_load = sorted(
                    y for y in normalized_years if nvdpol_start_y <= y <= nvdpol_end_y
                )
                include_modified = any(y >= (nvdpol_end_y - 1) for y in years_to_load)

                if not years_to_load:
                    ctx.logger.print_info(
                        "NVD Enabled, but no CVEs in configured year range; skipping NVD index build.",
                        label="NVD Cache Loader",
                    )
                    nvd_status = "Enabled (Skipped)"
                else:
                    cves_in_scan = set()
                    for asset in scan.assets:
                        for finding in asset.findings:
                            if finding.cves:
                                cves_in_scan.update(finding.cves)

                    ctx.logger.print_info(
                        f"Scan contains {len(cves_in_scan)} unique CVEs; filtering NVD index...",
                        label="NVD Optimization",
                    )

                    t0 = time.perf_counter()
                    nvd_cache.refresh(
                        config=cfg_yaml,
                        feed_cache=feed_cache,
                        refresh_cache=plan.refresh_cache,
                        offline=(plan.kev_source == "offline" and plan.epss_source == "offline"),
                        years=years_to_load,
                        include_modified=include_modified,
                        target_cves=cves_in_scan,
                    )
                    t1 = time.perf_counter()
                    logger.debug(
                        f"NVD Load time: {(t1 - t0):.2f}s",
                        extra={"vp_label": "Performance"},
                    )

        # Load KEV
        if plan.kev_enabled and plan.kev_source:
            print_section_header("CISA Known Exploited Vulnerabilities (KEV)")
            kev_data = load_kev(
                ctx,
                path_url=plan.kev_source,
                force_refresh=plan.refresh_cache,
                allow_regen=plan.allow_regen,
            )

        # Load EPSS
        if plan.epss_enabled and plan.epss_source:
            print_section_header("FIRST Exploit Prediction Scoring System (EPSS)")
            epss_data = load_epss(
                ctx,
                path_url=plan.epss_source,
                force_refresh=plan.refresh_cache,
                allow_regen=plan.allow_regen,
            )

        # Build source summary
        sources_summary = {
            "exploitdb": plan.exploit_enabled and (exploit_data is not None),
            "kev": kev_data is not None,
            "epss": epss_data is not None,
            "nvd": nvd_status,
        }

        return EnrichmentSourceResult(
            kev_data=kev_data,
            epss_data=epss_data,
            exploit_data=exploit_data,
            nvd_status=nvd_status,
            sources=sources_summary,
        )
