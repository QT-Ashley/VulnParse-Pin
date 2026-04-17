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
    ghsa_enabled: bool = False
    ghsa_source: Optional[str] = None
    ghsa_budget: Optional[int] = None
    ghsa_token_env: Optional[str] = None


@dataclass(frozen=True)
class EnrichmentSourceResult:
    """
    Represents loaded enrichment source data and status.
    """
    kev_data: Optional[dict]
    epss_data: Optional[dict]
    exploit_data: Optional[dict]
    ghsa_data: Optional[dict]
    ghsa_package_data: Optional[dict]
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
        ghsa_data = None
        ghsa_package_data = None
        ghsa_auth_token_rejections = 0
        nvd_status = "Enabled" if plan.nvd_enabled else "Disabled (--no-nvd)"

        cves_in_scan = set()
        for asset in scan.assets:
            for finding in asset.findings:
                if finding.cves:
                    cves_in_scan.update(finding.cves)

        # Load Exploit-DB
        if plan.exploit_enabled and plan.exploit_source:
            print_section_header("Exploit-DB")
            if str(plan.exploit_source).lower() == "online":
                logger.print_info(
                    f"Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}ONLINE{Style.RESET_ALL} source...",
                    label="Exploit-DB Loader",
                )
            else:
                logger.print_info(
                    f"Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{ctx.pfh.format_for_log(plan.exploit_source)}{Style.RESET_ALL}...",
                    label="Local Exploit-DB Cache",
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

        # Load GHSA (offline local advisory database)
        if plan.ghsa_enabled and plan.ghsa_source:
            from vulnparse_pin.utils.ghsa_enrichment import GHSAEnrichmentSource

            print_section_header("GitHub Security Advisories (GHSA)")
            logger.print_info(
                f"Loading GHSA advisories from {ctx.pfh.format_for_log(plan.ghsa_source)}",
                label="GHSA Loader",
            )
            ghsa = GHSAEnrichmentSource(ctx, token_env_name=plan.ghsa_token_env)
            ghsa_mode = str(plan.ghsa_source).strip().lower()
            loaded_ok = False
            if ghsa_mode == "online":
                summary = ghsa.preload_online_for_cves(
                    cves_in_scan,
                    max_lookups=plan.ghsa_budget if plan.ghsa_budget is not None else 25,
                )
                loaded_ok = True
                logger.print_info(
                    f"Online prefetch queried {summary['queried']}/{summary['requested']} CVEs with {summary['hits']} hit(s).",
                    label="GHSA Loader",
                )
            else:
                loaded_ok = ghsa.load_offline(
                    db_path=plan.ghsa_source,
                    target_cves=cves_in_scan,
                    force_reindex=plan.refresh_cache,
                )

            if loaded_ok:
                ghsa_data = dict(ghsa.ghsa_by_cve)
                ghsa_package_data = dict(ghsa.ghsa_by_package)
                ghsa_auth_token_rejections = ghsa.token_rejection_count
                logger.print_success(
                    f"Loaded GHSA advisory mappings ({len(ghsa_data)} CVEs, {len(ghsa_package_data)} packages)",
                    label="GHSA Loader",
                )
            else:
                ghsa_auth_token_rejections = ghsa.token_rejection_count
                logger.print_warning("GHSA load failed or returned no advisories.", label="GHSA Loader")

        # Build source summary
        sources_summary = {
            "exploitdb": plan.exploit_enabled and (exploit_data is not None),
            "kev": kev_data is not None,
            "epss": epss_data is not None,
            "ghsa": ghsa_data is not None,
            "ghsa_auth_token_rejections": int(ghsa_auth_token_rejections),
            "nvd": nvd_status,
        }

        return EnrichmentSourceResult(
            kev_data=kev_data,
            epss_data=epss_data,
            exploit_data=exploit_data,
            ghsa_data=ghsa_data,
            ghsa_package_data=ghsa_package_data,
            nvd_status=nvd_status,
            sources=sources_summary,
        )
