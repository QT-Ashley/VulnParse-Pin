# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass, is_dataclass, replace
from types import SimpleNamespace

from vulnparse_pin.app.index_builder import build_post_enrichment_index
from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult, Services


@dataclass(frozen=True)
class EnrichmentHandoffResult:
    """
    Stage 3 seam boundary output: post-enrichment index + rewired context.
    """

    ctx: RunContext
    scan_result: ScanResult


class EnrichmentHandoffBuilder:
    """
    Builds post-enrichment handoff state for derived pass execution.
    """

    @staticmethod
    def build(ctx: RunContext, scan_result: ScanResult) -> EnrichmentHandoffResult:
        logger = ctx.logger

        logger.phase("Post-Enrichment Indexing")
        logger.print_info("Building post-enrichment index for pass phases...", label="Index Builder")
        post_enrichment_index = build_post_enrichment_index(scan_result)
        logger.debug(
            "Index built: %d findings, %d assets, %d severity groups, %d CVE groups",
            len(post_enrichment_index.finding_by_id),
            len(post_enrichment_index.asset_observations),
            len(post_enrichment_index.findings_by_severity),
            len(post_enrichment_index.findings_by_cve),
            extra={"vp_label": "Index Builder"},
        )

        existing_services = getattr(ctx, "services", None)
        if existing_services is None:
            updated_services = Services(post_enrichment_index=post_enrichment_index)
        elif is_dataclass(existing_services):
            updated_services = replace(existing_services, post_enrichment_index=post_enrichment_index)
        elif isinstance(existing_services, SimpleNamespace):
            attrs = dict(vars(existing_services))
            attrs["post_enrichment_index"] = post_enrichment_index
            updated_services = SimpleNamespace(**attrs)
        else:
            updated_services = Services(
                feed_cache=getattr(existing_services, "feed_cache", None),
                nvd_cache=getattr(existing_services, "nvd_cache", None),
                scoring_config=getattr(existing_services, "scoring_config", None),
                topn_config=getattr(existing_services, "topn_config", None),
                post_enrichment_index=post_enrichment_index,
                ledger=getattr(existing_services, "ledger", None),
                runmanifest_mode=getattr(existing_services, "runmanifest_mode", "compact"),
                nmap_ctx_config=getattr(existing_services, "nmap_ctx_config", None),
                webhook_config=getattr(existing_services, "webhook_config", None),
                global_config=getattr(existing_services, "global_config", None),
            )

        if is_dataclass(ctx):
            updated_ctx = replace(ctx, services=updated_services)
        else:
            updated_ctx = RunContext(
                paths=ctx.paths,
                pfh=ctx.pfh,
                logger=ctx.logger,
                services=updated_services,
            )
        logger.print_success("Post-enrichment index built and wired to services")

        return EnrichmentHandoffResult(ctx=updated_ctx, scan_result=scan_result)
