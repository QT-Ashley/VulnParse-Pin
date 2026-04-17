from __future__ import annotations

from dataclasses import dataclass

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

        updated_services = Services(
            feed_cache=ctx.services.feed_cache,
            nvd_cache=ctx.services.nvd_cache,
            scoring_config=ctx.services.scoring_config,
            topn_config=ctx.services.topn_config,
            post_enrichment_index=post_enrichment_index,
            ledger=ctx.services.ledger,
            runmanifest_mode=ctx.services.runmanifest_mode,
        )
        updated_ctx = RunContext(
            paths=ctx.paths,
            pfh=ctx.pfh,
            logger=ctx.logger,
            services=updated_services,
        )
        logger.print_success("Post-enrichment index built and wired to services")

        return EnrichmentHandoffResult(ctx=updated_ctx, scan_result=scan_result)
