# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from typing import Any, Dict, Optional


class EnrichmentStats:
    def __init__(self) -> None:
        self.total_cves = 0
        self.kev_hits = 0
        self.epss_misses = 0
        self.cvss_vectors_assigned = 0
        self.cvss_vectors_validated = 0
        self.exploitdb_hits = 0

        # CVSSVector resolution statistics (batch logging optimization)
        self.cvss_scanner_v3_used = 0
        self.cvss_scanner_v2_used = 0
        self.cvss_nvd_fallback = 0
        self.cvss_score_only = 0
        self.cvss_not_found = 0
        self.cvss_no_cve_skipped = 0
        self.cvss_parse_errors = 0

        # v2 provenance / source counters
        self.ghsa_hits = 0
        self.osv_hits = 0
        self.cna_cvss_used = 0
        self.cvss_v4_used = 0

    def reset(self) -> None:
        self.__init__()

    def to_dict(self) -> Dict[str, int]:
        return {
            "total_cves": int(self.total_cves),
            "kev_hits": int(self.kev_hits),
            "epss_misses": int(self.epss_misses),
            "cvss_vectors_assigned": int(self.cvss_vectors_assigned),
            "cvss_vectors_validated": int(self.cvss_vectors_validated),
            "exploitdb_hits": int(self.exploitdb_hits),
            "cvss_scanner_v3_used": int(self.cvss_scanner_v3_used),
            "cvss_scanner_v2_used": int(self.cvss_scanner_v2_used),
            "cvss_nvd_fallback": int(self.cvss_nvd_fallback),
            "cvss_score_only": int(self.cvss_score_only),
            "cvss_not_found": int(self.cvss_not_found),
            "cvss_no_cve_skipped": int(self.cvss_no_cve_skipped),
            "cvss_parse_errors": int(self.cvss_parse_errors),
            "ghsa_hits": int(self.ghsa_hits),
            "osv_hits": int(self.osv_hits),
            "cna_cvss_used": int(self.cna_cvss_used),
            "cvss_v4_used": int(self.cvss_v4_used),
        }


def get_enrichment_stats(ctx: Optional[Any] = None) -> EnrichmentStats:
    """Return per-run EnrichmentStats from ctx/ctx.services, falling back to module singleton."""
    if ctx is not None:
        direct = getattr(ctx, "enrichment_stats", None)
        if direct is not None:
            return direct
        services = getattr(ctx, "services", None)
        if services is not None:
            svc_stats = getattr(services, "enrichment_stats", None)
            if svc_stats is not None:
                return svc_stats
    return stats


# Legacy fallback instance for callers without per-run EnrichmentStats on RunContext
stats = EnrichmentStats()