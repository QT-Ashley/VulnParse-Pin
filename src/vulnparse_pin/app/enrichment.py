# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass
import concurrent.futures as cf
from datetime import datetime, timezone
import json
from typing import Any, Dict, Iterable, List, Optional, Set

from vulnparse_pin.core.classes.dataclass import ScanResult, RunContext
from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.utils.enricher import (
    _extract_advisory_ids,
    _get_stats,
    _is_valid_cve_id,
    _normalize_confidence_policy,
    _parse_bounded_prob,
    _score_confidence_from_sources,
    enrich_scan_results,
    resolve_cvss_with_provenance,
    update_enrichment_status,
)
from vulnparse_pin.utils.exploit_enrichment_service import (
    apply_heuristic_exploit_tags_batch,
    enrich_exploit_availability,
    is_heuristic_exploit_mention,
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
        osv_data = getattr(source_result, "osv_data", None)
        osv_package_data = getattr(source_result, "osv_package_data", None)
        run_stats = _get_stats(ctx)

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
            or (osv_data is not None)
            or nvd_enabled
        ):
            offline_mode = (
                bool(getattr(args, "offline", False))
                if hasattr(args, "offline")
                else (getattr(args, "kev_source", None) == "offline" and getattr(args, "epss_source", None) == "offline")
            )
            enrich_scan_results(
                ctx,
                scan_result,
                kev_data,
                epss_data,
                offline_mode=offline_mode,
                nvd_cache=nvd_cache,
                ghsa_data=ghsa_data,
                ghsa_package_data=ghsa_package_data,
                confidence_policy=confidence_policy,
                osv_data=osv_data,
                osv_package_data=osv_package_data,
            )
            logger.print_success("All enrichments Applied")

        for asset in scan_result.assets:
            for finding in asset.findings:
                update_enrichment_status(finding)

        stats_summary = {
            "kev_hits": run_stats.kev_hits,
            "kev_total": run_stats.total_cves,
            "epss_hits": (run_stats.total_cves - run_stats.epss_misses),
            "epss_total": run_stats.total_cves,
            "nvd_vectors": run_stats.cvss_vectors_assigned,
            "nvd_validated": run_stats.cvss_vectors_validated,
            "exploit_hits": run_stats.exploitdb_hits,
            "ghsa_auth_token_rejections": int(source_result.sources.get("ghsa_auth_token_rejections", 0) or 0),
        }

        return EnrichmentApplyResult(scan_result=scan_result, stats_summary=stats_summary)


def _resolve_duckdb_conn(db: Any) -> Any:
    for attr in ("conn", "connection", "_conn"):
        candidate = getattr(db, attr, None)
        if candidate is not None and hasattr(candidate, "execute"):
            return candidate
    if hasattr(db, "execute"):
        return db
    raise TypeError("Expected VppDatabase or DuckDB connection with execute().")


def _extract_source_value(sources: Any, *keys: str, default: Any = None) -> Any:
    if isinstance(sources, dict):
        for key in keys:
            if key in sources and sources[key] is not None:
                return sources[key]
        return default
    for key in keys:
        val = getattr(sources, key, None)
        if val is not None:
            return val
    return default


def populate_enrichment_snapshots(
    db: Any,
    run_id: str,
    ctx: RunContext,
    sources: Any,
    target_cves: Optional[Iterable[str]] = None,
    target_purls: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Hydrate ONLY matched CVEs/PURLs from NVD, GHSA, OSV, EPSS v5, KEV, and Exploit-DB,
    compute unified CVSS provenance + confidence, and bulk-insert into `.vpp.db`'s
    `enrichment_snapshots` table (plus update `runs.intel_metadata_json`).
    """
    conn = _resolve_duckdb_conn(db)

    # 1. Resolve target CVEs from parameter or .vpp.db tables
    raw_cves: Set[str] = set()
    passed_list = list(target_cves) if target_cves is not None else []
    if passed_list:
        for c in passed_list:
            if isinstance(c, str) and _is_valid_cve_id(c):
                raw_cves.add(c.strip().upper())
    else:
        for query in (
            "SELECT DISTINCT cve_id FROM finding_cves WHERE run_id = ?",
            "SELECT DISTINCT primary_cve FROM findings WHERE run_id = ? AND primary_cve IS NOT NULL",
        ):
            try:
                for (cve_val,) in conn.execute(query, [run_id]).fetchall():
                    if isinstance(cve_val, str) and _is_valid_cve_id(cve_val):
                        raw_cves.add(cve_val.strip().upper())
            except Exception:
                continue

    # Resolve target PURLs from parameter or .vpp.db findings
    raw_purls: Set[str] = set()
    if target_purls is not None:
        for p in target_purls:
            if isinstance(p, str) and p.strip():
                raw_purls.add(p.strip())
    else:
        try:
            for (purl_val,) in conn.execute(
                "SELECT DISTINCT package_purl FROM findings WHERE run_id = ? AND package_purl IS NOT NULL",
                [run_id],
            ).fetchall():
                if isinstance(purl_val, str) and purl_val.strip():
                    raw_purls.add(purl_val.strip())
        except Exception:
            pass

    # Query negation-aware heuristic mention and PURLs from .vpp.db if available.
    # NOTE: Scanner-supplied CVSS is intentionally NOT aggregated per CVE here;
    # each finding resolves its own scanner_cvss_score/scanner_cvss_vector independently.
    heuristic_by_cve: Dict[str, bool] = {}
    purls_by_cve: Dict[str, Set[str]] = {}
    try:
        rows = conn.execute(
            """
            SELECT fc.cve_id, f.title, f.description, f.plugin_output, f.package_purl
            FROM finding_cves fc
            JOIN findings f ON f.run_id = fc.run_id AND f.finding_id = fc.finding_id
            WHERE fc.run_id = ?
            """,
            [run_id],
        ).fetchall()
        for cve_val, title, desc, plugin_out, purl_val in rows:
            if not isinstance(cve_val, str) or not _is_valid_cve_id(cve_val):
                continue
            c_up = cve_val.strip().upper()
            if not heuristic_by_cve.get(c_up):
                combined_text = "\n".join(str(x) for x in (title, desc, plugin_out) if x)
                if is_heuristic_exploit_mention(combined_text):
                    heuristic_by_cve[c_up] = True
            if isinstance(purl_val, str) and purl_val.strip():
                purls_by_cve.setdefault(c_up, set()).add(purl_val.strip())
    except Exception:
        pass

    # 2. Extract / normalize enrichment sources
    services = getattr(ctx, "services", None)
    nvd_cache = _extract_source_value(sources, "nvd_cache") or (
        getattr(services, "nvd_cache", None) if services is not None else None
    )
    if nvd_cache is not None and raw_cves and hasattr(nvd_cache, "_sqlite_hydrate_targets"):
        nvd_cache._sqlite_hydrate_targets(raw_cves)

    kev_data = _extract_source_value(sources, "kev_data", "kev") or {}
    epss_data = _extract_source_value(sources, "epss_data", "epss") or {}
    exploit_data = _extract_source_value(sources, "exploit_data", "exploitdb") or {}

    ghsa_source_obj = _extract_source_value(sources, "ghsa_source")
    ghsa_data = _extract_source_value(sources, "ghsa_data")
    if ghsa_data is None and ghsa_source_obj is not None and hasattr(ghsa_source_obj, "ghsa_by_cve"):
        if raw_cves and hasattr(ghsa_source_obj, "_sqlite_hydrate_targets"):
            ghsa_source_obj._sqlite_hydrate_targets(raw_cves)
        if raw_purls and hasattr(ghsa_source_obj, "_sqlite_hydrate_packages"):
            ghsa_source_obj._sqlite_hydrate_packages(target_purls=raw_purls)
        ghsa_data = ghsa_source_obj.ghsa_by_cve
    ghsa_data = ghsa_data or {}

    osv_source_obj = _extract_source_value(sources, "osv_source", "osv")
    if isinstance(osv_source_obj, dict) and not hasattr(osv_source_obj, "lookup_by_cve"):
        osv_data = _extract_source_value(sources, "osv_data") or osv_source_obj
        osv_source_obj = None
    else:
        osv_data = _extract_source_value(sources, "osv_data")
        if osv_data is None and osv_source_obj is not None and hasattr(osv_source_obj, "osv_by_cve"):
            if (raw_cves or raw_purls) and hasattr(osv_source_obj, "_sqlite_hydrate_targets"):
                osv_source_obj._sqlite_hydrate_targets(
                    target_cves=raw_cves or None,
                    target_purls=raw_purls or None,
                )
            osv_data = osv_source_obj.osv_by_cve
    osv_data = osv_data or {}

    confidence_policy = _normalize_confidence_policy(
        _extract_source_value(sources, "confidence_policy")
    )

    # Normalize KEV records & EPSS records
    kev_records: Dict[str, Dict[str, Any]] = {}
    if isinstance(getattr(kev_data, "records", None), dict):
        for c, rec in kev_data.records.items():
            kev_records[str(c).strip().upper()] = dict(rec)
    for c, v in (kev_data or {}).items():
        cu = str(c).strip().upper()
        if isinstance(v, dict):
            kev_records.setdefault(cu, dict(v))
        elif v:
            kev_records.setdefault(cu, {"cve_id": cu})

    epss_scores: Dict[str, float] = {}
    epss_percentiles: Dict[str, Optional[float]] = {}
    epss_model_version = getattr(epss_data, "model_version", None)
    epss_score_date = getattr(epss_data, "score_date", None)
    if isinstance(getattr(epss_data, "percentiles", None), dict):
        for c, pct in epss_data.percentiles.items():
            pct_val = _parse_bounded_prob(pct, allow_percent=True)
            if pct_val is not None:
                epss_percentiles[str(c).strip().upper()] = pct_val
    for c, val in (epss_data or {}).items():
        cu = str(c).strip().upper()
        if isinstance(val, dict):
            s_raw = val.get("epss_score") if val.get("epss_score") is not None else val.get("epss")
            s_val = _parse_bounded_prob(s_raw, allow_percent=False)
            if s_val is not None:
                epss_scores[cu] = s_val
            p_raw = val.get("epss_percentile") if val.get("epss_percentile") is not None else val.get("percentile")
            p_val = _parse_bounded_prob(p_raw, allow_percent=True)
            if p_val is not None:
                epss_percentiles[cu] = p_val
        elif val is not None:
            s_val = _parse_bounded_prob(val, allow_percent=False)
            if s_val is not None:
                epss_scores[cu] = s_val

    # 3. Build bulk rows for matched CVEs ONLY
    sorted_cves = sorted(raw_cves)
    snapshot_rows: List[tuple[Any, ...]] = []
    for cve in sorted_cves:
        nvd_rec = nvd_cache.get(cve) if nvd_cache is not None and hasattr(nvd_cache, "get") else None
        ghsa_advs = list(ghsa_data.get(cve, []) or [])
        if not ghsa_advs and ghsa_source_obj is not None and hasattr(ghsa_source_obj, "lookup_by_purl"):
            for p in purls_by_cve.get(cve, ()):
                ghsa_advs.extend(ghsa_source_obj.lookup_by_purl(p))
        osv_advs = list(osv_data.get(cve, []) or [])
        if not osv_advs and osv_source_obj is not None and hasattr(osv_source_obj, "lookup_by_cve"):
            osv_advs = osv_source_obj.lookup_by_cve(cve)
            if not osv_advs:
                for p in purls_by_cve.get(cve, ()):
                    osv_advs.extend(osv_source_obj.lookup_by_purl(p))

        resolved_cvss = resolve_cvss_with_provenance(
            ctx,
            scanner_vector=None,
            scanner_score=None,
            auth_cve=cve,
            nvd_record=nvd_rec,
            ghsa_advisories=ghsa_advs,
            osv_advisories=osv_advs,
        )
        snap_cvss_score = resolved_cvss["cvss_score"]
        snap_cvss_vector = resolved_cvss["resolved_vector"]
        snap_cvss_version = resolved_cvss["cvss_version"]
        snap_cvss_provenance = resolved_cvss["cvss_provenance"]
        if snap_cvss_provenance == "Scanner-Supplied":
            snap_cvss_score = None
            snap_cvss_vector = None
            snap_cvss_version = None
            snap_cvss_provenance = "Missing"

        in_kev = cve in kev_records
        kev_rec = kev_records.get(cve, {})
        epss_score = epss_scores.get(cve)
        epss_pct = epss_percentiles.get(cve)

        raw_exploit_refs = exploit_data.get(cve, []) if isinstance(exploit_data, dict) else []
        exploit_refs = [dict(r) for r in raw_exploit_refs if isinstance(r, dict)] if isinstance(raw_exploit_refs, list) else []
        verified_exploit = bool(exploit_refs)
        heuristic_mention = bool(heuristic_by_cve.get(cve, False))

        ghsa_ids = _extract_advisory_ids(ghsa_advs)
        osv_ids = _extract_advisory_ids(osv_advs)

        used_sources: List[str] = ["scanner"]
        if snap_cvss_provenance in ("NVD", "CNA"):
            used_sources.append("nvd")
        if in_kev:
            used_sources.append("kev")
        if epss_score is not None:
            used_sources.append("epss")
        if verified_exploit:
            used_sources.append("exploitdb")
        if ghsa_ids:
            used_sources.append("ghsa")
        if osv_ids:
            used_sources.append("osv")
        used_sources = sorted(set(used_sources))

        confidence, _ = _score_confidence_from_sources(
            used_sources,
            confidence_policy,
            ghsa_advisory_count=len(ghsa_advs),
        )

        snapshot_rows.append(
            (
                run_id,
                cve,
                snap_cvss_score,
                snap_cvss_vector,
                snap_cvss_version,
                snap_cvss_provenance,
                epss_score,
                epss_pct,
                epss_model_version,
                epss_score_date,
                in_kev,
                kev_rec.get("date_added") if in_kev else None,
                kev_rec.get("due_date") if in_kev else None,
                bool(kev_rec.get("known_ransomware", False)) if in_kev else False,
                kev_rec.get("required_action") if in_kev else None,
                verified_exploit,
                heuristic_mention,
                json.dumps(exploit_refs),
                json.dumps(ghsa_ids),
                json.dumps(osv_ids),
                confidence,
                json.dumps(used_sources),
            )
        )

    if snapshot_rows:
        conn.execute("BEGIN TRANSACTION")
        try:
            conn.execute(
                """
                CREATE TEMP TABLE _stg_enrich_snap (
                    run_id VARCHAR, cve_id VARCHAR, cvss_score DOUBLE, cvss_vector VARCHAR,
                    cvss_version VARCHAR, cvss_provenance VARCHAR, epss_score DOUBLE,
                    epss_percentile DOUBLE, epss_model_version VARCHAR, epss_date VARCHAR,
                    in_kev BOOLEAN, kev_date_added VARCHAR, kev_due_date VARCHAR,
                    kev_ransomware BOOLEAN, kev_required_action VARCHAR, verified_exploit BOOLEAN,
                    heuristic_exploit_mention BOOLEAN, exploit_refs_json VARCHAR, ghsa_ids_json VARCHAR,
                    osv_ids_json VARCHAR, enrichment_confidence DOUBLE, sources_json VARCHAR
                )
                """
            )
            with conn.appender("_stg_enrich_snap") as app:
                app.append_rows(snapshot_rows)
            conn.execute(
                """
                INSERT OR REPLACE INTO enrichment_snapshots
                SELECT * FROM _stg_enrich_snap
                """
            )
            conn.execute("DROP TABLE _stg_enrich_snap")
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    source_summary = _extract_source_value(sources, "sources", default={}) or {}
    intel_metadata = {
        "epss_model_version": epss_model_version or source_summary.get("epss_model_version"),
        "epss_score_date": epss_score_date or source_summary.get("epss_score_date"),
        "epss_sha256": getattr(epss_data, "source_sha256", None) or source_summary.get("epss_sha256"),
        "kev_catalog_version": getattr(kev_data, "catalog_version", None) or source_summary.get("kev_catalog_version"),
        "kev_date_released": getattr(kev_data, "date_released", None) or source_summary.get("kev_date_released"),
        "kev_sha256": getattr(kev_data, "source_sha256", None) or source_summary.get("kev_sha256"),
        "nvd_status": _extract_source_value(sources, "nvd_status") or source_summary.get("nvd"),
        "ghsa_enabled": bool(ghsa_data or ghsa_source_obj is not None),
        "osv_enabled": bool(osv_data or osv_source_obj is not None),
        "populated_cves": len(snapshot_rows),
        "updated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    try:
        conn.execute(
            "UPDATE runs SET intel_metadata_json = ? WHERE run_id = ?",
            [json.dumps(intel_metadata), run_id],
        )
    except Exception:
        pass

    return {
        "run_id": run_id,
        "target_cve_count": len(sorted_cves),
        "snapshots_written": len(snapshot_rows),
        "intel_metadata": intel_metadata,
    }


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

    osv_source = getattr(args, "osv", None)
    if not osv_source and isinstance(enrichment_cfg, dict):
        osv_source = enrichment_cfg.get("osv_source")
    offline_mode = (
        bool(getattr(args, "offline", False))
        if hasattr(args, "offline")
        else (getattr(args, "kev_source", None) == "offline" and getattr(args, "epss_source", None) == "offline")
    )

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
        offline=offline_mode,
        osv_enabled=bool(osv_source),
        osv_source=str(osv_source) if osv_source else None,
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
        args=args,
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
