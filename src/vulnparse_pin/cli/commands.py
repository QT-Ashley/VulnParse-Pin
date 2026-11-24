# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from contextlib import ExitStack, closing
from dataclasses import asdict, is_dataclass, replace
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
from hashlib import sha256
import hmac
from importlib import resources
import inspect
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
from uuid import uuid4

from vulnparse_pin import __version__
from vulnparse_pin.app.bootstrap import RuntimeBootstrapState, build_pfh, initialize_runtime
from vulnparse_pin.app.enrichment import populate_enrichment_snapshots
from vulnparse_pin.app.output import (
    export_v2_outputs,
    invoke_duckdb_csv_export,
    invoke_duckdb_json_export,
    write_text_via_pfh,
)
from vulnparse_pin.app.runtime_helpers import (
    authorize_output_dir,
    authorize_output_path,
    build_feed_cache_policy,
    build_run_log,
)
from vulnparse_pin.cli.errors import VppError
from vulnparse_pin.io.pfhandler import FilePathError, FilePermissionError, PermFileHandler
from vulnparse_pin.core.apppaths import AppPaths, ensure_user_configs
from vulnparse_pin.core.assets_context import AssetContextMatcher, DecisionsRegistry, upsert_decision
from vulnparse_pin.core.classes.dataclass import FeedSpec, RunContext, Services
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.config_projector import ConfigProjector
from vulnparse_pin.core.config_source import ConfigSource
from vulnparse_pin.core.config_validator import ConfigValidator
from vulnparse_pin.core.diff_engine import DiffEngine, evaluate_fail_gate
from vulnparse_pin.core.passes import run_v2_duckdb_pipeline
from vulnparse_pin.core.passes.Triage.triage_pass import TriageDecisionPass
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.storage.db import VppDatabase, _check_no_symlinks_or_loops, _validate_duckdb_paths
from vulnparse_pin.storage.repositories import (
    ensure_run,
    get_run_summary_counts,
    get_shadow_assets,
    insert_ledger_events,
    list_runs,
)
from vulnparse_pin.utils.feed_cache import FeedCacheManager
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.nvdcacher import NVDFeedCache, nvd_policy_from_config

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_FEED = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)


def _stream_file_sha256(path: Optional[Path]) -> Optional[str]:
    if path is None or not path.exists() or not path.is_file():
        return None
    h = sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def _is_http_url(value: str) -> bool:
    v = str(value).strip().lower()
    return v.startswith("http://") or v.startswith("https://")


def _build_v2_ctx(base_ctx: RunContext, *, db: Any, run_id: str, asset_matcher: Any = None, decisions_registry: Any = None) -> RunContext:
    services = getattr(base_ctx, "services", None)
    if services is not None and is_dataclass(services):
        updated_services = replace(
            services,
            db=db,
            run_id=run_id,
            asset_matcher=asset_matcher,
            decisions_registry=decisions_registry,
        )
    else:
        updated_services = Services(
            db=db,
            run_id=run_id,
            asset_matcher=asset_matcher,
            decisions_registry=decisions_registry,
        )
    return replace(
        base_ctx,
        services=updated_services,
        db=db,
        run_id=run_id,
        asset_matcher=asset_matcher,
        decisions_registry=decisions_registry,
    )


def _flush_ledger_to_db(db: Any, run_id: str, ctx: RunContext) -> int:
    services = getattr(ctx, "services", None)
    ledger = getattr(services, "ledger", None) if services is not None else None
    if ledger is None:
        return 0
    snap = ledger.snapshot()
    rows = [asdict(entry) for entry in snap.entries]
    db.execute("DELETE FROM ledger_events WHERE run_id = ?", [run_id])
    if not rows:
        return 0
    return insert_ledger_events(db, run_id, rows)


def _instantiate_parser(parser_cls: Any, ctx: RunContext, scan_path: Path, *, allow_large: bool) -> Any:
    try:
        sig = inspect.signature(parser_cls.__init__)
        params = sig.parameters
        accepts_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
        if accepts_kw or "allow_large" in params:
            return parser_cls(ctx, scan_path, allow_large=allow_large)
    except (TypeError, ValueError):
        pass
    return parser_cls(ctx, scan_path)


def _stream_files_to_db(
    ctx: RunContext,
    detector: SchemaDetector,
    db: VppDatabase,
    run_id: str,
    input_files: Sequence[Path],
    *,
    asset_matcher: Optional[AssetContextMatcher] = None,
    allow_large: bool = False,
    allow_degraded_input: bool = True,
    strict_ingestion: bool = False,
    min_ingestion_confidence: float = 0.0,
    show_ingestion_summary: bool = False,
) -> Dict[str, int]:
    from vulnparse_pin.app.normalization import enforce_batch_ingestion_gates, validate_scanner_input

    totals = {
        "assets_ingested": 0,
        "shadow_assets": 0,
        "raw_findings_ingested": 0,
        "unique_findings_ingested": 0,
        "deduplicated_findings": 0,
    }
    for scan_path in input_files:
        valid_path = validate_scanner_input(ctx, Path(scan_path), allow_large=allow_large)
        try:
            det = detector.select(ctx, valid_path, allow_large=allow_large)
            parser = _instantiate_parser(det.parser_cls, ctx, valid_path, allow_large=allow_large)
            raw_batches = parser.iter_batches(batch_size=10_000)
            gated = enforce_batch_ingestion_gates(
                ctx,
                raw_batches,
                allow_degraded_input=allow_degraded_input,
                strict_ingestion=strict_ingestion,
                min_ingestion_confidence=min_ingestion_confidence,
                show_ingestion_summary=show_ingestion_summary,
            )
            stats = db.ingest_normalized_batches(run_id, gated, asset_matcher=asset_matcher)
        except VppError:
            raise
        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            raise VppError(f"Failed to ingest scan file '{valid_path.name}': {exc}", exit_code=1) from exc

        for k in totals:
            totals[k] = max(totals[k], int(stats.get(k, 0) or 0))
    return totals


def _load_local_nvd_into_cache(
    ctx: RunContext,
    nvd_cache: NVDFeedCache,
    nvd_source: Path,
    *,
    target_cves: Optional[Set[str]] = None,
) -> int:
    """Load local NVD 2.0 JSON, .json.gz, or directory into NVDFeedCache + SQLite."""
    files: List[Path] = []
    if nvd_source.is_dir():
        files = sorted(
            p for p in nvd_source.iterdir()
            if p.is_file() and (p.name.endswith(".json") or p.name.endswith(".json.gz"))
        )
    elif nvd_source.is_file():
        files = [nvd_source]
    else:
        raise VppError(f"NVD source path not found: {nvd_source}", exit_code=1)

    loaded_count = 0
    for fpath in files:
        if fpath.name.endswith(".json.gz"):
            nvd_cache.target_cves = set(target_cves) if target_cves else None
            nvd_cache._parse_feed(str(fpath))
            loaded_count += len(nvd_cache.lookup)
            continue

        # Plain .json NVD 2.0 feed
        with ctx.pfh.open_for_read(fpath, mode="rb", label="Local NVD JSON", log=False) as raw_fh:
            try:
                import ijson
                items = ijson.items(raw_fh, "vulnerabilities.item")
                records: List[Dict[str, Any]] = []
                for item in items:
                    cve = (item or {}).get("cve", {}) or {}
                    raw_id = cve.get("id")
                    if not raw_id:
                        continue
                    cve_id = str(raw_id).strip().upper()
                    if target_cves and cve_id not in target_cves:
                        continue
                    descs = cve.get("descriptions") or []
                    desc = ""
                    if descs:
                        en_desc = next(
                            ((d or {}).get("value") for d in descs if isinstance(d, dict) and str(d.get("lang", "")).lower() == "en"),
                            None,
                        )
                        desc = en_desc if en_desc is not None else ((descs[0] or {}).get("value", "") or "")
                    cve_src = str(cve.get("sourceIdentifier") or "").strip() or None
                    cvss, vec, ver, prov, m_src = nvd_cache._choose_cvss(
                        cve.get("metrics") or {}, default_source_identifier=cve_src
                    )
                    rec = {
                        "id": cve_id,
                        "description": desc,
                        "cvss_score": cvss,
                        "cvss_vector": vec,
                        "cvss_version": ver,
                        "cvss_provenance": prov,
                        "source_identifier": m_src or cve_src,
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                    }
                    nvd_cache.lookup[cve_id] = rec
                    records.append(rec)
                if records:
                    nvd_cache._sqlite_upsert(records)
                    loaded_count += len(records)
            except ImportError:
                raw_fh.seek(0)
                payload = json.loads(raw_fh.read().decode("utf-8"))
                records = []
                for item in payload.get("vulnerabilities", []) or []:
                    cve = (item or {}).get("cve", {}) or {}
                    raw_id = cve.get("id")
                    if not raw_id:
                        continue
                    cve_id = str(raw_id).strip().upper()
                    if target_cves and cve_id not in target_cves:
                        continue
                    descs = cve.get("descriptions") or []
                    desc = ((descs[0] or {}).get("value", "") or "") if descs else ""
                    cve_src = str(cve.get("sourceIdentifier") or "").strip() or None
                    cvss, vec, ver, prov, m_src = nvd_cache._choose_cvss(
                        cve.get("metrics") or {}, default_source_identifier=cve_src
                    )
                    rec = {
                        "id": cve_id,
                        "description": desc,
                        "cvss_score": cvss,
                        "cvss_vector": vec,
                        "cvss_version": ver,
                        "cvss_provenance": prov,
                        "source_identifier": m_src or cve_src,
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                    }
                    nvd_cache.lookup[cve_id] = rec
                    records.append(rec)
                if records:
                    nvd_cache._sqlite_upsert(records)
                    loaded_count += len(records)
    return loaded_count


def _collect_run_cves_and_purls(db: VppDatabase, run_id: str) -> tuple[Set[str], Set[str]]:
    cves: Set[str] = set()
    purls: Set[str] = set()
    for (cve_val,) in db.execute(
        "SELECT DISTINCT cve_id FROM finding_cves WHERE run_id = ?", [run_id]
    ).fetchall():
        if isinstance(cve_val, str) and _CVE_RE.match(cve_val.strip()):
            cves.add(cve_val.strip().upper())
    for (purl_val,) in db.execute(
        "SELECT DISTINCT package_purl FROM findings WHERE run_id = ? AND package_purl IS NOT NULL",
        [run_id],
    ).fetchall():
        if isinstance(purl_val, str) and purl_val.strip():
            purls.add(purl_val.strip())
    return cves, purls


def _load_duckdb_sources(
    ctx: RunContext,
    db: VppDatabase,
    run_id: str,
    args: Any,
    runtime: RuntimeBootstrapState,
) -> Dict[str, Any]:
    from vulnparse_pin.utils.enricher import load_epss, load_kev
    from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
    from vulnparse_pin.utils.ghsa_enrichment import GHSAEnrichmentSource
    from vulnparse_pin.utils.osv_enrichment import OSVEnrichmentSource

    target_cves, target_purls = _collect_run_cves_and_purls(db, run_id)
    offline_mode = bool(getattr(args, "offline", False))
    cfg_yaml = runtime.cfg_yaml or {}
    enrich_cfg = cfg_yaml.get("enrichment", {}) if isinstance(cfg_yaml, dict) else {}
    confidence_policy = enrich_cfg.get("confidence") if isinstance(enrich_cfg, dict) else None
    fc = runtime.feed_cache

    # Exploit-DB
    exploit_data: Dict[str, Any] = {}
    if not bool(getattr(args, "no_exploit", False)):
        edb_arg = getattr(args, "exploit_db", None)
        if edb_arg:
            src_path = ctx.pfh.ensure_readable_file(edb_arg, label="Exploit-DB Input File")
            exploit_data = load_exploit_data(
                ctx,
                source=str(src_path),
                force_refresh=bool(getattr(args, "refresh_cache", False)),
                allow_regen=bool(getattr(args, "allow_regen", False)),
            )
        elif offline_mode or getattr(args, "exploit_source", "online") == "offline":
            cache_edb, _, _ = fc.resolve("exploit_db")
            if cache_edb.exists():
                exploit_data = load_exploit_data(
                    ctx,
                    source=str(cache_edb),
                    force_refresh=False,
                    allow_regen=bool(getattr(args, "allow_regen", False)),
                )
            elif getattr(args, "exploit_source", "online") == "offline" and not offline_mode:
                raise VppError("Offline Exploit-DB source requires --exploit-db PATH.", exit_code=2)
        else:
            exploit_data = load_exploit_data(
                ctx,
                source="online",
                force_refresh=bool(getattr(args, "refresh_cache", False)),
                allow_regen=bool(getattr(args, "allow_regen", False)),
            )

    # NVD
    nvd_cache = runtime.nvd_cache
    nvd_status = runtime.nvd_status
    nvd_override = getattr(args, "nvd_source", None)
    if not bool(getattr(args, "no_nvd", False)) and nvd_cache is not None:
        if nvd_override:
            nvd_path = Path(nvd_override)
            if not nvd_path.exists():
                raise VppError(f"NVD source path does not exist: {nvd_override}", exit_code=1)
            loaded_n = _load_local_nvd_into_cache(ctx, nvd_cache, nvd_path, target_cves=target_cves or None)
            nvd_status = f"Offline ({loaded_n} CVEs)"
        elif target_cves:
            years_seen = {int(m.group(1)) for c in target_cves if (m := _CVE_RE.match(c))}
            nvd_pol = nvd_policy_from_config(cfg_yaml)
            start_y = int(nvd_pol.get("start_year", 2002))
            end_y = int(nvd_pol.get("end_year", datetime.now(timezone.utc).year))
            years_to_load = {max(2002, y) for y in years_seen if start_y <= max(2002, y) <= end_y}
            if offline_mode:
                # Hydrate warm SQLite + only any locally cached year/modified feeds
                unresolved = nvd_cache._sqlite_hydrate_targets(target_cves)
                if unresolved:
                    mod_path, _, _ = fc.resolve("nvd.modified")
                    have_any_feed = mod_path.exists() or any(fc.resolve(f"nvd.year.{y}")[0].exists() for y in years_to_load)
                    if have_any_feed:
                        nvd_cache.refresh(
                            config=cfg_yaml,
                            feed_cache=fc,
                            refresh_cache=bool(getattr(args, "refresh_cache", False)),
                            offline=True,
                            years=years_to_load,
                            include_modified=True,
                            target_cves=target_cves,
                        )
                nvd_status = "Offline (Local/SQLite)"
            elif years_to_load:
                nvd_cache.refresh(
                    config=cfg_yaml,
                    feed_cache=fc,
                    refresh_cache=bool(getattr(args, "refresh_cache", False)),
                    offline=False,
                    years=years_to_load,
                    include_modified=any(y >= (end_y - 1) for y in years_to_load),
                    target_cves=target_cves,
                )
                nvd_status = "Enabled"

    # KEV
    kev_data: Any = {}
    if not bool(getattr(args, "no_kev", False)):
        kev_override = getattr(args, "kev_feed", None)
        kev_cache_path, _, _ = fc.resolve("kev")
        if kev_override:
            if offline_mode and _is_http_url(str(kev_override)):
                raise VppError("--offline does not allow HTTP/HTTPS KEV URLs.", exit_code=2)
            kev_src = (
                str(ctx.pfh.ensure_readable_file(kev_override, label="KEV Local File"))
                if (offline_mode or not _is_http_url(str(kev_override)))
                else str(kev_override)
            )
            kev_data = load_kev(
                ctx,
                kev_src,
                force_refresh=bool(getattr(args, "refresh_cache", False)),
                allow_regen=bool(getattr(args, "allow_regen", False)),
                target_cves=target_cves or None,
            )
        elif offline_mode or getattr(args, "kev_source", "online") == "offline":
            if kev_cache_path.exists():
                kev_data = load_kev(
                    ctx,
                    str(kev_cache_path),
                    force_refresh=False,
                    allow_regen=bool(getattr(args, "allow_regen", False)),
                    target_cves=target_cves or None,
                )
            elif not offline_mode:
                raise VppError(f"Missing offline KEV cache: {kev_cache_path}", exit_code=1)
        else:
            kev_data = load_kev(
                ctx,
                KEV_FEED,
                force_refresh=bool(getattr(args, "refresh_cache", False)),
                allow_regen=bool(getattr(args, "allow_regen", False)),
                target_cves=target_cves or None,
            )

    # EPSS
    epss_data: Any = {}
    if not bool(getattr(args, "no_epss", False)):
        epss_override = getattr(args, "epss_feed", None)
        epss_cache_path, _, _ = fc.resolve("epss")
        if epss_override:
            if offline_mode and _is_http_url(str(epss_override)):
                raise VppError("--offline does not allow HTTP/HTTPS EPSS URLs.", exit_code=2)
            epss_src = (
                str(ctx.pfh.ensure_readable_file(epss_override, label="EPSS Local File"))
                if (offline_mode or not _is_http_url(str(epss_override)))
                else str(epss_override)
            )
            epss_data = load_epss(
                ctx,
                path_url=epss_src,
                force_refresh=bool(getattr(args, "refresh_cache", False)),
                allow_regen=bool(getattr(args, "allow_regen", False)),
                target_cves=target_cves or None,
            )
        elif offline_mode or getattr(args, "epss_source", "online") == "offline":
            if epss_cache_path.exists():
                epss_data = load_epss(
                    ctx,
                    path_url=str(epss_cache_path),
                    force_refresh=False,
                    allow_regen=bool(getattr(args, "allow_regen", False)),
                    target_cves=target_cves or None,
                )
            elif not offline_mode:
                raise VppError(f"Missing offline EPSS cache: {epss_cache_path}", exit_code=1)
        else:
            epss_data = load_epss(
                ctx,
                path_url=EPSS_FEED,
                force_refresh=bool(getattr(args, "refresh_cache", False)),
                allow_regen=bool(getattr(args, "allow_regen", False)),
                target_cves=target_cves or None,
            )

    # GHSA
    ghsa_source_obj = None
    ghsa_arg = getattr(args, "ghsa", None)
    if ghsa_arg:
        ghsa_token_env = enrich_cfg.get("ghsa_token_env") if isinstance(enrich_cfg, dict) else None
        ghsa_source_obj = GHSAEnrichmentSource(ctx, token_env_name=ghsa_token_env)
        if str(ghsa_arg).strip().lower() == "online":
            if offline_mode:
                raise VppError("Online --ghsa mode cannot be combined with --offline.", exit_code=2)
            budget = getattr(args, "ghsa_budget", None) or enrich_cfg.get("ghsa_online_prefetch_budget") or 25
            ghsa_source_obj.preload_online_for_cves(target_cves, max_lookups=int(budget))
        else:
            ghsa_source_obj.load_offline(
                db_path=str(ghsa_arg),
                target_cves=target_cves,
                target_purls=target_purls or None,
                force_reindex=bool(getattr(args, "refresh_cache", False)),
            )

    # OSV
    osv_source_obj = None
    osv_arg = getattr(args, "osv", None) or (enrich_cfg.get("osv_source") if isinstance(enrich_cfg, dict) else None)
    if osv_arg:
        osv_source_obj = OSVEnrichmentSource(ctx)
        osv_source_obj.load_offline(
            db_path=str(osv_arg),
            target_cves=target_cves or None,
            target_purls=target_purls or None,
            force_reindex=bool(getattr(args, "refresh_cache", False)),
        )

    return {
        "nvd_cache": nvd_cache,
        "nvd_status": nvd_status,
        "kev_data": kev_data,
        "epss_data": epss_data,
        "exploit_data": exploit_data,
        "ghsa_source": ghsa_source_obj,
        "osv_source": osv_source_obj,
        "confidence_policy": confidence_policy,
        "sources": {
            "nvd": nvd_status,
            "kev": bool(kev_data),
            "kev_catalog_version": getattr(kev_data, "catalog_version", None),
            "kev_date_released": getattr(kev_data, "date_released", None),
            "kev_sha256": getattr(kev_data, "source_sha256", None),
            "epss": bool(epss_data),
            "epss_model_version": getattr(epss_data, "model_version", None),
            "epss_score_date": getattr(epss_data, "score_date", None),
            "epss_sha256": getattr(epss_data, "source_sha256", None),
            "exploitdb": bool(exploit_data),
            "ghsa": ghsa_source_obj is not None,
            "osv": osv_source_obj is not None,
        },
    }


def _print_v2_summary(
    db: VppDatabase,
    run_id: str,
    *,
    profile: str,
    diff_report: Optional[Any] = None,
    outputs: Optional[Dict[str, Optional[Path]]] = None,
    db_path: Optional[Path] = None,
) -> None:
    counts = get_run_summary_counts(db, run_id)
    shadows = get_shadow_assets(db, run_id)
    by_tier = counts.get("by_priority_tier", {})
    by_sla = counts.get("by_sla_bucket", {})
    by_status = counts.get("by_decision_status", {})

    inv_count = sum(
        int(by_status.get(k, 0) or 0)
        for k in ("deferred_invalidated", "accepted_invalidated", "mitigated_invalidated")
    )

    print("\n" + "=" * 64)
    print(f"  VulnParse-Pin v{__version__} Summary  |  run={run_id}  |  profile={profile}")
    print("=" * 64)
    print(
        f"  Assets: {counts['total_assets']} total "
        f"({counts['matched_assets']} matched, {counts['shadow_assets']} UNMATCHED SHADOW)"
    )
    print(
        f"  Findings: {counts['total_findings']} total "
        f"({counts['cve_findings']} cve_threat, {counts['exposure_findings']} exposure_weakness, "
        f"{counts['deduplicated_findings']} deduplicated across scanners)"
    )
    print(f"  KEV Matches: {counts['kev_findings']}")
    print(
        f"  Priority Tiers: P1={by_tier.get('P1', 0)}  P1B={by_tier.get('P1B', 0)}  "
        f"P2={by_tier.get('P2', 0)}  P3={by_tier.get('P3', 0)}  P4={by_tier.get('P4', 0)}"
    )
    if by_sla:
        sla_str = "  |  ".join(f"{k}: {v}" for k, v in sorted(by_sla.items()))
        print(f"  SLA Buckets: {sla_str}")
    if shadows:
        print(f"  [ALERT] Unmatched Shadow Assets ({len(shadows)}):")
        for s in shadows[:5]:
            ident = s.get("ip_address") or s.get("hostname") or s.get("canonical_key")
            print(
                f"    - {ident} (findings={s.get('finding_count', 0)}, "
                f"kev={s.get('kev_count', 0)}, internet_facing={s.get('internet_facing')})"
            )
    if inv_count > 0 or (diff_report is not None and getattr(diff_report, "invalidated_assumptions", None)):
        items = getattr(diff_report, "invalidated_assumptions", []) if diff_report is not None else []
        print(f"  [ALERT] Invalidated Deferrals/Assumptions: {max(inv_count, len(items))}")
        for item in items[:5]:
            print(
                f"    - {item.primary_cve or item.finding_id} ({item.decision_id or item.invalidation_kind}): "
                f"{', '.join(item.violated_predicates)}"
            )
    if diff_report is not None:
        sm = diff_report.summary
        print(
            f"  Diff ({diff_report.base_run_id} -> {diff_report.target_run_id}): "
            f"+{sm.newly_introduced_high_risk} high-risk | "
            f"{sm.threat_intel_escalated} escalated | "
            f"{sm.verified_remediated} remediated | "
            f"{sm.invalidated_assumptions} invalidated"
        )
    if db_path is not None:
        print(f"  Workspace DB: {db_path}")
    if outputs:
        for k, v in outputs.items():
            if v is not None:
                print(f"  Export ({k}): {v}")
    print("=" * 64 + "\n")


def run_scan_command(args: Any) -> int:
    # Enforce unsafe CSV guard immediately before bootstrapping directories/logs
    if getattr(args, "no_csv_sanitize", False) and not getattr(args, "confirm_unsafe_csv", False):
        raise VppError(
            "Refusing to disable CSV cell sanitization without explicit --confirm-unsafe-csv.",
            exit_code=2,
        )

    runtime = initialize_runtime(args)
    if runtime.debug_path_policy_only:
        return 0

    ctx = runtime.ctx
    pfh = runtime.pfh

    db_path = authorize_output_path(pfh, args.db, label="DuckDB Workspace")
    try:
        _validate_duckdb_paths(db_path)
    except ValueError as exc:
        raise VppError(str(exc), exit_code=1) from exc

    asset_matcher: Optional[AssetContextMatcher] = None
    assets_sha: Optional[str] = None
    if getattr(args, "assets", None):
        asset_file = ctx.pfh.ensure_readable_file(args.assets, label="Assets Config")
        try:
            asset_matcher = AssetContextMatcher.from_file(asset_file, pfh=pfh)
        except Exception as exc:
            raise VppError(f"Invalid assets.yaml '{asset_file}': {exc}", exit_code=1) from exc
        assets_sha = _stream_file_sha256(asset_file)

    decisions_reg: Optional[DecisionsRegistry] = None
    decisions_sha: Optional[str] = None
    if getattr(args, "decisions", None):
        dec_file = ctx.pfh.ensure_readable_file(args.decisions, label="Decisions Config")
        try:
            decisions_reg = DecisionsRegistry.from_file(dec_file, pfh=pfh)
        except Exception as exc:
            raise VppError(f"Invalid decisions.yaml '{dec_file}': {exc}", exit_code=1) from exc
        decisions_sha = _stream_file_sha256(dec_file)
    elif asset_matcher is not None and asset_matcher.inline_decisions:
        decisions_reg = asset_matcher.inline_decisions_registry()

    run_id = getattr(args, "run_id", None) or (
        f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:8]}"
    )
    config_hashes = {
        "config_yaml_sha256": _stream_file_sha256(runtime.cfg_yaml_path),
        "scoring_json_sha256": _stream_file_sha256(runtime.cfg_score_path),
        "tn_triage_json_sha256": _stream_file_sha256(runtime.cfg_topn_path),
        "assets_sha256": assets_sha,
        "decisions_sha256": decisions_sha,
    }

    with VppDatabase(db_path) as db:
        ensure_run(
            db,
            run_id,
            vpp_version=__version__,
            profile=args.profile,
            config_sha256=config_hashes["config_yaml_sha256"],
            assets_sha256=assets_sha,
            decisions_sha256=decisions_sha,
            input_files=[str(p) for p in args.input_files],
            baseline_run_id=getattr(args, "baseline_run_id", None),
            overwrite=bool(getattr(args, "run_id", None)),
        )

        _stream_files_to_db(
            ctx,
            runtime.detector,
            db,
            run_id,
            args.input_files,
            asset_matcher=asset_matcher,
            allow_large=bool(getattr(args, "allow_large", False)),
            allow_degraded_input=bool(getattr(args, "allow_degraded_input", True)),
            strict_ingestion=bool(getattr(args, "strict_ingestion", False)) or bool(getattr(args, "strict_schema", False)),
            min_ingestion_confidence=float(getattr(args, "min_ingestion_confidence", 0.0) or 0.0),
            show_ingestion_summary=bool(getattr(args, "show_ingestion_summary", False)),
        )

        sources = _load_duckdb_sources(ctx, db, run_id, args, runtime)
        target_cves, target_purls = _collect_run_cves_and_purls(db, run_id)
        populate_enrichment_snapshots(
            db,
            run_id,
            ctx,
            sources,
            target_cves=target_cves,
            target_purls=target_purls,
        )

        v2_ctx = _build_v2_ctx(
            ctx,
            db=db,
            run_id=run_id,
            asset_matcher=asset_matcher,
            decisions_registry=decisions_reg,
        )
        run_v2_duckdb_pipeline(
            v2_ctx,
            bundle=runtime.config_bundle,
            profile=args.profile,
            nmap_path=str(args.nmap_ctx) if getattr(args, "nmap_ctx", None) else None,
            decisions_registry=decisions_reg,
        )
        _flush_ledger_to_db(db, run_id, v2_ctx)

        diff_report = None
        if getattr(args, "baseline_run_id", None):
            diff_report = DiffEngine(db, decisions_registry=decisions_reg).compare(
                args.baseline_run_id, run_id, persist=True
            )

        written = export_v2_outputs(
            ctx=v2_ctx,
            db=db,
            run_id=run_id,
            args=args,
            diff_report=diff_report,
            config_hashes=config_hashes,
        )
        _print_v2_summary(
            db,
            run_id,
            profile=args.profile,
            diff_report=diff_report,
            outputs=written,
            db_path=db_path,
        )
    return 0


def run_demo_command(args: Any) -> int:
    from vulnparse_pin.reporting import renderer as _renderer
    from vulnparse_pin.utils.enricher import load_epss, load_kev
    from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
    from vulnparse_pin.utils.ghsa_enrichment import GHSAEnrichmentSource
    from vulnparse_pin.utils import runmanifest as _rm

    with ExitStack() as stack:
        demo_root = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        temp_work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vpp-demo-")))

        # Isolated AppPaths inside temp_work so demo never touches user cache or makes network calls
        cache_dir = temp_work / "cache"
        iso_paths = AppPaths(
            portable=True,
            base_dir=temp_work,
            config_dir=temp_work / "config",
            data_dir=temp_work,
            cache_dir=cache_dir,
            log_dir=temp_work / "logs",
            output_dir=temp_work / "outputs",
            nvd_dir=cache_dir / "nvd",
            nvd_feeds_dir=cache_dir / "nvd" / "feeds",
            kev_dir=cache_dir / "kev",
            epss_dir=cache_dir / "epss",
            exploitdb_dir=cache_dir / "exploit_db",
        )
        iso_paths.ensure_dirs()
        ensure_user_configs(iso_paths)

        bootstrap_log = iso_paths.log_dir / "demo.log"
        logger = LoggerWrapper(str(bootstrap_log), log_level=str(getattr(args, "log_level", "INFO") or "INFO"))
        pfh = build_pfh(iso_paths, logger, args)

        db_path = authorize_output_path(pfh, args.db, label="Demo DuckDB Workspace")
        try:
            _validate_duckdb_paths(db_path)
        except ValueError as exc:
            raise VppError(str(exc), exit_code=1) from exc
        if os.path.lexists(str(db_path)):
            db_path.unlink()
        wal_path = Path(f"{db_path}.wal")
        if os.path.lexists(str(wal_path)):
            wal_path.unlink()

        out_dir = authorize_output_dir(pfh, args.output_dir, label="Demo Output Directory")

        files = ConfigSource.ensure_files(iso_paths)
        init_ctx = RunContext(paths=iso_paths, pfh=pfh, logger=logger, services=None)
        payloads = ConfigSource.read_payloads(init_ctx, files)
        validation = ConfigValidator.validate(init_ctx, payloads)
        bundle = ConfigProjector.project(validation)
        cfg_yaml = bundle.global_config
        feed_policy = build_feed_cache_policy(cfg_yaml)
        feed_specs = {
            "epss": FeedSpec(key="epss", filename="epss_cache.csv", label="EPSS"),
            "kev": FeedSpec(key="kev", filename="kev_cache.json", label="CISA KEV"),
            "exploit_db": FeedSpec(key="exploit_db", filename="files_exploit.csv", label="Exploit-DB"),
        }
        feed_cache = FeedCacheManager.from_ctx(init_ctx, specs=feed_specs, policy=feed_policy)
        nvd_cache = NVDFeedCache(init_ctx)
        detector = SchemaDetector(PARSER_SPECS)

        def _make_run_ctx() -> RunContext:
            svc = Services(
                feed_cache=feed_cache,
                nvd_cache=nvd_cache,
                scoring_config=bundle.scoring_policy.to_v1_policy(),
                topn_config=None,
                ledger=LedgerService(),
                runmanifest_mode="compact",
                global_config=cfg_yaml,
            )
            return RunContext(paths=iso_paths, pfh=pfh, logger=logger, services=svc)

        assets_path = demo_root / "assets.yaml"
        decisions_path = demo_root / "decisions.yaml"
        asset_matcher = AssetContextMatcher.from_file(assets_path, pfh=pfh)
        decisions_reg = DecisionsRegistry.from_file(decisions_path, pfh=pfh)

        config_hashes = {
            "config_yaml_sha256": _stream_file_sha256(files.global_yaml),
            "scoring_json_sha256": _stream_file_sha256(files.scoring_json),
            "tn_triage_json_sha256": _stream_file_sha256(files.topn_json),
            "assets_sha256": _stream_file_sha256(assets_path),
            "decisions_sha256": _stream_file_sha256(decisions_path),
        }

        intel_dir = demo_root / "intel_snapshot"
        now_dt = datetime.now(timezone.utc)
        base_dt = now_dt - timedelta(days=7)

        with VppDatabase(db_path) as db:
            # 1. Baseline run (prior state before CVE-2024-3094 entered KEV and before Log4Shell/Nuclei/Shadow assets)
            base_run_id = "demo-baseline"
            ctx_base = _make_run_ctx()
            ensure_run(
                db,
                base_run_id,
                created_at_utc=base_dt.isoformat().replace("+00:00", "Z"),
                vpp_version=__version__,
                profile=args.profile,
                config_sha256=config_hashes["config_yaml_sha256"],
                assets_sha256=config_hashes["assets_sha256"],
                decisions_sha256=config_hashes["decisions_sha256"],
                input_files=["demo_baseline.nessus"],
                overwrite=True,
            )
            _stream_files_to_db(
                ctx_base,
                detector,
                db,
                base_run_id,
                [demo_root / "demo_baseline.nessus"],
                asset_matcher=asset_matcher,
            )
            base_cves, base_purls = _collect_run_cves_and_purls(db, base_run_id)
            _load_local_nvd_into_cache(ctx_base, nvd_cache, intel_dir / "nvd.json", target_cves=base_cves)
            base_sources = {
                "nvd_cache": nvd_cache,
                "nvd_status": "Offline (Demo Baseline Snapshot)",
                "kev_data": {},
                "epss_data": {
                    "CVE-2024-3094": {"epss_score": 0.005, "epss_percentile": 0.52},
                    "CVE-2023-38545": {"epss_score": 0.0021, "epss_percentile": 0.42},
                    "CVE-2023-4863": {"epss_score": 0.015, "epss_percentile": 0.72},
                },
                "exploit_data": {},
                "sources": {
                    "nvd": "Offline (Demo Baseline Snapshot)",
                    "kev": False,
                    "epss": True,
                    "epss_model_version": "v2025.03.14",
                    "epss_score_date": "2026-10-25",
                },
            }
            populate_enrichment_snapshots(
                db, base_run_id, ctx_base, base_sources, target_cves=base_cves, target_purls=base_purls
            )
            v2_base_ctx = _build_v2_ctx(
                ctx_base, db=db, run_id=base_run_id, asset_matcher=asset_matcher, decisions_registry=decisions_reg
            )
            run_v2_duckdb_pipeline(
                v2_base_ctx,
                bundle=bundle,
                profile=args.profile,
                decisions_registry=decisions_reg,
                now_utc=base_dt,
            )
            _flush_ledger_to_db(db, base_run_id, v2_base_ctx)

            # 2. Current multi-scanner run (Nessus + Trivy SARIF + Nuclei JSONL + Semgrep SARIF + Nmap)
            curr_run_id = "demo-current"
            ctx_curr = _make_run_ctx()
            demo_scan_files = [
                demo_root / "demo.nessus",
                demo_root / "demo_trivy.sarif",
                demo_root / "demo_nuclei.jsonl",
                demo_root / "demo_semgrep.sarif",
            ]
            ensure_run(
                db,
                curr_run_id,
                created_at_utc=now_dt.isoformat().replace("+00:00", "Z"),
                vpp_version=__version__,
                profile=args.profile,
                config_sha256=config_hashes["config_yaml_sha256"],
                assets_sha256=config_hashes["assets_sha256"],
                decisions_sha256=config_hashes["decisions_sha256"],
                input_files=[p.name for p in demo_scan_files],
                baseline_run_id=base_run_id,
                overwrite=True,
            )
            _stream_files_to_db(
                ctx_curr,
                detector,
                db,
                curr_run_id,
                demo_scan_files,
                asset_matcher=asset_matcher,
            )
            curr_cves, curr_purls = _collect_run_cves_and_purls(db, curr_run_id)
            _load_local_nvd_into_cache(ctx_curr, nvd_cache, intel_dir / "nvd.json", target_cves=curr_cves)
            kev_data = load_kev(
                ctx_curr, str(intel_dir / "kev.json"), force_refresh=True, allow_regen=True, target_cves=curr_cves
            )
            epss_data = load_epss(
                ctx_curr, path_url=str(intel_dir / "epss.csv"), force_refresh=True, allow_regen=True, target_cves=curr_cves
            )
            exploit_data = load_exploit_data(
                ctx_curr, source=str(intel_dir / "exploitdb.csv"), force_refresh=True, allow_regen=True
            )
            ghsa_src = GHSAEnrichmentSource(ctx_curr)
            ghsa_src.load_offline(
                db_path=str(intel_dir / "ghsa"),
                target_cves=curr_cves,
                target_purls=curr_purls or None,
                force_reindex=True,
            )
            curr_sources = {
                "nvd_cache": nvd_cache,
                "nvd_status": "Offline (Demo Intel Snapshot)",
                "kev_data": kev_data,
                "epss_data": epss_data,
                "exploit_data": exploit_data,
                "ghsa_source": ghsa_src,
                "sources": {
                    "nvd": "Offline (Demo Intel Snapshot)",
                    "kev": True,
                    "kev_catalog_version": getattr(kev_data, "catalog_version", None),
                    "kev_date_released": getattr(kev_data, "date_released", None),
                    "kev_sha256": getattr(kev_data, "source_sha256", None),
                    "epss": True,
                    "epss_model_version": getattr(epss_data, "model_version", None),
                    "epss_score_date": getattr(epss_data, "score_date", None),
                    "epss_sha256": getattr(epss_data, "source_sha256", None),
                    "exploitdb": True,
                    "ghsa": True,
                    "osv": False,
                },
            }
            populate_enrichment_snapshots(
                db, curr_run_id, ctx_curr, curr_sources, target_cves=curr_cves, target_purls=curr_purls
            )
            v2_curr_ctx = _build_v2_ctx(
                ctx_curr, db=db, run_id=curr_run_id, asset_matcher=asset_matcher, decisions_registry=decisions_reg
            )
            run_v2_duckdb_pipeline(
                v2_curr_ctx,
                bundle=bundle,
                profile=args.profile,
                nmap_path=str(demo_root / "demo_nmap.xml"),
                decisions_registry=decisions_reg,
                now_utc=now_dt,
            )
            _flush_ledger_to_db(db, curr_run_id, v2_curr_ctx)

            diff_report = DiffEngine(
                db, decisions_registry=decisions_reg, now_utc=now_dt
            ).compare(base_run_id, curr_run_id, persist=True)

            template_dir = getattr(args, "template_dir", None)
            dossier_paths = _renderer.export_dossier_bundle(
                db,
                curr_run_id,
                out_dir,
                diff_report=diff_report,
                template_dir=template_dir,
                pfh=pfh,
            )
            roadmap_html = _renderer.render_executive_roadmap_html(
                db,
                curr_run_id,
                diff_report=diff_report,
                template_dir=template_dir,
            )
            roadmap_path = write_text_via_pfh(
                pfh, out_dir / "executive_roadmap.html", roadmap_html, label="Executive Roadmap HTML"
            )

            rm_path = authorize_output_path(pfh, out_dir / "runmanifest.json", label="Demo RunManifest")
            outputs_meta = {
                "json": None,
                "csv": None,
                "executive_markdown": str(dossier_paths["markdown"]),
                "technical_markdown": str(dossier_paths["markdown"]),
                "dossier_html": str(dossier_paths["html"]),
                "executive_roadmap_html": str(roadmap_path),
            }
            build_rm_db = getattr(_rm, "build_runmanifest_from_db", None)
            if callable(build_rm_db):
                manifest = build_rm_db(
                    db,
                    curr_run_id,
                    config_hashes=config_hashes,
                    outputs=outputs_meta,
                    mode="compact",
                )
                _rm.write_runmanifest(v2_curr_ctx, manifest, rm_path)
                digest = (manifest.get("verification") or {}).get("manifest_digest")
                if digest:
                    db.execute("UPDATE runs SET manifest_digest = ? WHERE run_id = ?", [digest, curr_run_id])
            else:
                rm_path = None

            _print_v2_summary(
                db,
                curr_run_id,
                profile=args.profile,
                diff_report=diff_report,
                outputs={
                    "dossier_md": Path(dossier_paths["markdown"]),
                    "dossier_html": Path(dossier_paths["html"]),
                    "roadmap_html": roadmap_path,
                    "runmanifest": rm_path,
                },
                db_path=db_path,
            )

    if not bool(getattr(args, "no_ui", False)) and sys.stdout.isatty():
        try:
            import textual  # noqa: F401
            from vulnparse_pin.ui.app import VppApp
        except ImportError:
            print('Interactive TUI skipped (optional dependency missing). Install with: pip install "vulnparse-pin[ui]"')
            return 0
        app = VppApp(
            db_path=db_path,
            run_id="demo-current",
            output_dir=out_dir,
            template_dir=getattr(args, "template_dir", None),
        )
        app.run()

    return 0


def run_diff_command(args: Any) -> int:
    args._quiet_banner = True
    runtime = initialize_runtime(args, quiet_banner=True)
    ctx = runtime.ctx
    pfh = runtime.pfh

    base_arg = getattr(args, "base", None)
    target_arg = getattr(args, "target", None)
    decisions_reg = (
        DecisionsRegistry.from_file(args.decisions, pfh=pfh)
        if getattr(args, "decisions", None)
        else None
    )

    is_file_pair = (
        base_arg is not None
        and target_arg is not None
        and Path(base_arg).is_file()
        and Path(target_arg).is_file()
    )

    if is_file_pair:
        asset_matcher = (
            AssetContextMatcher.from_file(args.assets, pfh=pfh)
            if getattr(args, "assets", None)
            else None
        )
        with VppDatabase(":memory:") as db:
            base_id = "diff-base"
            target_id = "diff-target"
            now_dt = datetime.now(timezone.utc)
            base_dt = now_dt - timedelta(seconds=5)
            for rid, fpath, ts in ((base_id, Path(base_arg), base_dt), (target_id, Path(target_arg), now_dt)):
                ensure_run(
                    db,
                    rid,
                    created_at_utc=ts.isoformat().replace("+00:00", "Z"),
                    vpp_version=__version__,
                    profile=args.profile,
                    input_files=[str(fpath)],
                    overwrite=True,
                )
                _stream_files_to_db(ctx, runtime.detector, db, rid, [fpath], asset_matcher=asset_matcher)
                sources = _load_duckdb_sources(ctx, db, rid, args, runtime)
                cves, purls = _collect_run_cves_and_purls(db, rid)
                populate_enrichment_snapshots(db, rid, ctx, sources, target_cves=cves, target_purls=purls)
                v2_ctx = _build_v2_ctx(ctx, db=db, run_id=rid, asset_matcher=asset_matcher, decisions_registry=decisions_reg)
                run_v2_duckdb_pipeline(v2_ctx, bundle=runtime.config_bundle, profile=args.profile, decisions_registry=decisions_reg, now_utc=ts)
            report = DiffEngine(db, decisions_registry=decisions_reg).compare(base_id, target_id, persist=False)
    else:
        db_path = _authorize_existing_db_path(pfh, args.db, read_only=False)
        with VppDatabase(db_path) as db:
            try:
                report = DiffEngine(db, decisions_registry=decisions_reg).compare(
                    base_arg, target_arg, persist=True
                )
            except ValueError as exc:
                raise VppError(str(exc), exit_code=1) from exc

    sm = report.summary
    print(f"VPP Diff: {report.base_run_id} -> {report.target_run_id}")
    print(f"  Newly Introduced High Risk : {sm.newly_introduced_high_risk} (all new: {sm.newly_introduced_all})")
    print(f"  Threat Intel Escalated     : {sm.threat_intel_escalated}")
    print(
        f"  Verified Remediated        : {sm.verified_remediated} "
        f"(patched={sm.verified_remediated_confirmed}, asset_missing={sm.verified_remediated_asset_missing})"
    )
    print(f"  Invalidated Assumptions    : {sm.invalidated_assumptions}")
    print(
        f"  Shadow Assets Delta        : +{sm.shadow_assets_new} new / -{sm.shadow_assets_resolved} resolved"
    )

    template_dir = getattr(args, "template_dir", None)
    if getattr(args, "output_pr_comment", None):
        from vulnparse_pin.reporting import renderer as _renderer
        pr_md = _renderer.render_diff_pr_comment(report, template_dir=template_dir)
        write_text_via_pfh(pfh, Path(args.output_pr_comment), pr_md, label="PR Diff Comment")

    if getattr(args, "output_md", None):
        from vulnparse_pin.reporting import renderer as _renderer
        diff_md = _renderer.render_diff_pr_comment(report, template_dir=template_dir)
        write_text_via_pfh(pfh, Path(args.output_md), diff_md, label="Markdown Diff Report")

    if getattr(args, "output_json", None):
        out_json = authorize_output_path(pfh, args.output_json, label="JSON Diff Report")
        with pfh.open_for_write(out_json, mode="w", encoding="utf-8", label="JSON Diff Report") as fh:
            json.dump(report.to_dict(), fh, indent=2)
            fh.write("\n")

    try:
        return evaluate_fail_gate(report, getattr(args, "fail_on", "none"))
    except ValueError as exc:
        raise VppError(str(exc), exit_code=2) from exc


def _authorize_existing_db_path(pfh: Any, raw_db: Any, *, read_only: bool) -> Path:
    raw_path = Path(raw_db)
    try:
        _validate_duckdb_paths(raw_path)
    except ValueError as exc:
        raise VppError(str(exc), exit_code=1) from exc

    if not os.path.lexists(str(raw_path)):
        raise VppError(
            f"DuckDB workspace not found: {raw_path}. Run 'vpp scan' or 'vpp demo' first.",
            exit_code=1,
        )

    try:
        checked = pfh.ensure_readable_file(raw_path, label="DuckDB Workspace")
        if read_only:
            return checked
        return authorize_output_path(pfh, raw_path, label="DuckDB Workspace")
    except VppError:
        raise
    except Exception as exc:
        raise VppError(f"Invalid DuckDB workspace path '{raw_path}': {exc}", exit_code=1) from exc


def run_ui_command(args: Any) -> int:
    try:
        import textual  # noqa: F401
        from vulnparse_pin.ui.app import VppApp
    except ImportError as exc:
        msg = 'Textual UI dependencies are not installed. Install with: pip install "vulnparse-pin[ui]"'
        print(msg, file=sys.stderr)
        raise VppError(msg, exit_code=1) from exc

    args._quiet_banner = True
    runtime = initialize_runtime(args, quiet_banner=True)
    db_path = _authorize_existing_db_path(runtime.pfh, args.db, read_only=False)
    app = VppApp(
        db_path=db_path,
        run_id=getattr(args, "run_id", None),
        decisions_path=getattr(args, "decisions", None),
        output_dir=getattr(args, "output_dir", "."),
        template_dir=getattr(args, "template_dir", None),
        pfh=runtime.pfh,
    )
    app.run()
    return 0


def run_export_command(args: Any) -> int:
    args._quiet_banner = True
    runtime = initialize_runtime(args, quiet_banner=True)
    pfh = runtime.pfh

    db_path = _authorize_existing_db_path(pfh, args.db, read_only=True)

    with VppDatabase(db_path, read_only=True) as db:
        runs = list_runs(db)
        if not runs:
            raise VppError(f"No runs recorded in DuckDB workspace: {db_path}.", exit_code=1)
        run_id = getattr(args, "run_id", None) or runs[0]["run_id"]
        if not any(r["run_id"] == run_id for r in runs):
            raise VppError(f"Run '{run_id}' does not exist in {db_path}.", exit_code=1)

        diff_report = None
        if len(runs) >= 2:
            try:
                diff_report = DiffEngine(db).compare(target_run_id=run_id)
            except Exception:
                diff_report = None

        fmt = str(args.format)
        template_dir = getattr(args, "template_dir", None)
        finding_id = getattr(args, "finding_id", None)
        out_arg = getattr(args, "output", None)

        if fmt in ("dossier-md", "dossier-html", "roadmap-md", "roadmap-html"):
            from vulnparse_pin.reporting import renderer as _renderer
            if fmt == "dossier-md":
                content = _renderer.render_dossier_markdown(
                    db, run_id, finding_id=finding_id, diff_report=diff_report, template_dir=template_dir
                )
            elif fmt == "dossier-html":
                content = _renderer.render_dossier_html(
                    db, run_id, finding_id=finding_id, diff_report=diff_report, template_dir=template_dir
                )
            elif fmt == "roadmap-md":
                content = _renderer.render_executive_roadmap_markdown(
                    db, run_id, diff_report=diff_report, template_dir=template_dir
                )
            else:
                content = _renderer.render_executive_roadmap_html(
                    db, run_id, diff_report=diff_report, template_dir=template_dir
                )

            if out_arg:
                written = write_text_via_pfh(pfh, Path(out_arg), content, label=f"Export ({fmt})")
                print(f"[OK] Exported {fmt}: {written}")
            else:
                print(content)
            return 0

        if fmt == "csv":
            csv_sanitization = not bool(getattr(args, "no_csv_sanitize", False))
            if not csv_sanitization and not bool(getattr(args, "confirm_unsafe_csv", False)):
                msg = (
                    "Refusing to disable CSV cell sanitization without explicit --confirm-unsafe-csv "
                    "(spreadsheet formula injection protection)."
                )
                print(f"[ERROR] {msg}", file=sys.stderr)
                raise VppError(msg, exit_code=2)
            from vulnparse_pin.utils import csv_exporter as _csv_exp
            target = authorize_output_path(
                pfh, out_arg or f"vpp_{run_id}.csv", label="CSV Export File"
            )
            invoke_duckdb_csv_export(
                _csv_exp.export_duckdb_csv,
                db,
                run_id,
                target,
                profile=args.csv_profile,
                pfh=pfh,
                csv_sanitization=csv_sanitization,
            )
            print(f"[OK] Exported csv: {target}")
            return 0

        if fmt == "json":
            from vulnparse_pin.utils import reportgen as _reportgen
            target = authorize_output_path(
                pfh, out_arg or f"vpp_{run_id}.json", label="JSON Export File"
            )
            invoke_duckdb_json_export(
                _reportgen.export_duckdb_json,
                db,
                run_id,
                target,
                presentation=args.overlay_mode,
                pfh=pfh,
                pretty_print=bool(getattr(args, "pretty_print", False)),
            )
            print(f"[OK] Exported json: {target}")
            return 0

    raise VppError(f"Unsupported export format: {args.format}", exit_code=2)


def _build_verify_pfh(args: Any) -> PermFileHandler:
    import logging

    paths = AppPaths.resolve(portable=getattr(args, "portable", None))
    log_level = str(getattr(args, "log_level", "INFO") or "INFO").upper()
    silent_logger = logging.getLogger("vulnparse_pin.verify")
    if not silent_logger.handlers:
        silent_logger.addHandler(logging.NullHandler())
    silent_logger.propagate = False
    silent_logger.setLevel(getattr(logging, log_level, logging.INFO))

    pfh = build_pfh(paths, silent_logger, args)

    raw_log_file = getattr(args, "log_file", None)
    custom_log_requested = bool(
        raw_log_file
        and str(raw_log_file).strip()
        and str(raw_log_file).strip() != "vulnparse_pin.log"
    )
    if custom_log_requested:
        paths.ensure_dirs()
        run_log_name = build_run_log(str(raw_log_file).strip())
        run_log_path = pfh.ensure_writable_file(
            paths.log_dir / Path(run_log_name).name,
            label="Verify Log File",
            create_parents=True,
            overwrite=True,
        )
        pfh.logger = LoggerWrapper(str(run_log_path), log_level=log_level)

    if bool(getattr(args, "debug_path_policy", False)):
        if hasattr(pfh.logger, "print_info"):
            pfh.logger.print_info(f"\n{pfh.describe_policy()}", label="Path Policy")
        else:
            print(f"\n[Path Policy]\n{pfh.describe_policy()}")

    return pfh


def _verify_listed_manifest_outputs(
    manifest: Dict[str, Any],
    rm_module: Any,
    *,
    pfh: Optional[PermFileHandler] = None,
) -> None:
    """Verify non-null manifest output files exist on disk and match recorded SHA-256 hashes."""
    outputs = manifest.get("outputs") or {}
    output_hashes = manifest.get("output_hashes") or manifest.get("outputs_sha256") or {}
    if not isinstance(outputs, dict):
        return

    check_symlinks = True if pfh is None else bool(getattr(pfh, "forbid_symlinks_read", True))
    file_sha_fn = getattr(rm_module, "_file_sha256", None)
    checked_paths: Dict[str, Path] = {}
    for key, raw_path in outputs.items():
        if not raw_path:
            continue
        out_path = Path(str(raw_path))
        if check_symlinks:
            _check_no_symlinks_or_loops(out_path, label=f"output artifact '{key}'")
        if pfh is not None:
            out_path = Path(pfh.ensure_readable_file(out_path, label=f"output artifact '{key}'"))
        if not out_path.is_file():
            raise ValueError(f"Listed output artifact '{key}' is missing: {out_path}")
        checked_paths[str(key)] = out_path

    if isinstance(output_hashes, dict):
        for key, expected_hash in output_hashes.items():
            if not expected_hash:
                continue
            out_path = checked_paths.get(str(key))
            if out_path is None:
                raw_path = outputs.get(key)
                if not raw_path:
                    raise ValueError(f"Output hash recorded for missing output key '{key}'.")
                out_path = Path(str(raw_path))
                if check_symlinks:
                    _check_no_symlinks_or_loops(out_path, label=f"output artifact '{key}'")
                if pfh is not None:
                    out_path = Path(pfh.ensure_readable_file(out_path, label=f"output artifact '{key}'"))
                if not out_path.is_file():
                    raise ValueError(f"Listed output artifact '{key}' is missing: {out_path}")
            actual_hash = file_sha_fn(out_path) if callable(file_sha_fn) else None
            if not actual_hash or not hmac.compare_digest(str(expected_hash), str(actual_hash)):
                raise ValueError(
                    f"Output artifact '{key}' digest mismatch: expected {expected_hash}, got {actual_hash}"
                )


def run_verify_command(args: Any) -> int:
    import vulnparse_pin.utils.runmanifest as _rm

    verify_path = Path(args.runmanifest)
    verify_fn = getattr(_rm, "verify_runmanifest", None) or getattr(_rm, "verify_runmanifest_file")
    try:
        pfh = _build_verify_pfh(args)
        if getattr(pfh, "forbid_symlinks_read", True):
            _check_no_symlinks_or_loops(verify_path, label="RunManifest file")
        readable_verify_path = Path(pfh.ensure_readable_file(verify_path, label="RunManifest file"))
        try:
            manifest = verify_fn(readable_verify_path)
        except TypeError:
            manifest = _rm.verify_runmanifest_file(readable_verify_path)
        _verify_listed_manifest_outputs(manifest, _rm, pfh=pfh)
        entry_count = manifest.get("decision_ledger", {}).get("entry_count", 0)
        print(f"[OK] RunManifest verified: {verify_path} (entries={entry_count})")
        return 0
    except (ValueError, OSError, FilePathError, FilePermissionError) as exc:
        print(f"[FAIL] RunManifest verification failed: {verify_path}: {exc}", file=sys.stderr)
        return 1


def run_defer_command(args: Any) -> int:
    args._quiet_banner = True
    runtime = initialize_runtime(args, quiet_banner=True)
    pfh = runtime.pfh

    decisions_target = authorize_output_path(pfh, args.decisions, label="Decisions Config")
    raw_slug = re.sub(r"[^a-z0-9]+", "-", f"{args.cve_or_rule_id}-{args.asset_pattern}".lower()).strip("-")[:48]
    dec_id = getattr(args, "decision_id", None) or f"dec-{raw_slug or uuid4().hex[:8]}"

    entry: Dict[str, Any] = {
        "id": dec_id,
        "asset_pattern": str(args.asset_pattern),
        "cve_or_rule_id": str(args.cve_or_rule_id),
        "status": str(args.status),
        "rationale": str(args.rationale),
        "owner": str(args.owner),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    if getattr(args, "expires_at", None):
        entry["expires_at"] = str(args.expires_at)

    assumptions: Dict[str, Any] = {}
    if getattr(args, "in_kev", None) is not None:
        assumptions["in_kev"] = bool(args.in_kev)
    if getattr(args, "max_epss", None) is not None:
        assumptions["max_epss"] = float(args.max_epss)
    if getattr(args, "max_epss_percentile", None) is not None:
        assumptions["max_epss_percentile"] = float(args.max_epss_percentile)
    if getattr(args, "internet_facing", None) is not None:
        assumptions["internet_facing"] = bool(args.internet_facing)
    if getattr(args, "max_cvss", None) is not None:
        assumptions["max_cvss"] = float(args.max_cvss)
    if assumptions:
        entry["assumptions"] = assumptions

    try:
        saved = upsert_decision(decisions_target, entry, pfh=pfh)
    except Exception as exc:
        raise VppError(f"Failed to upsert decision: {exc}", exit_code=1) from exc

    print(
        f"[OK] Upserted decision '{saved['id']}' ({saved['status']}) for "
        f"{saved['cve_or_rule_id']} on '{saved['asset_pattern']}' -> {decisions_target}"
    )

    if getattr(args, "db", None):
        db_path = _authorize_existing_db_path(pfh, args.db, read_only=False)
        reg = DecisionsRegistry.from_file(decisions_target, pfh=pfh)
        with VppDatabase(db_path) as db:
            runs = list_runs(db)
            if runs:
                latest = runs[0]
                v2_ctx = _build_v2_ctx(runtime.ctx, db=db, run_id=latest["run_id"], decisions_registry=reg)
                TriageDecisionPass(
                    runtime.config_bundle.triage_policy,
                    profile=latest.get("profile") or "default",
                    decisions_registry=reg,
                ).run(v2_ctx)
                print(f"[OK] Refreshed triage decisions for run '{latest['run_id']}' in {db_path}")
    return 0


_ALLOWED_SQLITE_TABLES = frozenset(
    {"nvd_records", "epss_records", "kev_records", "ghsa_cve_index", "osv_advisories"}
)


def _compute_file_sha256_ro(path: Path, pfh: Any = None) -> str:
    digest = sha256()
    if pfh is not None and hasattr(pfh, "open_for_read"):
        with pfh.open_for_read(path, mode="rb", label="SQLite Index", log=False) as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    else:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _verify_sqlite_sig_ro(db_path: Path, sig_path: Path, pfh: Any = None) -> str:
    """Strictly read-only SQLite signature/permission/symlink verification."""
    try:
        _check_no_symlinks_or_loops(db_path, label="SQLite Index")
        for suffix in (".sig.json", "-wal", "-shm"):
            sidecar = Path(f"{db_path}{suffix}")
            if os.path.lexists(str(sidecar)):
                _check_no_symlinks_or_loops(sidecar, label=f"SQLite sidecar ({suffix})")
    except ValueError:
        return "symlink"

    if os.name == "posix":
        st_db = os.lstat(db_path)
        if bool(st_db.st_mode & stat.S_IWOTH):
            return "world-writable"
        if os.path.lexists(str(sig_path)):
            st_sig = os.lstat(sig_path)
            if bool(st_sig.st_mode & stat.S_IWOTH):
                return "world-writable"

    if not os.path.lexists(str(sig_path)):
        return "no-signature"

    try:
        if pfh is not None and hasattr(pfh, "open_for_read"):
            with pfh.open_for_read(sig_path, mode="r", encoding="utf-8", label="SQLite Signature", log=False) as fh:
                payload = json.load(fh)
        else:
            with open(sig_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        if not isinstance(payload, dict):
            return "tampered"

        mode = str(payload.get("mode", "sha256"))
        expected_sig = str(payload.get("signature", ""))
        expected_digest = str(payload.get("digest", ""))
        current_digest = _compute_file_sha256_ro(db_path, pfh=pfh)
        if not current_digest or not hmac.compare_digest(expected_digest, current_digest):
            return "tampered"

        secret_raw = os.getenv("VP_SQLITE_HMAC_KEY")
        if secret_raw:
            if mode != "hmac-sha256":
                return "tampered"
            expected_hmac = hmac.new(
                secret_raw.encode("utf-8"), current_digest.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            return "valid" if hmac.compare_digest(expected_sig, expected_hmac) else "tampered"

        if mode == "hmac-sha256":
            return "tampered"
        return "valid" if (mode == "sha256" and hmac.compare_digest(expected_sig, current_digest)) else "tampered"
    except PermissionError:
        return "world-writable"
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return "tampered"


def _inspect_sqlite_health(
    db_path: Path, table_name: str, *, sig_fn: Any = None, pfh: Any = None
) -> Dict[str, Any]:
    if table_name not in _ALLOWED_SQLITE_TABLES:
        raise ValueError(f"Unsupported SQLite table name: {table_name}")

    sig_path = Path(f"{db_path}.sig.json")
    try:
        st_db = os.lstat(db_path)
    except FileNotFoundError:
        return {"present": False, "health": "missing", "rows": 0, "path": str(db_path)}
    except OSError:
        return {"present": True, "health": "error", "rows": 0, "path": str(db_path)}

    if stat.S_ISLNK(st_db.st_mode):
        return {"present": True, "health": "symlink", "rows": 0, "path": str(db_path)}

    if callable(sig_fn):
        if not os.path.lexists(str(sig_path)):
            health = "no-signature"
        else:
            try:
                health = "valid" if sig_fn() else "tampered"
            except PermissionError:
                health = "world-writable"
            except Exception:
                health = "error"
    else:
        health = _verify_sqlite_sig_ro(db_path, sig_path, pfh=pfh)

    rows = 0
    if health == "valid":
        try:
            ro_uri = f"{Path(os.path.abspath(str(db_path))).as_uri()}?mode=ro"
            with closing(sqlite3.connect(ro_uri, uri=True)) as conn:
                rows = int(conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0])
        except Exception:
            health = "corrupt"

    return {
        "present": True,
        "health": health,
        "rows": rows,
        "path": str(db_path),
        "updated_at": datetime.fromtimestamp(st_db.st_mtime, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def _check_feed_health(fc: FeedCacheManager, key: str) -> Dict[str, Any]:
    data_path, sha_path, _ = fc.resolve(key)
    if not os.path.lexists(str(data_path)):
        return {
            "present": False,
            "fresh": False,
            "health": "missing",
            "last_updated": None,
            "path": str(data_path),
        }
    if os.path.islink(str(data_path)) or (sha_path and os.path.islink(str(sha_path))):
        return {
            "present": True,
            "fresh": False,
            "health": "symlink",
            "last_updated": None,
            "path": str(data_path),
        }
    meta = fc.load_meta(key) or {}
    fresh = fc.is_fresh(key)
    health = "valid"
    try:
        fc.ensure_feed_checksum(key, allow_regen=False)
    except PermissionError:
        health = "world-writable"
    except Exception as exc:
        if "symlink" in str(exc).lower():
            health = "symlink"
        else:
            health = "tampered" if (sha_path and os.path.lexists(str(sha_path))) else "missing-checksum"
    return {
        "present": True,
        "fresh": fresh,
        "health": health,
        "last_updated": meta.get("last_updated") or meta.get("created_at"),
        "path": str(data_path),
    }


def run_intel_command(args: Any) -> int:
    args._quiet_banner = True
    action = str(getattr(args, "action", "status") or "status").lower()
    if action == "status":
        args.no_nvd = True
    runtime = initialize_runtime(args, quiet_banner=True)
    ctx = runtime.ctx
    paths = runtime.paths
    fc = runtime.feed_cache
    pfh = runtime.pfh
    feed_sel = str(getattr(args, "feed", "all") or "all").lower()

    if action == "status":
        report: Dict[str, Any] = {}
        if feed_sel in ("all", "nvd"):
            nvd_files = sorted(paths.nvd_feeds_dir.glob("*.json.gz")) if paths.nvd_feeds_dir.exists() else []
            nvd_sq = _inspect_sqlite_health(
                paths.cache_dir / "nvd_cache.sqlite3",
                "nvd_records",
                pfh=pfh,
            )
            nvd_sq["feed_files"] = len(nvd_files)
            report["nvd"] = nvd_sq

        if feed_sel in ("all", "epss"):
            info = _check_feed_health(fc, "epss")
            info["sqlite"] = _inspect_sqlite_health(
                paths.cache_dir / "epss_cache.sqlite3", "epss_records", pfh=pfh
            )
            report["epss"] = info

        if feed_sel in ("all", "kev"):
            info = _check_feed_health(fc, "kev")
            info["sqlite"] = _inspect_sqlite_health(
                paths.cache_dir / "kev_cache.sqlite3", "kev_records", pfh=pfh
            )
            report["kev"] = info

        if feed_sel in ("all", "exploit_db"):
            report["exploit_db"] = _check_feed_health(fc, "exploit_db")

        if feed_sel in ("all", "ghsa"):
            report["ghsa"] = _inspect_sqlite_health(
                paths.cache_dir / "ghsa_cache.sqlite3", "ghsa_cve_index", pfh=pfh
            )

        if feed_sel in ("all", "osv"):
            report["osv"] = _inspect_sqlite_health(
                paths.cache_dir / "osv_cache.sqlite3", "osv_advisories", pfh=pfh
            )

        if getattr(args, "json_output", False):
            print(json.dumps(report, indent=2))
        else:
            print(f"Threat-Intel Cache Status ({paths.cache_dir}):")
            for k, v in report.items():
                present = "present" if v.get("present") else "missing"
                health = v.get("health", "unknown")
                fresh = v.get("fresh")
                fresh_str = f" | fresh={fresh}" if fresh is not None else ""
                rows_str = f" | rows={v['rows']}" if "rows" in v else ""
                sq = v.get("sqlite")
                sq_str = f" | sqlite={sq.get('health')}(rows={sq.get('rows', 0)})" if isinstance(sq, dict) else ""
                print(f"  - {k:<10} : {present} | integrity={health}{fresh_str}{rows_str}{sq_str}")
        return 0

    # action == "sync"
    from vulnparse_pin.utils.enricher import load_epss, load_kev
    from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
    from vulnparse_pin.utils.ghsa_enrichment import GHSAEnrichmentSource
    from vulnparse_pin.utils.osv_enrichment import OSVEnrichmentSource

    force = bool(getattr(args, "refresh", False))
    allow_regen = bool(getattr(args, "allow_regen", False))
    synced: List[str] = []

    if feed_sel in ("all", "kev"):
        src = getattr(args, "kev_feed", None) or KEV_FEED
        load_kev(ctx, str(src), force_refresh=force, allow_regen=allow_regen)
        synced.append("kev")

    if feed_sel in ("all", "epss"):
        src = getattr(args, "epss_feed", None) or EPSS_FEED
        load_epss(ctx, path_url=str(src), force_refresh=force, allow_regen=allow_regen)
        synced.append("epss")

    if feed_sel in ("all", "exploit_db"):
        src = getattr(args, "exploit_db", None) or "online"
        load_exploit_data(ctx, source=str(src), force_refresh=force, allow_regen=allow_regen)
        synced.append("exploit_db")

    if feed_sel in ("all", "nvd") and runtime.nvd_cache is not None:
        nvd_override = getattr(args, "nvd_source", None)
        if nvd_override:
            _load_local_nvd_into_cache(ctx, runtime.nvd_cache, Path(nvd_override))
        else:
            now_y = datetime.now(timezone.utc).year
            runtime.nvd_cache.refresh(
                config=runtime.cfg_yaml,
                feed_cache=fc,
                refresh_cache=force,
                offline=False,
                years={now_y},
                include_modified=True,
            )
        synced.append("nvd")

    if feed_sel in ("all", "ghsa") and getattr(args, "ghsa", None):
        ghsa_src = GHSAEnrichmentSource(ctx)
        ghsa_src.load_offline(db_path=str(args.ghsa), force_reindex=force)
        synced.append("ghsa")

    if feed_sel in ("all", "osv") and getattr(args, "osv", None):
        osv_src = OSVEnrichmentSource(ctx)
        osv_src.load_offline(db_path=str(args.osv), force_reindex=force)
        synced.append("osv")

    print(f"[OK] Synced intel feeds: {', '.join(synced) if synced else 'none'}")
    return 0
