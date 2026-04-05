# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

import json
from multiprocessing import freeze_support
from pathlib import Path
import time
from dataclasses import fields, is_dataclass
from typing import Any, Dict, Optional, Sequence
import argparse
import sys

from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.classes.dataclass import FeedCachePolicy, RunContext, ScanResult
from vulnparse_pin.io.pfhandler import PathLike
from vulnparse_pin.cli.args import get_args as _cli_get_args
from vulnparse_pin.cli.args import parse_mode as _cli_parse_mode
from vulnparse_pin.cli.args import valid_input_file as _cli_valid_input_file
from vulnparse_pin.cli.args import valid_log_level as _cli_valid_log_level
from vulnparse_pin.app.runtime_helpers import build_feed_cache_policy as _build_feed_cache_policy
from vulnparse_pin.app.runtime_helpers import build_run_log as _build_run_log
from vulnparse_pin.app.runtime_helpers import extract_cve_years as _extract_cve_years
from vulnparse_pin.app.runtime_helpers import format_runtime as _format_runtime
from vulnparse_pin.app.runtime_helpers import load_score_policy as _load_score_policy
from vulnparse_pin.app.runtime_helpers import resolve_feed_path as _resolve_feed_path
from vulnparse_pin.app.runtime_helpers import select_years as _select_years
from vulnparse_pin.app.runtime_helpers import _require as _runtime_require
from vulnparse_pin.app.bootstrap import initialize_runtime
from vulnparse_pin.app.io_resolution import resolve_io_paths_and_modes
from vulnparse_pin.app.normalization import normalize_input
from vulnparse_pin.app.enrichment import run_enrichment_pipeline
from vulnparse_pin.app.output import run_output_and_summary
from vulnparse_pin.utils.runmanifest import verify_runmanifest_file

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_FEED = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_MIN_YEAR = 2002

def print_summary_banner(ctx: "RunContext", scan_result, output_file: Path = None, sources=None):
    '''
    Prints a formatted summary banner with key metrics from the scan result.

    Args:
        scan_result (ScanResult): The final processed scan results.
        output_file (Path, optional): The path to the output JSON file.
        sources (dict, optional): Dict of enrichment source status, e.g.:
            {
                "exploitdb": True,
                "kev": True,
                "epss": True,
                "nvd": "Enabled (feeds 2017-2025, modified)" # or "Disabled (--no-nvd)", "Offline (feeds missing)"
            }

    Returns:
        None
    '''
    def _get_scoring(scan: "ScanResult") -> Dict[str, Any]:
        res = scan.derived.get("Scoring@1.0")
        if not res:
            return {}
        data = res.data or {}
        if not isinstance(data, dict):
            raise TypeError("Not a dict")
        return data

    def _as_dict(value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _as_float(value: Any) -> Optional[float]:
        return value if isinstance(value, (int, float)) else None

    def _format_optional_score(label: str, value: Optional[float], missing_text: str) -> str:
        if value is None:
            return f" {label:<31}: {missing_text}"
        return f" {label:<31}: {value:.2f}"

    # Pull from scoring pass
    scoring = _get_scoring(scan_result)
    scored_findings = _as_dict(scoring.get("scored_findings"))
    coverage = _as_dict(scoring.get("coverage"))
    highest_asset = scoring.get("highest_risk_asset")
    highest_asset_raw = _as_float(scoring.get("highest_risk_asset_score"))
    avg_raw = _as_float(scoring.get("avg_scored_risk"))
    avg_op = _as_float(scoring.get("avg_operational_risk"))
    coverage_ratio = _as_float(coverage.get("coverage_ratio")) or 0.0
    scored_count = coverage.get("scored_findings", 0)
    band_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }
    for sf in scored_findings.values():
        band = sf.get("risk_band", "Informational")
        band_counts[band] = band_counts.get(band, 0) + 1

    total_assets = len(scan_result.assets)
    total_findings = sum(len(asset.findings) for asset in scan_result.assets)
    exploit_findings = sum(
        sum(1 for f in asset.findings if getattr(f, 'exploit_available', False)) for asset in scan_result.assets
        )
    enriched_findings = sum(
        sum(1 for f in asset.findings if f.enriched) for asset in scan_result.assets
    )

    print("\n" + "="*60)
    print("🛡️          VulnParse-Pin Scan Summary (v1.0-RC)          🛡️")
    print("="*60)
    print(f" Total Assets Analyzed            : {total_assets:,}")
    print(f" Total Findings Triaged           : {total_findings:,}")
    print(_format_optional_score("Average Asset Risk Score", avg_raw, "Not Computed (Insufficient Scoring Inputs)"))
    print(_format_optional_score("Average Operational Risk Score", avg_op, "Not Available (Insufficient Scoring Inputs)"))
    print(f" Scoring Coverage                 : {coverage_ratio:.2%}")
    print(f" # of Scored Findings             : {scored_count:,}")
    if highest_asset:
        if highest_asset_raw is not None:
            print(f" Highest Risk Asset               : {highest_asset} (Score: {highest_asset_raw:.2f})")
        else:
            print(f" Highest Risk Asset               : {highest_asset} (Score: Not Computed (Insufficient Scoring Inputs))")
    else:
        print(" Highest Risk Asset               : N/A")
    print("-" * 60)
    print(f"💣 Findings with Known Exploits   : {exploit_findings:,}")
    print(f"🔥 Critical Risk Findings         : {band_counts.get("Critical"):,}")
    print(f"⚠️  High Risk Findings             : {band_counts.get("High"):,}")
    print(f"🟡 Medium Risk Findings           : {band_counts.get("Medium"):,}")
    print(f"🟢 Low Risk Findings              : {band_counts.get("Low"):,}")
    print(f"⚪ Informational Findings         : {band_counts.get("Informational"):,}")
    print("-" * 60)
    print(f"📊 Enriched Findings              : {enriched_findings:,}")
    if output_file:
        print(f"📁 Output Location                : {output_file.parent}")


    # Enrichment source status
    if sources:
        src_line = "🔗 Enrichment Sources             : "
        src_line += f"ExploitDB {'✅' if sources.get('exploitdb') else '❌'} | "
        src_line += f"KEV {'✅' if sources.get('kev') else '❌'} | "
        src_line += f"EPSS {'✅' if sources.get('epss') else '❌'} | "
        nvd_status = sources.get("nvd", "❌")
        src_line += f"NVD {nvd_status}"
        print(src_line)

        statsc = sources.get("stats", {})
        if statsc:
            kev_hits = statsc.get("kev_hits", 0)
            kev_total = statsc.get("kev_total", 0)
            epss_hits = statsc.get("epss_hits", 0)
            epss_total = statsc.get("epss_total", 0)
            nvd_vectors = statsc.get("nvd_vectors", 0)
            nvd_validated = statsc.get("nvd_validated", 0)
            exploit_hits = statsc.get("exploit_hits", 0)

            kev_pct = (kev_hits / kev_total * 100) if kev_total else 0.0
            epss_pct = (epss_hits / epss_total * 100 if epss_total else 0.0)

            print(f"🔑    KEV Hits                    : {kev_hits:,}/{kev_total:,} ({kev_pct:.2f}%)")
            print(f"📈    EPSS Coverage               : {epss_hits:,}/{epss_total:,} ({epss_pct:.2f}%)")
            print(f"📊    CVSS Vectors (Scanner/NVD)  : {nvd_vectors:,} assigned, {nvd_validated:,} validated")
            print(f"💣    Exploit-DB Hits             : {exploit_hits:,}")

    print("="*60 + "\n")

    avg_risk_log = f"{avg_raw:.2f}" if avg_raw is not None else "N/A"
    ctx.logger.info(
        f"Assets Analyzed: {total_assets:,},"
        f"Findings Triaged: {total_findings:,},"
        f"Average Risk Score: {avg_risk_log},"
        f"Highest Risk Asset: {highest_asset if highest_asset else 'N/A'},"
        f"Critical: {band_counts.get('Critical'):,}, High: {band_counts.get('High'):,}, Medium: {band_counts.get('Medium'):,}, Low: {band_counts.get('Low'):,}, Informational: {band_counts.get('Informational'):,}"
    )

def format_runtime(seconds: float) -> str:
    return _format_runtime(seconds)

def build_run_log(input_path: PathLike) -> Path:
    return _build_run_log(input_path)

def parse_mode(value: str) -> int:
    return _cli_parse_mode(value)

def _require(condition: bool, msg: str) -> None:
    _runtime_require(condition, msg)

def _json_default(obj: Any):
    """
    JSON default serializer that preserves backward-compatible output semantics.
    - Dataclasses are emitted as shallow field dicts (stream-friendly)
    - Path-like objects are converted to string paths
    - Everything else falls back to str()
    """
    if is_dataclass(obj):
        return {f.name: getattr(obj, f.name) for f in fields(obj)}
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def write_output(ctx: "RunContext", data: Any, file_path: PathLike, pretty_print=False):
    '''
    Write JSON results to disk using the path‑policy handler with streaming output.

    Args:
        ctx (RunContext): runtime context carrying ``pfh`` and ``logger``
        data (dict): JSON-able structure to dump
        file_path (PathLike): destination path
        pretty_print (bool): if true, indent the output
    '''
    target = ctx.pfh.ensure_writable_file(file_path, label="JSON Output File",
                                          create_parents=True, overwrite=True)

    # Determine data size for logging and optimization decisions
    data_size = _estimate_dict_size(data)

    with ctx.pfh.open_for_write(target, mode="w", encoding="utf-8", label="JSON Output") as f:
        if pretty_print:
            ctx.logger.print_info("Pretty-printing JSON - Standby...", label="Output")
            try:
                # For large datasets, stream to avoid memory spikes
                if data_size > 50_000_000:  # 50MB threshold
                    ctx.logger.debug(f"Large dataset detected ({data_size:,} bytes), using streaming JSON output", extra={"vp_label": "JSON Output"})
                    _stream_json_dump(data, f, indent=4)
                else:
                    json.dump(data, f, indent=4, default=_json_default)
                ctx.logger.print_success(f"Parsed results are stored in: {target}", label="Output")
            except Exception as e:
                ctx.logger.print_error(f"Error attempt to dump to JSON: {e}", label="Output")
                sys.exit(1)
        else:
            try:
                # Always use streaming for non-pretty output to minimize memory usage
                ctx.logger.debug(f"Streaming JSON output ({data_size:,} bytes)", extra={"vp_label": "JSON Output"})
                _stream_json_dump(data, f, indent=None)
                ctx.logger.print_success(f"JSON results available in: {target}", label="Output")
            except Exception as e:
                ctx.logger.print_error(f"Error attempt to dump to JSON: {e}", label="Output")
                ctx.logger.exception("Exception: %s", e)
                sys.exit(1)


def _estimate_dict_size(data: Any, sample_size: int = 100) -> int:
    """
    Estimate dictionary size in bytes for optimization decisions.
    Uses sampling for large datasets to avoid expensive computation.
    """
    if not isinstance(data, dict):
        return 0

    # For small datasets, calculate exactly
    if len(data) <= sample_size:
        return len(json.dumps(data, default=_json_default).encode('utf-8'))

    # For large datasets, sample and extrapolate
    sample_keys = list(data.keys())[:sample_size]
    sample_data = {k: data[k] for k in sample_keys}
    sample_bytes = len(json.dumps(sample_data, default=_json_default).encode('utf-8'))

    # Extrapolate: assume uniform distribution
    return int((sample_bytes / sample_size) * len(data))


def _stream_json_dump(data: Any, file_obj, indent=None):
    """
    Stream JSON dump to avoid loading entire structure into memory.
    Uses incremental writing for better memory efficiency.
    """
    # Non-dict payloads (e.g., ScanResult dataclass) are streamed directly.
    if not isinstance(data, dict):
        encoder = json.JSONEncoder(indent=indent, default=_json_default)
        for chunk in encoder.iterencode(data):
            file_obj.write(chunk)
        file_obj.write('\n')
        return

    file_obj.write('{')

    first_item = True

    for key, value in data.items():
        if not first_item:
            file_obj.write(',')
        first_item = False

        # Write key
        file_obj.write(json.dumps(key, default=_json_default))
        file_obj.write(':')

        if indent is not None:
            file_obj.write('\n')
            file_obj.write(' ' * indent)

        json.dump(value, file_obj, indent=indent, default=_json_default)

    # Write closing brace
    if indent is not None:
        file_obj.write('\n')
    file_obj.write('}')
    file_obj.write('\n')

def valid_input_file(path: PathLike) -> Path:
    return _cli_valid_input_file(path)

def valid_log_level(level):
    return _cli_valid_log_level(level)

def extract_cve_years(ctx: "RunContext", scan_result: ScanResult) -> set[int]:
    return _extract_cve_years(ctx, scan_result)

def select_years(ctx: "RunContext", years_seen: set[int]) -> set[int]:
    return _select_years(ctx, years_seen)

def load_score_policy(config: dict) -> ScoringPolicyV1:
    return _load_score_policy(config)

# Resolve feed sources.
def resolve_feed_path(arg_val, offline_mode: bool, default_online: PathLike, default_offline: PathLike) -> Any | str:
    return _resolve_feed_path(arg_val, offline_mode, default_online, default_offline)

def build_feed_cache_policy(config: dict) -> FeedCachePolicy:
    return _build_feed_cache_policy(config)

def get_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    return _cli_get_args(argv)


def main(argv: Optional[Sequence[str]] = None):
    start_time = time.time()
    args = get_args(argv)

    if getattr(args, "verify_runmanifest", None):
        verify_path = Path(args.verify_runmanifest)
        try:
            manifest = verify_runmanifest_file(verify_path)
            entry_count = manifest.get("decision_ledger", {}).get("entry_count", 0)
            print(f"[OK] RunManifest verified: {verify_path} (entries={entry_count})")
            return 0
        except (ValueError, OSError) as e:
            print(f"[FAIL] RunManifest verification failed: {verify_path}: {e}")
            return 1

    runtime = initialize_runtime(args)
    ctx = runtime.ctx
    cfg_yaml = runtime.cfg_yaml
    nvd_cache = runtime.nvd_cache
    nvdpol_start_y = runtime.nvdpol_start_y
    nvdpol_end_y = runtime.nvdpol_end_y
    feed_cache = runtime.feed_cache
    detector = runtime.detector
    passesList = runtime.passesList
    passOrchestrator = runtime.passOrchestrator

    io_state = resolve_io_paths_and_modes(args, runtime, kev_feed=KEV_FEED, epss_feed=EPSS_FEED)
    scanner_input = io_state.scanner_input
    json_output = io_state.json_output
    csv_output = io_state.csv_output
    md_output = io_state.md_output
    md_tech_output = io_state.md_tech_output
    runmanifest_output = io_state.runmanifest_output
    exploit_db = io_state.exploit_db
    csv_sanitization_enabled = io_state.csv_sanitization_enabled
    kev_source = io_state.kev_source
    epss_source = io_state.epss_source

    normalization = normalize_input(ctx, detector, scanner_input, allow_large=args.allow_large)
    scan_result: ScanResult = normalization.scan_result

    enrich_state = run_enrichment_pipeline(
        args=args,
        ctx=ctx,
        scan_result=scan_result,
        cfg_yaml=cfg_yaml,
        nvdpol_start_y=nvdpol_start_y,
        nvdpol_end_y=nvdpol_end_y,
        feed_cache=feed_cache,
        nvd_cache=nvd_cache,
        passes_list=passesList,
        pass_orchestrator=passOrchestrator,
        exploit_db=exploit_db,
        kev_source=kev_source,
        epss_source=epss_source,
    )
    scan_result = enrich_state.scan_result
    sources = enrich_state.sources

    return run_output_and_summary(
        args=args,
        ctx=ctx,
        scan_result=scan_result,
        sources=sources,
        json_output=json_output,
        csv_output=csv_output,
        md_output=md_output,
        md_tech_output=md_tech_output,
        runmanifest_output=runmanifest_output,
        scanner_input=scanner_input,
        csv_sanitization_enabled=csv_sanitization_enabled,
        kev_source=kev_source,
        epss_source=epss_source,
        start_time=start_time,
        write_output_fn=write_output,
        print_summary_banner_fn=print_summary_banner,
        json_default_fn=_json_default,
        format_runtime_fn=format_runtime,
    )



if __name__ == "__main__":
    # Ensure spawned worker processes bootstrap correctly in frozen binaries.
    freeze_support()
    rc = main(sys.argv[1:])
    raise SystemExit(rc)
