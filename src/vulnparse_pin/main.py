# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import argparse
from dataclasses import fields, is_dataclass
import json
from multiprocessing import freeze_support
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Sequence

from vulnparse_pin import __version__
from vulnparse_pin.app.runtime_helpers import (
    build_feed_cache_policy as _build_feed_cache_policy,
    build_run_log as _build_run_log,
    extract_cve_years as _extract_cve_years,
    format_runtime as _format_runtime,
    load_score_policy as _load_score_policy,
    resolve_feed_path as _resolve_feed_path,
    select_years as _select_years,
    _require as _runtime_require,
)
from vulnparse_pin.cli.args import (
    get_args as _cli_get_args,
    parse_mode as _cli_parse_mode,
    valid_input_file as _cli_valid_input_file,
    valid_log_level as _cli_valid_log_level,
)
from vulnparse_pin.cli.commands import (
    EPSS_FEED,
    KEV_FEED,
    run_defer_command,
    run_demo_command,
    run_diff_command,
    run_export_command,
    run_intel_command,
    run_scan_command,
    run_ui_command,
    run_verify_command,
)
from vulnparse_pin.cli.errors import VppError
from vulnparse_pin.core.classes.dataclass import FeedCachePolicy, RunContext, ScanResult
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.io.pfhandler import FilePathError, FilePermissionError, PathLike

NVD_MIN_YEAR = 2002


def print_summary_banner(ctx: "RunContext", scan_result, output_file: Path = None, sources=None):
    """Prints a formatted summary banner with key metrics from the scan result."""

    def _get_scoring(scan: "ScanResult") -> Dict[str, Any]:
        res = scan.derived.get("Scoring@3.0") or scan.derived.get("Scoring@2.0")
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
        "Informational": 0,
    }
    for sf in scored_findings.values():
        band = sf.get("risk_band", "Informational")
        band_counts[band] = band_counts.get(band, 0) + 1

    total_assets = len(scan_result.assets)
    total_findings = sum(len(asset.findings) for asset in scan_result.assets)
    exploit_findings = sum(
        sum(1 for f in asset.findings if getattr(f, "exploit_available", False)) for asset in scan_result.assets
    )
    enriched_findings = sum(
        sum(1 for f in asset.findings if f.enriched) for asset in scan_result.assets
    )

    print("\n" + "=" * 60)
    print(f"🛡️          VulnParse-Pin Scan Summary (v{__version__})          🛡️")
    print("=" * 60)
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
    print(f"🔥 Critical Risk Findings         : {band_counts.get('Critical', 0):,}")
    print(f"⚠️  High Risk Findings             : {band_counts.get('High', 0):,}")
    print(f"🟡 Medium Risk Findings           : {band_counts.get('Medium', 0):,}")
    print(f"🟢 Low Risk Findings              : {band_counts.get('Low', 0):,}")
    print(f"⚪ Informational Findings         : {band_counts.get('Informational', 0):,}")
    print("-" * 60)
    print(f"📊 Enriched Findings              : {enriched_findings:,}")
    if output_file:
        print(f"📁 Output Location                : {output_file.parent}")

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
            epss_pct = (epss_hits / epss_total * 100) if epss_total else 0.0

            print(f"🔑    KEV Hits                    : {kev_hits:,}/{kev_total:,} ({kev_pct:.2f}%)")
            print(f"📈    EPSS Coverage               : {epss_hits:,}/{epss_total:,} ({epss_pct:.2f}%)")
            print(f"📊    CVSS Vectors (Scanner/NVD)  : {nvd_vectors:,} assigned, {nvd_validated:,} validated")
            print(f"💣    Exploit-DB Hits             : {exploit_hits:,}")

    print("=" * 60 + "\n")

    avg_risk_log = f"{avg_raw:.2f}" if avg_raw is not None else "N/A"
    ctx.logger.info(
        f"Assets Analyzed: {total_assets:,},"
        f"Findings Triaged: {total_findings:,},"
        f"Average Risk Score: {avg_risk_log},"
        f"Highest Risk Asset: {highest_asset if highest_asset else 'N/A'},"
        f"Critical: {band_counts.get('Critical', 0):,}, High: {band_counts.get('High', 0):,}, "
        f"Medium: {band_counts.get('Medium', 0):,}, Low: {band_counts.get('Low', 0):,}, "
        f"Informational: {band_counts.get('Informational', 0):,}"
    )


def format_runtime(seconds: float) -> str:
    return _format_runtime(seconds)


def build_run_log(input_path: PathLike) -> str:
    return _build_run_log(input_path)


def parse_mode(value: str) -> int:
    return _cli_parse_mode(value)


def _require(condition: bool, msg: str) -> None:
    _runtime_require(condition, msg)


def _json_default(obj: Any):
    if is_dataclass(obj):
        return {f.name: getattr(obj, f.name) for f in fields(obj)}
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def write_output(ctx: "RunContext", data: Any, file_path: PathLike, pretty_print: bool = False):
    """Write JSON results to disk using the path-policy handler with streaming output."""
    target = ctx.pfh.ensure_writable_file(
        file_path, label="JSON Output File", create_parents=True, overwrite=True
    )
    data_size = _estimate_dict_size(data)

    with ctx.pfh.open_for_write(target, mode="w", encoding="utf-8", label="JSON Output") as f:
        if pretty_print:
            ctx.logger.print_info("Pretty-printing JSON - Standby...", label="Output")
            try:
                if data_size > 50_000_000:
                    ctx.logger.debug(
                        f"Large dataset detected ({data_size:,} bytes), using streaming JSON output",
                        extra={"vp_label": "JSON Output"},
                    )
                    _stream_json_dump(data, f, indent=4)
                else:
                    json.dump(data, f, indent=4, default=_json_default)
                ctx.logger.print_success(f"Parsed results are stored in: {target}", label="Output")
            except Exception as e:
                ctx.logger.print_error(f"Error attempt to dump to JSON: {e}", label="Output")
                raise VppError(f"Error attempting to dump JSON: {e}", exit_code=1) from e
        else:
            try:
                ctx.logger.debug(f"Streaming JSON output ({data_size:,} bytes)", extra={"vp_label": "JSON Output"})
                _stream_json_dump(data, f, indent=None)
                ctx.logger.print_success(f"JSON results available in: {target}", label="Output")
            except Exception as e:
                ctx.logger.print_error(f"Error attempt to dump to JSON: {e}", label="Output")
                ctx.logger.exception("Exception: %s", e)
                raise VppError(f"Error attempting to dump JSON: {e}", exit_code=1) from e


def _estimate_dict_size(data: Any, sample_size: int = 100) -> int:
    if not isinstance(data, dict):
        return 0
    if len(data) <= sample_size:
        return len(json.dumps(data, default=_json_default).encode("utf-8"))
    sample_keys = list(data.keys())[:sample_size]
    sample_data = {k: data[k] for k in sample_keys}
    sample_bytes = len(json.dumps(sample_data, default=_json_default).encode("utf-8"))
    return int((sample_bytes / sample_size) * len(data))


def _stream_json_dump(data: Any, file_obj, indent=None):
    if not isinstance(data, dict):
        encoder = json.JSONEncoder(indent=indent, default=_json_default)
        for chunk in encoder.iterencode(data):
            file_obj.write(chunk)
        file_obj.write("\n")
        return

    file_obj.write("{")
    first_item = True
    for key, value in data.items():
        if not first_item:
            file_obj.write(",")
        first_item = False
        file_obj.write(json.dumps(key, default=_json_default))
        file_obj.write(":")
        if indent is not None:
            file_obj.write("\n")
            file_obj.write(" " * indent)
        json.dump(value, file_obj, indent=indent, default=_json_default)
    if indent is not None:
        file_obj.write("\n")
    file_obj.write("}")
    file_obj.write("\n")


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


def resolve_feed_path(arg_val, offline_mode: bool, default_online: PathLike, default_offline: PathLike) -> Any | str:
    return _resolve_feed_path(arg_val, offline_mode, default_online, default_offline)


def build_feed_cache_policy(config: dict) -> FeedCachePolicy:
    return _build_feed_cache_policy(config)


def get_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    return _cli_get_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = get_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    dispatch = {
        "scan": run_scan_command,
        "demo": run_demo_command,
        "diff": run_diff_command,
        "ui": run_ui_command,
        "export": run_export_command,
        "verify": run_verify_command,
        "defer": run_defer_command,
        "intel": run_intel_command,
    }

    handler = dispatch.get(getattr(args, "command", ""))
    if handler is None:
        print(f"[ERROR] Unknown command: {getattr(args, 'command', None)}", file=sys.stderr)
        return 2

    try:
        return int(handler(args))
    except VppError as exc:
        print(f"[ERROR] {exc.message}", file=sys.stderr)
        return exc.exit_code
    except (FilePathError, FilePermissionError) as exc:
        print(f"[ERROR] Path policy error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    freeze_support()
    raise SystemExit(main(sys.argv[1:]))
