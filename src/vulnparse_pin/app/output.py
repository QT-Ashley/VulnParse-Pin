# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from copy import deepcopy
import json
import time
from pathlib import Path
from typing import Any, Callable

from vulnparse_pin.utils.csv_exporter import export_to_csv
from vulnparse_pin.utils.markdown_report import generate_markdown_report
from vulnparse_pin.utils.reportgen import materialize_presentation
from vulnparse_pin.utils.runmanifest import build_runmanifest, write_runmanifest
from vulnparse_pin.utils.webhook_delivery import emit_configured_webhooks


_PRESENTATION_ONLY_FINDING_KEYS = (
    "raw_risk_score",
    "risk_score",
    "risk_band",
    "score_trace",
)


def _materialize_default_json(scan_result: Any) -> Any:
    """Build default JSON output while keeping score fields in derived passes only."""
    if is_dataclass(scan_result):
        out = asdict(scan_result)
    elif isinstance(scan_result, dict):
        out = deepcopy(scan_result)
    else:
        return scan_result

    assets = out.get("assets") if isinstance(out, dict) else None
    if not isinstance(assets, list):
        return out

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        findings = asset.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for key in _PRESENTATION_ONLY_FINDING_KEYS:
                finding.pop(key, None)
    return out


def _json_payload_for_output(args: Any, scan_result: Any) -> Any:
    if args.presentation:
        if not scan_result.derived.get("Scoring@2.0"):
            raise RuntimeError("Presentation overlay requested, but Scoring@2.0 pass result not found.")
        return materialize_presentation(scan_result, overlay_mode=args.overlay_mode, scoring_pass_key="Scoring@2.0")
    return _materialize_default_json(scan_result)


def run_output_and_summary(
    args,
    ctx,
    scan_result,
    sources: dict,
    json_output,
    csv_output,
    md_output,
    md_tech_output,
    runmanifest_output,
    scanner_input: Path,
    csv_sanitization_enabled: bool,
    kev_source,
    epss_source,
    start_time: float,
    write_output_fn: Callable[..., Any],
    print_summary_banner_fn: Callable[..., Any],
    json_default_fn: Callable[..., Any],
    format_runtime_fn: Callable[[float], str],
) -> int:
    logger = ctx.logger

    if args.output or args.output_csv:
        logger.phase("Output")

    if args.output_all:
        out = _json_payload_for_output(args, scan_result)
        write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)
        # CSV
        export_to_csv(
            ctx,
            scan_result,
            csv_path=csv_output,
            csv_sanitization=csv_sanitization_enabled,
            csv_profile=getattr(args, "csv_profile", "full"),
        )
        
        # Markdown Exec
        generate_markdown_report(ctx, scan_result, md_output, report_type="executive", args=args)
        
        # Markdown Tech
        generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical", args=args)
    else:
        if args.output:
            out = _json_payload_for_output(args, scan_result)
            write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)

        if args.output_csv:
            export_to_csv(
                ctx,
                scan_result,
                csv_path=csv_output,
                csv_sanitization=csv_sanitization_enabled,
                csv_profile=getattr(args, "csv_profile", "full"),
            )

        if md_output:
            generate_markdown_report(ctx, scan_result, md_output, report_type="executive", args=args)

        if md_tech_output:
            generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical", args=args)

    emit_configured_webhooks(
        ctx=ctx,
        scan_result=scan_result,
        scanner_input=scanner_input,
        output_paths={
            "json": json_output,
            "csv": csv_output,
            "md": md_output,
            "md_technical": md_tech_output,
            "runmanifest": runmanifest_output,
        },
    )

    if runmanifest_output:
        runmanifest = build_runmanifest(
            ctx=ctx,
            _args=args,
            scan_result=scan_result,
            sources=sources,
            scanner_input=scanner_input,
            output_paths={
                "json": json_output,
                "csv": csv_output,
                "md": md_output,
                "md_technical": md_tech_output,
            },
        )
        write_runmanifest(ctx, runmanifest, runmanifest_output)
        logger.print_success(f"Run manifest generated: {runmanifest_output}", label="RunManifest")

    if args.pretty_print and not args.output:
        logger.print_info("Displaying results to console...")
        out = _json_payload_for_output(args, scan_result)
        print(json.dumps(out, indent=4, default=json_default_fn))

    if kev_source or epss_source:
        logger.phase("Summary")
        print_summary_banner_fn(ctx, scan_result, json_output if json_output else None, sources=sources)

    total_runtime = time.time() - start_time
    print(f"Total runtime: {format_runtime_fn(total_runtime)}")
    return 0
