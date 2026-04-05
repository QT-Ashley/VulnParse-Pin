# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from vulnparse_pin.utils.csv_exporter import export_to_csv
from vulnparse_pin.utils.markdown_report import generate_markdown_report
from vulnparse_pin.utils.reportgen import materialize_presentation
from vulnparse_pin.utils.runmanifest import build_runmanifest, write_runmanifest


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
        if args.presentation and not scan_result.derived.get("Scoring@1.0"):
            raise RuntimeError("Presentation overlay requested, but Scoring@1.0 pass result not found.")
        if args.presentation:
            out = materialize_presentation(scan_result, overlay_mode=args.overlay_mode, scoring_pass_key="Scoring@1.0")
            write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)
        else:
            write_output_fn(ctx, data=scan_result, file_path=json_output, pretty_print=args.pretty_print)
        # CSV
        export_to_csv(ctx, scan_result, csv_path=csv_output, csv_sanitization=csv_sanitization_enabled)
        
        # Markdown Exec
        generate_markdown_report(ctx, scan_result, md_output, report_type="executive")
        
        # Markdown Tech
        generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical")
    else:
        if args.output:
            if args.presentation and not scan_result.derived.get("Scoring@1.0"):
                raise RuntimeError("Presentation overlay requested, but Scoring@1.0 pass result not found.")
            if args.presentation:
                out = materialize_presentation(scan_result, overlay_mode=args.overlay_mode, scoring_pass_key="Scoring@1.0")
                write_output_fn(ctx, data=out, file_path=json_output, pretty_print=args.pretty_print)
            else:
                write_output_fn(ctx, data=scan_result, file_path=json_output, pretty_print=args.pretty_print)

        if args.output_csv:
            export_to_csv(ctx, scan_result, csv_path=csv_output, csv_sanitization=csv_sanitization_enabled)

        if md_output:
            generate_markdown_report(ctx, scan_result, md_output, report_type="executive")

        if md_tech_output:
            generate_markdown_report(ctx, scan_result, md_tech_output, report_type="technical")

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
        print(json.dumps(scan_result, indent=4, default=json_default_fn))

    if kev_source or epss_source:
        logger.phase("Summary")
        print_summary_banner_fn(ctx, scan_result, json_output if json_output else None, sources=sources)

    total_runtime = time.time() - start_time
    print(f"Total runtime: {format_runtime_fn(total_runtime)}")
    return 0
