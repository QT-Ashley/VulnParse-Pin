# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional, Sequence, Union

from vulnparse_pin import __version__

PathLikeSimple = Union[str, Path]

_DEMO_SAMPLE_NAME = "Lab_test_scaled_5k.nessus"

def _resolve_demo_sample() -> Optional[Path]:
    """Return the absolute path to the bundled demo sample, or None if not found.

    Uses importlib.resources so the file is correctly located whether the package
    is installed via pip (as a wheel/egg) or run directly from source.
    """
    from importlib import resources
    try:
        # Python 3.9+ path — returns a traversable that survives zip/wheel installs.
        ref = resources.files("vulnparse_pin.resources").joinpath(_DEMO_SAMPLE_NAME)
        if ref.is_file():
            # Materialize to a real filesystem path (works with zipimport too).
            with resources.as_file(ref) as p:
                return p.resolve()
    except (TypeError, FileNotFoundError, ModuleNotFoundError):
        pass
    return None


def parse_mode(value: str) -> int:
    """
    Parse a chmod-style mode string into an int.

    Accepted form:
    - "600"     -> octal
    - "0644"    -> octal
    - "0o600"   -> octal
    - "0x1A4"   -> octal
    """
    s = value.strip()

    try:
        if s.startswith(("0o", "0O")):
            mode = int(s, 8)
        elif s.startswith(("0x", "0X")):
            mode = int(s, 16)
        else:
            mode = int(s, 8)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"Invalid mode '{value}' is out of valid range (0000-7777)."
            f" Trace: {e}"
        )

    return mode


def valid_input_file(path: PathLikeSimple) -> Path:
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"File: '{path}' does not exist or is not a file.")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"File: '{path}' is not readable.")
    return Path(path)


def valid_log_level(level):
    levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    lvl = level.upper()
    if lvl not in levels:
        raise argparse.ArgumentTypeError(f"Invalid log level '{level}. Choce from {levels}.")
    return lvl


def get_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulnparse-pin",
        description="VulnParse-Pin: Enrich, prioritize, and triage vulnerability scan results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    gen_group = parser.add_argument_group("General Options", "General runtime flags.")
    enrich_group = parser.add_argument_group("Enrichment", "Vulnerability enrichment flags.")
    file_group = parser.add_argument_group("Filesystem Options", "[Security Warning] Filesystem I/O and permissions flags. Take caution and read documentation on potential effects of flags.")
    port_group = parser.add_argument_group("Portability", "Options to run VulnParse in a portable setting.")
    output_group = parser.add_argument_group("Output Options", "Flags that deal with output such as output location or presentation modes.")
    gen_group.add_argument("--file", "-f", help="Path to vulnerability scan file", required=False, default=None, type=valid_input_file)
    gen_group.add_argument("--demo", action="store_true", default=False, help="Run a full end-to-end pipeline demo using the bundled Lab_test.nessus sample. Takes no additional input.")
    enrich_group.add_argument("--no-kev", action="store_true", default=False, help="Disable KEV enrichment.")
    enrich_group.add_argument("--no-epss", action="store_true", default=False, help="Disable EPSS enrichment.")
    enrich_group.add_argument("--no-exploit", action="store_true", default=False, help="Disable Exploit-DB enrichment.")
    enrich_group.add_argument("--kev-source", choices=['online', 'offline'], default='online', help="Select KEV source mode (online feed or offline cache/file).")
    enrich_group.add_argument("--epss-source", choices=['online', 'offline'], default='online', help="Select EPSS source mode (online feed or offline cache/file).")
    enrich_group.add_argument("--exploit-source", "-es", choices=['online', 'offline'], default='online', help="Select if you want to pull exploit dataset from an online or offline source.")
    enrich_group.add_argument("--kev-feed", type=str, help="Optional KEV feed override (URL or local path).")
    enrich_group.add_argument("--epss-feed", type=str, help="Optional EPSS feed override (URL or local path).")
    output_group.add_argument("--output", "-o", metavar="FILE", help="File to output results to. Output is in JSON")
    output_group.add_argument(
        "--verify-runmanifest",
        metavar="PATH",
        type=str,
        help="Validate an existing runmanifest JSON file (schema + integrity) and exit.",
    )
    gen_group.add_argument("--pretty-print", "-pp", action="store_true", help="Output the JSON results with identation for readability to cli")
    gen_group.add_argument("--log-file", "-Lf", default="vulnparse_pin.log", help="Log File destination.")
    gen_group.add_argument("--log-level", "-Ll", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Sets Logging level for log.", type=valid_log_level)
    gen_group.add_argument("--version", "-v", help="Show program version and exit.", action="version", version=f"%(prog)s {__version__}")
    enrich_group.add_argument("--exploit-db", "-edb", type=str, help="Path to offline exploit database (CSV)")
    enrich_group.add_argument("--refresh-cache", action="store_true", help="Forces cache refesh for feeds.")
    enrich_group.add_argument("--allow_regen", action="store_true", help="Allows regeneration of cache meta and checksum if missing using 'best-effort'.", default=False)
    enrich_group.add_argument("--no-nvd", action="store_true", help="Disables NVD Enrichment module[No NVD enrichment processing]")
    output_group.add_argument("--output-csv", "-oC", type=str, metavar="PATH", help="Path to save enriched results in CSV format (optional)")
    output_group.add_argument("--output-md", "-oM", type=str, metavar="PATH", help="Generate executive summary Markdown report")
    output_group.add_argument("--output-md-technical", "-oMT", type=str, metavar="PATH", help="Generate detailed technical Markdown report")
    output_group.add_argument("--output-runmanifest", "-oRM", type=str, metavar="PATH", help="Generate run manifest JSON artifact with embedded decision ledger")
    output_group.add_argument(
        "--runmanifest-mode",
        choices=["compact", "expanded"],
        default="compact",
        help="Decision detail level in runmanifest ledger (compact keeps high-impact events; expanded includes broader detail).",
    )
    output_group.add_argument("--output_all", "-oA", type=str, metavar="BASENAME", default=None, help="Base name for all output artifacts. Derives .json, .csv, _summary.md, _technical.md, _runmanifest.json from this stem. Individual output flags override specific artifacts.")
    gen_group.add_argument("--allow-large", "-al", action="store_true", help="Allow parsing very large reports (up to ~50GB). Use only for enterprise-scale or synthetic stress tests. Default: False")
    output_group.add_argument("--no-csv-sanitize", "-noC", action="store_true", help="Disable CSV cell sanitization (dangerous: may allow CSV formula injection in spreadsheet tools). Default: Off")
    file_group.add_argument("--forbid-symlinks-read", "--forbid-symlinks_read", "-Sr", action="store_true", default=False, help="Disables following symlinks when resolving paths during read operations.")
    file_group.add_argument("--forbid-symlinks-write", "--forbid-symlinks_write", "-Sw", action="store_true", default=True, help="Disables following symlinks when resolving paths during write operations.")
    file_group.add_argument("--enforce-root-read", "-err", action="store_true", help="Enforces read operations only on files located within the list of acceptable roots.")
    file_group.add_argument("--enforce-root-write", "-erw", action="store_true", default=True, help="Enforces write operations only on files located within the list of acceptable roots.")
    file_group.add_argument("--file-mode", "-fm", type=parse_mode, default=0o700, metavar="0o700", help="POSIX ONLY - Enables file-level chmod permissions on file write operations (octal). Default 0700")
    file_group.add_argument("--dir-mode", "-dm", type=parse_mode, default=0o760, metavar="0o760", help="POSIX ONLY - Enables file-level chmod permissions on file write operations (octal). Default 0760")
    file_group.add_argument("--debug-path-policy", action="store_true", help="Display path policy for PFHandler and exit.")
    port_group.add_argument("--portable", "-P", action="store_true", help="Use ./data folder next to executable/script for application data(config/cache/logs/output).")
    output_group.add_argument("--presentation", action="store_true", help = "Export a presentation-friendly JSON view by overlaying derived pass output onto findings. (Does not change provenence of artifacts in memory)")
    output_group.add_argument("--overlay-mode", choices=["flatten", "namespace"], default="flatten", help="Overlay mode used with --presentation. "
                              "'flatten' injects scoring fields at finding root; "
                              "'namespace' stores scoring under finding.derived.")

    args = parser.parse_args(argv)

    # --demo: inject hardcoded sample path — takes no user input.
    if args.demo:
        demo_path = _resolve_demo_sample()
        if demo_path is None:
            parser.error(
                "--demo: sample file not found. Expected at "
                "'samples/nessus/Lab_test.nessus' relative to the project root or CWD."
            )
        if not os.access(demo_path, os.R_OK):
            parser.error(f"--demo: sample file is not readable: {demo_path}")
        args.file = demo_path
        # Demo mode is always online and runs a full end-to-end artifact set.
        args.no_kev = False
        args.no_epss = False
        args.no_exploit = False
        args.kev_source = "online"
        args.epss_source = "online"
        args.exploit_source = "online"
        args.no_nvd = False
        if not args.pretty_print:
            args.pretty_print = True
        if not args.output_all:
            args.output_all = "demo_output"
        if not args.output_runmanifest:
            args.output_runmanifest = "demo_runmanifest.json"
        print(
            "\n[DEMO MODE] Running full pipeline on bundled sample: "
            f"{demo_path}\n"
            "Enrichment forced: KEV/EPSS/Exploit enabled with online sources (NVD enabled).\n"
            "Artifacts enabled: JSON, CSV, executive Markdown, technical Markdown.\n"
            "Output will be written to the configured output directory.\n"
        )
    elif args.file is None and not args.verify_runmanifest:
        parser.error("the following arguments are required: --file/-f (or use --demo to run on the bundled sample)")

    # Individual flags, if explicitly provided, take precedence.
    if args.output_all:
        _base = str(Path(args.output_all).with_suffix(""))
        if not args.output:
            args.output = _base + ".json"
        if not args.output_csv:
            args.output_csv = _base + ".csv"
        if not args.output_md:
            args.output_md = _base + "_summary.md"
        if not args.output_md_technical:
            args.output_md_technical = _base + "_technical.md"
        if not args.output_runmanifest:
            args.output_runmanifest = _base + "_runmanifest.json"

    if args.verify_runmanifest:
        verify_path = os.path.abspath(args.verify_runmanifest)
        if not os.path.isfile(verify_path):
            parser.error(f"--verify-runmanifest: file does not exist or is not a file: {args.verify_runmanifest}")
        if not os.access(verify_path, os.R_OK):
            parser.error(f"--verify-runmanifest: file is not readable: {args.verify_runmanifest}")

    if args.output:
        output_dir = os.path.dirname(os.path.abspath(args.output)) or '.'
        if not os.access(output_dir, os.W_OK):
            parser.error(f"Output directory '{output_dir}' is not writable.")

    if args.overlay_mode != "flatten" and (not args.presentation):
        parser.error("--overlay-mode requires --presentation")

    if (not args.output_csv) and args.no_csv_sanitize:
        parser.error("[Security Warning] --no-csv-sanitize requires --output-csv")

    if (not args.no_exploit) and (args.exploit_source == "offline") and (not args.exploit_db):
        parser.error("Offline exploit source requires --exploit-db to be set.")

    return args
