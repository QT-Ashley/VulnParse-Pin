# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import argparse
import atexit
from contextlib import ExitStack
from datetime import date, datetime
import os
from pathlib import Path
import sys
from typing import Optional, Sequence, Union
from urllib.parse import urlsplit

from vulnparse_pin import __version__

PathLikeSimple = Union[str, Path]

SUBCOMMANDS = frozenset({"scan", "demo", "diff", "ui", "export", "verify", "defer", "intel"})

_DEMO_NMAP_SAMPLE_NAME = "base_test_nmap.xml"
_DEMO_OPENVAS_SAMPLE_NAME = "openvas_updated_test.xml"
_DEMO_RESOURCE_STACK = ExitStack()
atexit.register(_DEMO_RESOURCE_STACK.close)

_VALUE_TAKING_FLAGS = frozenset({
    "-f", "--file",
    "--kev-source", "--epss-source", "--exploit-source", "-es",
    "--kev-feed", "--kev",
    "--epss-feed", "--epss",
    "--nvd", "--nvd-source",
    "--osv",
    "--ghsa-budget",
    "--nmap-ctx", "--nmap", "-nmap",
    "--output", "-o", "--output-json",
    "--verify-runmanifest",
    "--log-file", "-Lf",
    "--log-level", "-Ll",
    "--exploit-db", "-edb",
    "--output-csv", "-oC", "--csv-profile",
    "--output-md", "-oM",
    "--output-md-technical", "-oMT",
    "--output-pr-comment",
    "--output-html",
    "--output-dossier",
    "--output-runmanifest", "-oRM", "--runmanifest-mode",
    "--output-all", "--output_all", "-oA",
    "--webhook-endpoint", "--webhook-oal-filter",
    "--file-mode", "-fm", "--dir-mode", "-dm",
    "--overlay-mode",
    "--min-ingestion-confidence",
    "--db", "--assets", "--decisions", "--profile",
    "--template-dir", "--run-id", "--baseline-run-id",
    "--output-dir", "--fail-on", "--format", "--finding-id",
    "--asset", "--id", "--status", "--rationale", "--owner", "--expires",
    "--in-kev", "--max-epss", "--max-epss-percentile", "--internet-facing",
    "--max-cvss", "--decision-id",
    "--feed",
})


def _resolve_demo_inputs() -> tuple[Optional[Path], Optional[Path]]:
    """Return (openvas_sample_path, nmap_sample_path) for legacy demo mode."""
    openvas_path: Optional[Path] = None
    nmap_path: Optional[Path] = None

    from importlib import resources
    try:
        openvas_ref = resources.files("vulnparse_pin.resources").joinpath(_DEMO_OPENVAS_SAMPLE_NAME)
        if openvas_ref.is_file():
            p = _DEMO_RESOURCE_STACK.enter_context(resources.as_file(openvas_ref))
            openvas_path = p.resolve()

        ref = resources.files("vulnparse_pin.resources").joinpath(_DEMO_NMAP_SAMPLE_NAME)
        if ref.is_file():
            p = _DEMO_RESOURCE_STACK.enter_context(resources.as_file(ref))
            nmap_path = p.resolve()
    except (TypeError, FileNotFoundError, ModuleNotFoundError):
        pass

    return openvas_path, nmap_path


def parse_mode(value: str) -> int:
    """Parse a chmod-style mode string into an int."""
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
            f"Invalid mode '{value}' is out of valid range (0000-7777). Trace: {e}"
        )
    return mode


def valid_input_file(path: PathLikeSimple) -> Path:
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"File: '{path}' does not exist or is not a file.")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"File: '{path}' is not readable.")
    return Path(path)


def valid_existing_path(path: PathLikeSimple) -> Path:
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"Path: '{path}' does not exist.")
    if not (os.path.isfile(path) or os.path.isdir(path)):
        raise argparse.ArgumentTypeError(f"Path: '{path}' must be a file or directory.")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"Path: '{path}' is not readable.")
    return Path(path)


def valid_nmap_adapter_file(path: PathLikeSimple) -> Path:
    resolved = valid_input_file(path)
    if resolved.suffix.lower() != ".xml":
        raise argparse.ArgumentTypeError("Nmap adapter source must be an .xml file.")
    return resolved


def valid_https_url(value: str) -> str:
    url = str(value).strip()
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise argparse.ArgumentTypeError("Webhook endpoint must use https.")
    if not parts.netloc:
        raise argparse.ArgumentTypeError("Webhook endpoint must include a host.")
    if parts.username or parts.password:
        raise argparse.ArgumentTypeError("Webhook endpoint must not embed credentials.")
    return url


def valid_log_level(level: str) -> str:
    levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    lvl = level.upper()
    if lvl not in levels:
        raise argparse.ArgumentTypeError(f"Invalid log level '{level}'. Choose from {levels}.")
    return lvl


def parse_tri_bool(value: str) -> bool:
    low = str(value).strip().lower()
    if low in {"true", "1", "yes", "y"}:
        return True
    if low in {"false", "0", "no", "n"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value '{value}'. Expected true or false.")


def valid_iso_date(value: str) -> str:
    raw = str(value).strip()
    try:
        if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
            date.fromisoformat(raw)
        else:
            iso = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
            datetime.fromisoformat(iso)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid date '{value}'. Expected YYYY-MM-DD or ISO-8601 timestamp."
        ) from exc
    return raw


def _find_first_positional(tokens: list[str]) -> tuple[Optional[int], Optional[str]]:
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            if i + 1 < len(tokens):
                return i + 1, tokens[i + 1]
            return None, None
        if tok.startswith("-"):
            if "=" in tok:
                i += 1
                continue
            if tok == "--ghsa":
                if i + 1 < len(tokens) and not tokens[i + 1].startswith("-") and tokens[i + 1] not in SUBCOMMANDS:
                    i += 2
                    continue
                i += 1
                continue
            if tok in _VALUE_TAKING_FLAGS:
                i += 2
                continue
            i += 1
            continue
        return i, tok
    return None, None


def _extract_flag_value(tokens: list[str], flag_names: tuple[str, ...]) -> tuple[Optional[str], list[str]]:
    extracted: Optional[str] = None
    remaining: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        matched_eq = next((f for f in flag_names if tok.startswith(f"{f}=")), None)
        if matched_eq is not None:
            extracted = tok.split("=", 1)[1]
            i += 1
            continue
        if tok in flag_names:
            if i + 1 < len(tokens):
                extracted = tokens[i + 1]
                i += 2
                continue
            i += 1
            continue
        remaining.append(tok)
        i += 1
    return extracted, remaining


def _preprocess_legacy_argv(raw_argv: Sequence[str]) -> tuple[list[str], bool]:
    """
    Transparently rewrite legacy v1 flag-style invocations into v2 subcommands,
    emitting a 1-line deprecation notice to stderr.
    Returns (rewritten_argv, is_legacy_demo).
    """
    tokens = list(raw_argv)
    if not tokens:
        return tokens, False

    # Legacy Alias Shim detection
    has_verify_rm = any(t == "--verify-runmanifest" or t.startswith("--verify-runmanifest=") for t in tokens)
    has_demo = "--demo" in tokens
    has_file = any(t in ("-f", "--file") or t.startswith("--file=") for t in tokens)
    has_debug_policy = "--debug-path-policy" in tokens

    if any(t in ("-h", "--help", "-v", "--version") for t in tokens) and not (
        has_verify_rm or has_demo or has_file or has_debug_policy
    ):
        pos_idx, pos_tok = _find_first_positional(tokens)
        if pos_tok is None:
            return tokens, False

    pos_idx, pos_tok = _find_first_positional(tokens)
    if pos_tok in SUBCOMMANDS:
        if pos_idx is not None and pos_idx > 0:
            reordered = [pos_tok, *tokens[:pos_idx], *tokens[pos_idx + 1 :]]
            return reordered, False
        return tokens, False

    if has_verify_rm:
        rm_path, rest = _extract_flag_value(tokens, ("--verify-runmanifest",))
        print(
            "[DEPRECATED] '--verify-runmanifest' is deprecated; use 'vpp verify <runmanifest.json>'.",
            file=sys.stderr,
        )
        out = ["verify"]
        if rm_path:
            out.append(rm_path)
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok in ("--log-level", "-Ll", "--log-file", "-Lf"):
                out.append(tok)
                if i + 1 < len(rest):
                    out.append(rest[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if tok.startswith(("--log-level=", "-Ll=", "--log-file=", "-Lf=")):
                out.append(tok)
                i += 1
                continue
            if tok in (
                "--portable",
                "-P",
                "--forbid-symlinks-read",
                "--forbid-symlinks_read",
                "-Sr",
                "--allow-symlinks-read",
                "--forbid-symlinks-write",
                "--forbid-symlinks_write",
                "-Sw",
                "--enforce-root-read",
                "-err",
                "--enforce-root-write",
                "-erw",
            ):
                out.append(tok)
                i += 1
                continue
            i += 1
        return out, False

    if has_demo:
        print(
            "[DEPRECATED] '--demo' is deprecated; use 'vpp demo --no-ui'.",
            file=sys.stderr,
        )
        filtered: list[str] = []
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--demo":
                i += 1
                continue
            if tok in ("--db", "--profile", "--output-dir", "--log-level", "-Ll", "--log-file", "-Lf", "--template-dir"):
                filtered.append(tok)
                if i + 1 < len(tokens):
                    filtered.append(tokens[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if tok.startswith(("--db=", "--profile=", "--output-dir=", "--log-level=", "--log-file=", "--template-dir=")):
                filtered.append(tok)
                i += 1
                continue
            if tok in ("--portable", "-P", "--forbid-symlinks-read", "--forbid-symlinks_read", "-Sr", "--allow-symlinks-read", "--forbid-symlinks-write", "--forbid-symlinks_write", "-Sw", "--enforce-root-read", "-err", "--enforce-root-write", "-erw"):
                filtered.append(tok)
                i += 1
                continue
            i += 1
        return ["demo", "--no-ui", *filtered], True

    if has_file or has_debug_policy:
        flag_desc = "-f/--file" if has_file else "--debug-path-policy"
        print(
            f"[DEPRECATED] Top-level '{flag_desc}' is deprecated; use 'vpp scan ...'.",
            file=sys.stderr,
        )
        return ["scan", *tokens], False

    return tokens, False


def _add_common_runtime_options(parser: argparse.ArgumentParser) -> None:
    gen_group = parser.add_argument_group("General Options", "General runtime flags.")
    file_group = parser.add_argument_group(
        "Filesystem Options",
        "[Security Warning] Filesystem I/O and permissions flags. Take caution and read documentation on potential effects of flags.",
    )
    port_group = parser.add_argument_group("Portability", "Options to run VulnParse in a portable setting.")

    gen_group.add_argument("--log-file", "-Lf", default="vulnparse_pin.log", help="Log file destination.")
    gen_group.add_argument(
        "--log-level",
        "-Ll",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Sets logging level for log.",
        type=valid_log_level,
    )
    gen_group.add_argument(
        "--version",
        "-v",
        help="Show program version and exit.",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    file_group.add_argument(
        "--forbid-symlinks-read",
        "--forbid-symlinks_read",
        "-Sr",
        action="store_true",
        default=True,
        help="Disables following symlinks when resolving paths during read operations (default: enabled).",
    )
    file_group.add_argument(
        "--allow-symlinks-read",
        dest="forbid_symlinks_read",
        action="store_false",
        help="Explicitly allow following symlinks when resolving paths during read operations.",
    )
    file_group.add_argument(
        "--forbid-symlinks-write",
        "--forbid-symlinks_write",
        "-Sw",
        action="store_true",
        default=True,
        help="Disables following symlinks when resolving paths during write operations.",
    )
    file_group.add_argument(
        "--enforce-root-read",
        "-err",
        action="store_true",
        default=False,
        help="Enforces read operations only on files located within the list of acceptable roots.",
    )
    file_group.add_argument(
        "--enforce-root-write",
        "-erw",
        action="store_true",
        default=True,
        help="Enforces write operations only on files located within the list of acceptable roots.",
    )
    file_group.add_argument(
        "--file-mode",
        "-fm",
        type=parse_mode,
        default=0o600,
        metavar="0o600",
        help="POSIX ONLY - Enables file-level chmod permissions on file write operations (octal).",
    )
    file_group.add_argument(
        "--dir-mode",
        "-dm",
        type=parse_mode,
        default=0o700,
        metavar="0o700",
        help="POSIX ONLY - Enables directory-level chmod permissions on directory creation (octal).",
    )
    file_group.add_argument(
        "--debug-path-policy",
        action="store_true",
        default=False,
        help="Display path policy for PFHandler and exit.",
    )

    port_group.add_argument(
        "--portable",
        "-P",
        action="store_true",
        default=False,
        help="Use ./data folder next to executable/script for application data (config/cache/logs/output).",
    )


def _configure_scan_parser(scan_parser: argparse.ArgumentParser) -> None:
    _add_common_runtime_options(scan_parser)
    scan_group = scan_parser.add_argument_group("Scan Inputs & Context", "Scanner input files and v2 context options.")
    enrich_group = scan_parser.add_argument_group("Enrichment", "Vulnerability enrichment flags.")
    output_group = scan_parser.add_argument_group("Output Options", "Flags controlling exported artifacts and presentation.")

    scan_group.add_argument("files", nargs="*", type=valid_input_file, help="Path(s) to vulnerability scan file(s).")
    scan_group.add_argument("--file", "-f", help="Path to vulnerability scan file (legacy compat).", required=False, default=None, type=valid_input_file)
    scan_group.add_argument("--db", default=".vpp.db", metavar="PATH", help="DuckDB workspace database path.")
    scan_group.add_argument("--assets", type=valid_input_file, default=None, metavar="PATH", help="Asset context inventory YAML (assets.yaml).")
    scan_group.add_argument("--decisions", type=valid_input_file, default=None, metavar="PATH", help="Triage decisions/deferrals YAML (decisions.yaml).")
    scan_group.add_argument("--profile", choices=["default", "bod-26-04"], default="default", help="Triage decision profile.")
    scan_group.add_argument("--run-id", default=None, metavar="ID", help="Explicit run identifier.")
    scan_group.add_argument("--baseline-run-id", default=None, metavar="ID", help="Baseline run_id for scan-over-scan diff.")
    scan_group.add_argument("--strict-schema", action="store_true", default=False, help="Enforce strict schema validation across inputs and configs.")

    scan_group.add_argument("--allow-large", "-al", action="store_true", default=False, help="Allow parsing very large reports (up to ~50GB).")
    scan_group.add_argument("--allow-degraded-input", action=argparse.BooleanOptionalAction, default=True, help="Allow partial/minimal ingestion findings to continue through pipeline.")
    scan_group.add_argument("--strict-ingestion", action="store_true", default=False, help="Fail normalization if degraded ingestion findings are present.")
    scan_group.add_argument("--min-ingestion-confidence", type=float, default=0.0, metavar="0.0-1.0", help="Reject findings whose ingestion confidence falls below this threshold.")
    scan_group.add_argument("--show-ingestion-summary", action="store_true", default=False, help="Print ingestion quality summary after parser normalization.")

    enrich_group.add_argument("--offline", action="store_true", default=False, help="Run 100%% offline using local caches and supplied feed paths.")
    enrich_group.add_argument("--no-kev", action="store_true", default=False, help="Disable KEV enrichment.")
    enrich_group.add_argument("--no-epss", action="store_true", default=False, help="Disable EPSS enrichment.")
    enrich_group.add_argument("--no-exploit", action="store_true", default=False, help="Disable Exploit-DB enrichment.")
    enrich_group.add_argument("--no-nvd", action="store_true", default=False, help="Disable NVD enrichment.")
    enrich_group.add_argument("--kev-source", choices=["online", "offline"], default="online", help="Select KEV source mode.")
    enrich_group.add_argument("--epss-source", choices=["online", "offline"], default="online", help="Select EPSS source mode.")
    enrich_group.add_argument("--exploit-source", "-es", choices=["online", "offline"], default="online", help="Select Exploit-DB source mode.")
    enrich_group.add_argument("--kev-feed", "--kev", dest="kev_feed", type=str, default=None, help="Optional KEV feed override (URL or local path).")
    enrich_group.add_argument("--epss-feed", "--epss", dest="epss_feed", type=str, default=None, help="Optional EPSS feed override (URL or local path).")
    enrich_group.add_argument("--nvd", "--nvd-source", dest="nvd_source", type=str, default=None, help="Optional local NVD JSON / .json.gz file or directory.")
    enrich_group.add_argument("--exploit-db", "-edb", type=str, default=None, help="Path to offline exploit database (CSV).")
    enrich_group.add_argument("--ghsa", nargs="?", const="online", default=None, metavar="[PATH|online]", help="Enable GHSA enrichment (online or offline local path).")
    enrich_group.add_argument("--ghsa-budget", type=int, default=None, metavar="COUNT", help="Optional GHSA online lookup budget override.")
    enrich_group.add_argument("--osv", type=str, default=None, metavar="PATH", help="Optional offline OSV JSON/directory/zip archive.")
    enrich_group.add_argument("--nmap", "--nmap-ctx", "-nmap", dest="nmap_ctx", type=valid_nmap_adapter_file, default=None, metavar="PATH", help="Optional Nmap XML adapter source.")
    enrich_group.add_argument("--refresh-cache", action="store_true", default=False, help="Force cache refresh for feeds.")
    enrich_group.add_argument("--allow_regen", "--allow-regen", dest="allow_regen", action="store_true", default=False, help="Allow regeneration of cache meta and checksum if missing.")

    output_group.add_argument("--template-dir", type=valid_existing_path, default=None, metavar="DIR", help="Custom Jinja2 reporting templates directory.")
    output_group.add_argument("--output-dossier", type=str, default=None, metavar="PATH", help="Write Decision Defense Dossier (.md and .html).")
    output_group.add_argument("--output-html", type=str, default=None, metavar="PATH", help="Write HTML Decision Defense Dossier.")
    output_group.add_argument("--output", "-o", "--output-json", dest="output", metavar="FILE", default=None, help="Write JSON output to PATH.")
    output_group.add_argument("--output-csv", "-oC", type=str, metavar="PATH", default=None, help="Write enriched results in CSV format.")
    output_group.add_argument("--csv-profile", choices=["full", "analyst", "audit"], default="full", help="CSV output profile.")
    output_group.add_argument("--output-md", "-oM", type=str, metavar="PATH", default=None, help="Generate Markdown report.")
    output_group.add_argument("--output-md-technical", "-oMT", type=str, metavar="PATH", default=None, help="Generate detailed technical Markdown report.")
    output_group.add_argument("--output-runmanifest", "-oRM", type=str, metavar="PATH", default=None, help="Generate RunManifest JSON artifact.")
    output_group.add_argument("--output-all", "--output_all", "-oA", dest="output_all", type=str, metavar="BASENAME", default=None, help="Base name for all output artifacts.")
    output_group.add_argument("--runmanifest-mode", choices=["compact", "expanded"], default="compact", help="Decision detail level in RunManifest ledger.")
    output_group.add_argument("--pretty-print", "-pp", action="store_true", default=False, help="Pretty-print JSON output.")
    output_group.add_argument("--presentation", action="store_true", default=False, help="Export presentation-friendly JSON view.")
    output_group.add_argument("--overlay-mode", choices=["flatten", "namespace"], default="flatten", help="Overlay mode used with --presentation.")
    output_group.add_argument("--no-csv-sanitize", "-noC", action="store_true", default=False, help="Disable CSV cell sanitization (requires --confirm-unsafe-csv).")
    output_group.add_argument("--confirm-unsafe-csv", action="store_true", default=False, help="Explicitly confirm disabling CSV formula-injection sanitization.")
    output_group.add_argument("--webhook-endpoint", type=valid_https_url, metavar="URL", default=None, help="Override configured webhook delivery target with an HTTPS endpoint.")
    output_group.add_argument("--webhook-oal-filter", choices=["all", "P1", "P1b", "P2"], metavar="LANE", default=None, help="Override webhook OAL lane filter.")


def _validate_scan_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if getattr(args, "debug_path_policy", False):
        return

    files_list: list[Path] = []
    if getattr(args, "file", None) is not None:
        files_list.append(args.file)
    for fpath in getattr(args, "files", None) or []:
        if fpath not in files_list:
            files_list.append(fpath)

    if not files_list:
        parser.error("scan requires at least one input scan file (<files...> or --file/-f)")

    args.input_files = files_list
    if args.file is None:
        args.file = files_list[0]

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

    if args.webhook_oal_filter and not (args.webhook_endpoint or args.file):
        parser.error("--webhook-oal-filter requires a normal scan execution context.")

    if args.output:
        cand = Path(os.path.abspath(args.output)).parent
        while not cand.exists() and cand.parent != cand:
            cand = cand.parent
        if cand.exists() and not os.access(cand, os.W_OK):
            parser.error(f"Output directory '{cand}' is not writable.")

    if args.overlay_mode != "flatten" and (not args.presentation):
        parser.error("--overlay-mode requires --presentation")

    if args.min_ingestion_confidence < 0.0 or args.min_ingestion_confidence > 1.0:
        parser.error("--min-ingestion-confidence must be between 0.0 and 1.0")

    if args.strict_ingestion:
        args.allow_degraded_input = False

    if (not args.output_csv) and args.no_csv_sanitize:
        parser.error("[Security Warning] --no-csv-sanitize requires --output-csv")

    if args.csv_profile != "full" and not args.output_csv:
        parser.error("--csv-profile requires --output-csv when using non-default profiles.")

    if (not args.no_exploit) and (args.exploit_source == "offline") and (not args.exploit_db):
        parser.error("Offline exploit source requires --exploit-db to be set.")

    if args.ghsa is not None:
        ghsa_value = str(args.ghsa).strip()
        if not ghsa_value or ghsa_value.lower() == "online":
            args.ghsa = "online"
        else:
            args.ghsa = valid_existing_path(ghsa_value)

    if args.ghsa_budget is not None and args.ghsa_budget < 1:
        parser.error("--ghsa-budget must be a positive integer.")

    if args.ghsa_budget is not None and args.ghsa != "online":
        parser.error("--ghsa-budget requires online GHSA mode (--ghsa or --ghsa online).")

    if args.nmap_ctx is not None:
        args.nmap_ctx = valid_nmap_adapter_file(args.nmap_ctx)


def build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    parser = argparse.ArgumentParser(
        prog="vpp",
        description="VulnParse-Pin (vpp): Parse, enrich, prioritize, diff, and defend vulnerability triage decisions offline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        "-v",
        help="Show program version and exit.",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # 1. vpp scan
    scan_p = subparsers.add_parser(
        "scan",
        help="Ingest, enrich, score, triage, and export vulnerability scan results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _configure_scan_parser(scan_p)

    # 2. vpp demo
    demo_p = subparsers.add_parser(
        "demo",
        help="Run 100%% offline end-to-end demo using bundled multi-scanner fixtures.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _add_common_runtime_options(demo_p)
    demo_p.add_argument("--db", default=".vpp-demo.db", metavar="PATH", help="Demo DuckDB workspace path.")
    demo_p.add_argument("--profile", choices=["default", "bod-26-04"], default="default", help="Triage decision profile.")
    demo_p.add_argument("--no-ui", action="store_true", default=False, help="Do not launch Textual TUI after demo walkthrough.")
    demo_p.add_argument("--output-dir", default="vpp_demo_output", metavar="DIR", help="Directory for exported demo artifacts.")
    demo_p.add_argument("--template-dir", type=valid_existing_path, default=None, metavar="DIR", help="Custom Jinja2 reporting templates directory.")

    # 3. vpp diff
    diff_p = subparsers.add_parser(
        "diff",
        help="Compare two scan runs (or scan files) and evaluate stale-assumption / CI fail gates.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _add_common_runtime_options(diff_p)
    diff_p.add_argument("base", nargs="?", default=None, help="Base run_id or scan file path.")
    diff_p.add_argument("target", nargs="?", default=None, help="Target run_id or scan file path.")
    diff_p.add_argument("--db", default=".vpp.db", metavar="PATH", help="DuckDB workspace path.")
    diff_p.add_argument("--decisions", type=valid_input_file, default=None, metavar="PATH", help="Decisions registry YAML.")
    diff_p.add_argument("--assets", type=valid_input_file, default=None, metavar="PATH", help="Optional assets.yaml when diffing two scan files on the fly.")
    diff_p.add_argument("--profile", choices=["default", "bod-26-04"], default="default", help="Triage profile if ingesting scan files.")
    diff_p.add_argument("--offline", action="store_true", default=False, help="Offline mode if ingesting scan files.")
    diff_p.add_argument("--fail-on", choices=["p1", "p2", "kev", "stale-assumption", "none"], default="none", help="Exit with code 2 when specified delta condition triggers.")
    diff_p.add_argument("--output-md", default=None, metavar="PATH", help="Write Markdown diff report.")
    diff_p.add_argument("--output-pr-comment", default=None, metavar="PATH", help="Write concise PR comment Markdown.")
    diff_p.add_argument("--output-json", default=None, metavar="PATH", help="Write structured JSON diff report.")
    diff_p.add_argument("--template-dir", type=valid_existing_path, default=None, metavar="DIR", help="Custom Jinja2 templates directory.")

    # 4. vpp ui
    ui_p = subparsers.add_parser(
        "ui",
        help="Launch interactive Textual TUI workbench over .vpp.db.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _add_common_runtime_options(ui_p)
    ui_p.add_argument("--db", default=".vpp.db", metavar="PATH", help="DuckDB workspace path.")
    ui_p.add_argument("--run-id", default=None, metavar="ID", help="Target run_id (defaults to latest run).")
    ui_p.add_argument("--decisions", type=valid_input_file, default=None, metavar="PATH", help="Optional decisions.yaml for interactive deferrals.")
    ui_p.add_argument("--output-dir", default=".", metavar="DIR", help="Directory for dossier exports triggered inside UI.")
    ui_p.add_argument("--template-dir", type=valid_existing_path, default=None, metavar="DIR", help="Custom Jinja2 templates directory.")

    # 5. vpp export
    export_p = subparsers.add_parser(
        "export",
        help="Export Decision Defense Dossiers, Executive Roadmaps, CSV, or JSON from .vpp.db.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _add_common_runtime_options(export_p)
    export_p.add_argument("--db", default=".vpp.db", metavar="PATH", help="DuckDB workspace path.")
    export_p.add_argument("--run-id", default=None, metavar="ID", help="Target run_id (defaults to latest run).")
    export_p.add_argument("--finding-id", default=None, metavar="ID", help="Optional single finding_id for dossier export.")
    export_p.add_argument(
        "--format",
        required=True,
        choices=["dossier-md", "dossier-html", "roadmap-md", "roadmap-html", "csv", "json"],
        help="Export artifact format.",
    )
    export_p.add_argument("--output", "-o", default=None, metavar="PATH", help="Output file path.")
    export_p.add_argument("--template-dir", type=valid_existing_path, default=None, metavar="DIR", help="Custom Jinja2 templates directory.")
    export_p.add_argument("--csv-profile", choices=["full", "analyst", "audit"], default="full", help="CSV export profile.")
    export_p.add_argument("--overlay-mode", choices=["flatten", "namespace"], default="namespace", help="JSON presentation mode.")
    export_p.add_argument("--pretty-print", "-pp", action="store_true", default=False, help="Pretty-print JSON output.")
    export_p.add_argument("--no-csv-sanitize", "-noC", action="store_true", default=False, help="Disable CSV cell sanitization (requires --confirm-unsafe-csv).")
    export_p.add_argument("--confirm-unsafe-csv", action="store_true", default=False, help="Explicitly confirm disabling CSV formula-injection sanitization.")

    # 6. vpp verify
    verify_p = subparsers.add_parser(
        "verify",
        help="Verify RunManifest schema, digest, and hash-chained decision ledger.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _add_common_runtime_options(verify_p)
    verify_p.add_argument("runmanifest", type=valid_input_file, help="Path to runmanifest JSON file.")

    # 7. vpp defer
    defer_p = subparsers.add_parser(
        "defer",
        help="Upsert a deferral, acceptance, or mitigation entry in decisions.yaml.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _add_common_runtime_options(defer_p)
    defer_p.add_argument("--asset", dest="asset_pattern", required=True, metavar="PATTERN", help="Asset ID or glob pattern.")
    defer_p.add_argument("--id", dest="cve_or_rule_id", required=True, metavar="CVE_OR_RULE", help="CVE ID or scanner rule/template ID.")
    defer_p.add_argument("--status", required=True, choices=["deferred", "accepted", "mitigated"], help="Decision status.")
    defer_p.add_argument("--rationale", required=True, metavar="TEXT", help="Audit-defensible rationale.")
    defer_p.add_argument("--owner", required=True, metavar="NAME", help="Responsible owner.")
    defer_p.add_argument("--expires", dest="expires_at", type=valid_iso_date, default=None, metavar="YYYY-MM-DD", help="Expiration date (YYYY-MM-DD or ISO-8601).")
    defer_p.add_argument("--in-kev", dest="in_kev", type=parse_tri_bool, default=None, metavar="true|false", help="Assumption: CVE is/is not in CISA KEV.")
    defer_p.add_argument("--max-epss", dest="max_epss", type=float, default=None, metavar="FLOAT", help="Assumption: maximum EPSS score [0.0-1.0].")
    defer_p.add_argument("--max-epss-percentile", dest="max_epss_percentile", type=float, default=None, metavar="FLOAT", help="Assumption: maximum EPSS percentile [0.0-1.0].")
    defer_p.add_argument("--internet-facing", dest="internet_facing", type=parse_tri_bool, default=None, metavar="true|false", help="Assumption: asset internet exposure state.")
    defer_p.add_argument("--max-cvss", dest="max_cvss", type=float, default=None, metavar="FLOAT", help="Assumption: maximum CVSS base score [0.0-10.0].")
    defer_p.add_argument("--decision-id", default=None, metavar="ID", help="Explicit decision identifier.")
    defer_p.add_argument("--decisions", default="decisions.yaml", metavar="PATH", help="Decisions registry YAML path.")
    defer_p.add_argument("--db", default=None, metavar="PATH", help="Optional .vpp.db to refresh triage decisions.")

    # 8. vpp intel
    intel_p = subparsers.add_parser(
        "intel",
        help="Inspect local threat-intel cache freshness/HMAC health or sync feeds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    _add_common_runtime_options(intel_p)
    intel_p.add_argument("action", nargs="?", choices=["status", "sync"], default="status", help="Intel action: status or sync.")
    intel_p.add_argument("--feed", choices=["all", "nvd", "epss", "kev", "exploit_db", "ghsa", "osv"], default="all", help="Specific feed to inspect or sync.")
    intel_p.add_argument("--refresh", action="store_true", default=False, help="Force feed refresh during sync.")
    intel_p.add_argument("--allow-regen", "--allow_regen", dest="allow_regen", action="store_true", default=False, help="Allow local checksum regeneration if missing.")
    intel_p.add_argument("--kev-feed", default=None, metavar="PATH_OR_URL", help="Custom KEV source.")
    intel_p.add_argument("--epss-feed", default=None, metavar="PATH_OR_URL", help="Custom EPSS source.")
    intel_p.add_argument("--exploit-db", "-edb", default=None, metavar="PATH", help="Local Exploit-DB CSV source.")
    intel_p.add_argument("--nvd", dest="nvd_source", default=None, metavar="PATH", help="Local NVD JSON / .json.gz / directory.")
    intel_p.add_argument("--ghsa", default=None, metavar="PATH", help="Local GHSA advisory JSON/directory.")
    intel_p.add_argument("--osv", default=None, metavar="PATH", help="Local OSV JSON/directory/zip.")
    intel_p.add_argument("--json", dest="json_output", action="store_true", default=False, help="Print status as JSON.")

    return parser, {
        "scan": scan_p,
        "demo": demo_p,
        "diff": diff_p,
        "ui": ui_p,
        "export": export_p,
        "verify": verify_p,
        "defer": defer_p,
        "intel": intel_p,
    }


def get_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    raw_argv = sys.argv[1:] if argv is None else list(argv)
    rewritten, is_legacy_demo = _preprocess_legacy_argv(raw_argv)

    parser, subparsers_map = build_parser()
    args = parser.parse_args(rewritten)

    if args.command == "scan":
        _validate_scan_args(subparsers_map["scan"], args)
    elif args.command == "defer":
        if args.max_epss is not None and not (0.0 <= args.max_epss <= 1.0):
            subparsers_map["defer"].error("--max-epss must be between 0.0 and 1.0")
        if args.max_epss_percentile is not None and not (0.0 <= args.max_epss_percentile <= 1.0):
            subparsers_map["defer"].error("--max-epss-percentile must be between 0.0 and 1.0")
        if args.max_cvss is not None and not (0.0 <= args.max_cvss <= 10.0):
            subparsers_map["defer"].error("--max-cvss must be between 0.0 and 10.0")
    elif args.command == "demo" and is_legacy_demo:
        demo_openvas_path, demo_nmap_path = _resolve_demo_inputs()
        if demo_openvas_path is None or demo_nmap_path is None:
            subparsers_map["demo"].error(
                "--demo: required demo samples not found. Expected OpenVAS fixture at "
                "packaged resource 'openvas_updated_test.xml' and packaged Nmap context "
                "sample 'base_test_nmap.xml'."
            )
        if not os.access(demo_openvas_path, os.R_OK):
            subparsers_map["demo"].error(f"--demo: OpenVAS sample file is not readable: {demo_openvas_path}")
        if not os.access(demo_nmap_path, os.R_OK):
            subparsers_map["demo"].error(f"--demo: Nmap sample file is not readable: {demo_nmap_path}")

        args.demo = True
        args.file = demo_openvas_path
        args.nmap_ctx = demo_nmap_path
        args.ghsa = "online"
        args.ghsa_budget = 25
        args.output_all = "demo_output"
        args.output_runmanifest = "demo_runmanifest.json"
        args._legacy_demo = True

    return args
