# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from datetime import datetime
import json
from pathlib import Path
import time
from dataclasses import asdict
from typing import Any, Optional, Sequence, Type
from vulnparse_pin.core.classes.dataclass import FeedCachePolicy, FeedSpec, RunContext, ScanResult, Services
from vulnparse_pin.utils.enricher import enrich_scan_results, load_epss, load_kev, update_enrichment_status
import argparse
import sys
from vulnparse_pin.utils.banner import print_banner
from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
from vulnparse_pin.utils.feed_cache import FeedCacheManager
from vulnparse_pin.utils.logger import LoggerWrapper
import vulnparse_pin.utils.logger_instance as log
import os
from vulnparse_pin.parsers.__init__ import parsers
from vulnparse_pin.utils.exploit_enrichment_service import *
from vulnparse_pin.utils.validations import *
from vulnparse_pin.utils.nvdcacher import NVDFeedCache
from vulnparse_pin.utils.enrichment_stats import stats
from vulnparse_pin.io.pfhandler import PathLike, PermFileHandler
from vulnparse_pin.utils.csv_exporter import export_to_csv
from vulnparse_pin.core.apppaths import AppPaths, ensure_user_configs, load_config
from vulnparse_pin import __version__

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_FEED = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

def print_summary_banner(scan_result, output_file=None, sources=None):
    '''
    Prints a formatted summary banner with key metrics from the scan result.
    
    Args:
        scan_result (ScanResult): The final processed scan results.
        output_file (str, optional): The path to the output JSON file.
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
    total_assets = len(scan_result.assets)
    total_findings = sum(len(asset.findings) for asset in scan_result.assets)
    exploit_findings = sum(
        sum(1 for f in asset.findings if getattr(f, 'exploit_available', False)) for asset in scan_result.assets
        )
    avg_risk_score = round(
        sum(asset.avg_risk_score for asset in scan_result.assets) / total_assets, 2
    ) if total_assets else 0.0
    highest_risk_asset = max(
        scan_result.assets, key=lambda a: a.avg_risk_score, default=None
    )
    enriched_findings = sum(
        sum(1 for f in asset.findings if f.enriched) for asset in scan_result.assets
    )
    critical_findings = sum(
        sum(1 for f in asset.findings if f.risk_band == 'Critical+') for asset in scan_result.assets
    )
    high_findings = sum(
        sum(1 for f in asset.findings if f.risk_band == 'High') for asset in scan_result.assets
    )
    medium_findings = sum(
        sum(1 for f in asset.findings if f.risk_band == 'Medium') for asset in scan_result.assets
    )
    low_findings = sum(
        sum(1 for f in asset.findings if f.risk_band == 'Low') for asset in scan_result.assets
    )

    print("\n" + "="*60)
    print("🛡️          VulnParse-Pin Scan Summary (v1.0-RC)          🛡️")
    print("="*60)
    print(f" Total Assets Analyzed            : {total_assets:,}")
    print(f" Total Findings Triaged           : {total_findings:,}")
    print(f" Average Asset Risk Score         : {avg_risk_score:.2f}")
    if highest_risk_asset:
        print(f" Highest Risk Asset               : {highest_risk_asset.hostname} (Score: {highest_risk_asset.avg_risk_score:.2f})")
    else:
        print(" Highest Risk Asset: N/A")
    print("-" * 60)
    print(f"💣 Findings with Known Exploits   : {exploit_findings:,}")
    print(f"🔥 Critical+ Risk Findings        : {critical_findings:,}")
    print(f"⚠️  High Risk Findings             : {high_findings:,}")
    print(f"🟡 Medium Risk Findings           : {medium_findings:,}")
    print(f"🟢 Low Risk Findings              : {low_findings:,}")
    print("-" * 60)
    print(f"📊 Enriched Findings              : {enriched_findings:,}")
    if output_file:
        print(f"📁 Output Location                : {output_file}")


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

    logger.info(f"Assets Analyzed: {total_assets:,}," 
                f"Findings Triaged: {total_findings:,}," 
                f"Average Risk Score: {avg_risk_score:.2f},"
                f"Highest Risk Asset: {highest_risk_asset.hostname if highest_risk_asset else 'N/A'},"
                f"Critical+: {critical_findings:,}, High: {high_findings:,}, Medium: {medium_findings:,}, Low: {low_findings:,}"
                )

def format_runtime(seconds: float) -> str:
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes > 0:
        return f"{minutes}m {secs:.2f}s"
    else:
        return f"{secs:2f}s"

def build_run_log(input_path: PathLike) -> Path:
    """
    Helper to create a log filename with timestamp.
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(input_path).stem
    return f"vulnparse-{stem}-{ts}.log"

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

def write_output(data: Dict, file_path: PathLike, pretty_print=False):
    '''
    Function to handle file writing operations for JSON results with the option of pretty printing JSON if the --pretty-print argument is True.

    Args:
        data ([dict]): JSON dict obj being dumped.
        file_path ([str]): File path/file that is being written to. 
        pretty_print ([bool]): True if --pretty-print argument is supplied.
        
    Returns:
        None: Write operations are completed with status messages printed to console.
    '''
    with open(file_path, 'w', encoding='utf-8') as f:
        if pretty_print:
            logger.print_info("Pretty-printing JSON - Standby...")
            try:
                json.dump(asdict(data), f, indent=4)
                logger.print_success(f"Parsed results are stored in: {file_path}")
            except Exception as e:
                logger.print_error(f"Error attempt to dump to JSON: {e}")
                sys.exit(1)
        else:
            try:
                logger.print_info("[*] Dumping JSON results...")
                json.dump(asdict(data), f)
                logger.print_success(f"JSON results available in: {file_path}")
            except Exception as e:
                logger.print_error(f"Error attempt to dump to JSON: {e}")
                logger.logger.exception("Exception: %s", e)
                sys.exit(1)

def valid_input_file(path: PathLike) -> Path:
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

def detect_parser(ctx: "RunContext", filepath: PathLike):
    """
    Detects and returns the correct parser class for given input.
    Uses detect_file() for lightweight header sniffing.
    """
    for parser_cls in parsers:
        try:
            if parser_cls.detect_file(filepath):
                ctx.logger.print_success(f"Detected parser for structure: {parser_cls.__name__}", label = "Normalization")
                return parser_cls
        except Exception:
            ctx.logger.debug("Parser detect failed: '%s'", parser_cls.__name__, exc_info=True)
            continue
    raise ValueError(f"No parser matched input: {filepath.name if isinstance(filepath, Path) else filepath}")


def force_under_root(root: Path, candidate: os.PathLike) -> Path:
    """
    Forces candidate file to live under designated root.
    """
    c = Path(candidate)
    if not c.is_absolute() and len(c.parts) == 1:
        return root / c
    return c

def load_and_parse(ctx: "RunContext", filepath: PathLike) -> ScanResult:
    """
    Detect parser, parse the file, and return ScanResult object.
    """
    parsercls = detect_parser(ctx, filepath)
    if parsercls:
        parser = parsercls(ctx)
        scan_result = parser.parse(filepath)
        return scan_result
    else:
        ctx.logger.print_error(f"Failure attemping to parse {filepath.name}", label = "Normalization")
        raise RuntimeError

# Resolve feed sources.
def resolve_feed_path(arg_val, offline_mode: bool, default_online: PathLike, default_offline: PathLike) -> Any | str:
    """
    Used to determine how the feeds should be resolved based on user input.
    
    :param arg_val: User input from flag
    :param offline_mode: Whethere or not offline mode flag is specified.
    :type offline_mode: bool
    :param default_online: Resolves online feed cache url.
    :type default_online: str
    :param default_offline: Resolve offline feed cache path.
    :type default_offline: str | Path
    :return: Feed Source
    :rtype: Any | str
    """
    if arg_val:
        return arg_val
    elif offline_mode:
        return default_offline
    else:
        return default_online

def build_feed_cache_policy(config: dict) -> FeedCachePolicy:
        fc = config.get("feed_cache", {}) or {}
        defaults = fc.get("defaults", {}) or {}
        default_ttl = int(defaults.get("ttl_hours", 24))

        ttl_map = fc.get("ttl_hours", {}) or {}
        ttl_map = {str(k): int(v) for k, v in ttl_map.items()}

        return FeedCachePolicy(default_ttl_hours = default_ttl, ttl_hours = ttl_map)

def get_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulnparse-pin",
        description="VulnParse-Pin: Enrich, prioritize, and triage vulnerability scan results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--file", "-f", help="Path to vulnerability scan file", required=True, type=valid_input_file)
    parser.add_argument("--enrich-kev", "-kev", nargs="?", help="Path/URL to CISA KEV JSON or JSON.gz file. If omitted, uses official CISA KEV feed.")
    parser.add_argument("--enrich-epss", "-epss", nargs="?", help="Path/URL to EPSS .csv or CSV.gz file. If omitted, use official EPSS feed.")
    parser.add_argument("--output", "-o", default="VP_triage_results.json", metavar="FILE", help="File to output results to. Output is in JSON")
    parser.add_argument("--pretty-print", "-pp", action="store_true", help="Output the JSON results with identation for readability to cli")
    parser.add_argument("--log-file", default="vulnparse_pin.log", help="Log File destination.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Sets Logging level for log.", type=valid_log_level)
    parser.add_argument("--version", "-v", help="Show program version and exit.", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--exploit-source", "-es", choices=['online', 'offline'], default='online', help="Select if you want to pull exploit dataset from an online or offline source.")
    parser.add_argument("--exploit-db", "-edb", type=str, help="Path to offline exploit database (CSV)")
    parser.add_argument("--enrich-exploit", "-ex", action="store_true", help="Enrich findings with exploit availability info.")
    parser.add_argument("--mode", choices=["online", "offline"], default="online", help="Set to 'offline' to disable epss and kev external enrichment requests and use local cache only.")
    parser.add_argument("--refresh-cache", action="store_true", help="Forces cache refesh for feeds.")
    parser.add_argument("--no-nvd", action="store_true", help="Disables NVD Enrichment module[No NVD enrichment processing]")
    parser.add_argument("--output-csv", type=str, metavar="PATH", help="Path to save enriched results in CSV format (optional)")
    parser.add_argument("--allow-large", action="store_true", help="Allow parsing very large reports (up to ~50GB). Use only for enterprise-scale or synthetic stress tests.")
    parser.add_argument("--no-csv-sanitize", action="store_true", help="Disable CSV cell sanitization (dangerous: may allow CSV formula injection in spreadsheet tools)")
    parser.add_argument("--forbid-symlinks", "-fbs", action="store_true", help="Disables following symlinks when resolving paths.")
    parser.add_argument("--enforce-root-read", "-err", action="store_true", help="Enforces read operations only on files located within the list of acceptable roots.")
    parser.add_argument("--enforce-root-write", "-erw", default=True, help="Enforces write operations only on files located within the list of acceptable roots.")
    parser.add_argument("--file-mode", "-fm", type=parse_mode, default=0o700, nargs=1, metavar="0o700", help="POSIX ONLY - Enables file-level chmod permissions on file write operations.")
    parser.add_argument("--dir-mode", "-dm", type=parse_mode, default=0o760, nargs=1, metavar="0o760", help="POSIX ONLY - Enables file-level chmod permissions on file write operations.")
    parser.add_argument("--debug-path-policy", action="store_true", help="Display path policy for PFHandler and exit.")
    parser.add_argument("--portable", action="store_true", help="Use ./data folder next to executable/script for application data(config/cache/logs/output).")

    args = parser.parse_args(argv)


    if args.output:
        output_dir = os.path.dirname(os.path.abspath(args.output)) or '.'
        if not os.access(output_dir, os.W_OK):
            parser.error(f"Output directory '{output_dir}' is not writable.")

    return args


def main(argv: Optional[Sequence[str]] = None):

    args = get_args(argv)

    # Paths
    paths = AppPaths.resolve(portable=getattr(args, "portable", None))
    paths.ensure_dirs()

    print_banner()

    # -------------------------------------
    #   Bootstrap Logger (( temp ))
    # -------------------------------------
    bootstrap_log = paths.log_dir / "bootstrap.log"
    logwrap = LoggerWrapper(str(bootstrap_log), log_level=args.log_level)
    logger = logwrap
    
    # -------------------------------------
    #   Init PFH
    # -------------------------------------
    pfh = PermFileHandler(
        logger = logger,
        root_dir = paths.base_dir,
        allowed_roots = [
            paths.config_dir,
            paths.cache_dir,
            paths.log_dir,
            paths.output_dir
            ],
        max_log_path_chars = 25,
        hide_home = True,
        forbid_symlinks = args.forbid_symlinks,
        enforce_roots_on_read = args.enforce_root_read,
        enforce_roots_on_write = args.enforce_root_write,
        file_mode = args.file_mode,
        dir_mode = args.dir_mode,
    )

    # Optional debug policy flag
    if args.debug_path_policy:
        logger.print_info(f"\n{pfh.describe_policy()}", label="Path Policy")
        sys.exit(0)


    # -------------------------------------
    #   Build Booststrap CTX
    # -------------------------------------
    ctx = RunContext(
        paths = paths,
        pfh = pfh,
        logger = logger,
        services = None
    )

    # -------------------------------------
    #   Load Global Config
    # -------------------------------------
    cfg_yaml_path, cfg_score_path = ensure_user_configs(paths)

    cfg_yaml, scoring_cfg = load_config(ctx)

    # --------- Build feed cache policy from YAML
    feed_policy = build_feed_cache_policy(cfg_yaml)

    # Services
    FEED_SPECS = {
        "epss": FeedSpec(key = "epss", filename = "epss_cache.csv", label = "EPSS"),
        "kev": FeedSpec(key = "kev", filename = "kev_cache.json", label = "CISA KEV"),
        "exploit_db": FeedSpec(key = "exploit_db", filename = "files_exploit.csv", label = "Exploit-DB"),
    }

    feed_cache = FeedCacheManager.from_ctx(ctx, specs = FEED_SPECS, policy = feed_policy)

    # Build NVD Cache and attach to ctx.services
    nvd_cache = NVDFeedCache(ctx)

    # Refresh
    nvd_cache.refresh(
        config=cfg_yaml,
        feed_cache=feed_cache,
        refresh_cache=args.refresh_cache,
        offline=(args.mode == "offline")
        )

    # Build/Init Services
    services = Services(feed_cache = feed_cache, nvd_cache = nvd_cache)
    # -------------------------------------
    #   Final CTX(Runtime)
    # -------------------------------------
    ctx = RunContext(paths = paths, pfh = pfh, logger = logger, services = services)

    # -------------------------------------
    #   Create run Logs
    # -------------------------------------
    run_log_name = build_run_log(args.log_file)
    run_log_path = pfh.ensure_writable_file(paths.log_dir / Path(run_log_name).name,
                                            label="Run Log File",
                                            create_parents=True,
                                            overwrite=True)

    # Rebuild logger to write to per-run log
    logwrap = LoggerWrapper(str(run_log_path), log_level=args.log_level)
    logger = logwrap

    # Have PFH use new logger + update ctx logger.
    pfh.logger = logger
    ctx = RunContext(paths = paths, pfh = pfh, logger = logger, services = services)

    logger.print_info(f'Using config: {cfg_yaml_path.name}', label="Global Config")
    logger.print_info(f'Using scoring config: {cfg_score_path.name}', label = "Scoring Weight Config")
    logger.debug("\n%s", pfh.describe_policy())

    # ----------------------------------------
    # Validate all CLI paths through PFH
    # ----------------------------------------
    # -f File
    scanner_input = pfh.ensure_readable_file(args.file, label="Scanner Input")

    # --enrich-kev PATH
    kev_path = None
    if getattr(args, "enrich_kev", None) and not args.enrich_kev.startswith("http"):
        kev_path = pfh.ensure_readable_file(args.enrich_kev, label="KEV Local Cache File")
    else:
        kev_path = ctx.paths.kev_dir

    # --enrich_epss PATH
    epss_path = None
    if getattr(args, "enrich_epss", None) and not args.enrich_epss.startswith("http"):
        epss_path = pfh.ensure_readable_file(args.enrich_epss, label="EPSS Local Cache File")
    else:
        epss_path = ctx.paths.epss_dir

    # --output
    json_output = None
    if getattr(args, "output", None):
        json_output = pfh.ensure_writable_file(
            paths.output_dir / Path(args.output).name,
            label="JSON Output File",
            create_parents=True,
            overwrite=True,
        )
    # --output_csv
    csv_output = None
    if getattr(args, "output_csv", None):
        csv_output = pfh.ensure_writable_file(
            paths.output_dir / Path(args.output_csv).name,
            label="CSV Output File",
            create_parents=True,
            overwrite=True,
        )
    # Exploit-DB Local
    src = None
    dst = None
    exploit_db = None
    if args.enrich_exploit and args.exploit_source == "offline":
        if args.exploit_db is not None and Path(args.exploit_db).suffix == ".csv":
            src = pfh.ensure_readable_file(args.exploit_db, label="Exploit-DB Input File")
            dst = pfh.ensure_writable_file(paths.cache_dir / "Exploit_DB" / "files_exploits.csv", label="Exploit-DB Cache File", create_parents=True, overwrite=True)

            with pfh.open_for_read(src, mode="rb", label="Exploit-DB Input File") as r, \
                pfh.open_for_write(dst, mode="wb", label="Exploit-DB Cached File") as w:
                    w.write(r.read())

            exploit_db = dst
        else:
            logger.print_error("Exploit enrichment flag + Offline mode set, but no proper local exploit database file passed. Supply the exploit-db with a proper file path and try again.")
            raise RuntimeError("Enrich-exploit and Offline mode set without specifying Exploit-DB argument. Please supply file path to --exploit-db and try again.")


    logger.debug('Scanner input: "%s"', pfh.format_for_log(scanner_input))
    if json_output:
        logger.debug('JSON output: "%s"', pfh.format_for_log(json_output))
    if csv_output:
        logger.debug('CSV output: "%s"', pfh.format_for_log(csv_output))


    # CSV Sanitization INIT
    csv_sanitization_enabled = not args.no_csv_sanitize
    if not csv_sanitization_enabled:
        while True:
            logger.print_warning(
                                  f"CSV Cell Sanitization has been disabled. This presents a {Fore.LIGHTRED_EX}MAJOR injection vulnerability in spreadsheet tools when opening this CSV.{Style.RESET_ALL}", label="CSV-DANGEROUS_ACTION")
            warn = input("Are you sure you want to proceed? Yes/No: ").strip().lower()

            if warn in ("yes", "y"):
                logger.print_warning(f"Running with CSV cell sanitization {Fore.LIGHTRED_EX}OFF{Style.RESET_ALL}. This action will be logged.", label="CSV-DANGEROUS_ACTION")
                break
            elif warn in ("no", "n"):
                logger.print_info("Aborting at user request.", label="CSV-DANGEROUS_ACTION")
                sys.exit(0)
            else:
                logger.print_warning("Please answer 'yes' or 'no'.", label="CSV-DANGEROUS_ACTION")
    else:
        logger.print_info("Sanitization is enabled: dangerous prefixes (=, +, -, @) will be escaped to prevent CSV formula injection.", label="CSV-Sanitization")


    # Resolve Enrichment Feed Sources
    kev_source = resolve_feed_path(
        arg_val=args.enrich_kev,
        offline_mode=(args.mode == "offline"),
        default_online=KEV_FEED,
        default_offline=kev_path
    )
    epss_source = resolve_feed_path(
        arg_val=args.enrich_epss,
        offline_mode=(args.mode == "offline"),
        default_online=EPSS_FEED,
        default_offline=epss_path
    )

    # Check Mode
    if args.mode == "offline":
        logger.print_info("[*] Offline mode enabled. Enrichment will use local cache only.\n", label="Mode-Offline")
        if not os.path.exists(kev_source):
            logger.print_error(f"[OFFLINE] KEV cache not found: {kev_source}", label="Mode-Offline")
            raise FileNotFoundError("Missing KEV cache.")
        if not os.path.exists(epss_source):
            logger.print_error(f"[OFFLINE] EPSS cache not found: {epss_source}", label="Mode-Offline")
            raise FileNotFoundError("Missing EPSS cache.")

    # Start Pipeline

    logger.print_info("Starting up VulnParse-Pin...", f"VulnParse-Pin {__version__}")
    logger.print_info(f"Loading file: {scanner_input.name}")

    input_file = scanner_input

    # If JSON - Check and validate json structure.
    if str(input_file).endswith(".json"):
        validator = FileInputValidator(input_file, allow_large=args.allow_large) #TODO: Incorporate CTX here.
        try:
            input_file = validator.validate()
        except Exception:
            sys.exit(1)


    # Available parsers
    #NessusParser(), OpenVASParser(), NessusXMLParser(), OpenVASMXLParser()] #TODO: Extend Parser classes
    # Detect parser class, initialize, and parse.
    logger.print_info("Scanning structure to determine the type of parser to use...", label="Normalization")
    scan_result = None
    try:
        scan_result = load_and_parse(ctx, input_file)
    except Exception as e:
        logger.print_error(f"Error occured while trying to determine parser to use. Msg: {e}", label="Normalization")
        return sys.exit(1)

    logger.print_success(f"Parsed {len(scan_result.assets)} assets, {sum(len(a.findings) for a in scan_result.assets)} findings", label="Normalization")

    # Start enrichment pipeline

    kev_data = None
    epss_data = None
    feed_cfg = config.get("feed_cache", {})

    # Load Exploit-DB if flagged.
    exploit_data = None
    if args.enrich_exploit:
        print()
        logger.print_info(f"{Fore.LIGHTBLUE_EX}[Enrich-Exploit]{Style.RESET_ALL} Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{args.exploit_source.upper()}{Style.RESET_ALL} source...")
        exploit_data = load_exploit_data(args.exploit_source, args.exploit_db, feed_cache=feed_cfg, force_refresh=args.refresh_cache)
        logger.print_success(f"{Fore.LIGHTBLUE_EX}[Enrich-Exploit]{Style.RESET_ALL} Loaded Exploit-DB data ({len(exploit_data)} CVEs with exploits)\n")


    # Load nvd config file
    nvd_cfg = config.get("nvd", {})

    if not args.no_nvd and nvd_cfg.get("enabled", True):
        start_year = nvd_cfg.get("start_year", 2017)
        end_year = nvd_cfg.get("end_year", datetime.now().year)
        years = list(range(start_year, end_year + 1))

        refresh_days = nvd_cfg.get("refresh_interval_days", 1)

        logger.print_info(f"{Fore.LIGHTYELLOW_EX}[NVD Cache]{Style.RESET_ALL} Initializing NVD Cache for {start_year}-{end_year}...")
        nvd_cache = NVDCache(cache_dir="./nvd_cache", refresh_days=refresh_days, offline=(args.mode == "offline"))
        nvd_cache.refresh(years=years) # skips download if offline
        logger.print_success("NVD Cache ready.")

        nvd_status = f"✅ (feeds {start_year}–{end_year}, modified)"
    elif args.no_nvd:
        nvd_cache = None
        nvd_status = "Disabled (--no-nvd)"
        logger.print_info("[NVD Cache] Disabled via --no-nvd flag. Skipping NVD enrichment per user flag.")
    else:
        nvd_cache = None
        nvd_status = "Disabled (config)"
        logger.print_info("[NVD Cache] Disabled via config.")

    # 1 Load enrichment data sources
    if kev_source:
        kev_data = load_kev_from_json(kev_source, feed_cache=feed_cfg, force_refresh=args.refresh_cache)

    if epss_source:
        epss_data = load_epss_from_csv(epss_source, feed_cache=feed_cfg, force_refresh=args.refresh_cache)
        print("="*25 + "Exploit Enrichment Results" + "="*25)


    # 2 Apply exploit enrichments
    if args.enrich_exploit and exploit_data:
        for asset in scan_result.assets:
            enriched_findings = enrich_exploit_availability(asset.findings, exploit_data)
            asset.findings = enriched_findings
        logger.print_success(f"{Fore.LIGHTBLUE_EX}[Enrich-Exploit]{Style.RESET_ALL}Exploit enrichment applied to findings.\n" + "="*25 + "Enrichment Processing" + "="*25)

    # 3 Apply heuristic tagging *before* enrichment and risk scoring
    for asset in scan_result.assets:
        for finding in asset.findings:
            apply_heuristic_exploit_tag(finding)

    # 4 Apply enrichments
    if kev_data or epss_data:
        enrich_scan_results(scan_result, kev_data, epss_data, offline_mode=args.mode == "offline", score_cfg=score_cfg, nvd_cache=nvd_cache)
        logger.print_success("Enrichments Applied")

    # 5 Do Post-Processing enrichment status update.
    for asset in scan_result.assets:
        for finding in asset.findings:
            update_enrichment_status(finding)


    # Build Sources dict
    sources = {
        "exploitdb": True, # Exploit-DB is always loaded
        "kev": kev_data is not None,
        "epss": epss_data is not None,
        "nvd": nvd_status,
        "stats": {
            "kev_hits": stats.kev_hits,
            "kev_total": stats.total_cves,
            "epss_hits": (stats.total_cves - stats.epss_misses),
            "epss_total": stats.total_cves,
            "nvd_vectors": stats.cvss_vectors_assigned,
            "nvd_validated": stats.cvss_vectors_validated,
            "exploit_hits": stats.exploitdb_hits,
        }
    }


    if args.output:
        write_output(data=scan_result, file_path=args.output, pretty_print=args.pretty_print)

    if args.output_csv:
        export_to_csv(scan_result, args.output_csv, csv_sanitization=csv_sanitization_enabled)

    if args.pretty_print and not args.output:
        logger.print_info("Displaying results to console...")
        print(json.dumps(asdict(scan_result), indent=4))

    if kev_source or epss_source:
        print_summary_banner(scan_result, args.output if args.output else None, sources=sources)
    return 0



if __name__ == "__main__":
    start = time.time()
    rc = main(sys.argv[1:])
    total_runtime = time.time() - start
    print(f"Total runtime: {format_runtime(total_runtime)}")
    raise SystemExit(rc)
