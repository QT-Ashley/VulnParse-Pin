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
import os
from vulnparse_pin.core.classes import ScoringPolicy
from vulnparse_pin.core.classes.ScoringPolicy import ScoringPolicyV1
from vulnparse_pin.core.classes.dataclass import FeedCachePolicy, FeedSpec, RunContext, ScanResult, Services
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.core.passes.ScoringPass import ScoringPass
from vulnparse_pin.utils.enricher import enrich_scan_results, load_epss, load_kev, update_enrichment_status
import argparse
import sys
from vulnparse_pin.utils.banner import print_banner
from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
from vulnparse_pin.utils.feed_cache import FeedCacheManager
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.parsers.__init__ import PARSER_SPECS
from vulnparse_pin.utils.exploit_enrichment_service import *
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.utils.validations import *
from vulnparse_pin.utils.nvdcacher import NVDFeedCache, nvd_policy_from_config
from vulnparse_pin.utils.enrichment_stats import stats
from vulnparse_pin.io.pfhandler import PathLike, PermFileHandler
from vulnparse_pin.utils.csv_exporter import export_to_csv
from vulnparse_pin.core.apppaths import AppPaths, ensure_user_configs, load_config
from vulnparse_pin import __version__

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_FEED = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_MIN_YEAR = 2002

def print_summary_banner(ctx: "RunContext", scan_result, output_file=None, sources=None):
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
    avg_risk_score = None # TODO: Wire up
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
    # print(f" Average Asset Risk Score         : {avg_risk_score:.2f}" if avg_risk_score > 0.0 else " Average Asset Risk Score         : Not Computed (Insufficient Scoring Inputs)")
    # if highest_risk_asset:
    #     print(f" Highest Risk Asset               : {highest_risk_asset.hostname} (Score: {highest_risk_asset.avg_risk_score:.2f})" if highest_risk_asset.avg_risk_score > 0.0 else f" Highest Risk Asset               : {highest_risk_asset.hostname} (Score: Not Computed (Insufficient Scoring Inputs))")
    # else:
    #     print(" Highest Risk Asset: N/A")
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

    ctx.logger.info(f"Assets Analyzed: {total_assets:,},"
                f"Findings Triaged: {total_findings:,},"
                # f"Average Risk Score: {avg_risk_score:.2f},"
                # f"Highest Risk Asset: {highest_risk_asset.hostname if highest_risk_asset else 'N/A'},"
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

def _require(condition: bool, msg: str) -> None:
    if not condition:
        raise ValueError(msg)

def write_output(ctx: "RunContext", data: Dict, file_path: PathLike, pretty_print=False):
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
            ctx.logger.print_info("Pretty-printing JSON - Standby...", label = "Output")
            try:
                json.dump(asdict(data), f, indent=4)
                ctx.logger.print_success(f"Parsed results are stored in: {file_path}", label = "Output")
            except Exception as e:
                ctx.logger.print_error(f"Error attempt to dump to JSON: {e}", label = "Output")
                sys.exit(1)
        else:
            try:
                ctx.logger.print_info("[*] Dumping JSON results...")
                json.dump(asdict(data), f)
                ctx.logger.print_success(f"JSON results available in: {file_path}", label = "Output")
            except Exception as e:
                ctx.logger.print_error(f"Error attempt to dump to JSON: {e}", label = "Output")
                ctx.logger.exception("Exception: %s", e)
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

def extract_cve_years(ctx: "RunContext", scan_result: ScanResult) -> set[int]:
    _CVE_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)
    years: set[int] = set()
    for asset in scan_result.assets:
        for f in asset.findings:
            for cve in (f.cves or []):
                m = _CVE_RE.match(str(cve).strip())
                if m:
                    years.add(int(m.group(1)))
    if (len(years) < 1):
        ctx.logger.debug("No CVEs could properly be extracted from the input file. Years is None; Years: %s", years, extra={"vp_label": "CVE Year Extraction"})
    else:
        ctx.logger.debug("Years seen: %s", years, extra={"vp_label": "CVE Year Extraction"})
    return years

def select_years(ctx: "RunContext", years_seen: set[int]) -> set[int]:
    normalized_years: set[int] = set()

    for y in years_seen:
        if y < NVD_MIN_YEAR:
            y = NVD_MIN_YEAR
            normalized_years.add(y)
        normalized_years.add(y)
    # dedup the years
    if normalized_years:
        ctx.logger.debug("Normalized years: %s", normalized_years, extra={"vp_label": "CVE Year Normalization"})
        return normalized_years
    else:
        raise RuntimeError("Unable to normalize years. Killswitching for failure mode.")

def load_score_policy(config: dict) -> ScoringPolicyV1:
    epss = config.get("epss", {})
    evp = config.get("evidence_points", {})
    bands = config.get("bands", {})
    agg = config.get("aggregation", {})
    weights = config.get("weights", {})
    risk_ceiling = config.get("risk_ceiling", {})

    return ScoringPolicyV1(
        epss_scale = float(epss.get("scale", 10.0)),
        epss_min = float(epss.get("min", 0.0)),
        epss_max = float(epss.get("max", 1.0)),
        kev_evd = float(evp.get("kev", 9.5)),
        exploit_evd = float(evp.get("exploit", 9.0)),
        band_critical = float(bands.get("critical", 8.9)),
        band_high = float(bands.get("high", 7.9)),
        band_medium = float(bands.get("medium", 4.0)),
        band_low = float(bands.get("low", 2.0)),
        asset_aggregation = str(agg.get("asset_score", "max")),
        w_epss_high = float(weights.get("epss_high", 2.0)),
        w_epss_medium = float(weights.get("epss_medium", 1.0)),
        w_kev = float(weights.get("kev", 1.25)),
        w_exploit = float(weights.get("exploit", 2)),
        max_raw_risk = float(risk_ceiling.get("max_raw_risk", 15)),
        max_op_risk = float(risk_ceiling.get("max_operational_risk", 10.0)),
    )

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
    parser.add_argument("--output", "-o", metavar="FILE", help="File to output results to. Output is in JSON")
    parser.add_argument("--pretty-print", "-pp", action="store_true", help="Output the JSON results with identation for readability to cli")
    parser.add_argument("--log-file", default="vulnparse_pin.log", help="Log File destination.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Sets Logging level for log.", type=valid_log_level)
    parser.add_argument("--version", "-v", help="Show program version and exit.", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--exploit-source", "-es", choices=['online', 'offline'], default='online', help="Select if you want to pull exploit dataset from an online or offline source.")
    parser.add_argument("--exploit-db", "-edb", type=str, help="Path to offline exploit database (CSV)")
    parser.add_argument("--enrich-exploit", "-ex", action="store_true", help="Enrich findings with exploit availability info.")
    parser.add_argument("--mode", choices=["online", "offline"], default="online", help="Set to 'offline' to disable epss and kev external enrichment requests and use local cache only.")
    parser.add_argument("--refresh-cache", action="store_true", help="Forces cache refesh for feeds.")
    parser.add_argument("--allow_regen", action="store_true", help="Allows regeneration of cache meta and checksum if missing using 'best-effort'. Default: True", default=True)
    parser.add_argument("--no-nvd", action="store_true", help="Disables NVD Enrichment module[No NVD enrichment processing]")
    parser.add_argument("--output-csv", type=str, metavar="PATH", help="Path to save enriched results in CSV format (optional)")
    parser.add_argument("--allow-large", action="store_true", help="Allow parsing very large reports (up to ~50GB). Use only for enterprise-scale or synthetic stress tests. Default: False")
    parser.add_argument("--no-csv-sanitize", action="store_true", help="Disable CSV cell sanitization (dangerous: may allow CSV formula injection in spreadsheet tools). Default: Off")
    parser.add_argument("--forbid-symlinks_read", "-fbsr", action="store_true", default=False, help="Disables following symlinks when resolving paths during read operations.")
    parser.add_argument("--forbid-symlinks_write", "-fbsw", action="store_true", default=True, help="Disables following symlinks when resolving paths during write operations.")
    parser.add_argument("--enforce-root-read", "-err", action="store_true", help="Enforces read operations only on files located within the list of acceptable roots.")
    parser.add_argument("--enforce-root-write", "-erw", action="store_true", default=True, help="Enforces write operations only on files located within the list of acceptable roots. Default: True")
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
    start_time = time.time()
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
    logger.print_info("Starting up VulnParse-Pin...", f"VulnParse-Pin {__version__}")

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
            paths.output_dir,
            ],
        max_log_path_chars = 25,
        hide_home = True,
        forbid_symlinks_read = args.forbid_symlinks_read,
        forbid_symlinks_write = args.forbid_symlinks_write,
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

    score_pol: ScoringPolicyV1 = load_score_policy(scoring_cfg)
    try:
        _require(score_pol.w_epss_high >= 0, "w_epss_high must be >= 0")
        _require(score_pol.w_epss_medium >= 0, "w_epss_medium must be >= 0")
        _require(score_pol.w_exploit >= 0, "w_exploit must be >= 0")
        _require(score_pol.w_kev >= 0, "w_kev must be >= 0")
        _require(score_pol.kev_evd >= 0, "kev_evd must be >= 0")
        _require(score_pol.exploit_evd >= 0, "exploit_evd must be >= 0")
        _require(score_pol.band_critical >= 0, "band_critical must be >= 0")
        _require(score_pol.band_high >= 0, "band_high must be >= 0")
        _require(score_pol.band_medium >= 0, "band_medium must be >= 0")
        _require(score_pol.band_low >= 0, "band_low must be >= 0")
        _require(score_pol.epss_scale > 0, "epss.scale must be > 0")
        _require(score_pol.band_critical > score_pol.band_high > score_pol.band_medium > score_pol.band_low >= 0, "Invalid band thresholds")
        _require(score_pol.w_epss_high >= score_pol.w_epss_medium >= 0, "Invalid EPSS weights: epss_high must be >= epss_medium")
    except ValueError as e:
        logger.print_error("Scoring config has invalid values.", label = "Scoring Config")
        raise RuntimeError(f"Scoring config has invalid values: {e}") from e

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
    if not args.no_nvd:
        nvd_cache = NVDFeedCache(ctx)
        nvd_status = "Enabled"
        nvdpol_start_y = cfg_yaml.get("feed_cache", {}).get("nvd", {}).get("start_year", (datetime.now().year - 1))
        nvdpol_end_y = cfg_yaml.get("feed_cache", {}).get("nvd", {}).get("end_year", datetime.now().year)
    else:
        nvd_cache = None
        nvd_status = "Disabled (--no-nvd)"
        logger.print_warning("NVD Cache is disabled. NVD data reconciliation will not be available during enrichment.")


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

    # Instantiate SchemaDetector
    detector = SchemaDetector(PARSER_SPECS)

    logger.phase("Initialization")
    logger.print_info(f'Using config: {cfg_yaml_path.name}', label="Global Config")
    logger.print_info(f'Using scoring config: {cfg_score_path.name}', label = "Scoring Weight Config")
    logger.debug("\n%s", pfh.describe_policy(), extra={"vp_label": "PFH Policy"})
    
    # Init PassRunner
    passesList = [
        ScoringPass(score_pol),
    ]
    passOrchestrator = PassRunner(passesList)

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
    logger.print_info(f"Loading file: {scanner_input.name}", label = "Target File")

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
    logger.phase("Normalization")
    logger.print_info("Scanning structure to determine the type of parser to use...", label="Normalization")
    scan_result = None
    try:
        det = detector.select(ctx, input_file)
        parser = det.parser_cls(ctx, input_file)
        scan_result = parser.parse()
        try:
            assert isinstance(scan_result, ScanResult)
        except (ValueError, TypeError) as exc:
            raise TypeError(f"Scan Object does is not of valid type(ScanResult), Trace: {exc}") from exc
    except Exception as e:
        logger.print_error(f"Error occured while trying to determine parser to use. Msg: {e}", label="Normalization")
        return sys.exit(1)

    logger.print_success(f"Parsed {len(scan_result.assets)} assets, {sum(len(a.findings) for a in scan_result.assets)} findings", label="Normalization")

    # Start enrichment pipeline
    print(" "*25 + "Threat Enrichment Feeds" + " "*25)
    logger.phase("Threat-Intel Enrichment Feeds")
    kev_data = None
    epss_data = None

    # Load Exploit-DB if flagged.
    exploit_data = None
    if args.enrich_exploit and args.exploit_source == "online":
        print("=" * 25 + "Exploit-DB" + "=" * 25)
        logger.print_info(f"Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{args.exploit_source.upper()}{Style.RESET_ALL} source...", label = "Exploit-DB Loader")

        exploit_data = load_exploit_data(ctx, source=args.exploit_source, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)
        logger.print_success(f"Loaded Exploit-DB data ({len(exploit_data)} CVEs with exploits)\n", label="Exploit-DB Loader")
    elif args.enrich_exploit and args.exploit_source == "offline":
        print("=" * 25 + "Exploit-DB" + "=" * 25)
        logger.print_info(f"Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{ctx.pfh.format_for_log(exploit_db)}{Style.RESET_ALL}...", label="Local Exploit-DB Cache")

        exploit_data = load_exploit_data(ctx, source=exploit_db, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)

        logger.print_success(f"Loaded Exploit-DB data ({len(exploit_data)} CVEs with expoits)", label="Exploit-DB Loader")


    # NVD

    if not args.no_nvd and cfg_yaml.get("feed_cache", {}).get("nvd").get("enabled"):
        if ctx.services.nvd_cache is not None:
            print("=" * 25 + "National Vulnerability Database (NVD)" + "=" * 25)
            nvd_policy = nvd_policy_from_config(cfg_yaml)
            logger.print_info(f"Policy: {nvd_policy}", label="NVD Cache Policy")
            years_seen = extract_cve_years(ctx, scan_result)
            normalized_years = select_years(ctx, years_seen)
            years_to_load = sorted(y for y in normalized_years if nvdpol_start_y <= y <= nvdpol_end_y)
            include_modified = any(y >= (nvdpol_end_y - 1) for y in years_to_load)
            if not years_to_load:
                ctx.logger.print_info("NVD Enabled, but no CVEs in configured year range; skipping NVD index build.", label = "NVD Cache Loader")
                nvd_status = "Enabled (Skipped)"
            else:
                # Initialize NVD if enabled
                t0 = time.perf_counter()
                ctx.logger.debug("Years seen during normalization: %s, Years Normalized: %s Years Selected: %s", years_seen, normalized_years, years_to_load, extra={"vp_label": "NVD Cache Loader"})
                ctx.services.nvd_cache.refresh(
                    config=cfg_yaml,
                    feed_cache=feed_cache,
                    refresh_cache=args.refresh_cache,
                    offline=(args.mode == "offline"),
                    years=years_to_load,
                    include_modified=include_modified,
                    )
                t1 = time.perf_counter()
                logger.debug(f"NVD Load time: {(t1 - t0)}", extra={"vp_label": "Performance"})
        else:
            raise ValueError("NVD Enrichment is enabled but no O1 Lookup exists. Check flags and try again.")

    # 1 Load enrichment data sources
    if kev_source:
        print("=" * 25 + "CISA Known Exploited Vulnerabilities (KEV)" + "=" * 25)
        kev_data = load_kev(ctx, path_url=kev_source, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)

    if epss_source:
        print("=" * 25 + "FIRST Exploit Prediction Scoring System (EPSS)" + "=" * 25)
        epss_data = load_epss(ctx, path_url=epss_source, force_refresh=args.refresh_cache, allow_regen=args.allow_regen)


    # 2 Apply exploit enrichments
    logger.phase("Exploit Enrichment")
    if args.enrich_exploit and exploit_data:
        print("="*25 + "Exploit Enrichment Results" + "="*25)
        for asset in scan_result.assets:
            enriched_findings = enrich_exploit_availability(ctx, asset.findings, exploit_data)
            asset.findings = enriched_findings
        logger.print_success("Exploit enrichment applied to findings.", label = "Enrichment")

    # 3 Apply heuristic tagging *before* enrichment and risk scoring
    for asset in scan_result.assets:
        for finding in asset.findings:
            apply_heuristic_exploit_tag(ctx, finding)

    # 4 Apply enrichments
    logger.phase("Enrichment Pipeline")
    if kev_data or epss_data and (args.enrich_kev or args.enrich_epss):
        print(" "*25 + "Enrichment Pipeline" + " "*25)
        enrich_scan_results(ctx, scan_result, kev_data, epss_data, offline_mode=args.mode == "offline", score_cfg=scoring_cfg, nvd_cache=nvd_cache)
        logger.print_success("All enrichments Applied") #TODO: Move scoring cfg out


    # 5 Passes
    # Scoring Pass
    scan_result = passOrchestrator.run_all(ctx = ctx, scan = scan_result)

    # 6 Do Post-Processing enrichment status update.
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

    if args.output or args.output_csv:
        logger.phase("Output")
        print("="*25 + "Output" + "="*25)

    if args.output:
        write_output(ctx, data=scan_result, file_path=args.output, pretty_print=args.pretty_print)

    if args.output_csv:
        export_to_csv(scan_result, args.output_csv, csv_sanitization=csv_sanitization_enabled)

    if args.pretty_print and not args.output:
        logger.print_info("Displaying results to console...")
        print(json.dumps(asdict(scan_result), indent=4))

    if kev_source or epss_source:
        logger.phase("Summary")
        print_summary_banner(ctx, scan_result, args.output if args.output else None, sources=sources)
    total_runtime = time.time() - start_time
    print(f"Total runtime: {format_runtime(total_runtime)}")
    return 0



if __name__ == "__main__":
    rc = main(sys.argv[1:])
    raise SystemExit(rc)
