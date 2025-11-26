from datetime import datetime
from http.client import FAILED_DEPENDENCY
import json
from pathlib import Path
import time
from dataclasses import asdict
from utils.enricher import enrich_scan_results, load_epss_from_csv, load_kev_from_json, update_enrichment_status
import argparse
import sys
from utils.banner import print_banner
from utils.exploit_enrichment_service import DEFAULT_LOCAL_PATH, load_exploit_data
from utils.logger import *
import utils.logger_instance as log
import os
from parsers.__init__ import *
from utils.exploit_enrichment_service import *
from utils.validations import *
from utils.nvdcacher import NVDCache
from utils.enrichment_stats import stats
from utils.config_loader import load_config

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
        
        stats = sources.get("stats", {})
        if stats:
            kev_hits = stats.get("kev_hits", 0)
            kev_total = stats.get("kev_total", 0)
            epss_hits = stats.get("epss_hits", 0)
            epss_total = stats.get("epss_total", 0)
            nvd_vectors = stats.get("nvd_vectors", 0)
            nvd_validated = stats.get("nvd_validated", 0)
            exploit_hits = stats.get("exploit_hits", 0)
            
            kev_pct = (kev_hits / kev_total * 100) if kev_total else 0.0
            epss_pct = (epss_hits / epss_total * 100 if epss_total else 0.0)
            
            print(f"🔑    KEV Hits                    : {kev_hits:,}/{kev_total:,} ({kev_pct:.2f}%)")
            print(f"📈    EPSS Coverage               : {epss_hits:,}/{epss_total:,} ({epss_pct:.2f}%)")
            print(f"📊    CVSS Vectors (Scanner/NVD)  : {nvd_vectors:,} assigned, {nvd_validated:,} validated")
            print(f"💣    Exploit-DB Hits             : {exploit_hits:,}")
        
    print("="*60 + "\n")
        
    log.log.logger.info(f"Assets Analyzed: {total_assets}," 
                f"Findings Triaged: {total_findings}," 
                f"Average Risk Score: {avg_risk_score},"
                f"Highest Risk Asset: {highest_risk_asset.hostname if highest_risk_asset else 'N/A'},"
                f"Critical+: {critical_findings}, High: {high_findings}, Medium: {medium_findings}, Low: {low_findings}"
                )

def format_runtime(seconds: float) -> str:
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes > 0:
        return f"{minutes}m {secs:.2f}s"
    else:
        return f"{secs:2f}s"
    
def build_run_log(input_path: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(input_path).stem
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / f"vulnparse-{stem}-{ts}.log"

def write_output(data, file_path, pretty_print=False):
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
            log.log.print_info(f"Pretty-printing JSON - Standby...")
            try:
                json.dump(asdict(data), f, indent=4)
                log.log.print_success(f"Parsed results are stored in: {file_path}")
            except Exception as e:
                log.log.print_error(f"Error attempt to dump to JSON: {e}")
                sys.exit(1)
        else:
            try:
                log.log.print_info(f"[*] Dumping JSON results...")
                json.dump(asdict(data), f)
                log.log.print_success(f"JSON results available in: {file_path}")
            except Exception as e:
                log.log.print_error(f"Error attempt to dump to JSON: {e}")
                log.logger.exception(f"Exception: {e}")
                sys.exit(1)
                
def valid_input_file(path):
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"File: '{path}' does not exist or is not a file.")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"File: '{path}' is not readable.")
    return path

def valid_log_level(level):
    levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    lvl = level.upper()
    if lvl not in levels:
        raise argparse.ArgumentTypeError(f"Invalid log level '{level}. Choce from {levels}.")
    return lvl

def detect_parser(filepath: str):
    """
    Detects and instanties the correct parser for the given file.
    Uses detect_file() for lightweight header sniffing.
    """
    for parser_cls in parsers:
        if parser_cls.detect_file(filepath):
            log.log.print_success(f"Detected parser for structure: {Fore.LIGHTMAGENTA_EX}{parser_cls.__name__}{Style.RESET_ALL}")
            return parser_cls(filepath)
    
    raise ValueError(f"No parser found for {filepath}")

def load_and_parse(filepath: str):
    """
    Detect parser, parse the file, and return ScanResult object.
    """
    parser = detect_parser(filepath)
    if parser:
        return parser.parse()
    else:
        log.log.print_error(f"Failure attemping to parse {filepath}")
    
def get_args():
    parser = argparse.ArgumentParser(
        description="VulnParse-Pin: Enrich, prioritize, and triage vulnerability scan results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--file", "-f", help="Path to vulnerability scan file", required=True, type=valid_input_file)
    parser.add_argument("--enrich-kev", nargs="?", help="Path/URL to CISA KEV JSON or JSON.gz file. If omitted, uses official CISA KEV feed.")
    parser.add_argument("--enrich-epss", nargs="?", help="Path/URL to EPSS .csv or CSV.gz file. If omitted, use official EPSS feed.")
    parser.add_argument("--output", "-o", metavar="FILE", help="File to output results to. Default is JSON")
    parser.add_argument("--pretty-print", "-pp", action="store_true", help="Output the JSON results with identation for readability to cli")
    parser.add_argument("--log-file", default="vulnparse_pin.log", help="Log File destination.")
    parser.add_argument("--log-level", default="DEBUG", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Sets Logging level for log.", type=valid_log_level)
    parser.add_argument("--version", "-v", action="version", version="VulnParse-Pin v1.0RC", help="Show program version and exit.")
    parser.add_argument("--exploit-source", "-es", choices=['online', 'offline'], default='online', help="Select if you want to pull exploit dataset from an online or offline source.")
    parser.add_argument("--exploit-db", "-edb", type=str, default=DEFAULT_LOCAL_PATH, help="Path to offline exploit database (CSV)")
    parser.add_argument("--enrich-exploit", "-ex", action="store_true", help="Enrich findings with exploit availability info.")
    parser.add_argument("--mode", choices=["online", "offline"], default="online", help="Set to 'offline' to disable epss and kev external enrichment requests and use local cache only.")
    parser.add_argument("--refresh-cache", action="store_true", help="Forces cache refesh for feeds.")
    parser.add_argument("--no-nvd", action="store_true", help="Disables NVD Enrichment module[No NVD enrichment processing]")
    parser.add_argument("--output-csv", type=str, metavar="PATH TO SAVE CSV FILE", help="Path to save enriched results in CSV format (optional)")
    parser.add_argument("--allow-large", action="store_true", help="Allow parsing very large reports (up to ~50GB). Use only for enterprise-scale or synthetic stress tests.")
    parser.add_argument("--no-csv-sanitize", action="store_true", help="Disable CSV cell sanitization (dangerous: may allow CSV formula injection in spreadsheet tools)")
    
    args = parser.parse_args()
    
    
    if args.output:
        output_dir = os.path.dirname(os.path.abspath(args.output)) or '.'
        if not os.access(output_dir, os.W_OK):
            parser.error(f"Output directory '{output_dir}' is not writable.")
        
    return args
       

def main():
    print_banner()
    
    args = get_args()
    
    # Init Logs
    log_path = build_run_log(args.file)
    
    log.log = LoggerWrapper(str(log_path), args.log_level)
    
    # Load config 
    config = load_config("config.yaml")
    
    # CSV Sanitization INIT
    csv_sanitization_enabled = not args.no_csv_sanitize
    if not csv_sanitization_enabled:
        while True:
            log.log.print_warning(f"{Fore.LIGHTRED_EX}[DANGEROUS_ACTION]{Style.RESET_ALL}"
                                  f"CSV Cell Sanitization has been disabled. This presents a {Fore.LIGHTRED_EX}MAJOR injection vulnerability in spreadsheet tools when opening this CSV.{Style.RESET_ALL}")
            warn = input("Are you sure you want to proceed? Yes/No: ").strip().lower()
            
            if warn in ("yes", "y"):
                log.log.print_success(f"{Fore.LIGHTRED_EX}[DANGEROUS_ACTION]{Style.RESET_ALL} "
                                      "Running with CSV cell sanitization OFF. This action will be logged.")
                break
            elif warn in ("no", "n"):
                log.log.print_info(f"{Fore.LIGHTRED_EX}[DANGEROUS_ACTION]{Style.RESET_ALL} "
                                   "Aborting at user request.")
                sys.exit(0)
            else:
                log.log.print_info("Please answer 'yes' or 'no'.")
    else:
        log.log.print_info(f"Sanitization is enabled: dangerous prefixes (=, +, -, @) will be escaped to prevent CSV formula injection.", label="[CSV-Sanitization]")
                    
    
    # Resolve feed sources.
    def resolve_feed_path(arg_val, offline_mode: bool, default_online: str, default_offline: str):
        if arg_val:
            return arg_val
        elif offline_mode:
            return default_offline
        else:
            return default_online
    
    kev_source = resolve_feed_path(
        arg_val=args.enrich_kev,
        offline_mode=args.mode == "offline",
        default_online="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        default_offline="./data/kev_cache.json"
    )
    epss_source = resolve_feed_path(
        arg_val=args.enrich_epss,
        offline_mode=args.mode == "offline",
        default_online="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        default_offline="./data/epss_cache.csv.gz"
    )
    
    
    if args.mode == "offline":
        log.log.print_info("[*] Offline mode enabled. Enrichment will use local cache only.\n")
        if not os.path.exists(kev_source):
            log.log.print_error(f"[OFFLINE] KEV cache not found: {kev_source}")
            raise FileNotFoundError(f"Missing KEV cache.")
        if not os.path.exists(epss_source):
            log.log.print_error(f"[OFFLINE] EPSS cache not found: {epss_source}")
            raise FileNotFoundError(f"Missing EPSS cache.")
        
        
    
    if args.exploit_source == "offline":
        if not os.path.isfile(args.exploit_db):
            log.log.print_error(f"Exploit database file not found at: {args.exploit_db}")
            sys.exit(1)
        if not os.access(args.exploit_db, os.R_OK):
            log.log.print_error(f"Exploit database file is not readable: {args.exploit_db}")
            sys.exit(1)
    
    
    
    log.log.print_info("Starting up VulnParse-Pin...")
    log.log.print_info(f"Loading file: {args.file}")
    
    input_file = args.file
    
    # If JSON - Check and validate json structure.
    if input_file.endswith(".json"):
        validator = FileInputValidator(input_file, allow_large=args.allow_large)
        try:
            input_file = validator.validate()
        except Exception:
            sys.exit(1)
    
        
    # Available parsers
    #NessusParser(), OpenVASParser(), NessusXMLParser(), OpenVASMXLParser()] #TODO: Extend Parser classes
    # Detect parser class, initialize, and parse.
    log.log.print_info("Scanning structure to determine the type of parser to use...")
    scan_result = None
    try:
        scan_result = load_and_parse(input_file)
    except Exception as e:
        log.log.print_error(f"Error occured while trying to determine parser to use. Msg: {e}")
    
    log.log.print_success(f"Parsed {len(scan_result.assets)} assets, {sum(len(a.findings) for a in scan_result.assets)} findings")
    
    # Start enrichment pipeline
    
    kev_data = None
    epss_data = None
    feed_cfg = config.get("feed_cache", {})
    
    # Load Exploit-DB if flagged.
    exploit_data = None
    if args.enrich_exploit:
        print()
        log.log.print_info(f"{Fore.LIGHTBLUE_EX}[Enrich-Exploit]{Style.RESET_ALL} Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{args.exploit_source.upper()}{Style.RESET_ALL} source...")
        exploit_data = load_exploit_data(args.exploit_source, args.exploit_db, feed_cache=feed_cfg, force_refresh=args.refresh_cache)
        log.log.print_success(f"{Fore.LIGHTBLUE_EX}[Enrich-Exploit]{Style.RESET_ALL} Loaded Exploit-DB data ({len(exploit_data)} CVEs with exploits)\n")
        
    
    # Load nvd config file
    nvd_cfg = config.get("nvd", {})
    
    if not args.no_nvd and nvd_cfg.get("enabled", True):
        start_year = nvd_cfg.get("start_year", 2017)
        end_year = nvd_cfg.get("end_year", datetime.now().year)
        years = list(range(start_year, end_year + 1))
        
        refresh_days = nvd_cfg.get("refresh_interval_days", 1)
        
        log.log.print_info(f"{Fore.LIGHTYELLOW_EX}[NVD Cache]{Style.RESET_ALL} Initializing NVD Cache for {start_year}-{end_year}...")
        nvd_cache = NVDCache(cache_dir="./nvd_cache", refresh_days=refresh_days, offline=(args.mode == "offline"))
        nvd_cache.refresh(years=years) # skips download if offline
        log.log.print_success("NVD Cache ready.")
        
        nvd_status = f"✅ (feeds {start_year}–{end_year}, modified)"
    elif args.no_nvd:
        nvd_cache = None
        nvd_status = "Disabled (--no-nvd)"
        log.log.print_info("[NVD Cache] Disabled via --no-nvd flag. Skipping NVD enrichment per user flag.")
    else:
        nvd_cache = None
        nvd_status = "Disabled (config)"
        log.log.print_info("[NVD Cache] Disabled via config.")
    
    # 1 Load enrichment data sources
    if kev_source:
        kev_data = load_kev_from_json(kev_source, feed_cache=feed_cfg, force_refresh=args.refresh_cache)
        
    if epss_source:
        epss_data = load_epss_from_csv(epss_source, feed_cache=feed_cfg, force_refresh=args.refresh_cache)
        print(f"="*25 + "Exploit Enrichment Results" + "="*25)
        
        
    # 2 Apply exploit enrichments
    if args.enrich_exploit and exploit_data:
        for asset in scan_result.assets:
            enriched_findings = enrich_exploit_availability(asset.findings, exploit_data)
            asset.findings = enriched_findings
        log.log.print_success(f"{Fore.LIGHTBLUE_EX}[Enrich-Exploit]{Style.RESET_ALL}Exploit enrichment applied to findings.\n" + "="*25 + "Enrichment Processing" + "="*25)
    
    # 3 Apply heuristic tagging *before* enrichment and risk scoring
    for asset in scan_result.assets:
        for finding in asset.findings:
            apply_heuristic_exploit_tag(finding)
    
    # 4 Apply enrichments
    if kev_data or epss_data:
        enrich_scan_results(scan_result, kev_data, epss_data, offline_mode=args.mode == "offline", nvd_cache=nvd_cache)
        log.log.print_success(f"Enrichments Applied")
    
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
        from utils.csv_exporter import export_to_csv
        export_to_csv(scan_result, args.output_csv, csv_sanitization=csv_sanitization_enabled)
        
    if args.pretty_print and not args.output:
        log.log.print_info("Displaying results to console...")
        print(json.dumps(asdict(scan_result), indent=4))
        
    if kev_source or epss_source:
        print_summary_banner(scan_result, args.output if args.output else None, sources=sources)

                
            
if __name__ == "__main__":
    start = time.time()
    main()
    total_runtime = (time.time() - start)
    print(f"Total runtime: {format_runtime(total_runtime)}")
 