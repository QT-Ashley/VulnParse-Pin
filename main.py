import json
import time
from parsers.nessus_parser import NessusParser
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

def print_summary_banner(scan_result, output_file=None):
    '''
    Prints a formatted summary banner with key metrics from the scan result.
    
    Args:
        scan_result (ScanResult): The final processed scan results.
        output_file (str, optional): The path to the output JSON file.
        
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
    print("🛡️                  VulnParse-Pin Scan Summary             🛡️")
    print("="*60)
    print(f" Total Assets Analyzed            : {total_assets}")
    print(f" Total Findings Triaged           : {total_findings}")
    print(f" Average Asset Risk Score         : {avg_risk_score}")
    if highest_risk_asset:
        print(f" Highest Risk Asset               : {highest_risk_asset.hostname} (Score: {highest_risk_asset.avg_risk_score})")
    else:
        print(" Highest Risk Asset: N/A")
    print(f"💣 Findings with Known Exploits   : {exploit_findings}")
    print(f"🔥 Critical+ Risk Findings        : {critical_findings}")
    print(f"⚠️  High Risk Findings             : {high_findings}")
    print(f"🟡 Medium Risk Findings           : {medium_findings}")
    print(f"🟢 Low Risk Findings              : {low_findings}")
    print(f"📊 Enriched Findings              : {enriched_findings}")
    if output_file:
        print(f"📁 Output Location                : {output_file}")
    print("="*60 + "\n")
    log.log.logger.info(f"Assets Analyzed: {total_assets}," 
                f"Findings Triaged: {total_findings}," 
                f"Average Risk Score: {avg_risk_score},"
                f"Highest Risk Asset: {highest_risk_asset.hostname if highest_risk_asset else 'N/A'},"
                f"Critical+: {critical_findings}, High: {high_findings}, Medium: {medium_findings}, Low: {low_findings}"
                )

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
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Sets Logging level for log.", type=valid_log_level)
    parser.add_argument("--version", "-v", action="version", version="VulnParse-Pin v1.0", help="Show program version and exit.")
    parser.add_argument("--exploit-source", "-es", choices=['online', 'offline'], default='online', help="Select if you want to pull exploit dataset from an online or offline source.")
    parser.add_argument("--exploit-db", "-edb", type=str, default=DEFAULT_LOCAL_PATH, help="Path to offline exploit database (CSV)")
    parser.add_argument("--enrich-exploit", "-ex", action="store_true", help="Enrich findings with exploit availability info.")
    parser.add_argument("--mode", choices=["online", "offline"], default="online", help="Set to 'offline' to disable epss and kev external enrichment requests and use local cache only.")
    
    args = parser.parse_args()
    
    
    if args.output:
        output_dir = os.path.dirname(os.path.abspath(args.output)) or '.'
        if not os.access(output_dir, os.W_OK):
            parser.error(f"Output director '{output_dir}' is not writable.")
        
    return args
                

def main():
    print_banner()
    
    args = get_args()
    log.log = LoggerWrapper(args.log_file, args.log_level)
    
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
    
    # Check and validate json structure.
    validator = FileInputValidator(args.file)
    try:
        report_json = validator.validate()
    except Exception:
        sys.exit(1)
    
        
    # Available parsers
    parsers = [NessusParser(), OpenVASParser()] #TODO: Extend Parser classes
    
    log.log.print_info("Scanning JSON structure to determine the type of parser to use...")
    parser_used = None
    for parser in parsers:
        if parser.detect(report_json):
            parser_used = parser
            break
    
    if not parser_used:
        log.log.print_error("No compatible parsed found for this file.")
        sys.exit(1)
        
    log.log.print_success(f"Detected parser for JSON structure: {Fore.LIGHTMAGENTA_EX}{parser_used.__class__.__name__}{Style.RESET_ALL}")
    scan_result = parser_used.parse(report_json)
    
    
    kev_data = None
    epss_data = None
    
    # Load Exploit-DB if flagged.
    exploit_data = None
    if args.enrich_exploit:
        print()
        log.log.print_info(f"{Fore.LIGHTGREEN_EX}[Enrich-Exploit]{Style.RESET_ALL}Loading Exploit-DB data from {Fore.LIGHTYELLOW_EX}{args.exploit_source.upper()}{Style.RESET_ALL} source...")
        exploit_data = load_exploit_data(args.exploit_source, args.exploit_db)
        log.log.print_success(f"{Fore.LIGHTGREEN_EX}[Enrich-Exploit]{Style.RESET_ALL}Loaded Exploit-DB data ({len(exploit_data)} CVEs with exploits)\n")
        
    log.log.print_success(f"Parsed {len(scan_result.assets)} assets, {sum(len(a.findings) for a in scan_result.assets)} findings")
    
    # 1 Load enrichment data sources
    if kev_source:
        log.log.print_info(f"Loading CISA KEV data from {Fore.LIGHTYELLOW_EX}{kev_source}{Style.RESET_ALL}")
        kev_data = load_kev_from_json(kev_source)
        log.log.print_success(f"Loaded CISA KEV data from {Fore.LIGHTYELLOW_EX}{kev_source}{Style.RESET_ALL}")
        
    if epss_source:
        log.log.print_info(f"Loading EPSS data from {Fore.LIGHTYELLOW_EX}{epss_source}{Style.RESET_ALL}")
        epss_data = load_epss_from_csv(epss_source)
        log.log.print_success(f"Loaded EPSS data from {Fore.LIGHTYELLOW_EX}{epss_source}{Style.RESET_ALL}\n" + "="*25 + "Exploit Enrichment Results" + "="*25)
        
    # 2 Apply exploit enrichments
    if args.enrich_exploit and exploit_data:
        for asset in scan_result.assets:
            enriched_findings = enrich_exploit_availability(asset.findings, exploit_data)
            asset.findings = enriched_findings
        log.log.print_success(f"{Fore.LIGHTGREEN_EX}[Enrich-Exploit]{Style.RESET_ALL}Exploit enrichment applied to findings.\n" + "="*25 + "Enrichment Processing" + "="*25)
    
    # 3 Apply heuristic tagging *before* enrichment and risk scoring
    for asset in scan_result.assets:
        for finding in asset.findings:
            apply_heuristic_exploit_tag(finding)
    
    # 4 Apply enrichments
    if kev_data or epss_data:
        enrich_scan_results(scan_result, kev_data, epss_data, offline_mode=args.mode == "offline")
        log.log.print_success(f"Enrichments Applied")
    
    # 5 Do Post-Processing enrichment status update.
    for asset in scan_result.assets:
        for finding in asset.findings:
            update_enrichment_status(finding)
    
        
    if args.output:
        write_output(data=scan_result, file_path=args.output, pretty_print=args.pretty_print)
        
    if args.pretty_print and not args.output:
        log.log.print_info("Displaying results to console...")
        print(json.dumps(asdict(scan_result), indent=4))
        
    if kev_source or epss_source:
        print_summary_banner(scan_result, args.output if args.output else None)

                
            
if __name__ == "__main__":
    start = time.time()
    main()
    print(f"Total runtime: {(time.time() - start):.2f} seconds")
 