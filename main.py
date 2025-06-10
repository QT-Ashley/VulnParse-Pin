import json
from parsers.nessus_parser import NessusParser
from dataclasses import asdict
from utils.enricher import enrich_scan_results, load_epss_from_csv, load_kev_from_json
from pprint import pprint
import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser(description="VulnParse-Pin: Vulnerability triage tool", usage="%(prog)s -f file [options]")
    
    parser.add_argument("--file", "-f", help="Path to vulnerability scan file", required=True)
    
    parser.add_argument("--enrich-kev", nargs="?", const="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", help="Path/URL to CISA KEV JSON or JSON.gz file. If omitted, uses official CISA KEV feed.")
    
    parser.add_argument("--enrich-epss", nargs="?", const="https://epss.cyentia.com/epss_scores-current.csv.gz", help="Path/URL to EPSS CSV or CSV.gz file. If omitted, use official EPSS feed.")
    
    parser.add_argument("--output", "-o", metavar="FILE", help="File to output results to. Default is JSON")
    # TODO: More args to come
    return parser.parse_args()

def main():
    args = parse_args()
    
    print("[!] Starting up VulnParse-Pin... - Developer: QTShade")
    print(f"Loading file: {args.file}")
    
    # Load JSON report
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            report_json = json.load(f)
    except Exception as e:
        print(f"[!] Error loading file: {e}")
        sys.exit(1)
        
    # Available parsers
    parsers = [NessusParser()]
    
    parser_used = None
    for parser in parsers:
        if parser.detect(report_json):
            parser_used = parser
            break
    
    if not parser_used:
        print("[!] No compatible parsed found for this file.")
        sys.exit(1)
        
    print(f"[+] Detected parser for JSON structure: {parser_used.__class__.__name__}")
    scan_result = parser_used.parse(report_json)
    
    
    kev_data = None
    epss_data = None
    
    if args.enrich_kev:
        print(f"[+] Loading CISA KEV data from {args.enrich_kev}")
        kev_data = load_kev_from_json(args.enrich_kev)
        
    if args.enrich_epss:
        print(f"[+] Loading EPSS data from {args.enrich_epss}")
        epss_data = load_epss_from_csv(args.enrich_epss)
        
    # Apply enrichments
    if kev_data or epss_data:
        enrich_scan_results(scan_result, kev_data, epss_data)
        print(f"[+] Applied enrichments.")
        
    print(f"[+] Parsed {len(scan_result.assets)} assets, {sum(len(a.findings) for a in scan_result.assets)} findings")
        
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as out_file:
                json.dump(asdict(scan_result), out_file, indent=4)
        except Exception as e:
            print(f"Error attempting to dump json to {args.output}: {e}")
    else:
        pprint(json.dumps(asdict(scan_result), indent=4))
            
if __name__ == "__main__":
    main()

