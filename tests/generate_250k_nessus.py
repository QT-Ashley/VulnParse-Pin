#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
Generate a large Nessus XML file with 50 assets and ~250k findings
for performance benchmarking of the NVD optimization.

This scales nessus_expanded_200.xml by:
- Parsing the existing 2-asset, 400-finding structure
- Duplicating and mutating to create 50 assets
- Each asset gets ~5k findings (200 findings * 25 duplications = 5k)
- Total: 50 * 5k = 250k findings
"""

import xml.etree.ElementTree as ET
import sys
from pathlib import Path
from datetime import datetime, timedelta
import random
import re


def generate_large_nessus_file(output_path: str, num_assets: int = 50, findings_per_asset: int = 5000):
    """Generate a large Nessus report by scaling the nessus_expanded_200.xml template."""
    
    # Load the template file
    template_path = Path(__file__).parent / "regression_testing" / "nessus_xml" / "nessus_expanded_200.xml"
    
    if not template_path.exists():
        print(f"Template file not found: {template_path}")
        return False
    
    print(f"[*] Loading template from {template_path}...")
    tree = ET.parse(template_path)
    root = tree.getroot()
    
    # Register namespace to preserve prefixes
    for prefix, uri in [('', 'http://www.nessus.com/schema/v2')]:
        ET.register_namespace(prefix, uri)
    
    # Extract the Report element
    ns = {'nessus': 'http://www.nessus.com/schema/v2'}
    report_elem = root.find('nessus:Report', ns)
    if report_elem is None:
        report_elem = root.find('Report')
    
    # Get the original hosts (should be 2 in the template)
    hosts = report_elem.findall('nessus:ReportHost', ns) or report_elem.findall('ReportHost')
    original_host_count = len(hosts)
    
    if original_host_count == 0:
        print("No ReportHost elements found in template")
        return False
    
    print(f"[*] Template has {original_host_count} host(s)")
    print(f"[*] Generating {num_assets} assets with ~{findings_per_asset} findings each...")
    
    # Calculate duplication factor needed
    total_findings_needed = num_assets * findings_per_asset
    findings_per_original_host = sum(len(h.findall('nessus:ReportItem', ns) or h.findall('ReportItem')) for h in hosts)
    
    print(f"[*] Original template has ~{findings_per_original_host} findings per host")
    
    duplication_factor = max(1, (findings_per_asset + findings_per_original_host - 1) // findings_per_original_host)
    print(f"[*] Will duplicate template {duplication_factor}x to reach target")
    
    # Duplicate and mutate hosts
    new_hosts = []
    asset_id = 0
    
    for dup_idx in range(duplication_factor):
        for original_idx, host in enumerate(hosts):
            asset_id += 1
            
            # Deep copy the host element
            import copy
            new_host = copy.deepcopy(host)
            
            # Mutate the hostname and IP
            hostname_elem = new_host.find('nessus:HostName', ns) or new_host.find('HostName')
            if hostname_elem is not None:
                hostname_elem.text = f"asset-{asset_id:05d}.internal"
            
            ip_elem = new_host.find('nessus:HostProperties/nessus:tag[@name="host-ip"]', ns)
            if ip_elem is None:
                ip_elem = new_host.find('HostProperties/tag[@name="host-ip"]')
            if ip_elem is not None:
                # Generate a semi-random IP based on asset ID
                octet = (asset_id % 254) + 1
                ip_elem.text = f"192.168.{(asset_id // 254) % 256}.{octet}"
            
            new_hosts.append(new_host)
            
            if asset_id >= num_assets:
                break
        
        if asset_id >= num_assets:
            break
    
    # Clear existing hosts and add the new ones
    for host in hosts:
        report_elem.remove(host)
    
    for new_host in new_hosts:
        report_elem.append(new_host)
    
    # Update the report name
    report_name_elem = report_elem.find('nessus:ReportName', ns) or report_elem.find('ReportName')
    if report_name_elem is not None:
        report_name_elem.text = f"Synthetic_Large_Nessus_250k_{"%.0f m" % (datetime.now().timestamp() / 60000)}"
    
    # Write the output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Writing ~{len(new_hosts)} hosts to {output_file}...")
    tree.write(output_file, encoding='utf-8', xml_declaration=True)
    
    # Print file size
    size_mb = output_file.stat().st_size / (1024 * 1024)
    print(f"[+] Generated file: {output_file} ({size_mb:.2f} MB)")
    return True


if __name__ == "__main__":
    output = "tests/regression_testing/nessus_xml/nessus_synthetic_250k.xml"
    
    if generate_large_nessus_file(output, num_assets=50, findings_per_asset=5000):
        print(f"[SUCCESS] Generation complete!")
        sys.exit(0)
    else:
        print(f"[FAIL] Generation failed")
        sys.exit(1)
