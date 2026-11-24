#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
Generate a truly large Nessus XML file with aggressive multi-factor scaling.
Target: 50+ assets, 250k+ findings total.

Strategy: Clone report items within each host multiple times rather than
cloning entire hosts.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import copy
import sys


def scale_nessus_xml(template_path: str, output_path: str, target_total_findings: int = 250000):
    """
    Scale up a Nessus XML file by:
    1. Duplicating each host
    2. Duplicating report items within each host
    """
    
    print(f"[*] Loading template: {template_path}")
    tree = ET.parse(template_path)
    root = tree.getroot()
    
    # Handle namespace
    ET.register_namespace('', 'http://www.nessus.com/schema/v2')
    ns = {'nessus': 'http://www.nessus.com/schema/v2'}
    
    report = root.find('.//nessus:Report', ns) or root.find('.//Report')
    if report is None:
        print("[ERROR] Could not find Report element")
        return False
    
    # Count current content
    hosts = report.findall('nessus:ReportHost', ns) or report.findall('ReportHost')
    items_per_host = len(hosts[0].findall('nessus:ReportItem', ns) or hosts[0].findall('ReportItem')) if hosts else 0
    current_total = len(hosts) * items_per_host
    
    print(f"[*] Current: {len(hosts)} hosts × {items_per_host} items = {current_total} findings")
    print(f"[*] Target: {target_total_findings} findings")
    
    # Strategy: Duplicate findings within each host
    scale_factor = max(1, (target_total_findings + current_total - 1) // current_total)
    print(f"[*] Will scale items {scale_factor}x within each host")
    
    # For each host, duplicate its report items
    for host in hosts:
        items = host.findall('nessus:ReportItem', ns) or host.findall('ReportItem')
        items_to_add = []
        
        for dup_idx in range(scale_factor - 1):
            for item in items:
                # Deep copy and mutate plugin output or other fields to make unique
                new_item = copy.deepcopy(item)
                
                # Mutate a field to make it unique (e.g., plugin_output if it exists)
                plugin_output = new_item.find('nessus:plugin_output', ns) or new_item.find('plugin_output')
                if plugin_output is not None and plugin_output.text:
                    plugin_output.text += f" [VARIANT {dup_idx + 1}]"
                
                items_to_add.append(new_item)
        
        # Add all duplicated items
        for new_item in items_to_add:
            host.append(new_item)
    
    # Also duplicate hosts to get the asset count up
    # If we want many assets, clone the host list
    min_hosts_target = 50
    new_hosts_to_add = []
    
    if len(hosts) < min_hosts_target:
        clones_needed = min_hosts_target - len(hosts)
        for idx in range(clones_needed):
            original_host = hosts[0]  # Clone the first host
            new_host = copy.deepcopy(original_host)
            
            # Mutate the hostname to make it unique
            hostname_elem = new_host.find('nessus:HostName', ns) or new_host.find('HostName')
            if hostname_elem is not None:
                hostname_elem.text = f"asset-{len(hosts) + idx + 1:05d}.internal"
            
            # Mutate IP
            ip_elem = new_host.find('.//nessus:tag[@name="host-ip"]', ns)
            if ip_elem is None:
                ip_elem = new_host.find('.//tag[@name="host-ip"]')
            if ip_elem is not None:
                asset_id = len(hosts) + idx + 1
                octet = (asset_id % 254) + 1
                ip_elem.text = f"192.168.{(asset_id // 254) % 256}.{octet}"
            
            new_hosts_to_add.append(new_host)
    
    # Append new hosts
    for new_host in new_hosts_to_add:
        report.append(new_host)
    
    # Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    total_findings_final = (len(hosts) + len(new_hosts_to_add)) * (items_per_host * scale_factor)
    print(f"[*] Final: {len(hosts) + len(new_hosts_to_add)} hosts × {items_per_host * scale_factor} items = {total_findings_final} findings")
    print(f"[*] Writing to {output_file}...")
    
    tree.write(str(output_file), encoding='utf-8', xml_declaration=True)
    
    size_mb = output_file.stat().st_size / (1024 * 1024)
    print(f"[+] Success! Generated {size_mb:.2f} MB file with ~{total_findings_final} findings")
    
    return True


if __name__ == "__main__":
    template = "tests/regression_testing/nessus_xml/nessus_expanded_200.xml"
    output = "tests/regression_testing/nessus_xml/nessus_synthetic_massive_250k.xml"
    
    if scale_nessus_xml(template, output, target_total_findings=250000):
        print("[SUCCESS] Done!")
        sys.exit(0)
    else:
        print("[FAIL]")
        sys.exit(1)
