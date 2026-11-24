#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
Generate a moderately large Nessus XML with 50k findings that's valid and parseable.
Strategy: Clone full hosts rather than duplicating items within, to preserve structure.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import copy
import sys


def scale_nessus_safe(template_path: str, output_path: str, target_findings: int = 50000):
    """Safe scaling by duplicating entire hosts with valid structure."""
    
    print(f"[*] Loading template: {template_path}")
    tree = ET.parse(template_path)
    root = tree.getroot()
    
    # Namespace handling
    for event, elem in ET.iterparse(template_path, events=['start-ns']):
        prefix, uri = event if isinstance(event, tuple) else ('', '')
        if uri:
            ET.register_namespace(prefix, uri)
    
    tree = ET.parse(template_path)  # Reload after registration
    root = tree.getroot()
    
    ns = {'nessus': 'http://www.nessus.com/schema/v2'}
    report = root.find('.//nessus:Report', ns) or root.find('.//Report')
    
    if report is None:
        print("[ERROR] No Report element")
        return False
    
    # Get original hosts
    hosts = list(report.findall('nessus:ReportHost', ns) or report.findall('ReportHost'))
    if not hosts:
        print("[ERROR] No hosts")
        return False
    
    findings_per_host = len(hosts[0].findall('.//nessus:ReportItem', ns) or hosts[0].findall('.//ReportItem'))
    current_total = len(hosts) * findings_per_host
    
    print(f"[*] Template: {len(hosts)} hosts × {findings_per_host} items = {current_total} findings")
    print(f"[*] Target: {target_findings} findings")
    
    # Calculate how many host clones needed
    hosts_needed = max(len(hosts), (target_findings + findings_per_host - 1) // findings_per_host)
    clones_to_add = hosts_needed - len(hosts)
    
    print(f"[*] Need {hosts_needed} total hosts; will add {clones_to_add} clones")
    
    # Clone hosts
    for clone_idx in range(clones_to_add):
        template_host = hosts[clone_idx % len(hosts)]
        new_host = copy.deepcopy(template_host)
        
        # Mutate hostname and IP
        host_id = len(hosts) + clone_idx + 1
        
        hostname_elem = new_host.find('nessus:HostName', ns) or new_host.find('HostName')
        if hostname_elem is not None:
            hostname_elem.text = f"asset-{host_id:05d}.internal"
        
        # Find and update host IP in properties
        for tag_elem in new_host.findall('.//nessus:tag', ns) or new_host.findall('.//tag'):
            if tag_elem.get('name') == 'host-ip':
                octet = (host_id % 254) + 1
                tag_elem.text = f"192.168.{(host_id // 254) % 256}.{octet}"
                break
        
        # Append to report
        report.append(new_host)
        
        if (clone_idx + 1) % 10 == 0:
            print(f"  [+] Added {clone_idx + 1}/{clones_to_add} clones...")
    
    # Finalize and write
    final_host_count = len(report.findall('nessus:ReportHost', ns) or report.findall('ReportHost'))
    final_total = final_host_count * findings_per_host
    
    print(f"[*] Final structure: {final_host_count} hosts × {findings_per_host} items = {final_total} findings")
    print(f"[*] Writing to {output_path}...")
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    tree.write(str(output_file), encoding='utf-8', xml_declaration=True)
    
    size_mb = output_file.stat().st_size / (1024 * 1024)
    print(f"[+] Success! {size_mb:.2f} MB | {final_total} findings")
    
    return True


if __name__ == "__main__":
    tpl = "tests/regression_testing/nessus_xml/nessus_expanded_200.xml"
    out = "tests/regression_testing/nessus_xml/nessus_benchmark_50k.xml"
    
    if scale_nessus_safe(tpl, out, target_findings=50000):
        print("[SUCCESS]")
        sys.exit(0)
    else:
        print("[FAILED]")
        sys.exit(1)
