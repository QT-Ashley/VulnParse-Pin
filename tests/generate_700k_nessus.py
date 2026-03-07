#!/usr/bin/env python3
"""
Generate a massive Nessus XML file for stress testing Steps 4-5 optimizations.
Target: 700k findings with realistic CVE distribution.

This tests process-pool scoring and SQLite NVD cache performance under heavy load.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import copy
import random
import os
import sys


def scale_nessus_xml_700k(template_path: str, output_path: str, target_total_findings: int = 700000):
    """
    Scale up a Nessus XML file to 700k findings:
    1. Duplicate report items within each host
    2. Generate additional hosts for realistic asset distribution
    """
    
    print(f"[*] Loading template: {template_path}")
    tree = ET.parse(template_path)
    root = tree.getroot()
    
    seed = int(os.getenv("VP_700K_SEED", "1337"))
    rng = random.Random(seed)

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

    # Build a realistic CVE pool from template + synthetic valid CVE IDs.
    cve_pool = set()
    for host in hosts:
        items = host.findall('nessus:ReportItem', ns) or host.findall('ReportItem')
        for item in items:
            cve_nodes = item.findall('nessus:cve', ns) or item.findall('cve')
            for cve_node in cve_nodes:
                if cve_node is not None and cve_node.text:
                    cve_pool.add(cve_node.text.strip().upper())

    for year in range(2018, 2027):
        for _ in range(150):
            cve_pool.add(f"CVE-{year}-{rng.randint(1000, 99999)}")

    cve_pool_list = sorted(cve_pool)
    print(f"[*] CVE pool size: {len(cve_pool_list)} (seed={seed})")

    def randomize_item_cves(report_item, variant_id: int) -> None:
        cve_nodes = report_item.findall('nessus:cve', ns) or report_item.findall('cve')
        if not cve_nodes:
            return

        # Assign 1-3 randomized CVEs across available CVE nodes.
        sample_size = min(len(cve_nodes), rng.randint(1, 3))
        sampled = rng.sample(cve_pool_list, k=sample_size)
        for idx, cve_node in enumerate(cve_nodes):
            cve_node.text = sampled[idx % sample_size]

        plugin_output = report_item.find('nessus:plugin_output', ns) or report_item.find('plugin_output')
        if plugin_output is not None and plugin_output.text:
            plugin_output.text += f" [CVE-RAND {variant_id}]"
    
    # Calculate scaling strategy
    # For 700k findings, we want ~140 hosts with ~5000 findings each
    target_hosts = 140
    target_items_per_host = target_total_findings // target_hosts
    
    items_scale_factor = max(1, (target_items_per_host + items_per_host - 1) // items_per_host)
    print(f"[*] Will scale items {items_scale_factor}x within each host")
    print(f"[*] Will generate {target_hosts} total hosts")
    
    # For each existing host, duplicate its report items
    print("[*] Duplicating report items within existing hosts...")
    for host_idx, host in enumerate(hosts):
        if (host_idx + 1) % 10 == 0:
            print(f"    - Processing host {host_idx + 1}/{len(hosts)}")
        
        items = host.findall('nessus:ReportItem', ns) or host.findall('ReportItem')
        items_to_add = []
        
        for dup_idx in range(items_scale_factor - 1):
            for item in items:
                # Deep copy and mutate plugin output to make unique
                new_item = copy.deepcopy(item)
                randomize_item_cves(new_item, dup_idx + 1)
                
                items_to_add.append(new_item)
        
        # Add all duplicated items
        for new_item in items_to_add:
            host.append(new_item)
    
    # Clone hosts to reach target host count
    print(f"[*] Cloning hosts to reach {target_hosts} total...")
    new_hosts_to_add = []
    
    if len(hosts) < target_hosts:
        clones_needed = target_hosts - len(hosts)
        print(f"    - Need to add {clones_needed} host clones")
        
        for idx in range(clones_needed):
            if (idx + 1) % 20 == 0:
                print(f"    - Generated {idx + 1}/{clones_needed} hosts")
            
            # Cycle through original hosts for variety
            source_host = hosts[idx % len(hosts)]
            new_host = copy.deepcopy(source_host)
            
            # Mutate hostname to make it unique
            hostname_elem = new_host.find('nessus:HostName', ns) or new_host.find('HostName')
            if hostname_elem is not None:
                hostname_elem.text = f"asset-{len(hosts) + idx + 1:05d}.internal"
            
            # Mutate IP address
            host_properties = new_host.find('nessus:HostProperties', ns) or new_host.find('HostProperties')
            if host_properties is not None:
                # Find host-ip tag
                for tag_elem in (host_properties.findall('nessus:tag', ns) or host_properties.findall('tag')):
                    if tag_elem.get('name') == 'host-ip':
                        asset_id = len(hosts) + idx + 1
                        # Generate IP in 10.x.x.x range for large networks
                        octet2 = (asset_id // (256 * 256)) % 256
                        octet3 = (asset_id // 256) % 256
                        octet4 = (asset_id % 254) + 1
                        tag_elem.text = f"10.{octet2}.{octet3}.{octet4}"
                        break
            
            new_hosts_to_add.append(new_host)
    
    # Append new hosts
    print(f"[*] Adding {len(new_hosts_to_add)} new hosts to report...")
    for new_host in new_hosts_to_add:
        report.append(new_host)
    
    # Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    total_hosts_final = len(hosts) + len(new_hosts_to_add)
    total_items_final = items_per_host * items_scale_factor
    total_findings_final = total_hosts_final * total_items_final
    
    print(f"[*] Final: {total_hosts_final} hosts × {total_items_final} items = {total_findings_final} findings")
    print(f"[*] Writing to {output_file}...")
    
    tree.write(str(output_file), encoding='utf-8', xml_declaration=True)
    
    size_mb = output_file.stat().st_size / (1024 * 1024)
    print(f"[+] Success! Generated {size_mb:.2f} MB file with {total_findings_final:,} findings")
    
    return True


if __name__ == "__main__":
    template = "tests/regression_testing/nessus_xml/nessus_expanded_200.xml"
    output = "tests/regression_testing/nessus_xml/nessus_stress_700k.xml"
    
    print("=" * 70)
    print("GENERATING 700K FINDINGS STRESS TEST SAMPLE")
    print("=" * 70)
    
    if scale_nessus_xml_700k(template, output, target_total_findings=700000):
        print("=" * 70)
        print("[SUCCESS] 700k sample generated!")
        print("=" * 70)
        sys.exit(0)
    else:
        print("[FAIL] Generation failed")
        sys.exit(1)
