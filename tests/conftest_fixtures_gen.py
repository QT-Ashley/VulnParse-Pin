# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
Fixture generator for creating realistic expanded test data.
Generates multiple assets with 120-400 findings each.
"""
import json
import random
from pathlib import Path
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, ElementTree

# --------- helper functions ---------

def random_cve_id():
    """Generate plausible CVE ID."""
    year = random.randint(2018, 2025)
    num = random.randint(1000, 9999)
    return f"CVE-{year}-{num}"

def random_cves(count=1):
    """Generate list of random CVE IDs."""
    return [random_cve_id() for _ in range(count)]

def random_ip():
    """Generate random private IP address."""
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

def random_port():
    """Generate random port."""
    common = [22, 80, 443, 3389, 445, 135, 139, 3306, 5432, 27017]
    if random.random() < 0.5:
        return random.choice(common)
    return random.randint(1024, 65535)

def random_severity():
    """Return random severity level."""
    return random.choice([0, 1, 2, 3, 4])

def random_cvss_score():
    """Generate plausible CVSS score (0.0-10.0)."""
    return round(random.uniform(0, 10), 1)

def random_hostname(asset_id):
    """Generate hostname for an asset."""
    return f"host-{asset_id}.internal.corp"

PLUGIN_TEMPLATES = [
    {
        "id": 11936,
        "name": "OS Identification",
        "family": "General",
        "risk": "None",
        "desc": "This plugin performs multiple remote OS detection methods.",
    },
    {
        "id": 10662,
        "name": "Network Time Protocol (NTP) Server Detection",
        "family": "Service Detection",
        "risk": "None",
        "desc": "NTP service was detected.",
    },
    {
        "id": 10330,
        "name": "SSH Server Type and Version Detection",
        "family": "Service Detection",
        "risk": "None",
        "desc": "SSH is running on this port.",
    },
    {
        "id": 34220,
        "name": "SSL Certificate Expiry",
        "family": "SSL and TLS",
        "risk": "High",
        "desc": "The SSL certificate will expire soon.",
    },
    {
        "id": 57608,
        "name": "Microsoft Windows OS End of Life Detection",
        "family": "Policy Compliance",
        "risk": "High",
        "desc": "Windows OS is out of support.",
    },
    {
        "id": 10092,
        "name": "SMB Signing Not Required",
        "family": "Windows",
        "risk": "Medium",
        "desc": "SMB signing is not enforced.",
    },
    {
        "id": 20007,
        "name": "SSL/TLS Use of Weak Cipher",
        "family": "SSL and TLS",
        "risk": "High",
        "desc": "Weak cipher detected.",
    },
]

# --------- Nessus XML generation ---------

def generate_nessus_xml_expanded(num_assets=5, findings_per_asset=150):
    """Generate an expanded Nessus XML with multiple assets and findings."""
    root = Element("NessusClientData_v2")

    # Policy
    policy = SubElement(root, "Policy")
    policy_name = SubElement(policy, "policyName")
    policy_name.text = "Expanded Test Scan"

    # Report
    report = SubElement(root, "Report")
    report.set("name", "ExpandedTestReport")

    for asset_idx in range(1, num_assets + 1):
        ip = random_ip()
        hostname = random_hostname(asset_idx)

        host = SubElement(report, "ReportHost")
        host.set("name", ip)

        # Host properties
        props = SubElement(host, "HostProperties")
        _add_tag(props, "host-ip", ip)
        _add_tag(props, "host-fqdn", hostname)
        _add_tag(props, "netbios-name", hostname.split(".")[0])
        _add_tag(props, "os", random.choice(["Windows 10 Pro", "Ubuntu 20.04 LTS", "CentOS 8"]))

        # Generate findings
        for finding_idx in range(findings_per_asset):
            template = random.choice(PLUGIN_TEMPLATES)
            port = random_port() if random.random() < 0.8 else 0
            severity = random_severity()
            cvss = random_cvss_score() if severity > 0 else 0.0
            cves = random_cves(random.randint(0, 3)) if severity > 1 else []

            item = SubElement(host, "ReportItem")
            item.set("port", str(port))
            item.set("severity", str(severity))
            item.set("pluginID", str(template["id"]))
            item.set("pluginName", template["name"])
            item.set("pluginFamily", template["family"])

            _add_elem(item, "plugin_name", template["name"])
            _add_elem(item, "plugin_id", str(template["id"]))
            _add_elem(item, "risk_factor", template["risk"])
            _add_elem(item, "description", template["desc"])
            _add_elem(item, "solution", "Apply vendor patches.")
            _add_elem(item, "synopsis", f"{template['name']} was detected.")
            _add_elem(item, "cvss_base_score", str(cvss))

            # Add CVEs
            for cve in cves:
                _add_elem(item, "cve", cve)

            # Port info
            if port > 0:
                _add_elem(item, "port", str(port))
                _add_elem(item, "protocol", random.choice(["tcp", "udp"]))

    return ElementTree(root)

def _add_tag(parent, name, value):
    """Add a tag element under HostProperties."""
    tag = SubElement(parent, "tag")
    tag.set("name", name)
    tag.text = str(value)

def _add_elem(parent, name, value):
    """Add a child element."""
    elem = SubElement(parent, name)
    elem.text = str(value)

# --------- OpenVAS XML generation ---------

def generate_openvas_xml_expanded(num_assets=5, findings_per_asset=150):
    """Generate an expanded OpenVAS XML with multiple assets and findings."""
    results = []

    for asset_idx in range(1, num_assets + 1):
        ip = random_ip()
        hostname = random_hostname(asset_idx)

        for finding_idx in range(findings_per_asset):
            template = random.choice(PLUGIN_TEMPLATES)
            port = random_port()
            severity = random.uniform(0, 10.0)
            cves = random_cves(random.randint(0, 2))

            result = {
                "host": ip,
                "hostname": hostname,
                "port": f"{port}/tcp",
                "threat": _severity_to_threat(severity),
                "severity": severity,
                "nvt": {
                    "oid": f"1.3.6.1.4.1.25623.1.0.{template['id']}",
                    "name": template["name"],
                    "family": template["family"],
                    "cvss_base": str(round(severity, 2)),
                    "cvss_base_vector": _generate_cvss_vector(severity),
                    "cve": "|".join(cves) if cves else "",
                },
                "description": template["desc"],
                "solution": "Apply vendor patches.",
            }
            results.append(result)

    report = {
        "report": {
            "scan_start": datetime.now().isoformat() + "Z",
            "scan_end": datetime.now().isoformat() + "Z",
            "results": results,
        }
    }
    return report

def _severity_to_threat(severity):
    """Map CVSS score to threat level."""
    if severity >= 9:
        return "Critical"
    elif severity >= 7:
        return "High"
    elif severity >= 4:
        return "Medium"
    elif severity > 0:
        return "Low"
    return "None"

def _generate_cvss_vector(score):
    """Generate a plausible CVSS v2 vector."""
    return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# --------- File writing ---------

def write_nessus_xml(filepath, num_assets=5, findings_per_asset=150):
    """Write expanded Nessus XML to file."""
    tree = generate_nessus_xml_expanded(num_assets, findings_per_asset)
    tree.write(str(filepath), encoding="utf-8", xml_declaration=True)
    print(f"Generated {num_assets} assets × {findings_per_asset} findings → {filepath}")

def write_openvas_xml(filepath, num_assets=5, findings_per_asset=150):
    """Write expanded OpenVAS JSON to file."""
    data = generate_openvas_xml_expanded(num_assets, findings_per_asset)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {num_assets} assets × {findings_per_asset} findings → {filepath}")

if __name__ == "__main__":
    # Generate expanded fixtures
    test_dir = Path("tests/regression_testing")

    # Nessus: 2 assets with 200 findings each
    write_nessus_xml(test_dir / "nessus_xml" / "nessus_expanded_200.xml", num_assets=2, findings_per_asset=200)

    # Nessus: 5 assets with 120 findings each
    write_nessus_xml(test_dir / "nessus_xml" / "nessus_expanded_5a_120.xml", num_assets=5, findings_per_asset=120)

    # OpenVAS: 3 assets with 150 findings each
    write_openvas_xml(test_dir / "openvas_json" / "openvas_expanded_3a_150.json", num_assets=3, findings_per_asset=150)

    # OpenVAS: 4 assets with 200 findings each
    write_openvas_xml(test_dir / "openvas_json" / "openvas_expanded_4a_200.json", num_assets=4, findings_per_asset=200)

    print("\nExpanded fixtures generated successfully!")
