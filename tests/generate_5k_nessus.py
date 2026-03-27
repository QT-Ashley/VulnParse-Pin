#!/usr/bin/env python3
"""Generate a 5k-finding Nessus sample derived from Lab_test.nessus.

Output characteristics:
- 10 assets
- 5,000 findings total (500 per asset)
- every finding has one CVE from years 2019-2025
- titles and plugin_output are populated consistently
"""

from __future__ import annotations

import copy
import xml.etree.ElementTree as ET
from pathlib import Path


TEMPLATE_PATH = Path("samples/nessus/Lab_test.nessus")
OUTPUT_PATH = Path("samples/nessus/Lab_test_scaled_5k.nessus")
TARGET_ASSETS = 10
TARGET_FINDINGS = 5_000
FINDINGS_PER_ASSET = TARGET_FINDINGS // TARGET_ASSETS
YEARS = tuple(range(2019, 2026))

SEVERITY_PROFILES = (
    {
        "severity": "1",
        "risk_factor": "Low",
        "cvss3_base_score": "3.7",
        "cvss_base_score": "2.6",
        "cvss3_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
        "cvss_vector": "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N",
    },
    {
        "severity": "2",
        "risk_factor": "Medium",
        "cvss3_base_score": "5.9",
        "cvss_base_score": "4.3",
        "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L",
        "cvss_vector": "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P",
    },
    {
        "severity": "3",
        "risk_factor": "High",
        "cvss3_base_score": "8.1",
        "cvss_base_score": "6.9",
        "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
        "cvss_vector": "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:P",
    },
    {
        "severity": "4",
        "risk_factor": "Critical",
        "cvss3_base_score": "9.8",
        "cvss_base_score": "10.0",
        "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_vector": "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
    },
)

SERVICE_PORTS = (
    ("www", "tcp", "80"),
    ("ssl", "tcp", "443"),
    ("ssh", "tcp", "22"),
    ("msrpc", "tcp", "135"),
    ("netbios-ssn", "tcp", "139"),
    ("microsoft-ds", "tcp", "445"),
    ("mysql", "tcp", "3306"),
    ("rdp", "tcp", "3389"),
    ("postgresql", "tcp", "5432"),
    ("http-alt", "tcp", "8080"),
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _find_report(root: ET.Element) -> ET.Element:
    report = root.find(".//Report")
    _require(report is not None, "No <Report> element found in template.")
    return report


def _get_or_create(parent: ET.Element, tag: str) -> ET.Element:
    child = parent.find(tag)
    if child is None:
        child = ET.SubElement(parent, tag)
    return child


def _set_child_text(parent: ET.Element, tag: str, text: str) -> None:
    child = _get_or_create(parent, tag)
    child.text = text


def _replace_singletons(item: ET.Element, tag: str, text: str) -> None:
    for child in list(item.findall(tag)):
        item.remove(child)
    ET.SubElement(item, tag).text = text


def _set_see_also(item: ET.Element, cve_id: str, plugin_id: str) -> None:
    for child in list(item.findall("see_also")):
        item.remove(child)
    refs = (
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        f"https://www.tenable.com/plugins/nessus/{plugin_id}",
    )
    for ref in refs:
        ET.SubElement(item, "see_also").text = ref


def _update_host_properties(host: ET.Element, asset_index: int) -> tuple[str, str]:
    hostname = f"lab-node-{asset_index + 1:02d}.corp.local"
    ip_addr = f"10.20.{asset_index + 10}.{asset_index + 11}"

    host.set("name", hostname)
    host_props = _get_or_create(host, "HostProperties")

    tags: dict[str, ET.Element] = {}
    for tag in host_props.findall("tag"):
        name = tag.get("name")
        if name:
            tags[name] = tag

    def set_tag(name: str, value: str) -> None:
        tag = tags.get(name)
        if tag is None:
            tag = ET.SubElement(host_props, "tag", {"name": name})
            tags[name] = tag
        tag.text = value

    set_tag("host-ip", ip_addr)
    set_tag("host-fqdn", hostname)
    set_tag("netbios-name", f"LABNODE{asset_index + 1:02d}")
    set_tag("host-rdns", hostname)
    set_tag("operating-system", "Windows Server 2019 Datacenter")
    set_tag("system-type", "general-purpose")
    set_tag("mac-address", f"00:50:56:AA:{asset_index + 16:02X}:{asset_index + 32:02X}")

    return hostname, ip_addr


def _build_item(template_item: ET.Element, asset_index: int, finding_index: int, global_index: int, hostname: str, ip_addr: str) -> ET.Element:
    item = copy.deepcopy(template_item)

    year = YEARS[global_index % len(YEARS)]
    profile = SEVERITY_PROFILES[global_index % len(SEVERITY_PROFILES)]
    service_name, protocol, port = SERVICE_PORTS[global_index % len(SERVICE_PORTS)]
    plugin_id = str(700000 + global_index)
    cve_id = f"CVE-{year}-{10000 + global_index:05d}"
    title = f"Synthetic {profile['risk_factor']} Exposure {plugin_id} - {cve_id} on {service_name.upper()}"
    description = (
        f"Synthetic Nessus finding generated from Lab_test.nessus for scalability testing. "
        f"Asset {hostname} exposed a {profile['risk_factor'].lower()} weakness on {service_name}/{port} "
        f"associated with {cve_id}."
    )
    synopsis = f"{hostname} is affected by {cve_id} on {service_name}/{port}."
    solution = f"Apply the vendor remediation for {cve_id} and validate the {service_name}/{port} service configuration."
    plugin_output = (
        f"Host: {hostname} ({ip_addr})\n"
        f"Service: {service_name}/{port}/{protocol}\n"
        f"Observed indicator: synthetic vulnerable banner matched plugin {plugin_id}.\n"
        f"Associated vulnerability: {cve_id}.\n"
        f"Evidence record: asset={asset_index + 1}, finding={finding_index + 1}, year={year}."
    )

    item.set("pluginID", plugin_id)
    item.set("pluginName", title)
    item.set("port", port)
    item.set("protocol", protocol)
    item.set("svc_name", service_name)
    item.set("severity", profile["severity"])

    _set_child_text(item, "plugin_name", title)
    _set_child_text(item, "synopsis", synopsis)
    _set_child_text(item, "description", description)
    _set_child_text(item, "solution", solution)
    _set_child_text(item, "plugin_output", plugin_output)
    _set_child_text(item, "risk_factor", profile["risk_factor"])
    _set_child_text(item, "cvss3_base_score", profile["cvss3_base_score"])
    _set_child_text(item, "cvss_base_score", profile["cvss_base_score"])
    _set_child_text(item, "cvss3_vector", profile["cvss3_vector"])
    _set_child_text(item, "cvss_vector", profile["cvss_vector"])
    _set_child_text(item, "plugin_publication_date", f"{year}/03/15")
    _set_child_text(item, "patch_publication_date", f"{year}/04/12")
    _set_child_text(item, "plugin_modification_date", "2026/03/26")
    _set_child_text(item, "vuln_publication_date", f"{year}/02/01")

    _replace_singletons(item, "cve", cve_id)
    _set_see_also(item, cve_id, plugin_id)

    return item


def generate_scaled_nessus(template_path: Path = TEMPLATE_PATH, output_path: Path = OUTPUT_PATH) -> Path:
    tree = ET.parse(template_path)
    root = tree.getroot()
    report = _find_report(root)
    source_hosts = report.findall("ReportHost")

    _require(source_hosts, "Template contains no ReportHost entries.")

    template_items = []
    for host in source_hosts:
        template_items.extend(host.findall("ReportItem"))
    _require(template_items, "Template contains no ReportItem entries.")
    _require(TARGET_FINDINGS % TARGET_ASSETS == 0, "Target findings must divide evenly across assets.")

    base_host = source_hosts[0]

    for host in list(report.findall("ReportHost")):
        report.remove(host)

    global_index = 0
    for asset_index in range(TARGET_ASSETS):
        new_host = copy.deepcopy(base_host)
        hostname, ip_addr = _update_host_properties(new_host, asset_index)

        for item in list(new_host.findall("ReportItem")):
            new_host.remove(item)

        for finding_index in range(FINDINGS_PER_ASSET):
            template_item = template_items[global_index % len(template_items)]
            new_host.append(
                _build_item(template_item, asset_index, finding_index, global_index, hostname, ip_addr)
            )
            global_index += 1

        report.append(new_host)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    return output_path


if __name__ == "__main__":
    created = generate_scaled_nessus()
    print(f"[+] Generated {created} with {TARGET_ASSETS} assets and {TARGET_FINDINGS} findings")