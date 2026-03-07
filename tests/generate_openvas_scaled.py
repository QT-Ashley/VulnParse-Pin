#!/usr/bin/env python3
"""
Generate high-volume OpenVAS XML stress datasets from a real OpenVAS sample.

This script uses `openvas_real.xml` as seed data but emits a compact XML
representation to keep very large datasets under parser size limits.
"""

from __future__ import annotations

import argparse
import copy
import os
import random
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path


def _strip_host_text(host_text: str | None) -> str:
    if not host_text:
        return "10.0.0.1"
    return host_text.strip()


def _host_for_index(index: int) -> str:
    asset_id = index + 1
    octet2 = (asset_id // (256 * 256)) % 256
    octet3 = (asset_id // 256) % 256
    octet4 = (asset_id % 254) + 1
    return f"10.{octet2}.{octet3}.{octet4}"


def _build_compact_result(template_result: ET.Element) -> ET.Element:
    out = ET.Element("result")
    out.set("id", str(uuid.uuid4()))

    name = (template_result.findtext("name") or "OpenVAS Finding").strip()
    port = (template_result.findtext("port") or "0/tcp").strip()
    threat = (template_result.findtext("threat") or "Medium").strip()
    severity = (template_result.findtext("severity") or "5.0").strip()
    description = ""

    out_name = ET.SubElement(out, "name")
    out_name.text = name

    out_host = ET.SubElement(out, "host")
    out_host.text = _strip_host_text(template_result.findtext("host"))

    out_port = ET.SubElement(out, "port")
    out_port.text = port

    nvt_src = template_result.find("nvt")
    nvt_out = ET.SubElement(out, "nvt")
    nvt_out.set("oid", nvt_src.get("oid") if nvt_src is not None and nvt_src.get("oid") else f"1.3.6.1.4.1.25623.1.0.{random.randint(10000, 99999)}")

    nvt_name = ET.SubElement(nvt_out, "name")
    nvt_name.text = ((nvt_src.findtext("name") if nvt_src is not None else name) or name)[:80]

    nvt_family = ET.SubElement(nvt_out, "family")
    nvt_family.text = (nvt_src.findtext("family") if nvt_src is not None else "General") or "General"

    nvt_cvss = ET.SubElement(nvt_out, "cvss_base")
    nvt_cvss.text = (nvt_src.findtext("cvss_base") if nvt_src is not None else severity) or severity

    refs_out = ET.SubElement(nvt_out, "refs")
    cve_refs_added = 0
    if nvt_src is not None:
        refs_src = nvt_src.find("refs")
        if refs_src is not None:
            for ref in refs_src.findall("ref"):
                if ref.get("type") == "cve":
                    ref_out = ET.SubElement(refs_out, "ref")
                    ref_out.set("type", "cve")
                    cve_id = (ref.get("id") or "").strip()
                    if cve_id:
                        ref_out.set("id", cve_id)
                        cve_refs_added += 1
                if cve_refs_added >= 3:
                    break

    if cve_refs_added == 0:
        fallback_ref = ET.SubElement(refs_out, "ref")
        fallback_ref.set("type", "cve")
        fallback_ref.set("id", "CVE-1999-0001")

    tags_out = ET.SubElement(nvt_out, "tags")
    tags_out.text = "cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:P/A:P"

    solution_out = ET.SubElement(nvt_out, "solution")
    solution_out.set("type", "Mitigation")
    solution_out.text = "Remediate per guidance."

    out_threat = ET.SubElement(out, "threat")
    out_threat.text = threat

    out_severity = ET.SubElement(out, "severity")
    out_severity.text = severity

    out_desc = ET.SubElement(out, "description")
    out_desc.text = description

    return out


def generate_scaled_openvas(
    template_path: Path,
    output_path: Path,
    target_findings: int,
    target_hosts: int,
    seed: int,
) -> None:
    rng = random.Random(seed)
    random.seed(seed)

    print(f"[*] Loading template: {template_path}")
    tree = ET.parse(template_path)
    root = tree.getroot()

    template_results = root.findall(".//result")
    if not template_results:
        raise ValueError("No <result> nodes found in template")

    print(f"[*] Template findings: {len(template_results)}")
    print(f"[*] Target findings: {target_findings:,} | Target hosts: {target_hosts:,} | Seed: {seed}")

    # Build compact skeleton
    out_root = ET.Element("report", {"id": str(uuid.uuid4())})
    ET.SubElement(out_root, "creation_time").text = "2026-03-07T00:00:00Z"
    ET.SubElement(out_root, "scan_run_status").text = "Done"
    out_hosts = ET.SubElement(out_root, "hosts")
    ET.SubElement(out_hosts, "count").text = str(target_hosts)
    out_vulns = ET.SubElement(out_root, "vulns")
    ET.SubElement(out_vulns, "count").text = str(target_findings)
    out_results = ET.SubElement(out_root, "results")
    out_results.set("max", "-1")
    out_results.set("start", "1")

    compact_templates = [_build_compact_result(r) for r in template_results]

    host_pool = [_host_for_index(i) for i in range(target_hosts)]

    for idx in range(target_findings):
        if (idx + 1) % 50000 == 0:
            print(f"    - generated {idx + 1:,}/{target_findings:,} findings")

        template = compact_templates[idx % len(compact_templates)]
        result = copy.deepcopy(template)
        result.set("id", str(uuid.uuid4()))

        host_ip = host_pool[idx % target_hosts]
        host_elem = result.find("host")
        if host_elem is not None:
            host_elem.text = host_ip

        nvt_elem = result.find("nvt")
        if nvt_elem is not None and rng.random() < 0.30:
            refs = nvt_elem.find("refs")
            if refs is not None:
                cve_ref = ET.SubElement(refs, "ref")
                cve_ref.set("type", "cve")
                cve_ref.set("id", f"CVE-{rng.randint(2018, 2026)}-{rng.randint(1000, 99999)}")

        out_results.append(result)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] Writing output: {output_path}")

    ET.ElementTree(out_root).write(str(output_path), encoding="utf-8", xml_declaration=True)
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"[+] Done: {output_path.name} | findings={target_findings:,} | size={size_mb:.2f} MB")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate scaled OpenVAS XML stress datasets")
    parser.add_argument(
        "--template",
        default="tests/regression_testing/openvas_xml/openvas_real.xml",
        help="Input real OpenVAS XML sample",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        type=int,
        default=[20000, 100000, 700000],
        help="Target finding counts to generate",
    )
    parser.add_argument(
        "--out-dir",
        default="tests/regression_testing/openvas_xml",
        help="Output directory",
    )
    parser.add_argument("--seed", type=int, default=int(os.getenv("VP_OPENVAS_SEED", "1337")))
    args = parser.parse_args()

    template = Path(args.template)
    out_dir = Path(args.out_dir)

    if not template.exists():
        raise FileNotFoundError(f"Template not found: {template}")

    host_map = {
        20000: 20,
        100000: 80,
        700000: 140,
    }

    for target in args.targets:
        target_hosts = host_map.get(target, max(10, min(200, target // 5000)))
        out_path = out_dir / f"openvas_real_stress_{target // 1000}k.xml"
        generate_scaled_openvas(template, out_path, target, target_hosts, args.seed)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
