# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""
Reproducible multi-scanner scale benchmark harness for VulnParse-Pin v2.0.0.

Usage:
    python benchmarks/bench_scale.py --findings 500000 --findings 700000
    python benchmarks/bench_scale.py --findings 500000 --findings 700000 --json-out bench.json
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from dataclasses import asdict, dataclass, replace as dc_replace
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import platform
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from xml.sax.saxutils import escape as xml_escape

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = _REPO_ROOT / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from vulnparse_pin.app.enrichment import populate_enrichment_snapshots
from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.assets_context import AssetContextMatcher, DecisionsRegistry
from vulnparse_pin.core.classes.dataclass import FeedCachePolicy, FeedSpec, RunContext, Services
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.config_projector import ConfigProjector
from vulnparse_pin.core.passes import run_v2_duckdb_pipeline
from vulnparse_pin.core.schema_detector import SchemaDetector
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers import PARSER_SPECS
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    get_run_summary_counts,
    get_shadow_assets,
    query_findings_page,
)
from vulnparse_pin.utils.enricher import load_epss, load_kev
from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
from vulnparse_pin.utils.feed_cache import FeedCacheManager
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.nvdcacher import NVDFeedCache


_SEVERITY_LEVELS: Tuple[Tuple[str, int, float, str], ...] = (
    ("Critical", 4, 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    ("High", 3, 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("Medium", 2, 5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    ("Low", 1, 3.1, "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N"),
)

_CWE_POOL: Tuple[str, ...] = (
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-200",
    "CWE-287",
    "CWE-306",
    "CWE-502",
    "CWE-798",
    "CWE-918",
)

_ACI_PHRASES: Tuple[str, ...] = (
    "Remote code execution via unauthenticated JNDI lookup allows command execution.",
    "SQL injection in login handler enables authentication bypass and database extraction.",
    "Unsafe Java deserialization leads to arbitrary command execution on edge endpoint.",
    "Server-side request forgery allows access to internal cloud metadata service.",
    "Administrative management panel exposed with default credentials.",
    "Outdated TLS cipher configuration detected during routine banner inspection.",
    "Verbose stack trace information disclosure in error handler.",
)

_NUCLEI_TEMPLATES: Tuple[Tuple[str, str, str, Tuple[str, ...], str], ...] = (
    ("default-login-admin", "Default Admin Login Exposed", "critical", ("default-login", "auth-bypass", "panel"), "CWE-798"),
    ("exposed-env-file", "Exposed .env Configuration", "medium", ("exposure", "config", "env"), "CWE-200"),
    ("cve-rce-probe", "Remote Code Execution Probe", "critical", ("cve", "rce", "oast"), "CWE-94"),
    ("sqli-error-probe", "Error-Based SQL Injection", "high", ("sqli", "owasp-top10"), "CWE-89"),
    ("ssrf-metadata-check", "Cloud Metadata SSRF Check", "high", ("ssrf", "cloud"), "CWE-918"),
)

_SAST_RULES: Tuple[Tuple[str, str, str, str, str], ...] = (
    ("python.lang.security.audit.subprocess-shell", "Command Injection via shell=True", "error", "CWE-78", "8.6"),
    ("python.django.security.injection.sql-raw", "Raw SQL Query String Formatting", "error", "CWE-89", "8.1"),
    ("python.lang.security.deserialization.pickle", "Untrusted Pickle Deserialization", "error", "CWE-502", "9.1"),
    ("python.flask.security.audit.xss-unescaped", "Unescaped Template Output (XSS)", "warning", "CWE-79", "6.1"),
    ("python.lang.security.audit.ssrf-requests", "Unvalidated URL Passed to requests.get", "warning", "CWE-918", "7.5"),
)


@dataclass(frozen=True)
class _HostSpec:
    ip: str
    hostname: str
    image: str
    uri: str
    os_name: str
    credentialed: bool
    is_shadow: bool
    ports: Tuple[int, ...]


@dataclass
class ScaleBenchmarkResult:
    raw_findings: int
    unique_findings: int
    deduplicated_findings: int
    total_assets: int
    shadow_assets: int
    p1_findings: int
    kev_findings: int
    synth_gen_s: float
    parse_ingest_s: float
    enrichment_s: float
    pipeline_s: float
    ui_query_s: float
    total_s: float
    throughput_raw_per_sec: float
    throughput_unique_per_sec: float
    peak_rss_mib: float
    db_size_mib: float
    profile: str
    batch_size: int


def _peak_rss_mib() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return float(rss) / (1024.0 * 1024.0)
    return float(rss) / 1024.0


def _split_counts(total: int) -> Tuple[int, int, int, int]:
    if total < 4:
        return (total, 0, 0, 0)
    n_nessus = int(round(total * 0.45))
    n_trivy = int(round(total * 0.25))
    n_nuclei = int(round(total * 0.20))
    n_semgrep = total - n_nessus - n_trivy - n_nuclei
    if n_semgrep < 0:
        n_nessus += n_semgrep
        n_semgrep = 0
    return (n_nessus, n_trivy, n_nuclei, n_semgrep)


def _build_cve_pool(total: int) -> List[str]:
    pool_size = min(max(200, total // 150), 2500)
    cves = ["CVE-2021-44228", "CVE-2024-3094", "CVE-2023-44487", "CVE-2024-21626"]
    idx = 0
    while len(cves) < pool_size:
        year = 2020 + (idx % 7)
        num = 10000 + idx
        cves.append(f"CVE-{year}-{num}")
        idx += 1
    return cves


def _build_host_pool(total: int) -> List[_HostSpec]:
    host_count = max(12, min(1200, total // 250))
    hosts: List[_HostSpec] = []
    for i in range(host_count):
        octet3 = (i // 200) + 1
        octet4 = (i % 200) + 10
        is_shadow = (i % 7) == 6
        is_edge = (i % 4) == 0
        if is_shadow:
            ip = f"198.51.100.{octet4}"
            hostname = f"shadow-node-{i:04d}.unmanaged.test"
            ports = (22, 80, 8443)
        elif is_edge:
            ip = f"203.0.113.{octet4}"
            hostname = f"edge-svc-{i:04d}.prod.acme.test"
            ports = (80, 443, 8443)
        elif i % 3 == 0:
            ip = f"172.16.{octet3}.{octet4}"
            hostname = f"api-{i:04d}.prod.acme.test"
            ports = (443, 5432)
        else:
            ip = f"10.20.{octet3}.{octet4}"
            hostname = f"worker-{i:04d}.corp.acme.test"
            ports = (22, 6379)
        hosts.append(
            _HostSpec(
                ip=ip,
                hostname=hostname,
                image=f"ghcr.io/acme/svc-{i % 40}:1.{i % 10}.0",
                uri=f"https://{hostname}:{ports[0]}",
                os_name="Ubuntu 24.04 LTS" if i % 2 == 0 else "Debian 12",
                credentialed=(i % 5 != 4),
                is_shadow=is_shadow,
                ports=ports,
            )
        )
    return hosts


def _generate_assets_and_decisions(
    work_dir: Path,
    hosts: Sequence[_HostSpec],
) -> Tuple[Path, Path]:
    lines = [
        "version: v2",
        "defaults:",
        "  criticality: medium",
        "  internet_facing: false",
        "  owner: platform-sec",
        "rules:",
    ]
    # Alias rules linking Nessus host + Trivy image + Nuclei URI for top edge hosts
    alias_count = min(40, len(hosts))
    seen_imgs: Set[str] = set()
    for idx in range(alias_count):
        h = hosts[idx]
        if h.is_shadow or h.image in seen_imgs:
            continue
        seen_imgs.add(h.image)
        lines.extend(
            [
                f"  - id: rule-alias-{idx}",
                f"    aliases:",
                f"      - {h.ip}",
                f"      - {h.hostname}",
                f"      - {h.image}",
                f"      - {h.uri}",
                f"    internet_facing: {str(h.ip.startswith('203.0.113.')).lower()}",
                f"    criticality: {'critical' if h.ip.startswith('203.0.113.') else 'high'}",
                "    owner: edge-platform",
                "    env:",
                "      - prod",
            ]
        )

    lines.extend(
        [
            "  - id: rule-edge-net",
            "    cidrs:",
            "      - 203.0.113.0/24",
            "    internet_facing: true",
            "    criticality: critical",
            "    owner: edge-ops",
            "    env: prod",
            "  - id: rule-prod-glob",
            "    hostnames:",
            '      - "*.prod.acme.test"',
            "    internet_facing: false",
            "    criticality: high",
            "    owner: prod-eng",
            "  - id: rule-corp-cidr",
            "    cidrs:",
            "      - 10.0.0.0/8",
            "      - 172.16.0.0/12",
            "    internet_facing: false",
            "    criticality: medium",
            "    owner: corp-infra",
        ]
    )
    assets_path = work_dir / "assets.yaml"
    assets_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    decisions_yaml = """version: v2
decisions:
  - id: dec-valid-internal-deferral
    asset_pattern: "10.20.*"
    cve_or_rule_id: "CVE-2020-10002"
    status: deferred
    rationale: "Mitigated behind internal VPC firewall pending scheduled Q2 patching."
    owner: corp-infra
    created_at: "2026-10-01"
    expires_at: "2027-06-01"
    assumptions:
      in_kev: false
      max_epss: 0.15
      internet_facing: false
  - id: dec-stale-kev-flip
    asset_pattern: "*"
    cve_or_rule_id: "CVE-2021-44228"
    status: deferred
    rationale: "Legacy waiver assumed non-KEV status."
    owner: edge-ops
    created_at: "2025-01-01"
    expires_at: "2026-12-31"
    assumptions:
      in_kev: false
      max_epss: 0.05
"""
    decisions_path = work_dir / "decisions.yaml"
    decisions_path.write_text(decisions_yaml, encoding="utf-8")
    return assets_path, decisions_path


def _generate_intel_snapshot(
    intel_dir: Path,
    cves: Sequence[str],
    rng: random.Random,
) -> Dict[str, Path]:
    intel_dir.mkdir(parents=True, exist_ok=True)

    # 1. EPSS v5 CSV (#model_version header + epss + percentile)
    epss_path = intel_dir / "epss_v5.csv"
    epss_lines = [
        "#model_version:v2025.03.14,score_date:2026-11-24T00:00:00+0000\n",
        "cve,epss,percentile\n",
    ]
    for i, cve in enumerate(cves):
        if i == 0:
            epss, pct = 0.974, 0.999
        elif i == 1:
            epss, pct = 0.851, 0.992
        elif i % 15 == 0:
            epss = round(rng.uniform(0.12, 0.78), 5)
            pct = round(rng.uniform(0.95, 0.998), 5)
        elif i % 5 == 0:
            epss = round(rng.uniform(0.04, 0.119), 5)
            pct = round(rng.uniform(0.85, 0.949), 5)
        else:
            epss = round(rng.uniform(0.0005, 0.039), 5)
            pct = round(rng.uniform(0.05, 0.84), 5)
        epss_lines.append(f"{cve},{epss:.5f},{pct:.5f}\n")
    epss_path.write_text("".join(epss_lines), encoding="utf-8")

    # 2. CISA KEV JSON (~4% of CVEs)
    kev_vulns = []
    for i, cve in enumerate(cves):
        if i in (0, 1) or i % 25 == 0:
            kev_vulns.append(
                {
                    "cveID": cve,
                    "vulnerabilityName": f"Synthetic KEV Advisory for {cve}",
                    "dateAdded": "2025-03-15",
                    "dueDate": "2025-04-05",
                    "knownRansomwareCampaignUse": "Known" if i % 50 == 0 else "Unknown",
                    "requiredAction": "Apply vendor mitigations per BOD 22-01.",
                }
            )
    kev_path = intel_dir / "kev.json"
    kev_path.write_text(
        json.dumps({"catalogVersion": "2026.11.24", "vulnerabilities": kev_vulns}),
        encoding="utf-8",
    )

    # 3. Exploit-DB CSV (~10% of CVEs)
    edb_path = intel_dir / "exploitdb.csv"
    edb_lines = ["id,file,description,date_published,author,type,platform,port,date_updated,verified,codes\n"]
    for i, cve in enumerate(cves):
        if i % 10 == 0:
            edb_lines.append(
                f"{50000 + i},exploits/linux/remote/{50000 + i}.py,\"PoC for {cve}\",2025-02-01,researcher,remote,linux,443,2025-02-02,1,{cve}\n"
            )
    edb_path.write_text("".join(edb_lines), encoding="utf-8")

    # 4. NVD 2.0 JSON.GZ (~80% of CVEs, mixing v4.0, v3.1 NVD Primary, and CNA Secondary)
    nvd_vulns = []
    for i, cve in enumerate(cves):
        if i % 5 == 4:
            continue
        metrics: Dict[str, Any] = {}
        if i % 6 == 0:
            metrics["cvssMetricV40"] = [
                {
                    "type": "Primary",
                    "source": "nvd@nist.gov",
                    "cvssData": {
                        "version": "4.0",
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        "baseScore": 9.3,
                    },
                }
            ]
        elif i % 4 == 3:
            metrics["cvssMetricV31"] = [
                {
                    "type": "Secondary",
                    "source": "cna@vendor.test",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                        "baseScore": 7.1,
                    },
                }
            ]
        else:
            sev_score = 9.8 if i % 7 == 0 else (7.5 if i % 2 == 0 else 5.3)
            vec = (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                if sev_score >= 9.0
                else (
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    if sev_score >= 7.0
                    else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                )
            )
            metrics["cvssMetricV31"] = [
                {
                    "type": "Primary",
                    "source": "nvd@nist.gov",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": vec,
                        "baseScore": sev_score,
                    },
                }
            ]
        nvd_vulns.append(
            {
                "cve": {
                    "id": cve,
                    "sourceIdentifier": "nvd@nist.gov" if i % 4 != 3 else "cna@vendor.test",
                    "descriptions": [{"lang": "en", "value": f"Synthetic NVD description for {cve}"}],
                    "published": "2025-01-15T00:00:00Z",
                    "lastModified": "2026-02-01T00:00:00Z",
                    "metrics": metrics,
                }
            }
        )
    nvd_path = intel_dir / "nvd_2026.json.gz"
    with gzip.open(nvd_path, "wt", encoding="utf-8") as gz:
        json.dump({"vulnerabilities": nvd_vulns}, gz)

    return {"epss": epss_path, "kev": kev_path, "exploitdb": edb_path, "nvd": nvd_path}


def _write_nessus_xml(
    out_path: Path,
    count: int,
    hosts: Sequence[_HostSpec],
    cves: Sequence[str],
) -> None:
    if count <= 0:
        return
    num_hosts = min(len(hosts), max(1, count // 25))
    per_host_base, rem = divmod(count, num_hosts)
    n_cves = len(cves)
    n_phrases = len(_ACI_PHRASES)
    n_cwes = len(_CWE_POOL)

    with out_path.open("w", encoding="utf-8", buffering=1024 * 1024) as fh:
        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n<NessusClientData_v2>\n  <Report name="ScaleBench">\n')
        global_idx = 0
        for h_idx in range(num_hosts):
            h = hosts[h_idx]
            item_count = per_host_base + (1 if h_idx < rem else 0)
            cred_str = "yes" if h.credentialed else "no"
            chunks = [
                f'    <ReportHost name="{xml_escape(h.hostname)}">\n',
                "      <HostProperties>\n",
                f'        <tag name="host-ip">{xml_escape(h.ip)}</tag>\n',
                f'        <tag name="host-fqdn">{xml_escape(h.hostname)}</tag>\n',
                f'        <tag name="Credentialed_checks">{cred_str}</tag>\n',
                f'        <tag name="operating-system">{xml_escape(h.os_name)}</tag>\n',
                "      </HostProperties>\n",
            ]
            for j in range(item_count):
                sev_name, sev_num, cvss_val, cvss_vec = _SEVERITY_LEVELS[global_idx % 4]
                port = h.ports[global_idx % len(h.ports)]
                is_non_cve = (global_idx % 6) == 5
                phrase = _ACI_PHRASES[global_idx % n_phrases]
                cwe = _CWE_POOL[global_idx % n_cwes]
                plugin_id = 100000 + (global_idx % 20000)
                if is_non_cve:
                    cve_block = ""
                    title = f"Exposure Finding {plugin_id} ({cwe})"
                else:
                    cve = cves[(global_idx + h_idx) % n_cves]
                    cve_block = f"<cve>{cve}</cve>"
                    title = f"Package Security Update {cve}"
                chunks.append(
                    f'      <ReportItem pluginID="{plugin_id}" pluginName="{title}" severity="{sev_num}" port="{port}" protocol="tcp" svc_name="https">'
                    f"<description>{phrase} ({cwe})</description>"
                    f"<solution>Apply vendor update or restrict network exposure.</solution>"
                    f"<plugin_output>Verified on port {port}/tcp.</plugin_output>"
                    f"<risk_factor>{sev_name}</risk_factor>"
                    f"<cvss_base_score>{cvss_val:.1f}</cvss_base_score>"
                    f"<cvss3_vector>{cvss_vec}</cvss3_vector>"
                    f"{cve_block}</ReportItem>\n"
                )
                global_idx += 1
                if len(chunks) >= 2000:
                    fh.write("".join(chunks))
                    chunks.clear()
            chunks.append("    </ReportHost>\n")
            fh.write("".join(chunks))
        fh.write("  </Report>\n</NessusClientData_v2>\n")


def _write_trivy_sarif(
    out_path: Path,
    count: int,
    hosts: Sequence[_HostSpec],
    cves: Sequence[str],
) -> None:
    if count <= 0:
        return
    # Group across distinct container images (starting with hosts[0..39] to test alias cross-scanner dedup)
    image_hosts = list(dict.fromkeys(h.image for h in hosts[: min(40, len(hosts))]))
    num_runs = len(image_hosts)
    per_run_base, rem = divmod(count, num_runs)
    n_cves = len(cves)

    # Pre-build reusable rules template per run
    rules = []
    for idx, cve in enumerate(cves[: min(100, n_cves)]):
        cwe = _CWE_POOL[idx % len(_CWE_POOL)]
        rules.append(
            {
                "id": cve,
                "name": f"Vuln {cve}",
                "shortDescription": {"text": f"Container package vulnerability {cve}"},
                "properties": {"tags": ["vulnerability", cwe], "security-severity": "8.5"},
            }
        )
    rules_json = json.dumps(rules, separators=(",", ":"))

    with out_path.open("w", encoding="utf-8", buffering=1024 * 1024) as fh:
        fh.write('{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[')
        global_idx = 0
        for r_idx, image_name in enumerate(image_hosts):
            if r_idx > 0:
                fh.write(",")
            run_count = per_run_base + (1 if r_idx < rem else 0)
            fh.write(
                '{"tool":{"driver":{"name":"Trivy","semanticVersion":"0.56.0","rules":'
                + rules_json
                + '}},"properties":{"imageName":'
                + json.dumps(image_name)
                + '},"results":['
            )
            buf: List[str] = []
            for j in range(run_count):
                cve = cves[(global_idx + r_idx) % n_cves]
                sev_name, _, cvss_val, cvss_vec = _SEVERITY_LEVELS[global_idx % 4]
                level = "error" if sev_name in ("Critical", "High") else "warning"
                pkg = f"openssl-{1 + (global_idx % 3)}.0.{global_idx % 12}"
                res = {
                    "ruleId": cve,
                    "level": level,
                    "message": {"text": f"Package {pkg} is affected by {cve}: {_ACI_PHRASES[global_idx % len(_ACI_PHRASES)]}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"usr/lib/{pkg}.so"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": f"trivy-{r_idx}-{j}"},
                    "properties": {
                        "purl": f"pkg:deb/debian/{pkg}@1.0.0",
                        "cvss": {"nvd": {"V3Score": cvss_val, "V3Vector": cvss_vec}},
                    },
                }
                prefix = "," if j > 0 else ""
                buf.append(prefix + json.dumps(res, separators=(",", ":")))
                global_idx += 1
                if len(buf) >= 2000:
                    fh.write("".join(buf))
                    buf.clear()
            if buf:
                fh.write("".join(buf))
            fh.write("]}")
        fh.write("]}\n")


def _write_semgrep_sarif(
    out_path: Path,
    count: int,
    hosts: Sequence[_HostSpec],
) -> None:
    if count <= 0:
        return
    repo_hosts = list(dict.fromkeys(h.image for h in hosts[: min(16, len(hosts))]))
    num_runs = len(repo_hosts)
    per_run_base, rem = divmod(count, num_runs)
    rules = [
        {
            "id": rid,
            "name": name,
            "shortDescription": {"text": name},
            "properties": {"tags": ["security", cwe], "security-severity": sec_sev},
        }
        for rid, name, _, cwe, sec_sev in _SAST_RULES
    ]
    rules_json = json.dumps(rules, separators=(",", ":"))

    with out_path.open("w", encoding="utf-8", buffering=1024 * 1024) as fh:
        fh.write('{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[')
        global_idx = 0
        for r_idx, repo_name in enumerate(repo_hosts):
            if r_idx > 0:
                fh.write(",")
            run_count = per_run_base + (1 if r_idx < rem else 0)
            fh.write(
                '{"tool":{"driver":{"name":"Semgrep","semanticVersion":"1.90.0","rules":'
                + rules_json
                + '}},"properties":{"repository":'
                + json.dumps(repo_name)
                + '},"results":['
            )
            buf: List[str] = []
            for j in range(run_count):
                rid, name, level, cwe, _ = _SAST_RULES[global_idx % len(_SAST_RULES)]
                res = {
                    "ruleId": rid,
                    "ruleIndex": global_idx % len(_SAST_RULES),
                    "level": level,
                    "message": {"text": f"{name} ({cwe}) detected in handler_{global_idx % 200}.py"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"src/api/handler_{global_idx % 200}.py"},
                                "region": {"startLine": 10 + (j % 400)},
                            }
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": f"sast-{r_idx}-{j}"},
                }
                prefix = "," if j > 0 else ""
                buf.append(prefix + json.dumps(res, separators=(",", ":")))
                global_idx += 1
                if len(buf) >= 2000:
                    fh.write("".join(buf))
                    buf.clear()
            if buf:
                fh.write("".join(buf))
            fh.write("]}")
        fh.write("]}\n")


def _write_nuclei_jsonl(
    out_path: Path,
    count: int,
    hosts: Sequence[_HostSpec],
    cves: Sequence[str],
) -> None:
    if count <= 0:
        return
    n_hosts = len(hosts)
    n_cves = len(cves)
    n_tpl = len(_NUCLEI_TEMPLATES)

    with out_path.open("w", encoding="utf-8", buffering=1024 * 1024) as fh:
        buf: List[str] = []
        for idx in range(count):
            h = hosts[idx % n_hosts]
            tpl_id, tpl_name, sev, tags, cwe = _NUCLEI_TEMPLATES[idx % n_tpl]
            is_cve = (idx % 2) == 0
            port = h.ports[0]
            classification: Dict[str, Any] = {"cwe-id": [cwe]}
            if is_cve:
                cve = cves[idx % n_cves]
                effective_tpl = cve
                classification["cve-id"] = [cve]
                classification["cvss-score"] = 9.8 if sev == "critical" else 7.5
                classification["cvss-metrics"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                name = f"{tpl_name} ({cve})"
            else:
                effective_tpl = f"{tpl_id}-{idx % 40}"
                name = tpl_name
            row = {
                "template-id": effective_tpl,
                "info": {
                    "name": name,
                    "severity": sev,
                    "description": _ACI_PHRASES[idx % len(_ACI_PHRASES)],
                    "tags": list(tags),
                    "classification": classification,
                },
                "type": "http",
                "scheme": "https",
                "host": h.uri,
                "ip": h.ip,
                "port": str(port),
                "matched-at": f"{h.uri}/v{(idx % 5) + 1}/endpoint/{idx % 500}",
                "matcher-name": "status-and-body",
            }
            buf.append(json.dumps(row, separators=(",", ":")) + "\n")
            if len(buf) >= 2000:
                fh.write("".join(buf))
                buf.clear()
        if buf:
            fh.write("".join(buf))


def _write_nmap_xml(out_path: Path, hosts: Sequence[_HostSpec]) -> None:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner="nmap" args="nmap -sV">\n']
    # Include ~65% of scan hosts + 2 Nmap-only shadow hosts
    for i, h in enumerate(hosts):
        if i % 3 == 2:
            continue
        lines.append(
            f'  <host starttime="1700000000" endtime="1700000010">\n'
            f'    <status state="up" reason="syn-ack"/>\n'
            f'    <address addr="{xml_escape(h.ip)}" addrtype="ipv4"/>\n'
            f'    <hostnames><hostname name="{xml_escape(h.hostname)}" type="PTR"/></hostnames>\n'
            f"    <ports>\n"
        )
        for p in h.ports:
            svc = "https" if p in (443, 8443) else ("http" if p == 80 else "ssh" if p == 22 else "tcp")
            lines.append(
                f'      <port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack"/>'
                f'<service name="{svc}"/></port>\n'
            )
        lines.append("    </ports>\n  </host>\n")
    for extra in ("198.51.100.250", "198.51.100.251"):
        lines.append(
            f'  <host><status state="up"/><address addr="{extra}" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https"/></port></ports></host>\n'
        )
    lines.append("</nmaprun>\n")
    out_path.write_text("".join(lines), encoding="utf-8")


def _make_bench_ctx(work_dir: Path, db: VppDatabase, run_id: str, profile: str) -> RunContext:
    cache_dir = work_dir / "cache"
    nvd_dir = cache_dir / "nvd"
    cache_dir.mkdir(parents=True, exist_ok=True)
    nvd_dir.mkdir(parents=True, exist_ok=True)

    logger = LoggerWrapper(log_file=str(work_dir / "bench.log"), log_level="ERROR")
    pfh = PermFileHandler(
        logger,
        root_dir=work_dir,
        allowed_roots=[work_dir],
        enforce_roots_on_read=False,
        enforce_roots_on_write=True,
        forbid_symlinks_read=True,
        forbid_symlinks_write=True,
    )
    paths = dc_replace(
        AppPaths.resolve(portable=True),
        cache_dir=cache_dir,
        nvd_feeds_dir=nvd_dir,
        log_dir=work_dir,
        output_dir=work_dir,
    )
    specs = {
        "epss": FeedSpec(key="epss", filename="epss_cache.csv", label="EPSS"),
        "kev": FeedSpec(key="kev", filename="kev_cache.json", label="CISA KEV"),
        "exploit_db": FeedSpec(key="exploit_db", filename="files_exploit.csv", label="Exploit-DB"),
    }
    policy = FeedCachePolicy(default_ttl_hours=24, ttl_hours={"epss": 24, "kev": 24, "exploit_db": 24})
    fc = FeedCacheManager(
        cache_dir=cache_dir,
        pfh=pfh,
        logger=logger,
        specs=specs,
        policy=policy,
        nvd_feeds_dir=nvd_dir,
    )
    nvd_cache = NVDFeedCache(
        RunContext(
            paths=paths,
            pfh=pfh,
            logger=logger,
            services=Services(feed_cache=fc, global_config={"feed_cache": {"feeds": {"nvd": {"enabled": True}}}}),
        )
    )
    ledger = LedgerService()
    services = Services(
        feed_cache=fc,
        nvd_cache=nvd_cache,
        ledger=ledger,
        global_config={"feed_cache": {"feeds": {"nvd": {"enabled": True}}}},
        db=db,
        run_id=run_id,
    )
    ctx = RunContext(
        paths=paths,
        pfh=pfh,
        logger=logger,
        services=services,
        db=db,
        run_id=run_id,
    )
    object.__setattr__(ctx, "profile", profile)
    return ctx


def _iter_multi_scanner_batches(
    ctx: RunContext,
    scan_files: Sequence[Path],
    batch_size: int,
) -> Iterator[List[Dict[str, Any]]]:
    detector = SchemaDetector(PARSER_SPECS)
    for path in scan_files:
        det = detector.select(ctx, path, allow_large=True)
        parser = det.parser_cls(ctx, path, allow_large=True)
        for batch in parser.iter_batches(batch_size=batch_size):
            if batch:
                yield batch


def run_single_scale(
    num_findings: int,
    *,
    profile: str = "bod-26-04",
    batch_size: int = 10_000,
    seed: int = 42,
    keep_temp: bool = False,
) -> ScaleBenchmarkResult:
    rng = random.Random(seed)
    tmp_dir = Path(tempfile.mkdtemp(prefix=f"vpp_bench_{num_findings}_"))
    db: Optional[VppDatabase] = None

    try:
        # 0. Generate synthetic multi-scanner dataset + intel snapshots (timed separately)
        t_gen0 = time.perf_counter()
        cves = _build_cve_pool(num_findings)
        hosts = _build_host_pool(num_findings)
        n_nessus, n_trivy, n_nuclei, n_semgrep = _split_counts(num_findings)

        scan_files: List[Path] = []
        if n_nessus > 0:
            p = tmp_dir / "synthetic.nessus"
            _write_nessus_xml(p, n_nessus, hosts, cves)
            scan_files.append(p)
        if n_trivy > 0:
            p = tmp_dir / "synthetic_trivy.sarif"
            _write_trivy_sarif(p, n_trivy, hosts, cves)
            scan_files.append(p)
        if n_nuclei > 0:
            p = tmp_dir / "synthetic_nuclei.jsonl"
            _write_nuclei_jsonl(p, n_nuclei, hosts, cves)
            scan_files.append(p)
        if n_semgrep > 0:
            p = tmp_dir / "synthetic_semgrep.sarif"
            _write_semgrep_sarif(p, n_semgrep, hosts)
            scan_files.append(p)

        nmap_path = tmp_dir / "synthetic_nmap.xml"
        _write_nmap_xml(nmap_path, hosts)
        assets_path, decisions_path = _generate_assets_and_decisions(tmp_dir, hosts)
        intel_paths = _generate_intel_snapshot(tmp_dir / "intel", cves, rng)
        synth_gen_s = time.perf_counter() - t_gen0

        db_path = tmp_dir / "bench.vpp.db"
        run_id = f"bench-{num_findings}"
        db = VppDatabase(db_path)
        ctx = _make_bench_ctx(tmp_dir, db, run_id, profile)
        bundle = ConfigProjector.load_packaged_default_bundle()
        matcher = AssetContextMatcher.from_file(assets_path, pfh=ctx.pfh)
        decisions_registry = DecisionsRegistry.from_file(decisions_path, pfh=ctx.pfh)

        # Stage 1: Streaming parser iter_batches() -> VppDatabase.ingest_normalized_batches()
        t_pipe0 = time.perf_counter()
        t1_0 = time.perf_counter()
        db.ensure_run(
            run_id,
            vpp_version="2.0.0",
            profile=profile,
            input_files=[p.name for p in scan_files],
        )
        ingest_stats = db.ingest_normalized_batches(
            run_id,
            _iter_multi_scanner_batches(ctx, scan_files, batch_size),
            asset_matcher=matcher,
        )
        parse_ingest_s = time.perf_counter() - t1_0

        # Stage 2: Matched CVE hydration + populate_enrichment_snapshots()
        t2_0 = time.perf_counter()
        matched_cves = {
            r[0]
            for r in db.execute(
                "SELECT DISTINCT cve_id FROM finding_cves WHERE run_id = ?",
                [run_id],
            ).fetchall()
            if r[0]
        }
        epss_data = load_epss(
            ctx,
            path_url=str(intel_paths["epss"]),
            force_refresh=False,
            allow_regen=True,
            target_cves=matched_cves,
        )
        kev_data = load_kev(
            ctx,
            str(intel_paths["kev"]),
            force_refresh=False,
            allow_regen=True,
        )
        exploit_data = load_exploit_data(
            ctx,
            source=str(intel_paths["exploitdb"]),
            force_refresh=False,
            allow_regen=True,
        )
        nvd_cache = ctx.services.nvd_cache
        if nvd_cache is not None and matched_cves:
            nvd_cache.target_cves = set(matched_cves)
            nvd_cache._parse_feed(str(intel_paths["nvd"]))

        populate_enrichment_snapshots(
            db,
            run_id,
            ctx,
            {
                "nvd_cache": nvd_cache,
                "epss_data": epss_data,
                "kev_data": kev_data,
                "exploit_data": exploit_data,
            },
            target_cves=matched_cves,
        )
        enrichment_s = time.perf_counter() - t2_0

        # Stage 3: Full v2 DuckDB pipeline (Nmap + ACI@2.0 + Scoring@3.0 + Triage@2.0 + TopN@2.0 + Summary@2.0)
        t3_0 = time.perf_counter()
        run_v2_duckdb_pipeline(
            ctx,
            bundle=bundle,
            profile=profile,
            nmap_path=str(nmap_path),
            decisions_registry=decisions_registry,
        )
        pipeline_s = time.perf_counter() - t3_0

        # Stage 4: Paged UI query + summary query + shadow assets query
        t4_0 = time.perf_counter()
        p1_rows, p1_total = query_findings_page(db, run_id, priority_tier="P1", limit=100, offset=0)
        _ = len(p1_rows)
        summary_counts = get_run_summary_counts(db, run_id)
        _ = get_shadow_assets(db, run_id)
        ui_query_s = time.perf_counter() - t4_0

        total_s = time.perf_counter() - t_pipe0

        # Flush DuckDB WAL cleanly before reading .vpp.db disk footprint
        db.close()
        db = None
        db_bytes = db_path.stat().st_size if db_path.exists() else 0
        wal_path = Path(f"{db_path}.wal")
        if wal_path.exists():
            db_bytes += wal_path.stat().st_size
        db_size_mib = db_bytes / (1024.0 * 1024.0)

        raw_cnt = int(ingest_stats["raw_findings_ingested"])
        uniq_cnt = int(ingest_stats["unique_findings_ingested"])
        dedup_cnt = int(ingest_stats["deduplicated_findings"])

        return ScaleBenchmarkResult(
            raw_findings=raw_cnt,
            unique_findings=uniq_cnt,
            deduplicated_findings=dedup_cnt,
            total_assets=int(summary_counts["total_assets"]),
            shadow_assets=int(summary_counts["shadow_assets"]),
            p1_findings=int(p1_total),
            kev_findings=int(summary_counts["kev_findings"]),
            synth_gen_s=round(synth_gen_s, 3),
            parse_ingest_s=round(parse_ingest_s, 3),
            enrichment_s=round(enrichment_s, 3),
            pipeline_s=round(pipeline_s, 3),
            ui_query_s=round(ui_query_s, 4),
            total_s=round(total_s, 3),
            throughput_raw_per_sec=round(raw_cnt / max(total_s, 1e-6), 1),
            throughput_unique_per_sec=round(uniq_cnt / max(total_s, 1e-6), 1),
            peak_rss_mib=round(_peak_rss_mib(), 2),
            db_size_mib=round(db_size_mib, 2),
            profile=profile,
            batch_size=batch_size,
        )
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        if keep_temp:
            print(f"[keep-temp] Preserved benchmark directory: {tmp_dir}", file=sys.stderr)
        else:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _format_markdown_table(results: Sequence[ScaleBenchmarkResult]) -> str:
    headers = (
        "| Raw Findings | Unique Findings | Assets (Shadow) | Parse+Ingest (s) | "
        "Enrich (s) | Pipeline DAG (s) | UI+Summary (s) | Total (s) | "
        "Throughput (raw/s) | Peak RSS (MiB) | `.vpp.db` (MiB) |"
    )
    sep = (
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    )
    rows = [headers, sep]
    for r in results:
        rows.append(
            f"| {r.raw_findings:,} | {r.unique_findings:,} | "
            f"{r.total_assets:,} ({r.shadow_assets:,}) | "
            f"{r.parse_ingest_s:.3f} | {r.enrichment_s:.3f} | {r.pipeline_s:.3f} | "
            f"{r.ui_query_s:.4f} | {r.total_s:.3f} | {r.throughput_raw_per_sec:,.1f} | "
            f"{r.peak_rss_mib:.2f} | {r.db_size_mib:.2f} |"
        )
    return "\n".join(rows)


def _run_isolated_subprocess(
    num_findings: int,
    *,
    profile: str,
    batch_size: int,
    seed: int,
    keep_temp: bool,
) -> ScaleBenchmarkResult:
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--findings",
        str(num_findings),
        "--profile",
        profile,
        "--batch-size",
        str(batch_size),
        "--seed",
        str(seed),
        "--_single-json",
    ]
    if keep_temp:
        cmd.append("--keep-temp")
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    if proc.stderr.strip():
        print(proc.stderr.strip(), file=sys.stderr)
    payload = json.loads(proc.stdout.strip())
    return ScaleBenchmarkResult(**payload)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reproducible multi-scanner v2.0 DuckDB scale benchmark for VulnParse-Pin."
    )
    parser.add_argument(
        "--findings",
        action="append",
        type=int,
        dest="findings",
        help="Target raw finding count (repeatable, e.g. --findings 500000 --findings 700000). Defaults to 500000 and 700000.",
    )
    parser.add_argument(
        "--profile",
        default="bod-26-04",
        choices=["default", "bod-26-04"],
        help="Triage profile to execute (default: bod-26-04).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10_000,
        help="Streaming parser batch size (default: 10000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="PRNG seed for synthetic threat-intel snapshot generation (default: 42).",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write structured JSON benchmark results.",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Preserve temporary generated scan files and .vpp.db workspace after completion.",
    )
    parser.add_argument(
        "--_single-json",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args(argv)
    targets = args.findings or [500_000, 700_000]
    for t in targets:
        if t < 1:
            parser.error(f"--findings must be >= 1, got {t}")

    if args._single_json:
        with redirect_stdout(sys.stderr):
            res = run_single_scale(
                targets[0],
                profile=args.profile,
                batch_size=args.batch_size,
                seed=args.seed,
                keep_temp=args.keep_temp,
            )
        print(json.dumps(asdict(res)))
        return 0

    results: List[ScaleBenchmarkResult] = []
    if len(targets) == 1:
        results.append(
            run_single_scale(
                targets[0],
                profile=args.profile,
                batch_size=args.batch_size,
                seed=args.seed,
                keep_temp=args.keep_temp,
            )
        )
    else:
        for t in targets:
            results.append(
                _run_isolated_subprocess(
                    t,
                    profile=args.profile,
                    batch_size=args.batch_size,
                    seed=args.seed,
                    keep_temp=args.keep_temp,
                )
            )

    env_info = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "profile": args.profile,
        "batch_size": args.batch_size,
    }

    print("### VulnParse-Pin v2.0.0 Scale Benchmark Results\n")
    print(
        f"- **Environment**: Python `{env_info['python']}`, `{env_info['platform']}`, "
        f"`{env_info['cpu_count']}` CPUs, profile `{args.profile}`, batch size `{args.batch_size}`\n"
    )
    print(_format_markdown_table(results))

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "environment": env_info,
            "results": [asdict(r) for r in results],
        }
        args.json_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote JSON results to {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
