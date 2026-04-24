"""
Generate a scaled OpenVAS XML (15 assets, 100 findings, all with real CVEs)
and a matching Nmap XML covering all 15 IPs in 192.168.170.0/24 with
realistic open ports — so the NmapAdapterPass join succeeds for every asset.

Usage:
    python tests/generate_openvas_nmap_scaled.py
Outputs:
    tests_output/scaled_openvas_15a_100f.xml
    tests_output/scaled_nmap_15hosts.xml
"""

import random
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

SEED = 42
random.seed(SEED)

OUT_DIR = Path(__file__).parent.parent / "tests_output"
OUT_DIR.mkdir(exist_ok=True)

OPENVAS_OUT = OUT_DIR / "scaled_openvas_15a_100f.xml"
NMAP_OUT    = OUT_DIR / "scaled_nmap_15hosts.xml"

# ---------------------------------------------------------------------------
# Asset / IP layout
# ---------------------------------------------------------------------------
NUM_ASSETS = 15
# .140 is preserved to match the original Nmap scan; rest are random in subnet
FIXED_IP = "192.168.170.140"
ALL_HOSTS = [FIXED_IP] + [
    f"192.168.170.{o}"
    for o in random.sample([x for x in range(2, 254) if x != 140], NUM_ASSETS - 1)
]

# ---------------------------------------------------------------------------
# CVE pool — real CVEs with realistic CVSS v2 vectors + severities
# ---------------------------------------------------------------------------
CVE_POOL = [
    # (cve_id, nvt_name, cvss_score, cvss_vector, port, severity_label, family, solution_type, summary)
    ("CVE-2021-44228", "Apache Log4j RCE (Log4Shell)",
     10.0, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "8080/tcp", "High",
     "Web application abuses", "VendorFix",
     "A critical RCE vulnerability in Apache Log4j 2 allows remote code execution via JNDI lookup."),
    ("CVE-2021-45046", "Apache Log4j JNDI Thread Context Lookup RCE",
     9.0, "AV:N/AC:H/Au:N/C:C/I:C/A:C", "8080/tcp", "High",
     "Web application abuses", "VendorFix",
     "Incomplete fix for CVE-2021-44228 allows context lookup bypass in certain configurations."),
    ("CVE-2022-22965", "Spring Framework RCE (Spring4Shell)",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "8080/tcp", "High",
     "Web application abuses", "VendorFix",
     "Spring MVC/WebFlux applications using JDK 9+ are vulnerable to remote code execution."),
    ("CVE-2017-5638", "Apache Struts2 RCE via Content-Type header",
     10.0, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "80/tcp", "High",
     "Web application abuses", "VendorFix",
     "Remote code execution in Apache Struts2 via malicious Content-Type header."),
    ("CVE-2014-6271", "Bash Shellshock Remote Code Execution",
     10.0, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "80/tcp", "High",
     "General", "VendorFix",
     "Bash processes trailing strings after function definitions in environment variables."),
    ("CVE-2019-0708", "BlueKeep RDP Pre-Auth RCE",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "3389/tcp", "High",
     "Windows", "VendorFix",
     "A use-after-free vulnerability in Windows RDP allows unauthenticated RCE."),
    ("CVE-2017-0144", "EternalBlue SMB RCE",
     9.3, "AV:N/AC:M/Au:N/C:C/I:C/A:C", "445/tcp", "High",
     "Windows", "VendorFix",
     "SMBv1 allows remote code execution via specially crafted packets."),
    ("CVE-2021-26855", "Microsoft Exchange Server SSRF (ProxyLogon)",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "Windows", "VendorFix",
     "Exchange Server SSRF allows unauthenticated attackers to authenticate as Exchange server."),
    ("CVE-2020-1472", "Zerologon Netlogon Privilege Escalation",
     10.0, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "445/tcp", "High",
     "Windows", "VendorFix",
     "A cryptographic flaw in MS-NRPC allows privilege escalation to domain administrator."),
    ("CVE-2021-34527", "PrintNightmare Windows Print Spooler RCE",
     8.8, "AV:N/AC:L/Au:S/C:C/I:C/A:C", "445/tcp", "High",
     "Windows", "VendorFix",
     "Remote code execution in the Windows Print Spooler service."),
    ("CVE-2022-30190", "Follina MSDT RCE",
     7.8, "AV:N/AC:M/Au:N/C:C/I:C/A:C", "445/tcp", "High",
     "Windows", "VendorFix",
     "Malicious Word documents can invoke MSDT and execute arbitrary code."),
    ("CVE-2023-23397", "Microsoft Outlook Privilege Escalation NTLM Relay",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "445/tcp", "High",
     "Windows", "VendorFix",
     "Zero-click Outlook vulnerability leaks Net-NTLMv2 hash via calendar item."),
    ("CVE-2021-21985", "VMware vCenter RCE via vSAN Health Check",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "General", "VendorFix",
     "Remote code execution in vCenter Server vSAN Health Check plugin."),
    ("CVE-2018-13379", "Fortinet FortiOS SSL VPN Path Traversal",
     9.8, "AV:N/AC:L/Au:N/C:C/I:N/A:N", "443/tcp", "High",
     "General", "VendorFix",
     "Unauthenticated path traversal exposes system files including VPN credentials."),
    ("CVE-2019-11510", "Pulse Secure VPN Pre-Auth Arbitrary File Read",
     10.0, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "General", "VendorFix",
     "Pre-authentication arbitrary file read allows credential disclosure."),
    ("CVE-2021-22986", "F5 BIG-IP iControl REST Unauthenticated RCE",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "General", "VendorFix",
     "Unauthenticated remote code execution via iControl REST interface."),
    ("CVE-2020-5902", "F5 BIG-IP TMUI RCE",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "General", "VendorFix",
     "Remote code execution in TMUI (Traffic Management User Interface)."),
    ("CVE-2021-40444", "Microsoft MSHTML Remote Code Execution",
     8.8, "AV:N/AC:M/Au:N/C:C/I:C/A:C", "445/tcp", "High",
     "Windows", "VendorFix",
     "ActiveX control in MSHTML allows remote code execution via malicious Office documents."),
    ("CVE-2022-26134", "Atlassian Confluence OGNL Injection RCE",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "8090/tcp", "High",
     "Web application abuses", "VendorFix",
     "Critical OGNL injection vulnerability in Confluence Server and Data Center."),
    ("CVE-2021-27101", "Accellion FTA SQL Injection",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "General", "VendorFix",
     "SQL injection in Accellion FTA allows unauthenticated remote code execution."),
    # Medium severity
    ("CVE-2016-2183", "SWEET32 DES/3DES Birthday Attack on TLS",
     7.5, "AV:N/AC:L/Au:N/C:P/I:N/A:N", "443/tcp", "Medium",
     "SSL/TLS", "WillNotFix",
     "3DES ciphers in TLS/SSL are vulnerable to birthday attacks on 64-bit block ciphers."),
    ("CVE-2015-4000", "Logjam TLS DHE Key Exchange Weakness",
     3.7, "AV:N/AC:H/Au:N/C:P/I:N/A:N", "443/tcp", "Medium",
     "SSL/TLS", "WillNotFix",
     "Weak Diffie-Hellman parameters allow man-in-the-middle downgrade attack."),
    ("CVE-2014-3566", "POODLE SSLv3 Information Disclosure",
     5.0, "AV:N/AC:M/Au:N/C:P/I:N/A:N", "443/tcp", "Medium",
     "SSL/TLS", "WillNotFix",
     "SSLv3 CBC mode is vulnerable to padding oracle attacks leaking plaintext."),
    ("CVE-2013-2566", "RC4 Cipher Weakness in TLS",
     5.0, "AV:N/AC:M/Au:N/C:P/I:N/A:N", "443/tcp", "Medium",
     "SSL/TLS", "WillNotFix",
     "RC4 cipher in TLS/SSL has statistical biases that allow plaintext recovery."),
    ("CVE-2012-4929", "CRIME TLS Compression Information Disclosure",
     5.0, "AV:N/AC:M/Au:N/C:P/I:N/A:N", "443/tcp", "Medium",
     "SSL/TLS", "WillNotFix",
     "TLS compression allows oracle attacks to recover session cookies."),
    ("CVE-2022-0778", "OpenSSL BN_mod_sqrt Infinite Loop DoS",
     7.5, "AV:N/AC:L/Au:N/C:N/I:N/A:C", "443/tcp", "Medium",
     "SSL/TLS", "VendorFix",
     "Specially crafted certificate causes OpenSSL to loop indefinitely during parsing."),
    ("CVE-2021-3449", "OpenSSL NULL pointer dereference DoS",
     5.9, "AV:N/AC:H/Au:N/C:N/I:N/A:C", "443/tcp", "Medium",
     "SSL/TLS", "VendorFix",
     "A server using TLSv1.2 with renegotiation may crash via a ClientHello with a missing signature_algorithms extension."),
    ("CVE-2019-1010218", "Cherokee Web Server Heap Buffer Overflow",
     6.5, "AV:N/AC:L/Au:N/C:P/I:P/A:N", "80/tcp", "Medium",
     "Web Servers", "VendorFix",
     "Heap buffer overflow allows remote attackers to cause DoS or code execution."),
    ("CVE-2021-41773", "Apache HTTP Server 2.4.49 Path Traversal",
     7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P", "80/tcp", "Medium",
     "Web Servers", "VendorFix",
     "Path traversal vulnerability in Apache 2.4.49 allows disclosure of files outside root."),
    ("CVE-2021-42013", "Apache HTTP Server 2.4.49/50 Path Traversal RCE",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "80/tcp", "High",
     "Web Servers", "VendorFix",
     "Incomplete fix for CVE-2021-41773 allows RCE when mod_cgi is enabled."),
    ("CVE-2018-11776", "Apache Struts2 RCE via namespace",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "80/tcp", "High",
     "Web application abuses", "VendorFix",
     "RCE via namespace value without value and upper package not having a namespace."),
    ("CVE-2020-11022", "jQuery XSS via HTML passed to DOM manipulation methods",
     6.1, "AV:N/AC:L/Au:N/C:P/I:P/A:N", "80/tcp", "Medium",
     "Web application abuses", "VendorFix",
     "XSS vulnerability in jQuery when passing HTML containing < option > elements from untrusted sources."),
    ("CVE-2021-23017", "nginx DNS Resolver Off-by-One Heap Write",
     7.7, "AV:N/AC:H/Au:N/C:C/I:C/A:C", "80/tcp", "Medium",
     "Web Servers", "VendorFix",
     "Off-by-one error in DNS resolver allows memory corruption."),
    ("CVE-2022-31813", "Apache HTTP Server mod_proxy X-Forwarded-For Forgery",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "80/tcp", "High",
     "Web Servers", "VendorFix",
     "Apache mod_proxy may forward unexpected X-Forwarded-For headers."),
    ("CVE-2021-3156", "Sudo Heap Buffer Overflow (Baron Samedit)",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "Heap-based buffer overflow in sudo allows local privilege escalation to root."),
    ("CVE-2021-4034", "Polkit pkexec Local Privilege Escalation (PwnKit)",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "Memory corruption in pkexec allows local privilege escalation on all major Linux distros."),
    ("CVE-2022-0847", "Linux Kernel Dirty Pipe LPE",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "Overwriting data in arbitrary read-only files via pipe page flags."),
    ("CVE-2016-5195", "Dirty COW Linux Kernel Privilege Escalation",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "Race condition in Linux kernel memory subsystem allows privilege escalation."),
    ("CVE-2021-33909", "Linux Kernel seq_file Heap Buffer Overflow (Sequoia)",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "fs/seq_file.c size_t-to-int conversion flaw allows privilege escalation."),
    ("CVE-2023-0386", "Linux Kernel OverlayFS Privilege Escalation",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "OverlayFS allows privilege escalation when unprivileged user namespaces are available."),
    ("CVE-2023-2640", "Ubuntu OverlayFS Privilege Escalation (GameOver(lay))",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "Ubuntu-specific OverlayFS patch introduces privilege escalation via SUID binaries."),
    ("CVE-2021-41091", "Docker moby File Permissions Weakness",
     6.3, "AV:L/AC:L/Au:N/C:C/I:P/A:N", "2376/tcp", "Medium",
     "General", "VendorFix",
     "Incorrect permissions allow low-privilege users to access files in overlay filesystems."),
    ("CVE-2019-5736", "runc Container Escape",
     8.6, "AV:N/AC:M/Au:N/C:C/I:C/A:C", "2376/tcp", "High",
     "General", "VendorFix",
     "runc allows container escape via overwriting the host runc binary."),
    ("CVE-2022-0492", "Linux Kernel cgroup Release Agent Escape",
     7.8, "AV:L/AC:L/Au:N/C:C/I:C/A:C", "22/tcp", "High",
     "Privilege escalation", "VendorFix",
     "cgroups v1 release_agent file can be used to escape container."),
    ("CVE-2023-27997", "Fortinet FortiOS SSL-VPN Heap Overflow RCE",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "General", "VendorFix",
     "Pre-authentication heap overflow in FortiOS SSL-VPN allows RCE."),
    ("CVE-2023-34362", "MOVEit Transfer SQL Injection RCE",
     9.8, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "443/tcp", "High",
     "General", "VendorFix",
     "SQL injection in MOVEit Transfer web application allows RCE and data exfiltration."),
    ("CVE-2023-4966", "Citrix Bleed NetScaler Token Disclosure",
     9.4, "AV:N/AC:L/Au:N/C:C/I:C/A:N", "443/tcp", "High",
     "General", "VendorFix",
     "Buffer over-read leaks memory including session tokens from NetScaler ADC/Gateway."),
    ("CVE-2023-20198", "Cisco IOS XE Web UI Privilege Escalation",
     10.0, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "80/tcp", "High",
     "General", "VendorFix",
     "Unauthenticated attackers can create privilege level 15 accounts via Web UI."),
    ("CVE-2023-22515", "Atlassian Confluence Broken Access Control",
     10.0, "AV:N/AC:L/Au:N/C:C/I:C/A:C", "8090/tcp", "High",
     "Web application abuses", "VendorFix",
     "Unauthenticated attackers can create Confluence administrator accounts."),
    ("CVE-2023-44487", "HTTP/2 Rapid Reset DDoS",
     7.5, "AV:N/AC:L/Au:N/C:N/I:N/A:C", "443/tcp", "Medium",
     "Web Servers", "VendorFix",
     "HTTP/2 RST_STREAM flood allows unauthenticated DoS via rapid stream reset."),
    # Low severity
    ("CVE-1999-0524", "ICMP Timestamp Reply Information Disclosure",
     2.1, "AV:N/AC:L/Au:N/C:P/I:N/A:N", "general/icmp", "Low",
     "General", "Mitigation",
     "Remote host responds to ICMP timestamp requests, disclosing system time."),
    ("CVE-2000-0649", "NetBIOS Name Service Enumeration",
     5.0, "AV:N/AC:L/Au:N/C:P/I:N/A:N", "137/udp", "Medium",
     "Windows", "Mitigation",
     "NetBIOS name service reveals host and domain information."),
    ("CVE-1999-0261", "Finger Service Information Disclosure",
     5.0, "AV:N/AC:L/Au:N/C:P/I:N/A:N", "79/tcp", "Medium",
     "General", "Mitigation",
     "Finger service reveals user account information to remote attackers."),
    ("CVE-1999-0517", "SNMP Default Community String",
     7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P", "161/udp", "Medium",
     "General", "Mitigation",
     "Default SNMP community strings allow unauthorized read/write access."),
    ("CVE-2002-1054", "phpMyAdmin Information Disclosure",
     5.0, "AV:N/AC:L/Au:N/C:P/I:N/A:N", "80/tcp", "Medium",
     "Web application abuses", "VendorFix",
     "phpMyAdmin discloses server path and PHP version information."),
]

# ---------------------------------------------------------------------------
# Distribute 100 findings across 15 assets
# (roughly 6–7 findings each)
# ---------------------------------------------------------------------------
NUM_FINDINGS = 100

random.shuffle(CVE_POOL)
# Cycle through CVE pool to reach 100 entries
finding_templates = [CVE_POOL[i % len(CVE_POOL)] for i in range(NUM_FINDINGS)]
random.shuffle(finding_templates)

# Assign findings to assets
asset_findings = {ip: [] for ip in ALL_HOSTS}
for idx, tmpl in enumerate(finding_templates):
    ip = ALL_HOSTS[idx % NUM_ASSETS]
    asset_findings[ip].append(tmpl)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def new_uuid():
    return str(uuid.uuid4())

def make_asset_id(ip):
    import hashlib
    return "asset-" + hashlib.md5(ip.encode()).hexdigest()[:12]

NOW = "2025-09-24T23:44:11Z"
SCAN_START = "2025-09-24T23:35:37Z"
SCAN_END   = "2025-09-24T23:52:08Z"

def make_result_elem(ip, tmpl, result_id=None):
    cve, name, score, vector, port, threat, family, sol_type, summary = tmpl
    result_id = result_id or new_uuid()
    asset_id  = make_asset_id(ip)

    r = ET.Element("result", id=result_id)
    ET.SubElement(r, "name").text = name
    ET.SubElement(r, "modification_time").text = NOW
    ET.SubElement(r, "comment")
    ET.SubElement(r, "creation_time").text = NOW

    host_el = ET.SubElement(r, "host")
    host_el.text = ip
    ET.SubElement(host_el, "asset", asset_id=asset_id)
    ET.SubElement(host_el, "hostname")
    ET.SubElement(r, "port").text = port

    oid = f"1.3.6.1.4.1.25623.1.0.{abs(hash(cve)) % 900000 + 10000}"
    nvt = ET.SubElement(r, "nvt", oid=oid)
    ET.SubElement(nvt, "type").text = "nvt"
    ET.SubElement(nvt, "name").text = name
    ET.SubElement(nvt, "family").text = family
    ET.SubElement(nvt, "cvss_base").text = str(score)
    sevs = ET.SubElement(nvt, "severities", score=str(score))
    sev  = ET.SubElement(sevs, "severity", type="cvss_base_v2")
    ET.SubElement(sev, "origin")
    ET.SubElement(sev, "date").text = "2020-01-01T00:00:00Z"
    ET.SubElement(sev, "score").text = str(score)
    ET.SubElement(sev, "value").text = vector

    tags_text = (
        f"cvss_base_vector={vector}|summary={summary}"
        f"|solution=Refer to vendor advisory.|solution_type={sol_type}"
    )
    ET.SubElement(nvt, "tags").text = tags_text
    sol = ET.SubElement(nvt, "solution", type=sol_type)
    sol.text = "Refer to vendor advisory and apply the recommended patch."

    refs = ET.SubElement(nvt, "refs")
    ET.SubElement(refs, "ref", type="cve", id=cve)

    ET.SubElement(r, "scan_nvt_version").text = "2025-01-01T00:00:00Z"
    ET.SubElement(r, "threat").text = threat
    ET.SubElement(r, "severity").text = str(score)
    qod = ET.SubElement(r, "qod")
    ET.SubElement(qod, "value").text = "70"
    ET.SubElement(qod, "type")
    ET.SubElement(r, "original_threat").text = threat
    ET.SubElement(r, "original_severity").text = str(score)
    ET.SubElement(r, "compliance").text = "undefined"
    return r

# ---------------------------------------------------------------------------
# Build OpenVAS XML
# ---------------------------------------------------------------------------
def build_openvas():
    scan_id = new_uuid()
    outer = ET.Element("report",
                        content_type="text/xml",
                        extension="xml",
                        id=scan_id,
                        format_id="5057e5cc-b825-11e4-9d0e-28d24461215b",
                        config_id="")
    ET.SubElement(outer, "owner").text = "admin"
    ET.SubElement(outer, "name").text  = "2025-09-24T23:35:23Z"
    inner = ET.SubElement(outer, "report", id=scan_id)

    gmp = ET.SubElement(inner, "gmp")
    ET.SubElement(gmp, "version").text = "22.7"

    results_el = ET.SubElement(inner, "results", max="-1", start="1")
    total = 0
    for ip, findings in asset_findings.items():
        for tmpl in findings:
            results_el.append(make_result_elem(ip, tmpl))
            total += 1

    # host summaries
    for ip in ALL_HOSTS:
        host_el = ET.SubElement(inner, "host")
        ET.SubElement(host_el, "ip").text = ip
        ET.SubElement(host_el, "asset", asset_id=make_asset_id(ip))
        ET.SubElement(host_el, "start").text = SCAN_START
        ET.SubElement(host_el, "end").text   = SCAN_END

    rc = ET.SubElement(inner, "result_count")
    rc.text = str(total)

    ET.SubElement(inner, "severity").text = "10.0"
    return ET.ElementTree(outer)


# ---------------------------------------------------------------------------
# Build Nmap XML covering all 15 IPs
# ---------------------------------------------------------------------------
PORT_MAP = {
    "22/tcp":   ("ssh",   "OpenSSH",  "8.9p1 Debian"),
    "80/tcp":   ("http",  "Apache httpd", "2.4.49 (Unix)"),
    "443/tcp":  ("https", "Apache httpd", "2.4.49 (Unix)"),
    "445/tcp":  ("microsoft-ds", "Samba", "4.17.5"),
    "3389/tcp": ("ms-wbt-server", "xrdp", "0.9.17"),
    "8080/tcp": ("http-proxy", "nginx", "1.22.0"),
    "8090/tcp": ("http", "Confluence", "8.0.0"),
    "2376/tcp": ("docker", "Docker", "20.10"),
}

def ports_for_ip(ip):
    """Deterministically assign 2-4 open ports per host."""
    rng = random.Random(ip)
    pool = list(PORT_MAP.keys())
    return rng.sample(pool, k=rng.randint(2, 4))

def build_nmap():
    ts = "1776910608"
    root = ET.Element("nmaprun",
                       scanner="nmap",
                       args="/usr/bin/nmap -sS -sV -p- -oX scaled_nmap_15hosts.xml 192.168.170.0/24",
                       start=ts,
                       startstr="Wed Apr 23 00:00:00 2026",
                       version="7.99",
                       xmloutputversion="1.05")
    ET.SubElement(root, "scaninfo", type="syn", protocol="tcp",
                  numservices="65535", services="1-65535")

    for ip in ALL_HOSTS:
        host = ET.SubElement(root, "host",
                             starttime=ts, endtime=str(int(ts)+30))
        status = ET.SubElement(host, "status", state="up",
                               reason="arp-response", reason_ttl="64")
        ET.SubElement(host, "address", addr=ip, addrtype="ipv4")
        ports_el = ET.SubElement(host, "ports")
        for portspec in ports_for_ip(ip):
            portid, proto = portspec.split("/")
            svc_name, product, version = PORT_MAP[portspec]
            port_el = ET.SubElement(ports_el, "port",
                                    protocol=proto, portid=portid)
            ET.SubElement(port_el, "state", state="open",
                          reason="syn-ack", reason_ttl="64")
            ET.SubElement(port_el, "service",
                          name=svc_name, product=product,
                          version=version, method="probed", conf="10")

        times = ET.SubElement(host, "times",
                              srtt="700", rttvar="200", to="100000")

    rs = ET.SubElement(root, "runstats")
    fin = ET.SubElement(rs, "finished",
                        time=str(int(ts)+60),
                        timestr="Wed Apr 23 00:01:00 2026",
                        summary="Nmap done",
                        elapsed="60.0",
                        exit="success")
    hosts_el = ET.SubElement(rs, "hosts",
                              up=str(NUM_ASSETS), down="0",
                              total=str(NUM_ASSETS))
    return ET.ElementTree(root)


# ---------------------------------------------------------------------------
# Write files
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ET.indent(build_openvas().getroot())
    build_openvas().write(str(OPENVAS_OUT), encoding="unicode", xml_declaration=True)
    print(f"OpenVAS: {OPENVAS_OUT}  ({OPENVAS_OUT.stat().st_size:,} bytes)")

    ET.indent(build_nmap().getroot())
    build_nmap().write(str(NMAP_OUT), encoding="unicode", xml_declaration=True)
    print(f"Nmap:    {NMAP_OUT}  ({NMAP_OUT.stat().st_size:,} bytes)")

    # Quick validation
    import xml.etree.ElementTree as ET2
    ov = ET2.parse(str(OPENVAS_OUT))
    results = ov.findall(".//result")
    ips = {r.findtext("host") for r in results}
    cves = [r.find(".//ref[@type='cve']") for r in results]
    print(f"OpenVAS: {len(results)} results across {len(ips)} IPs — all have CVE: {all(c is not None for c in cves)}")

    nm = ET2.parse(str(NMAP_OUT))
    nmap_ips = {a.get("addr") for a in nm.findall(".//address[@addrtype='ipv4']")}
    print(f"Nmap:    {len(nmap_ips)} hosts — IPs match OpenVAS assets: {nmap_ips == set(ALL_HOSTS)}")
