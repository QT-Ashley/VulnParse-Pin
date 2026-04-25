"""Regenerate src/vulnparse_pin/resources/openvas_updated_test.xml with 30 profiles.

Headline profiles (10): appear exactly once per asset — guarantees TopN k=5 picks distinct titles.
Filler profiles (20): cycle through remaining ~133 findings per asset.
"""
import random
import os

random.seed(24042026)

# ---------------------------------------------------------------------------
# 30 vulnerability profiles
# ---------------------------------------------------------------------------
PROFILES = [
    # HEADLINE 0-9 — high CVSS, appear ONCE per asset
    dict(name="Log4Shell Remote Code Execution via JNDI",
         port="8080/tcp", cvss="10.0", threat="Critical", family="General",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Log4j JNDI lookup enables unauthenticated remote code execution via crafted log message.",
         summary="remote code execution, command execution, rce, initial access pathway, exploit available",
         solution="Upgrade Log4j to 2.17.1 or later and remove JndiLookup class from classpath."),
    dict(name="Spring4Shell Remote Code Execution",
         port="8443/tcp", cvss="9.8", threat="Critical", family="Web application abuses",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Spring Framework ClassLoader manipulation permits unauthenticated remote code execution.",
         summary="remote code execution, command execution, rce, initial access, exploit",
         solution="Upgrade Spring Framework to 5.3.18+ and Spring Boot to 2.6.6+."),
    dict(name="Remote Code Execution via Unsafe Deserialization",
         port="8080/tcp", cvss="9.4", threat="Critical", family="General",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Unsafe deserialization permits unauthenticated remote code execution and initial access foothold.",
         summary="remote code execution, command execution, exploit available, initial access pathway",
         solution="Disable unsafe deserialization paths and patch affected middleware immediately."),
    dict(name="EternalBlue SMB Remote Code Execution MS17-010",
         port="445/tcp", cvss="9.3", threat="Critical", family="Windows",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Unpatched SMBv1 vulnerability MS17-010 allows remote code execution without authentication.",
         summary="rce, remote code execution, smb, lateral movement, exploit available, initial access",
         solution="Apply MS17-010 patch, disable SMBv1 and restrict port 445 at the perimeter."),
    dict(name="SQL Injection in Authentication Workflow",
         port="443/tcp", cvss="9.1", threat="Critical", family="Web application abuses",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Insufficient input sanitization allows SQL injection using UNION SELECT against authentication endpoints.",
         summary="sql injection, union select, information disclosure, sensitive data leak from database query execution",
         solution="Apply parameterized queries and deploy WAF signatures for SQL injection patterns."),
    dict(name="Apache HTTP Server Path Traversal",
         port="80/tcp", cvss="8.6", threat="High", family="Web Servers",
         vector="AV:N/AC:L/Au:N/C:P/I:P/A:P",
         desc="Path traversal in Apache HTTP Server may allow unauthorized file read and remote compromise of web content.",
         summary="path traversal, local file inclusion, file read, /etc/passwd exposure risk on internet-facing service",
         solution="Upgrade Apache HTTP Server to a patched release and harden request normalization controls."),
    dict(name="Privilege Escalation Through Sudo Misconfiguration",
         port="22/tcp", cvss="8.2", threat="High", family="Privilege escalation",
         vector="AV:L/AC:L/Au:N/C:C/I:C/A:C",
         desc="Sudo policy permits privilege escalation to root via command injection on maintenance scripts.",
         summary="privilege escalation, sudo, setuid, command injection and persistence startup path",
         solution="Correct sudoers configuration and remove unsafe privileged command delegates."),
    dict(name="Authentication Bypass with Default Credentials",
         port="8443/tcp", cvss="7.4", threat="Medium", family="General",
         vector="AV:N/AC:L/Au:N/C:P/I:P/A:P",
         desc="Administrative portal accepts default credential combinations enabling authentication bypass and initial access.",
         summary="authentication bypass, bypass login, default credential, credential access and initial access risk",
         solution="Rotate all default credentials and enforce MFA and account lockout controls."),
    dict(name="Kerberos Ticket Exposure in Logs",
         port="88/tcp", cvss="6.9", threat="Medium", family="Windows",
         vector="AV:N/AC:M/Au:N/C:P/I:N/A:N",
         desc="Verbose logging leaks Kerberos ticket material and credential artifacts usable for lateral movement.",
         summary="credential, password hash, token leakage, smb and rpc movement opportunities",
         solution="Restrict log verbosity and scrub credential artifacts from authentication logs."),
    dict(name="XML External Entity Injection in API Parser",
         port="443/tcp", cvss="7.5", threat="Medium", family="Web application abuses",
         vector="AV:N/AC:L/Au:N/C:P/I:P/A:N",
         desc="XXE injection in XML API parser allows server-side request forgery and sensitive file read.",
         summary="information disclosure, sensitive data, lfi, local file inclusion, ssrf via xxe injection",
         solution="Disable external entity resolution in XML parsers and validate all incoming XML input."),

    # FILLER 10-29 — cycle for remaining findings
    dict(name="Sensitive API Keys Stored in World-Readable Files",
         port="22/tcp", cvss="6.6", threat="Medium", family="General",
         vector="AV:L/AC:L/Au:N/C:C/I:N/A:N",
         desc="Application configuration stores API keys and private key material in world-readable filesystem paths.",
         summary="api key, token, secret, private key, hardcoded credential and information disclosure risk",
         solution="Move secrets to a vault solution and restrict file permissions to owner-only read."),
    dict(name="SMB Signing Disabled on File Service",
         port="445/tcp", cvss="5.8", threat="Medium", family="Windows",
         vector="AV:N/AC:M/Au:N/C:P/I:P/A:N",
         desc="SMB signing is disabled allowing relay and man-in-the-middle credential capture.",
         summary="smb signing, credential relay, lateral movement, rpc relay potential",
         solution="Enable SMB signing via Group Policy on all hosts and restrict NTLM relay paths."),
    dict(name="TLS Deprecated Cipher Suites Enabled",
         port="443/tcp", cvss="3.9", threat="Low", family="SSL and TLS",
         vector="AV:N/AC:H/Au:N/C:P/I:N/A:N",
         desc="Server advertises deprecated cipher suites enabling downgrade and weak key negotiation.",
         summary="tls downgrade, weak cipher, information disclosure risk on encrypted transport channel",
         solution="Remove RC4, DES, and 3DES cipher suites and enforce TLS 1.2+ with strong cipher lists."),
    dict(name="Directory Listing Enabled on Web Root",
         port="80/tcp", cvss="3.4", threat="Low", family="Web Servers",
         vector="AV:N/AC:L/Au:N/C:P/I:N/A:N",
         desc="Web server directory listing reveals internal file structure and sensitive file paths.",
         summary="information disclosure, directory listing, sensitive data exposure on public web root",
         solution="Disable directory listing in web server configuration and enforce access controls."),
    dict(name="Redis Server Unauthenticated Access",
         port="6379/tcp", cvss="9.8", threat="Critical", family="Databases",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Redis service exposed without authentication allows arbitrary key read, write, and OS command execution.",
         summary="remote code execution, initial access, credential, sensitive data, database command execution",
         solution="Require requirepass authentication and bind Redis to loopback or VPN interface only."),
    dict(name="FTP Anonymous Login Enabled",
         port="21/tcp", cvss="7.5", threat="Medium", family="FTP",
         vector="AV:N/AC:L/Au:N/C:P/I:P/A:N",
         desc="FTP service permits anonymous login enabling unauthenticated file read and write.",
         summary="information disclosure, sensitive data, initial access, file read via ftp anonymous credential",
         solution="Disable anonymous FTP and enforce authenticated TLS-secured connections."),
    dict(name="Telnet Service Running in Cleartext",
         port="23/tcp", cvss="8.8", threat="High", family="General",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Telnet transmits credentials and session data in cleartext enabling credential theft.",
         summary="credential, password, initial access, information disclosure, cleartext auth bypass risk",
         solution="Disable Telnet and migrate to SSH with key-based authentication and strong ciphers."),
    dict(name="SNMP Default Community String Accepted",
         port="161/udp", cvss="7.5", threat="Medium", family="SNMP",
         vector="AV:N/AC:L/Au:N/C:P/I:P/A:N",
         desc="SNMP accepts default community strings public and private exposing full MIB tree.",
         summary="information disclosure, sensitive data, credential, default credential, initial access via snmp",
         solution="Change SNMP community strings, migrate to SNMPv3 with auth and privacy options."),
    dict(name="OpenSSL Heartbleed Memory Disclosure",
         port="443/tcp", cvss="7.5", threat="Medium", family="SSL and TLS",
         vector="AV:N/AC:L/Au:N/C:C/I:N/A:N",
         desc="Heartbleed allows remote read of heap memory including private keys and session credentials.",
         summary="information disclosure, sensitive data, private key, credential, token leakage via openssl",
         solution="Upgrade OpenSSL to 1.0.1g or later and revoke and reissue all certificates."),
    dict(name="Unrestricted File Upload Leading to RCE",
         port="8080/tcp", cvss="9.0", threat="Critical", family="Web application abuses",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
         desc="Upload endpoint accepts arbitrary file types enabling web shell upload and remote code execution.",
         summary="remote code execution, command execution, rce, initial access, exploit via file upload",
         solution="Validate MIME type and extension server-side and store uploads outside webroot."),
    dict(name="Insecure Direct Object Reference in REST API",
         port="443/tcp", cvss="6.5", threat="Medium", family="Web application abuses",
         vector="AV:N/AC:L/Au:S/C:C/I:N/A:N",
         desc="API endpoints expose internal object identifiers allowing cross-account data access.",
         summary="information disclosure, sensitive data, credential, token exposure via insecure reference",
         solution="Enforce object-level authorization checks and mask internal identifiers in API responses."),
    dict(name="Weak JWT Signing Algorithm in Auth Token",
         port="443/tcp", cvss="8.1", threat="High", family="Web application abuses",
         vector="AV:N/AC:L/Au:N/C:C/I:C/A:N",
         desc="Application accepts JWTs signed with the none algorithm enabling authentication bypass.",
         summary="authentication bypass, bypass login, token, credential access, initial access via jwt weakness",
         solution="Require strong HMAC or RSA signature algorithms and reject unsigned or weakly signed tokens."),
    dict(name="SSH Weak Key Exchange Algorithms Permitted",
         port="22/tcp", cvss="5.9", threat="Medium", family="General",
         vector="AV:N/AC:H/Au:N/C:P/I:P/A:N",
         desc="SSH server negotiates deprecated Diffie-Hellman groups enabling passive key recovery.",
         summary="credential, private key, information disclosure, weak kex downgrade on ssh service",
         solution="Remove diffie-hellman-group1-sha1 and diffie-hellman-group14-sha1 from sshd_config."),
    dict(name="Cross-Site Request Forgery on Admin Panel",
         port="80/tcp", cvss="7.1", threat="Medium", family="Web application abuses",
         vector="AV:N/AC:M/Au:N/C:N/I:C/A:N",
         desc="Admin panel lacks CSRF tokens enabling attacker-crafted requests to modify configuration.",
         summary="authentication bypass, credential, initial access risk, bypass login via csrf attack",
         solution="Implement synchronizer token pattern and SameSite cookie attribute on all state-changing endpoints."),
    dict(name="Reflected XSS in Error Page Parameter",
         port="80/tcp", cvss="6.1", threat="Medium", family="Web application abuses",
         vector="AV:N/AC:L/Au:N/C:P/I:P/A:N",
         desc="Error page reflects unsanitized URL parameters enabling script injection in victim sessions.",
         summary="information disclosure, token, credential, sensitive data via xss script injection",
         solution="Sanitize all user-supplied input rendered in HTML and enforce a strict Content-Security-Policy."),
    dict(name="DNS Zone Transfer Allowed from Any Source",
         port="53/tcp", cvss="5.3", threat="Medium", family="DNS",
         vector="AV:N/AC:L/Au:N/C:P/I:N/A:N",
         desc="DNS server permits zone transfer to any requester exposing internal host inventory.",
         summary="information disclosure, sensitive data, credential, internal network topology leak via dns axfr",
         solution="Restrict AXFR queries to authorised secondary nameservers using allow-transfer ACLs."),
    dict(name="HTTP Security Headers Missing on Web Application",
         port="80/tcp", cvss="4.3", threat="Low", family="Web Servers",
         vector="AV:N/AC:M/Au:N/C:P/I:N/A:N",
         desc="Application responses omit X-Frame-Options, HSTS, and CSP headers enabling content injection.",
         summary="information disclosure, sensitive data, token, credential leakage via missing security headers",
         solution="Configure X-Frame-Options DENY, Strict-Transport-Security, and Content-Security-Policy headers."),
    dict(name="Outdated jQuery Version with Known XSS Vulnerabilities",
         port="443/tcp", cvss="4.3", threat="Low", family="Web application abuses",
         vector="AV:N/AC:M/Au:N/C:P/I:N/A:N",
         desc="Application loads jQuery version with prototype pollution and XSS vulnerabilities.",
         summary="information disclosure, token, sensitive data, credential exposure via client-side library",
         solution="Upgrade jQuery to the latest stable release and implement Subresource Integrity checks."),
    dict(name="NFS Share World-Readable Without Authentication",
         port="2049/tcp", cvss="6.5", threat="Medium", family="NFS",
         vector="AV:N/AC:L/Au:N/C:C/I:N/A:N",
         desc="NFS export accessible from any host exposing filesystem contents without authentication.",
         summary="information disclosure, sensitive data, api key, private key, credential via nfs read access",
         solution="Restrict NFS exports to specific IP ranges and enforce Kerberos authentication."),
    dict(name="Memcached UDP Amplification Attack Surface",
         port="11211/udp", cvss="5.3", threat="Medium", family="General",
         vector="AV:N/AC:L/Au:N/C:N/I:N/A:P",
         desc="Memcached UDP port exposed enabling amplification-based denial of service.",
         summary="information disclosure, sensitive data exposure via open memcached udp service",
         solution="Disable UDP on Memcached and bind to loopback interface or authenticated VPN only."),
]

HEADLINE_COUNT = 10
FILLER_COUNT   = 20
assert len(PROFILES) == HEADLINE_COUNT + FILLER_COUNT

REAL_CVES_ASSET0 = [
    "CVE-2021-44228","CVE-2021-45046","CVE-2022-22965","CVE-2017-5638","CVE-2014-6271",
    "CVE-2019-0708","CVE-2020-1472","CVE-2021-34527","CVE-2017-0144","CVE-2019-19781",
    "CVE-2021-26084","CVE-2021-21985","CVE-2021-44832","CVE-2022-22963","CVE-2021-26855",
    "CVE-2021-27065","CVE-2020-0601","CVE-2020-14882","CVE-2020-14750","CVE-2020-17519",
    "CVE-2019-11510","CVE-2019-18935","CVE-2018-13379","CVE-2020-5902","CVE-2021-22986",
    "CVE-2021-40438","CVE-2021-41773","CVE-2021-42013","CVE-2022-1388","CVE-2022-26134",
    "CVE-2022-30190","CVE-2021-34473","CVE-2021-31207","CVE-2021-26857","CVE-2021-26858",
    "CVE-2021-27078","CVE-2022-24682","CVE-2021-21972","CVE-2021-21974","CVE-2021-22005",
]

NUM_ASSETS         = 15
FILLER_PER_ASSET   = 133
TOTAL_PER_ASSET    = HEADLINE_COUNT + FILLER_PER_ASSET  # 143

TOTAL_FINDINGS = NUM_ASSETS * TOTAL_PER_ASSET
multi_cve_targets = set(random.sample(range(TOTAL_FINDINGS), 30))

SERVICES = ["22/tcp","80/tcp","443/tcp","8080/tcp","8443/tcp","21/tcp",
            "23/tcp","25/tcp","3389/tcp","445/tcp","88/tcp","3306/tcp",
            "6379/tcp","27017/tcp","5432/tcp"]

lines = []
lines.append("<?xml version='1.0' encoding='utf-8'?>")
lines.append("<report>")
lines.append('  <report id="demo-openvas-realistic">')
lines.append("    <creation_time>2026-04-24T21:05:00Z</creation_time>")
lines.append("    <results>")

global_idx = 0
for asset in range(NUM_ASSETS):
    ip = f"192.168.170.{20 + asset}"

    # Per-asset CVE pool (disjoint across assets)
    if asset == 0:
        cve_pool = list(REAL_CVES_ASSET0)
        cve_pool += [f"CVE-2023-{50000 + i}" for i in range(300 - len(cve_pool))]
    else:
        start = 1000 + asset * 300
        cve_pool = [f"CVE-20{21 + (asset // 5)}-{start + i:05d}" for i in range(300)]

    cve_pos = [0]

    def next_cve() -> str:
        c = cve_pool[cve_pos[0] % len(cve_pool)]
        cve_pos[0] += 1
        return c

    local_idx = 0

    # --- headline findings (one per headline profile, unique title per asset) ---
    for hi in range(HEADLINE_COUNT):
        p = PROFILES[hi]
        oid = f"1.3.6.1.4.1.25623.1.0.{asset + 1:02d}{local_idx + 1:04d}"
        rid = f"demo-r-{asset + 1:02d}-{local_idx + 1:04d}"
        cves = [next_cve()]
        if global_idx in multi_cve_targets:
            cves.append(next_cve())
        refs_xml = "".join(
            f'          <ref type="cve" id="{c}" />\n' for c in cves
        )
        lines.append(f'      <result id="{rid}">')
        lines.append(f'        <name>{p["name"]}</name>')
        lines.append("        <creation_time>2026-04-24T21:05:00Z</creation_time>")
        lines.append("        <modification_time>2026-04-24T21:05:00Z</modification_time>")
        lines.append(f"        <host>{ip}</host>")
        lines.append(f'        <port>{p["port"]}</port>')
        lines.append(f'        <description>{p["desc"]}</description>')
        lines.append(f'        <nvt oid="{oid}">')
        lines.append(f'          <name>{p["name"]}</name>')
        lines.append(f'          <family>{p["family"]}</family>')
        lines.append(f'          <cvss_base>{p["cvss"]}</cvss_base>')
        lines.append(
            f'          <tags>cvss_base_vector={p["vector"]}|summary={p["summary"]}'
            f'|solution={p["solution"]}|solution_type=VendorFix</tags>'
        )
        lines.append(f'          <solution type="VendorFix">{p["solution"]}</solution>')
        lines.append("          <refs>")
        for c in cves:
            lines.append(f'            <ref type="cve" id="{c}" />')
        lines.append("          </refs>")
        lines.append("        </nvt>")
        lines.append(f'        <threat>{p["threat"]}</threat>')
        lines.append(f'        <severity>{p["cvss"]}</severity>')
        lines.append("      </result>")
        local_idx += 1
        global_idx += 1

    # --- filler findings (cycle through profiles 10-29) ---
    for fi in range(FILLER_PER_ASSET):
        pi = HEADLINE_COUNT + (fi % FILLER_COUNT)
        p = PROFILES[pi]
        oid = f"1.3.6.1.4.1.25623.1.0.{asset + 1:02d}{local_idx + 1:04d}"
        rid = f"demo-r-{asset + 1:02d}-{local_idx + 1:04d}"
        cves = [next_cve()]
        if global_idx in multi_cve_targets:
            cves.append(next_cve())
        # vary port on repeated cycles
        port = p["port"] if fi < FILLER_COUNT else SERVICES[fi % len(SERVICES)]
        lines.append(f'      <result id="{rid}">')
        lines.append(f'        <name>{p["name"]}</name>')
        lines.append("        <creation_time>2026-04-24T21:05:00Z</creation_time>")
        lines.append("        <modification_time>2026-04-24T21:05:00Z</modification_time>")
        lines.append(f"        <host>{ip}</host>")
        lines.append(f"        <port>{port}</port>")
        lines.append(f'        <description>{p["desc"]}</description>')
        lines.append(f'        <nvt oid="{oid}">')
        lines.append(f'          <name>{p["name"]}</name>')
        lines.append(f'          <family>{p["family"]}</family>')
        lines.append(f'          <cvss_base>{p["cvss"]}</cvss_base>')
        lines.append(
            f'          <tags>cvss_base_vector={p["vector"]}|summary={p["summary"]}'
            f'|solution={p["solution"]}|solution_type=VendorFix</tags>'
        )
        lines.append(f'          <solution type="VendorFix">{p["solution"]}</solution>')
        lines.append("          <refs>")
        for c in cves:
            lines.append(f'            <ref type="cve" id="{c}" />')
        lines.append("          </refs>")
        lines.append("        </nvt>")
        lines.append(f'        <threat>{p["threat"]}</threat>')
        lines.append(f'        <severity>{p["cvss"]}</severity>')
        lines.append("      </result>")
        local_idx += 1
        global_idx += 1

lines.append("    </results>")
lines.append("  </report>")
lines.append("</report>")

xml = "\n".join(lines)
out_path = os.path.join(
    os.path.dirname(__file__), "..", "src", "vulnparse_pin", "resources", "openvas_updated_test.xml"
)
out_path = os.path.abspath(out_path)
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(xml)

print(f"Written {len(xml):,} bytes to {out_path}")
print(f"Total findings: {global_idx}  ({NUM_ASSETS} assets x {TOTAL_PER_ASSET} each)")
print(f"Headline profiles per asset: {HEADLINE_COUNT} (unique titles guaranteed in TopN)")
print(f"Filler cycle: {FILLER_COUNT} profiles x ~{FILLER_PER_ASSET // FILLER_COUNT} per asset")
