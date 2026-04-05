# ScanResult JSON Schema

## Overview

The `ScanResult` object is the primary output structure from VulnParse-Pin. It contains all vulnerability data parsed and enriched from your scanner reports. This document describes the complete schema structure so you can understand and validate the JSON output.

## Schema Location

The official JSON Schema for ScanResult is included with VulnParse-Pin:

```
vulnparse_pin/core/schemas/scanResult.schema.json
```

This schema conforms to [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/schema) and is used for runtime validation of all ScanResult objects.

## Top-Level Structure

Every ScanResult contains three required properties:

```json
{
  "scan_metadata": { ... },
  "assets": [ ... ],
  "derived": { ... }
}
```

---

## ScanMetaData

Contains information about the source scan.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | string | ✓ | Vulnerability scanner source (e.g., `"Nessus"`, `"OpenVAS"`) |
| `scan_date` | string/number | ✓ | ISO 8601 timestamp or Unix timestamp of scan execution |
| `asset_count` | integer | ✓ | Total number of scanned assets (≥ 0) |
| `vulnerability_count` | integer | ✓ | Total vulnerabilities detected (≥ 0) |
| `parsed_at` | string/null | - | ISO 8601 timestamp when VulnParse-Pin parsed this report |
| `source_file` | string/null | - | Original scanner report file path |
| `scan_name` | string/null | - | Human-readable scan name/identifier |

### Example

```json
{
  "source": "Nessus",
  "scan_date": "2026-03-28T14:32:00Z",
  "asset_count": 42,
  "vulnerability_count": 1205,
  "parsed_at": "2026-03-28T14:35:12.123456Z",
  "source_file": "/scans/network_perimeter_v1.nessus",
  "scan_name": "Q1 2026 Network Perimeter"
}
```

---

## Assets

An array of scanned systems or network devices.

### Asset Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | ✓ | FQDN or hostname (non-empty) |
| `ip_address` | string | ✓ | IPv4 or IPv6 address |
| `asset_id` | string/null | - | Auto-generated unique identifier (hash of hostname + IP) |
| `criticality` | string/null | - | Asset criticality level: `"Extreme"` (3+ Critical findings), `"High"` (1+ Critical or 2+ High), `"Medium"` (1 High), `"Low"` (none). Used in TopN exposure inference rules (as lowercase: `extreme`, `high`, `medium`, `low`) |
| `avg_risk_score` | number/null | - | Average risk score across all findings (0-10 scale) |
| `os` | string/null | - | Detected operating system |
| `shodan_data` | object/null | - | Additional intelligence from Shodan (if enrichment enabled) |
| `findings` | array | ✓ | Array of vulnerabilities on this asset |

### Example

```json
{
  "asset_id": "A-db8f3e5d",
  "hostname": "web-prod-01.example.com",
  "ip_address": "203.0.113.42",
  "criticality": "Extreme",
  "avg_risk_score": 7.8,
  "os": "Linux 5.15.0-1234",
  "findings": [...]
}
```

---

## Findings

Individual vulnerability records. Each asset contains an array of findings.

### Finding Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `finding_id` | string | ✓ | Unique ID (hash of asset, scanner_sig, protocol, port, title) |
| `vuln_id` | string | ✓ | Scanner plugin/OID identifier |
| `title` | string | ✓ | Vulnerability name (non-empty) |
| `description` | string | ✓ | Detailed vulnerability description |
| `severity` | string | ✓ | Scanner severity (e.g., `"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Info"`) |
| `cves` | array | ✓ | Associated CVE IDs (array of strings) |
| `asset_id` | string/null | - | Reference to parent asset |

### Scoring Fields

| Field | Type | Description |
|-------|------|-------------|
| `cvss_score` | number/null | CVSS score (0-10) |
| `cvss_vector` | string/null | CVSS vector string (e.g., `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`) |
| `raw_risk_score` | number/null | Initial score from scoring pass (before adjustments) |
| `risk_score` | number/null | Final adjusted risk score after TopN prioritization |
| `risk_band` | string/null | Risk classification (`"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Minimal"`) |

### Intelligence Fields

| Field | Type | Description |
|-------|------|-------------|
| `epss_score` | number/null | EPSS score from CISA/NVD (0-1) |
| `cisa_kev` | boolean/null | Whether on CISA Known Exploited Vulnerabilities list |
| `exploit_available` | boolean/null | Public exploit exists |
| `exploit_references` | array/null | References to public exploits |
| `enriched` | boolean/null | Whether enrichment was applied |
| `enrichment_source_cve` | string/null | CVE from which enrichment data was sourced |

### Scanner Details

| Field | Type | Description |
|-------|------|-------------|
| `detection_plugin` | string/null | Scanner detection method |
| `plugin_output` | string/null | Raw scanner plugin output |
| `plugin_evidence` | array/null | Evidence items from scanner |
| `affected_port` | integer/null | Network port (0-65535) |
| `protocol` | string/null | Protocol (tcp, udp, icmp, etc.) |

### Remediation Fields

| Field | Type | Description |
|-------|------|-------------|
| `solution` | string/null | Patching/remediation guidance |
| `references` | array/null | External references (URLs, documentation) |
| `triage_priority` | string/null | Priority from TopN triage pass |

### Example

```json
{
  "finding_id": "F-a7c2b9e1",
  "vuln_id": "95054",
  "asset_id": "A-db8f3e5d",
  "title": "Remote Code Execution in OpenSSH",
  "description": "A remote attacker can execute arbitrary code...",
  "severity": "Critical",
  "cves": ["CVE-2024-6387"],
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "epss_score": 0.76,
  "cisa_kev": true,
  "exploit_available": true,
  "affected_port": 22,
  "protocol": "tcp",
  "raw_risk_score": 8.5,
  "risk_score": 9.2,
  "risk_band": "Critical",
  "triage_priority": "Critical",
  "enriched": true,
  "enrichment_source_cve": "CVE-2024-6387",
  "solution": "Upgrade OpenSSH to version 9.8 or later",
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"
  ]
}
```

---

## Derived Context

Container for results from post-parsing passes (Scoring, TopN, etc.).

| Field | Type | Description |
|-------|------|-------------|
| `passes` | object | Dictionary mapping pass names to their results |

---

## Schema Validation

### Using jsonschema Library

```python
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema

# After parsing/enriching your scan
validate_scan_result_schema(my_scan_result)
# Raises ValueError if validation fails
```

### Validating JSON Files

To validate a VulnParse-Pin JSON output file against the schema:

```bash
# Using Python
python -m jsonschema \
  -i output.json \
  -s vulnparse_pin/core/schemas/scanResult.schema.json
```

### Custom Validation

You can also use the schema directly with your preferred JSON Schema validator:

```python
from jsonschema import Draft202012Validator
import json

with open('output.json') as f:
    data = json.load(f)

with open('vulnparse_pin/core/schemas/scanResult.schema.json') as f:
    schema = json.load(f)

validator = Draft202012Validator(schema)
for error in validator.iter_errors(data):
    print(f"Validation error: {error.message}")
```

---

## Common Patterns

### Filter by Risk Band

```python
critical_findings = [
    f for asset in scan.assets 
    for f in asset.findings 
    if f.risk_band == "Critical"
]
```

### Find CISA KEV Vulnerabilities

```python
kev_findings = [
    f for asset in scan.assets 
    for f in asset.findings 
    if f.cisa_kev
]
```

### Group by Severity

```python
from collections import defaultdict

by_severity = defaultdict(list)
for asset in scan.assets:
    for finding in asset.findings:
        by_severity[finding.severity].append(finding)
```

### Export to CSV

See the `--output-csv` flag in the [CLI documentation](Usage.md) for direct CSV export with schema-aware field handling.

---

## Notes

- **asset_id**: Auto-generated as a hash of the hostname and IP address. Same asset across multiple scans will have the same ID.
- **finding_id**: Uniquely identifies a vulnerability on a specific asset. Deduplication by finding_id prevents double-counting the same vulnerability instance.
- **Times**: Can be ISO 8601 strings or Unix timestamps; both are handled transparently.
- **Nullability**: Fields marked as nullable (type `"string/null"`) will be `null` if data is unavailable.
- **Risk Scores**: After enrichment and the Scoring pass, findings will have raw/risk scores. Before these passes, these fields may be `null`.

---

## Related Documentation

- [Installation](Installation.md)
- [Detection and Parsing](Detection%20and%20Parsing.md)
- [Getting Started In 5 Minutes](Getting%20Started%20In%205%20Minutes.md)
- [Pass Phases](Pass%20Phases.md)
