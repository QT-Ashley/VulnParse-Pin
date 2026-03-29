# Detection and Parsing

This document explains how VulnParse-Pin decides what parser to use and how it converts scanner output into a unified model.

## Detection subsystem

Schema detection is implemented in `src/vulnparse_pin/core/schema_detector.py`.

### Detection strategy

1. **Format sniff** from the leading bytes of the file
2. **Parser probe** via parser `detect_file()` methods
3. **Confidence tie-break** using score, parser priority, and stable ordering
4. **Decision evidence** retained for transparency/debugging

Registered parser specs are defined in `src/vulnparse_pin/parsers/__init__.py`.

### Graduated confidence scoring (v1.0.3+)

`detect_file()` classmethods return `(float, list[tuple[str, str]])` instead of a plain boolean.
The float is a **confidence score in [0.0, 1.0]** built from additive weighted signals.
A parser is considered *matched* when `confidence >= 0.50`.

`SchemaDetector` also handles legacy `bool` returns for third-party parsers (maps `True → 0.9`, `False → 0.0`).

### Format sniff and BOM handling

`SchemaDetector._sniff_format` reads the first 4 KB and checks the leading byte:

- `{` or `[` → `"json"`
- `<` → `"xml"`

A UTF-8 BOM (`\xef\xbb\xbf`) is stripped before inspection so BOM-prefixed files are classified correctly.

## Supported parser classes

### Production-ready (v1.0 stable)

- `NessusXMLParser` (`src/vulnparse_pin/parsers/nessusXML_parser.py`) — Full v1.0 API contract
- `OpenVASXMLParser` (`src/vulnparse_pin/parsers/openvasXML_parser.py`) — Full v1.0 API contract

These parsers have been tested extensively with real-world fixtures and are recommended for production workflows. Their input/output contracts are stable and will not change without a major version bump.

### Experimental (subject to change)

- `NessusParser` JSON (`src/vulnparse_pin/parsers/nessus_parser.py`) — Fallback path, not default
- `OpenVASParser` JSON (`src/vulnparse_pin/parsers/openvas_parser.py`) — Fallback path, not default

The JSON parsers are marked experimental and are not the default path for production workflows. Their behavior and output format may evolve in future releases, and should not be relied upon for long-term integrations. Use XML formats where possible for v1.0.

## Base parser utilities

Common parser helper behavior lives in `src/vulnparse_pin/parsers/base_parser.py`:

- Safe numeric conversion (`_safe_float`, `_safe_int`)
- Safe text normalization (`_safe_text`)
- Evidence chunking/summarization for plugin output

This keeps parser-specific code focused on schema mapping instead of low-level data hygiene.

## Nessus XML parsing behavior

`NessusXMLParser` detects files by validating the expected root/tag structure and required report nodes.

#### Nessus detection signals

| Signal | Weight | Notes |
|--------|-------:|-------|
| Root tag is `NessusClientData_v2` | **+0.50** | Absent → hard 0.0 (no match) |
| Nested `NessusClientData_v2` (not root) | **+0.35** | Still diagnostic |
| `ReportHost` present | **+0.20** | Structural confirmation |
| `ReportItem` present | **+0.20** | Structural confirmation |
| `HostProperties` present | **+0.05** | Secondary structural |
| First `ReportItem.pluginID` is numeric | **+0.05** | Nessus-specific attribute |
| File extension is `.nessus` | **+0.10** | Unambiguous extension bonus |

Typical scores: `.nessus` file with full structure → **1.0** (capped) | `.xml`  file with full structure → **0.90** | Root tag only → **0.50** (matched at threshold).

Typical mapped fields:

- Host metadata (`HostProperties`)
- Plugin IDs and plugin names
- Severity and CVSS (v3 preferred when present)
- CVE references
- Remediation/solution text
- Summarized plugin evidence output

## OpenVAS XML parsing behavior

`OpenVASXMLParser` detects OpenVAS structures while explicitly rejecting Nessus root tags to avoid false positives.

#### OpenVAS detection signals

| Signal | Weight | Notes |
|--------|-------:|-------|
| Hard negative: `NessusClientData_v2` found | **0.0** | Immediate rejection |
| Root tag in `{report, get_reports_response, omp, get_results_response}` | **+0.20** | Known GVM root elements |
| `results//result` structure | **+0.30** | Core scan data structure |
| `nvt` element present | **+0.25** | GVM-specific plugin concept |
| OID attribute on `nvt` matches `^\d+(\.\d+)+$` | **+0.10** | GVM dotted-numeric OID |
| `creation_time` element present | **+0.05** | Present on all well-formed GVM reports |
| `host` elements present | **+0.05** | Confirms actual scan results |

Typical scores: full report with OID → **0.95** | no OID → **0.75** | `nvt` + results, no root tag → **0.55** (matched at threshold).
Only `.xml` extension is accepted; other extensions return 0.0 immediately.

Typical mapped fields:

- Host and service identity from result records
- NVT metadata and OID
- Port/protocol normalization from scanner value strings
- CVE extraction from refs/tags where available
- CVSS extraction with fallback rules

## Fallback and sentinel behavior

Parsers are designed to continue parsing when optional fields are missing.

You may see sentinel values such as:

- `SENTINEL:No_Description`
- `SENTINEL:No_Plugin_Output`
- `SENTINEL:Vector_Unavailable`

These are intentional provenance markers and help downstream tooling distinguish “missing” from empty values.
### CSV export robustness (v1.0)

When findings lack numeric scores (e.g., findings without CVEs or in offline mode with limited enrichment), the CSV exporter uses a sentinel value (-1.0) to represent missing scores. This ensures exports complete successfully even with incomplete enrichment. See [Known Limitations](Known%20Limitations.md) for details on enrichment coverage.
## Edge-case resilience

Tests cover malformed or sparse scanner output, including:

- Missing OpenVAS NVT structures
- Malformed port/protocol strings
- Missing titles/descriptions
- Real-world XML parser regression cases

See tests in `tests/test_openvas_*` and `tests/test_xml_parsers_realworld.py`.

## Extending parsing support

To add a parser:

1. Implement parser class (prefer inheriting from `BaseParser`)
2. Add robust `detect_file()` logic
3. Register parser in `PARSER_SPECS`
4. Add edge-case tests and real-world regression samples
5. Ensure normalized model consistency (`Finding`, `Asset`, `ScanResult`)
