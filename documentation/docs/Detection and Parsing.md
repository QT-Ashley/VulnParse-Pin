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

Typical mapped fields:

- Host metadata (`HostProperties`)
- Plugin IDs and plugin names
- Severity and CVSS (v3 preferred when present)
- CVE references
- Remediation/solution text
- Summarized plugin evidence output

## OpenVAS XML parsing behavior

`OpenVASXMLParser` detects OpenVAS structures while explicitly rejecting Nessus root tags to avoid false positives.

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
