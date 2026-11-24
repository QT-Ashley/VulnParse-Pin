# Detection and Parsing

This document explains how VulnParse-Pin v2.0.0 (`Apache-2.0`) validates input files, selects parsers safely in O(1) bounded memory, and streams normalized records into the DuckDB workspace (`.vpp.db`).

## Input validation (`FileInputValidator`)

Before parser selection, `validate_scanner_input()` (`src/vulnparse_pin/app/normalization.py`) runs `FileInputValidator` (`src/vulnparse_pin/utils/validations.py`):

- **Allowed extensions:** `.xml`, `.nessus`, `.csv`, `.json`, `.sarif`, `.jsonl`, `.ndjson`.
- **Size guardrails:**
  - Default maximum file size: **500 MiB** (`max_size_mb = 500`).
  - Large-report ceiling with `--allow-large` (`-al`): **50 GiB** (`50 * 1024 * 1024 * 1024` bytes).
- **Streaming format & safety checks:**
  - **XML / `.nessus`:** Detects BOM and BOM-less UTF-16LE/BE or UTF-32 encodings and validates the XML prolog up to 1 MiB via `inspect_xml_prolog()`.
  - **JSON / `.sarif`:** Strips UTF-8 BOM (`\xef\xbb\xbf`), detects accidental JSONL payloads, runs full `ijson.basic_parse` for files `<= 2 MiB`, and bounded prefix `ijson` + `IncompleteJSONError` sniffing (256 KiB prefix) for larger files.
  - **JSONL / `.ndjson`:** Validates up to 16 non-empty lines with a per-line cap of **8 MiB** (`_MAX_JSONL_LINE_BYTES`).
  - **CSV:** Rejects NUL bytes (`\x00`), XML/JSON prefixes, and headers without recognized delimiters (`,`, `;`, `\t`, `|`).

## Detection subsystem (`SchemaDetector`)

Schema detection lives in `src/vulnparse_pin/core/schema_detector.py`, with registered specs in `PARSER_SPECS` (`src/vulnparse_pin/parsers/__init__.py`).

1. **Single bounded read (64 KiB):** `SchemaDetector.select()` enforces PFH read checks and reads at most `_SNIFF_READ_BYTES = 65_536` bytes once per input file, passing `head_bytes` to candidate `detect_file()` methods.
2. **Format classification (`_classify_head_bytes`):**
   - Handles UTF-16 BOM (`\xff\xfe`, `\xfe\xff`) and UTF-8 BOM (`\xef\xbb\xbf`).
   - Classifies `xml`, `jsonl`, `sarif` (`.sarif` suffix or `"runs"` + `"2.1.0"`/`sarif`/`tool.driver`), `json`, `csv`, or `unknown`.
3. **Graduated confidence scoring:** `detect_file()` returns `(confidence, evidence)` where `confidence >= 0.50` counts as matched. Legacy boolean `detect_file()` hooks map `True -> 0.9`, `False -> 0.0`.
4. **Deterministic tie-breaking (`_pick_winner`):** Highest `confidence`, then lowest `ParserSpec.priority`, then `parser_name`.

## Registered parsers (`PARSER_SPECS`)

| Parser Name | Class / Module | Formats | Scanner | Status |
| --- | --- | --- | --- | --- |
| `nessus-xml` | `NessusXMLParser` (`nessusXML_parser.py`) | `xml`, `nessus` | `nessus` | `stable` |
| `openvas-xml` | `OpenVASXMLParser` (`openvasXML_parser.py`) | `xml` | `openvas` | `stable` |
| `qualys-xml` | `QualysXMLParser` (`qualys_parser.py`) | `xml` | `qualys` | `stable` |
| `nmap-xml` | `NmapXMLParser` (`nmap_parser.py`) | `xml` | `nmap` | `stable` |
| `sarif-2.1.0` | `SarifParser` (`sarif_parser.py`) | `sarif`, `json` | `sarif` | `stable` |
| `nuclei-jsonl` | `NucleiJSONLParser` (`nuclei_jsonl_parser.py`) | `jsonl`, `json` | `nuclei` | `stable` |
| `nessus-csv` | `NessusCSVParser` (`nessus_csv_parser.py`) | `csv` | `nessus` | `stable` |
| `qualys-csv` | `QualysCSVParser` (`qualys_csv_parser.py`) | `csv` | `qualys` | `stable` |
| `openvas-json` | `OpenVASParser` (`openvas_parser.py`) | `json` | `openvas` | `experimental` (`deprecated=True`) |
| `nessus-json` | `NessusParser` (`nessus_parser.py`) | `json`, `nessus` | `nessus` | `experimental` (`deprecated=True`) |

> [!NOTE]
> JSON fallback parsers (`openvas-json`, `nessus-json`) are experimental and deprecated; `SchemaDetector` emits a warning when selected. Prefer XML, SARIF 2.1.0, Nuclei JSONL, or CSV inputs for production workflows.

## Hardened streaming XML parsing (`_xml_security.py`)

VulnParse-Pin v2.0.0 does **not** use `defusedxml`. All XML parsers (`nessus-xml`, `openvas-xml`, `qualys-xml`, `nmap-xml`, and `NmapAdapterPass`) use hardened streaming `lxml.etree.iterparse` and `lxml.etree.XMLPullParser` helpers in `src/vulnparse_pin/parsers/_xml_security.py`:

- **XML prolog inspection (`inspect_xml_prolog`, `_PrologGuardedStream`):**
  - Bounds prolog bytes before the root element to `MAX_XML_PROLOG_BYTES = 1 MiB`.
  - Detects UTF-8 BOM, UTF-16 BOM, UTF-32 BOM, and **BOM-less UTF-16LE / UTF-16BE** prologs (`<\x00` / `\x00<` after optional UTF-16 whitespace) and decodes strictly before scanning.
  - Rejects `<!ENTITY`, `SYSTEM`, `PUBLIC`, parameter entities (`%`), internal DTD subsets, NUL bytes, and unterminated DOCTYPE declarations before `lxml` parses the stream.
- **Hardened `lxml` configuration & full-subtree entity checks:**
  - `safe_iterparse()` initializes `lxml.etree.iterparse(..., resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False)`.
  - Internally iterates all elements even when `tag=` filtering is requested, calling `assert_no_entity_nodes(elem)` across element subtrees so entity nodes outside filtered tags cannot evade fail-closed rejection.
- **O(1) streaming memory:** `prune_element(elem)` clears processed elements and deletes preceding siblings (`del parent[0]`).

## Streaming SARIF 2.1.0, Nuclei JSONL, and CSV parsers

- **SARIF 2.1.0 (`SarifParser`, `sarif_parser.py`):**
  - Supports Trivy, Grype, Semgrep, CodeQL, Snyk Container, Clair, Anchore, Syft, and Dockle.
  - Uses `_FastSarifStreamReader`, which decodes UTF-8 incrementally in **4 MiB chunks** (`chunk_bytes = 4 * 1024 * 1024`) via `json.JSONDecoder.raw_decode`, skips irrelevant top-level JSON values in O(1) memory (`_skip_json_value`), and streams `runs[].results[]` via `iter_batches()` without materializing giant arrays. Uses `ijson` for bounded sniffing/validation.
  - Emits `detection_mode = "sca_container"` (for container/SCA tools) or `"static_sast"` (for SAST tools), along with `package_purl`, `location_uri`, and `line_number`.
- **Nuclei JSONL (`NucleiJSONLParser`, `nuclei_jsonl_parser.py`):**
  - Streams line-by-line JSON objects (`.jsonl`, `.ndjson`, or JSONL-formatted `.json`), extracting `template-id`, `info.tags`, CVEs/CWEs, and `detection_mode = "active_dast"`.
- **CSV (`NessusCSVParser`, `QualysCSVParser`):**
  - Raises `csv.field_size_limit` to **32 MiB** (`_MAX_CSV_FIELD_BYTES = min(32 * 1024 * 1024, sys.maxsize)`).
  - Sniffs delimiters across `,`, `;`, `\t`, `|`, builds a single-pass header index map, skips malformed rows that violate column contracts, and emits ledger events when rows are dropped.

## Ingestion quality metadata & batch gates

Every parser emits normalized records (`NormalizedFindingRecord`) via `iter_batches()` carrying:

- `detection_mode` (`credentialed_host`, `active_dast`, `sca_container`, `uncredentialed_banner`, `static_sast`, `network_probe`)
- `signal_reliability`, `ingestion_confidence`, `fidelity_tier` (`full`, `partial`, `minimal`), `degraded_input`, `source_format`
- Provenance sentinels when optional fields are absent (e.g., `SENTINEL:No_Description`, `SENTINEL:No_Plugin_Output`, `SENTINEL:Vector_Unavailable`).

`enforce_batch_ingestion_gates()` (`src/vulnparse_pin/app/normalization.py`) enforces `--strict-ingestion`, `--no-allow-degraded-input`, and `--min-ingestion-confidence` per streamed batch and logs gate rejections to `LedgerService`.

## Extending parsing support

1. Subclass `BaseParser` in `src/vulnparse_pin/parsers/`.
2. Implement bounded `detect_file(..., head_bytes=...)` returning `(confidence, evidence)` and streaming `iter_batches(batch_size=...)` (plus `parse()` compatibility if needed).
3. Use `_xml_security.safe_iterparse` + `prune_element` for XML inputs; never introduce `defusedxml`.
4. Register `ParserSpec` in `PARSER_SPECS` (`src/vulnparse_pin/parsers/__init__.py`) with explicit `stability` and `deprecated` flags.
5. Add parser smoke, streaming, and XXE/edge-case tests under `tests/`.
