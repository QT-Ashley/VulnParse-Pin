# Extension Playbooks

This guide provides implementation playbooks for extending VulnParse-Pin v2.0.0 (`Apache-2.0`) while preserving streaming memory bounds, DuckDB persistence contracts, and zero-copyleft runtime licensing.

## Playbook 1: Add a New Streaming Parser

### Where to implement

1. Create a parser module under `src/vulnparse_pin/parsers/`.
2. Subclass `BaseParser` (`src/vulnparse_pin/parsers/base_parser.py`) implementing `detect_file()` and `iter_batches(batch_size=...)`.
3. Register a `ParserSpec` in `PARSER_SPECS` (`src/vulnparse_pin/parsers/__init__.py`).

### Hardened streaming & licensing rules

- **XML parsers:** Must use `safe_iterparse()` and `prune_element()` from `src/vulnparse_pin/parsers/_xml_security.py` (backed by `lxml.etree.iterparse`). Never introduce `defusedxml` or `xml.etree.ElementTree`.
- **JSON / SARIF / JSONL parsers:** Must stream via chunked `json.JSONDecoder.raw_decode` (see `_FastSarifStreamReader` in `sarif_parser.py`), `ijson`, or bounded line iteration (`nuclei_jsonl_parser.py`)—never materialize multi-hundred-MB DOMs with `json.load()`.
- **CSV parsers:** Must enforce `_MAX_CSV_FIELD_BYTES` (32 MiB), build a single-pass header index map, and emit ledger events on malformed/dropped rows.
- **Zero-copyleft dependency gate:** All new parser or utility dependencies must be `Apache-2.0`-compatible (MIT, BSD, PSF, Apache-2.0). Never add `AGPL`, `GPL`, or `LGPL` runtime dependencies.

### Minimal streaming parser skeleton

```python
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from vulnparse_pin.parsers.base_parser import BaseParser


class CustomStreamParser(BaseParser):
    NAME = "custom-stream"

    @classmethod
    def detect_file(
        cls,
        filepath: str | Path,
        *,
        ctx: Optional[Any] = None,
        allow_large: Optional[bool] = None,
        head_bytes: Optional[bytes] = None,
    ) -> tuple[float, list[tuple[str, str]]]:
        return 0.85, [("format", "custom")]

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        path = self._validate_filepath_and_size()
        # Stream records via self._open_read(path, self.ctx, ...) and yield NormalizedFindingRecord dicts
        yield []
```

### Parser extension checklist

1. `detect_file()` inspects only bounded `head_bytes` (`<= 64 KiB`).
2. `iter_batches()` emits complete `NormalizedFindingRecord` fields (`detection_mode`, `signal_reliability`, `ingestion_confidence`, `fidelity_tier`, `source_format`).
3. Regression fixtures and tests cover detection, streaming batches, and malformed/adversarial edge cases (`tests/test_streaming_parsers.py`, `tests/test_xxe_hardening.py`).

---

## Playbook 2: Add or Extend a DuckDB Repository Query or Pass

### Where to implement

- **Schema & workspace lifecycle:** `src/vulnparse_pin/storage/schema.sql`, `src/vulnparse_pin/storage/db.py` (`VppDatabase`).
- **Parameterized repository helpers:** `src/vulnparse_pin/storage/repositories.py`.
- **Derived pass:** `src/vulnparse_pin/core/passes/<PassName>/`, wired into `run_v2_duckdb_pipeline()` (`src/vulnparse_pin/core/passes/__init__.py`).

### Rules for DuckDB extensions

1. **Parameterized SQL only:** Never interpolate user/scanner strings into SQL. Use `?` parameter bindings and explicit allowlists for sort/table identifiers.
2. **Deterministic ordering:** Every query driving scores, triage, diffing, or UI pagination must end with deterministic tie-breakers (`asset_id ASC` / `finding_id ASC`).
3. **Bulk ingestion via Appender:** Batch writes (`> 100` rows) must stage via `TEMP TABLE` + `conn.appender(...)` inside `BEGIN TRANSACTION` / `COMMIT`.
4. **Pass DAG isolation:** Declare `name`, semantic `version`, and `requires_passes` on the `Pass` subclass, write outputs to `.vpp.db` tables for the active `run_id`, and return `DerivedPassResult`.
5. **Test coverage:** Update `tests/test_storage_duckdb.py`, `tests/test_pass_contracts.py`, and `tests/test_iter2_cross_component.py`.

---

## Playbook 3: Add a New Threat-Intel Source or Triage Profile

### Enrichment sources

1. Implement source loading inside `EnrichmentSourceLoader` (`src/vulnparse_pin/app/enrichment_source_loader.py`).
2. If maintaining a local SQLite cache, inherit or mirror `_SignedSQLiteFeedCache` (`0o600` POSIX perms, `S_IWOTH` rejection, `VP_SQLITE_HMAC_KEY` anti-downgrade, `.tampered.<UTCSTAMP>` quarantine, `<= 900`-parameter SQLite chunking).
3. If fetching over HTTPS, use `_open_https_stream()` / `stream_https_get_bytes()` (`allow_redirects=False`, per-hop HTTPS validation, bounded byte cap).
4. Wire snapshot hydration into `populate_enrichment_snapshots()` (`src/vulnparse_pin/app/enrichment.py`), expose health in `vpp intel status` / `vpp intel sync` (`src/vulnparse_pin/cli/commands.py`), and update `tests/test_intel_v2.py` + `tests/test_iter1_intel_sec.py`.

### Triage profiles (`Triage@2.0`)

1. Register profile normalization in `normalize_triage_profile()` (`src/vulnparse_pin/core/config_validator.py`) and `cli/args.py`.
2. Implement deterministic SSVC / SLA mapping in `TriageDecisionPass` (`src/vulnparse_pin/core/passes/Triage/triage_pass.py`) while preserving `DecisionsRegistry` (`decisions.yaml`) assumption checks and `static_sast_p1_cap`.
3. Verify `DiffEngine` (`src/vulnparse_pin/core/diff_engine.py`) and `renderer.py` Dossier/Roadmap templates handle the profile cleanly (`tests/test_bod_26_04.py`, `tests/test_diff_engine.py`, `tests/test_reporting_v2.py`).

---

## Verification Commands

```bash
pytest tests/test_streaming_parsers.py tests/test_xxe_hardening.py -v
pytest tests/test_storage_duckdb.py tests/test_pass_contracts.py -v
pytest tests/test_intel_v2.py tests/test_iter1_intel_sec.py -v
pytest tests/test_bod_26_04.py tests/test_diff_engine.py tests/test_reporting_v2.py -v
pytest tests/test_cli_v2.py tests/test_iter2_cross_component.py -v
```

## Related Docs

- [Architecture](Architecture.md)
- [Architecture Review Checklist](Architecture%20Review%20Checklist.md)
- [Detection and Parsing](Detection%20and%20Parsing.md)
- [Pipeline System](Pipeline%20System.md)
- [Enrichment Seam Contract](Enrichment%20Seam%20Contract.md)
- [Config Seam Contract](Config%20Seam%20Contract.md)
- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
