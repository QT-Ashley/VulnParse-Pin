# Extension Playbooks

This guide provides practical implementation playbooks for extending VulnParse-Pin in its current architecture.

Current extension seams are explicit but code-driven:

- Parser extensions are registered through `PARSER_SPECS`.
- Pass extensions are wired in bootstrap into `PassRunner`.
- Enrichment extensions are integrated in the enrichment pipeline and supporting enrichment modules.

## Playbook 1: Add a New Parser

### Goal (Parser extension)

Add support for a new scanner format while preserving schema detection behavior and normalization contracts.

### Where to implement (Parser extension)

1. Create parser module under `src/vulnparse_pin/parsers/`.
2. Implement `BaseParser` subclass with `parse()` and `detect_file()`.
3. Register parser in `src/vulnparse_pin/parsers/__init__.py` via `PARSER_SPECS`.

### Minimal parser skeleton

```python
from pathlib import Path
from typing import List, Tuple

from vulnparse_pin.core.classes.dataclass import ScanResult
from vulnparse_pin.parsers.base_parser import BaseParser


class CustomXMLParser(BaseParser):
    @classmethod
    def detect_file(cls, filepath: str | Path):
        # Preferred: return (confidence, evidence)
        # confidence >= 0.50 means matched
        # evidence: list[tuple[str, str]]
        return 0.85, [("root_tag", "custom_scan"), ("extension", ".xml")]

    def parse(self) -> ScanResult:
        # Build normalized ScanResult with assets/findings populated
        raise NotImplementedError
```

### Register parser

Add to `PARSER_SPECS` with a stable name, scanner label, format hints, and tie-break priority.

```python
ParserSpec(
    name="custom-xml",
    parser_cls=CustomXMLParser,
    formats=("xml",),
    scanner="custom",
    priority=15,
    stability="stable",
    deprecated=False,
)
```

Lifecycle metadata recommendations:

1. Production parser paths should set `stability="stable"`.
2. In-progress parser paths should set `stability="experimental"`.
3. Sunset parser paths should set `deprecated=True` and provide `deprecation_notice`.

### Detection contract notes

1. `SchemaDetector` first does lightweight format sniffing.
2. Candidate parsers then run `detect_file()`.
3. Winner selection uses confidence, then priority, then parser name.
4. Legacy boolean `detect_file()` returns still work, but confidence tuple is preferred.

### Parser extension checklist

1. Parser returns valid `ScanResult` with stable `asset_id` mapping.
2. Findings include required identity and vulnerability fields.
3. Fallback chains are deterministic for title/description/port/protocol extraction.
4. Regression sample is added under `tests/regression_testing/`.
5. Parser tests updated (`tests/test_parser_smoke.py` plus targeted fallback tests).
6. Parser lifecycle metadata is set intentionally and documented if user-visible.

## Playbook 2: Add a New Pass

### Goal (Pass extension)

Add a new derived-analysis pass while preserving append-only derived context and pass pipeline determinism.

### Where to implement (Pass extension)

1. Create pass module under `src/vulnparse_pin/core/passes/<PassName>/`.
2. Implement `Pass` protocol: `name`, `version`, and `run(ctx, scan)`.
3. Return `DerivedPassResult` with `PassMeta` and structured data.
4. Wire pass into bootstrap pass list in `src/vulnparse_pin/app/bootstrap.py`.

### Minimal pass skeleton

```python
from datetime import datetime, timezone

from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass, PassMeta


class ExposurePass(Pass):
    name = "Exposure"
    version = "1.0"

    def run(self, ctx, scan):
        data = {"status": "ok"}
        return DerivedPassResult(
            meta=PassMeta(
                name=self.name,
                version=self.version,
                created_at_utc=datetime.now(timezone.utc).isoformat(),
                notes="Exposure analysis",
            ),
            data=data,
        )
```

### Wiring in pipeline

Add your pass to bootstrap pass order, respecting dependencies (for example, TopN depends on scoring output).

### Pass extension checklist

1. Pass output key (`Name@Version`) is unique.
2. Output shape is deterministic and testable.
3. Pass behavior is documented if user-visible.
4. Contract tests are added or updated in `tests/test_pass_contracts.py`.
5. If output impacts reports/exporters, update report/export tests.

## Playbook 3: Add a New Enrichment Source

### Goal

Add a new intelligence source (or enrich signal) without breaking existing KEV/EPSS/Exploit/NVD flow.

### Where to implement

Current enrichment flow is orchestrated in `src/vulnparse_pin/app/enrichment.py` and helper modules under `src/vulnparse_pin/utils/`.

Common integration points:

1. Source loader function (pattern similar to `load_kev` / `load_epss`).
2. Per-finding enrichment transform.
3. Enrichment pipeline integration and stats reporting.
4. Optional feed cache spec and cache policy integration.

### Suggested implementation pattern

1. Add a loader function with online/offline support and bounded logging.
2. Normalize keys once for lookup efficiency.
3. Apply enrichment in batch loops with clear fallback behavior.
4. Update enrichment stats and status fields.
5. Keep behavior compatible with `--log-level` and large-workload patterns.

### Enrichment extension checklist

1. New source can be enabled/disabled explicitly.
2. Offline path behavior is defined and tested.
3. Source failures degrade gracefully (warn and continue where safe).
4. Output fields are documented and do not silently collide with existing keys.
5. Tests cover source hit, source miss, malformed input, and offline fallback.

## Testing Matrix for Extension Work

Use this minimum matrix for extension PRs:

1. Parser contract and smoke tests for parser changes.
2. Pass contract tests for pass changes.
3. Enrichment-specific tests plus runmanifest checks for enrichment changes.
4. At least one representative end-to-end run.

Recommended commands:

```bash
pytest tests/test_parser_smoke.py -v
pytest tests/test_pass_contracts.py -v
pytest tests/test_runmanifest.py -v
pytest tests/ -v
```

## Documentation and Changelog Requirements

When extension behavior is user-visible:

1. Update `documentation/docs/Usage.md` as needed.
2. Update migration/troubleshooting docs if semantics changed.
3. Add changelog notes in `CHANGELOG.md`.

When extension behavior is architecture-impacting:

1. Add or update an ADR using [ADR Workflow](ADR%20Workflow.md).
2. Complete [Architecture Review Checklist](Architecture%20Review%20Checklist.md) in the PR description.

## Related Docs

- [Architecture](Architecture.md)
- [Detection and Parsing](Detection%20and%20Parsing.md)
- [Pipeline System](Pipeline%20System.md)
- [Enrichment Seam Contract](Enrichment%20Seam%20Contract.md)
- [Config Seam Contract](Config%20Seam%20Contract.md)
- [Testing Guide](Testing%20Guide.md)
<<<<<<< HEAD
- [Contributing](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/CONTRIBUTING.md)
=======
- [Contributing](../../CONTRIBUTING.md)
>>>>>>> main
