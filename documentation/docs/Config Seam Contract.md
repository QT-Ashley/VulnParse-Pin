# Config Seam Contract

This document defines the shipped v2.0.0 configuration architecture separating file discovery/provisioning, schema & semantic validation, `v1 -> v2` projection, and typed runtime policy bundles, plus workspace inventory/decision context configs.

## Objective

Enforce clean boundaries across four stages of runtime configuration plus two workspace context surfaces:

1. **File discovery and provisioning** (`ConfigSource`)
2. **Draft 2020-12 schema and semantic validation** (`ConfigValidator`)
3. **Version compatibility projection & typed runtime bundle** (`ConfigProjector`)
4. **Workspace context configs** (`assets.yaml` via `AssetContextMatcher`, `decisions.yaml` via `DecisionsRegistry`)

## Implemented Contracts

### Contract A: Config Source (`src/vulnparse_pin/core/config_source.py`)

`ConfigSource` discovers, provisions missing defaults from `vulnparse_pin.resources`, and reads `config.yaml`, `scoring.json`, and `tn_triage.json` through `PermFileHandler` (`YAML(typ="safe", pure=True)` + `json.load`):

- `ConfigSource.ensure_files(paths) -> ConfigFileSet(global_yaml, scoring_json, topn_json)`
- `ConfigSource.read_payloads(ctx, files) -> RawConfigPayloads(global_config, scoring_config, topn_config)`
- `ConfigSource.load_packaged_defaults() -> RawConfigPayloads`

### Contract B: Config Validator (`src/vulnparse_pin/core/config_validator.py`)

`ConfigValidator.validate(ctx, payloads) -> ConfigValidationResult` enforces:

1. JSON Schema Draft 2020-12 validation against `config.schema.json`, `scoring.schema.json`, and `topN.schema.json`.
2. Webhook URL/timeout invariants (`https://` only, no embedded credentials, `timeout_seconds >= max(connect_timeout_seconds, read_timeout_seconds)`).
3. Scoring semantic invariants (monotonically non-decreasing `epss.breakpoints`, strictly ordered `bands`: `critical > high > medium > low >= 0`).
4. Version policy (`SUPPORTED_CONFIG_VERSIONS = ("v1", "v2")`): accepts `v2` cleanly and auto-projects `v1` (or unversioned) configs to `v2` defaults (`_project_global_v1_to_v2`, `_project_scoring_v1_to_v2`) while emitting structured warnings. Unsupported versions raise `RuntimeError`.

### Contract C: Config Projector (`src/vulnparse_pin/core/config_projector.py`)

`ConfigProjector.project(validation) -> RuntimeConfigBundle` builds immutable typed policy dataclasses:

- `RuntimeConfigBundle.v2_config` (`VppConfigV2`)
- `RuntimeConfigBundle.scoring_policy` (`ScoringPolicyV2` with `.to_v1_policy()` bridge)
- `RuntimeConfigBundle.triage_policy` (`TriagePolicyV2` — `default` / `bod-26-04`, `static_sast_p1_cap`)
- `RuntimeConfigBundle.aci_policy` (`ACIPolicyV2`)
- `RuntimeConfigBundle.signal_reliability` (`SignalReliabilityPolicy`)

### Contract D: Workspace Context Configs (`src/vulnparse_pin/core/assets_context.py`)

Optional per-engagement / per-repository context files are loaded separately from global `AppPaths` configs and validated against Draft 2020-12 schemas:

- **`assets.yaml` (`--assets`):** Validated against `assets.schema.json` (`version: v1|v2`, `defaults`, `rules[]`, optional inline `decisions[]`) via `AssetContextMatcher.from_file(path, pfh=ctx.pfh)`.
- **`decisions.yaml` (`--decisions`):** Validated against `decisions.schema.json` (`version: v1|v2`, `decisions[]`) via `DecisionsRegistry.from_file(path, pfh=ctx.pfh)`.

## Related Docs

- [Configs](Configs.md)
- [Architecture](Architecture.md)
- [Pipeline System](Pipeline%20System.md)
- [Enrichment Seam Contract](Enrichment%20Seam%20Contract.md)
- [ADR-0001: Config Seam Architecture](adr/ADR-0001-config-seam.md)
