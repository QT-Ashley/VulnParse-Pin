<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where practical.

## Upgrade Notes

- GHSA is now explicit CLI opt-in only. Use `--ghsa` for online mode or `--ghsa <path>` for offline advisory enrichment.
- TopN now expects `ACI@1.0` output; when missing, it emits a soft no-op artifact with error metadata instead of failing.
- Scoring semantics changes under `Scoring@2.0` to whole-of-CVEs aggregation with bounded decay; scoring traces now include contributor-level metadata for auditability.
- Packaged scoring config is now `version: v2` to reflect new scoring semantics and trace fields. Review custom 'scoring.json' files for compatibility before upgrading.
- Default JSON output suppresses presentation-only score overlay fields unless `--presentation` is enabled, while preserving derived scoring artifacts for auditability.

## [1.2.1] - Hotfix Release for NVD Enrichment Skip Issue

### Fixed

- NVD enrichment no longer skips when using default config: bootstrap initialization now correctly reads NVD year policy from canonical path (`feed_cache.feeds.nvd`) with fallback to legacy path (`feed_cache.nvd`), matching the path hierarchy used by enrichment layers and preventing silent skips on demo/standard runs.
- Updated packaged `config.yaml` nvd start year path to match the canonical path (`feed_cache.feeds.nvd.start_year`) to prevent confusion and ensure consistency across config and code.

## [1.2.0] - 2026-04-24 ACI, Whole-of-CVEs, and Release Hardening

### Added

#### Attack Capability Inference (ACI)

- Attack Capability Inference pass integration in default pipeline (`ACI@1.0`) between `Scoring@2.0` and `TopN@1.0`, including typed output contracts for finding semantics, asset semantics, and ACI metrics.
- ACI configuration model in TopN policy semantics and schema (`topN.schema.json` / `tn_triage.json`), including capability rules, chain rules, token governance (`token_mode`, `signal_aliases`, `disabled_core_tokens`), bounded uplift controls, and exploit-boost tuning.
- ACI-focused test coverage for pass behavior and tie-break integration (`tests/test_aci_pass.py`) plus regression updates across pass-contract/parser smoke/CSV/TopN-alignment tests to ensure `Scoring -> ACI -> TopN` pipeline parity.
- ACI documentation set:
  - `documentation/docs/ACI Feature Explanation.md`
  - `documentation/docs/ACI Rule Authoring Tutorial.md`
  - `documentation/docs/ACI Technical Deep Dive.md`
- Analyst tabletop prioritization guidance in documentation: explicit Operational Action Lane (`OAL`) categories, default precedence rule, and escalation exception criteria for exploitability-vs-chain decisions.
- Repeatable ACI phrase-quality benchmark harness (`tests/test_aci_phrase_benchmark.py`) with curated positive/negative phrase cases (`tests/benchmarks/aci_phrase_benchmark.json`) to track inference drift over time.

#### Whole-of-CVEs Scoring

- Whole-of-CVEs scoring in `ScoringPass` (`Scoring@2.0`): findings with `cve_analysis` now score across all retained CVE records using bounded decay aggregation rather than selecting one authoritative CVE for score calculation.
- Per-finding `score_trace` persistence on normalized finding objects and in scoring derived output, including contributor CVE IDs, per-CVE raw contribution, decay weight, CVSS/EPSS/KEV/exploit metadata, and final scoring rationale.
- Scoring policy knobs for finding-level CVE aggregation in `scoring.json`: `aggregation.finding_cve_score`, `aggregation.finding_cve_decay`, and `aggregation.finding_cve_max_contributors`.

#### GHSA Enrichment

- GHSA CLI-first activation contract: `--ghsa` is now the explicit opt-in path, with bare flag meaning online mode and `--ghsa <path>` meaning offline local advisory source.
- GHSA online lookup budget override via CLI (`--ghsa-budget`) with config default support through `enrichment.ghsa_online_prefetch_budget`.
- GHSA GitHub token env configuration (`enrichment.ghsa_token_env`) now defaults to `VP_GHSA_TK` with fallback to `GITHUB_TOKEN` for authenticated advisory API sessions.
- GHSA enrichment metadata on findings (`enrichment_sources`, `confidence`, `confidence_evidence`) with schema coverage updates.
- Global packaged enrichment config support for GHSA source selection and confidence policy tuning (`resources/config.yaml` + config schema).
- Enrichment seam flow completion across source loading, application, and post-enrichment handoff/indexing boundaries.
- GHSA offline file I/O governed by `ctx.pfh` (`ensure_readable_file`, `ensure_readable_dir`, `open_for_read`) matching the existing PFH contract; regression test added to `test_ghsa_enrichment.py`.
- GHSA SQLite warm-cache (`ghsa_cache.sqlite3`) keyed on `(cve_id, advisory_id)`: target CVE hydration on warm runs skips full advisory-directory rescan entirely.
- GHSA SQLite signature/quarantine hardening: SHA-256 digest with optional HMAC-SHA-256 (`VP_SQLITE_HMAC_KEY` env var), tamper-detected files are quarantined with a timestamp suffix and a clean index is rebuilt automatically — mirrors the NVD `nvd_cache.sqlite3` pattern.
- GHSA SQLite permission hardening: POSIX `0o600` enforcement and world-writable rejection; Windows PFH readability check.
- `_is_valid_cve_id()` validator on `GHSAEnrichmentSource` — CVE IDs are validated before use in SQL queries to prevent unexpected query behaviour from malformed input.
- Parallel advisory JSON reads during cold GHSA directory parse (`ThreadPoolExecutor`, up to 8 workers) — I/O-bound phase is now multi-threaded.
- GHSA SQLite upsert batch size increased 1 000 → 2 000; signature file is rewritten after every batch commit.
- GHSA cache retention policy controls under `enrichment.ghsa_cache` with schema-validated keys: `sqlite_max_age_hours` and `sqlite_max_rows`.
- GHSA online CVE advisory lookup added using GitHub advisories query endpoint (`/advisories?cve_id=...`) with per-CVE response caching.
- GHSA SQLite prune telemetry counters added (`runs`, `age_deleted`, `cap_deleted`, `last_row_count`) with debug logging for retention observability.
- GHSA pipeline online source mode enabled via `enrichment.ghsa_source: online`; loader now prefetches a bounded CVE set for run-time enrichment without local advisory files.
- GHSA package-based fallback matching wired: findings now derive package tokens from title/description/plugin text and match against GHSA advisory package index when CVE-based GHSA misses.
- GHSA confidence policy now supports advisory-derived signal tuning through `confidence.ghsa_signals`, including bounded advisory bonuses and optional high-severity exploitability promotion.

#### Qualys and Ingestion Quality Controls

- Qualys parser integration (`qualys_parser.py`) with detector wiring and regression coverage in `test_qualys_parser.py`.
- Qualys XML parser guardrails and schema-variant support upgrades: root/tag aliases (`SCAN`/`SCAN_REPORT`, `ASSET`/`HOST`, `VULN`/`VULNERABILITY`), defensive size/value bounds, and broader CVSS/CVE field extraction compatibility.
- New Qualys CSV parser (`qualys_csv_parser.py`) with detector registration, schema-variant header aliases, delimiter sniffing, malformed-row skipping, and ingestion metadata propagation.
- Ingestion quality controls on normalization path: `--allow-degraded-input` (bool optional), `--strict-ingestion`, `--min-ingestion-confidence`, and `--show-ingestion-summary`.
- Ingestion metadata fields on findings are now first-class output contract elements (`source_format`, `fidelity_tier`, `missing_fields`, `degraded_input`, `ingestion_confidence`, `confidence_reasons`) with schema and CSV coverage.
- RunManifest decision-ledger ingestion events for parser row quality and ingestion gate outcomes (dropped rows, malformed rows skipped, strict-mode rejection, min-confidence threshold rejection).

#### Nmap Context Integration

- Nmap parser scaffold (`nmap_parser.py`) added as an experimental foundation path for future enrichment/context signals.
- `NmapAdapterPass` (`nmap_adapter@1.0`) wired as a derived-context pass: parses Nmap XML output, maps open ports and NSE CVEs to scan asset IDs, and writes a `DerivedPassResult` that downstream passes consume without mutating findings.
- `--nmap-ctx` / `-nmap` CLI flag: accepts a path to a Nmap XML file (`.xml` extension enforced); opt-in only, `None` by default.
- TopN ranking tiebreak on Nmap-confirmed open ports: equal-score findings and assets that have a confirmed open port rank higher than those without, producing deterministic ordering without changing numeric scores.
- `nmap_ctx` config section in `config.yaml` and `config.schema.json` with two policy knobs:
  - `port_tiebreak_enabled` (bool, default `true`): gates the TopN ranking tiebreak.
  - `scoring_port_bonus` (float, 0.0–5.0, default `0.0`): optional raw-score addend applied when an Nmap open port is confirmed on a finding's service port.
- `ScoringPolicyV1.nmap_port_bonus` field: sourced from `nmap_ctx.scoring_port_bonus`; propagated through both inline and process-pool scoring paths.
- `Services.nmap_ctx_config`: passes the runtime `nmap_ctx` config dict to all passes without re-reading config files.
- Decision ledger events for all four `NmapAdapterPass` execution paths (`NMAP_CTX_DISABLED`, `NMAP_CTX_ENABLED`, `NMAP_CTX_FAILED`, `NMAP_CTX_INVALID_FORMAT`) with structured evidence fields (host count, matched asset count, join rate, source file, error text).
- `DecisionReasonCodes` extended with four new nmap_ctx reason codes.

#### Reporting and Export

- CSV output presentation profiles via `--csv-profile` (`full`, `analyst`, `audit`) with default backward-compatible schema preserved under `full`.
- Markdown report enrichment to surface aggregated whole-of-CVEs context in top-risk sections (Finding Agg CVEs, Agg Exploitable, Agg KEV).
- Executive and technical markdown quality sections: Decision Context, Data Quality Scorecard, Remediation Plan by Time Horizon, Risk Concentration, Tie-Break Explainability, Analyst Caveats, and Trust and Provenance framing.
- Markdown terminology clarification: top-risk tables now use `Finding Agg CVEs` to explicitly denote finding-level score-contributor breadth.
- RunManifest pass-summary metric alignment for whole-of-CVEs semantics: Scoring, TopN, and Summary now surface aggregated-context counters needed for audit and operator traceability.
- Output interpretation documentation for analyst workflows, including JSON/CSV/Markdown/RunManifest reading order and practical triage guidance.

#### Webhooks and External Integrations

- HMAC-SHA256 signed webhook delivery (`utils/webhook_delivery.py`): scan-complete events are POSTed to one or more configured HTTPS endpoints with `X-VPP-Signature`, `X-VPP-Timestamp`, `X-VPP-Nonce`, `X-VPP-Key-Id`, and `X-VPP-Event` headers; redirects are blocked.
- Webhook config block in `config.schema.json` and `resources/config.yaml`: 13 validated fields including `signing_key_env`, `key_id`, connect/read/total timeouts, `max_retries`, `max_payload_bytes`, `replay_window_seconds`, `allow_spool`, `spool_subdir`, and a typed `endpoints` array (max 32) each with `url`, `oal_filter`, and `format`.
- `WebhookEndpointConfig` and `WebhookRuntimeConfig` frozen dataclasses added to the domain model; `Services` carries a `webhook_config` field populated at bootstrap.
- Semantic validation for webhook config in `ConfigValidator._validate_webhook_config()`: enforces HTTPS-only URLs, no embedded credentials, total timeout ≥ max(connect, read), and at least one enabled endpoint when `enabled: true`.
- `--webhook-endpoint URL` CLI flag for one-off HTTPS delivery without a config file change; `--webhook-oal-filter LANE` restricts payload to a single Operational Action Lane (`all`, `P1`, `P1b`, `P2`).
- OAL lane filtering in webhook payload construction: `top_findings` are filtered to the configured lane before serialisation; `oal_filter_applied` field in the payload body records which lane was active.
- Spool fallback (`webhook_spool/webhook_<ts>_<nonce>.json`) written when HTTP POST fails or raises an exception, so no event is silently dropped.
- Six new `DecisionReasonCodes` constants (`WEBHOOK_EMIT_STARTED`, `WEBHOOK_EMIT_SUCCEEDED`, `WEBHOOK_EMIT_FAILED`, `WEBHOOK_EMIT_SKIPPED_DISABLED`, `WEBHOOK_EMIT_SKIPPED_POLICY`, `WEBHOOK_EMIT_SPOOLED_FOR_RETRY`) recorded via `LedgerService.append_event()` for full RunManifest traceability.
- Webhook emission called in `run_output_and_summary()` before RunManifest snapshot, guaranteeing all delivery events appear in the final audit trail.

### Changed

- Dependency baseline refresh for release packaging:
  - `requests >= 2.33.1`
  - `platformdirs >= 4.9.6`
  - `pytest (dev) >= 9.0.3`
  - `cyclonedx-bom (sbom) >= 7.3.0`
- Packaging metadata now explicitly advertises Python 3.13 and 3.14 classifier support.
- README Python support badge corrected to match package minimum (`3.11+`).

- TopN now explicitly requires `ACI@1.0`; when ACI output is missing, TopN emits a soft no-op artifact with dependency-aware status/error metadata and decision-ledger evidence.
- TopN ranking keys now incorporate bounded ACI uplift as deterministic tie-break signal at finding/global/asset ordering layers while preserving score semantics.
- Markdown report generation now receives runtime CLI args so enrichment-source status is rendered from actual run flags instead of static assumptions.
- Executive/technical markdown reports now include ACI metric snapshots, capability and chain distributions, confidence buckets, and top-asset finding-to-capability mapping with analyst caveats.
- Triage methodology language standardized across docs to reflect a real-world impact probability first default model, with explicit guidance to tune config/policy to environment, risk appetite, compliance obligations, and business goals.
- TopN config model now includes `triage_policy` controls for operational lane policy (`P1`/`P1b`/`P2`) with schema + semantic validation and packaged defaults in `tn_triage.json`.
- Markdown ACI mapping tables now render policy-lane classification per finding (config-backed), so analyst handoff includes explicit lane context alongside confidence and chain signals.
- Markdown ACI asset mapping now includes TopN-derived asset context tags (for example externally-facing inference, public-service-port inference, exposure confidence, criticality, and concentration hints).
- Default JSON output now suppresses presentation-only score overlay fields unless `--presentation` is enabled, while preserving derived scoring pass artifacts for auditability.

- Security hardening stream completed for feed/download surfaces: decompression size caps, HTTPS-only feed override handling, and response-size guardrails for external threat-intel fetch paths.
- PFH hardening and reliability updates landed, including chmod error-path handling and tighter policy enforcement behavior under protected write/read flows.
- GHSA activation is now strict CLI-only at runtime: config no longer auto-enables GHSA when `--ghsa` is absent.
- GHSA loader now supports advisory-database repository layout directly (`advisories/github-reviewed/...`) for local offline enrichment operations.
- GHSA source loader in `enrichment_source_loader.py` now passes scan target CVEs and `force_reindex` flag into `load_offline()` for focused SQLite hydration.
- All GHSA SQLite operations (`_sqlite_has_rows`, `_sqlite_hydrate_targets`, `_sqlite_upsert_rows`, `_sqlite_clear`) now verify signature before acting and quarantine on failure.
- `_extract_cves` normalisation tightened: `strip()` applied before `upper()` to handle whitespace-padded alias strings.
- GHSA SQLite now prunes stale and excess rows using config-driven retention policy during init and post-upsert cycles.
- GHSA `enrich_finding(..., online=True)` now performs real CVE-based GHSA API lookup when offline maps miss, then indexes returned advisories for subsequent cache hits.
- Enrichment core now accepts and processes `ghsa_package_data` alongside `ghsa_data` so package-derived GHSA matches contribute references and confidence metadata.
- GHSA online requests now build authenticated GitHub advisory headers when a token env var is present, without logging secret values.
- `load_score_policy` in `runtime_helpers.py` now accepts `nmap_port_bonus` kwarg and threads it through to `ScoringPolicyV1`.
- `policy_values` dict in `_score_parallel` extended with `nmap_port_bonus` key so the process-pool scoring path stays in sync with the inline path.
- Packaged scoring config advanced to `version: v2` to reflect whole-of-CVEs scoring semantics.
- `ScoringPass` now writes `raw_risk_score`, `risk_score`, `risk_band`, and `score_trace` back onto mutable finding objects so vulnerability-level JSON output carries the same audit trace as the derived scoring artifact.
- TopN ranking tie-breakers now account for whole-of-CVEs breadth signals from scoring traces (exploitable contributor count, KEV contributor count, and total contributor count) before falling back to stable IDs.
- Summary metrics now consume `Scoring@2.0` trace union flags and contributor metadata so overview counts, top-risk entries, and remediation priority buckets reflect aggregated CVE context rather than only finding-level booleans.
- Output orchestration now threads `--csv-profile` through CSV export generation.
- TopN process-pool worker ranking logic now mirrors sequential tie-break behavior for whole-of-CVEs contributor breadth signals, preserving deterministic ordering parity across execution paths.
- TopN `finding_text` inference hardening: source-weighted token scoring (title/description/plugin_output with configurable weights), diminishing-return scaling on repeated token hits, bounded weighted cap, conflict-token penalty layer, and deterministic per-finding evidence traces; all knobs are configurable via `tn_triage` inference policy.
- Regression coverage expanded for output-presentation workflows (`--csv-profile`, markdown report rendering, and CLI output flag matrix behavior).

### Performance

- GHSA cold vs warm loader benchmark on local advisory database (target set: 5,000 CVEs) showed `33.865s` cold vs `0.182s` warm (`~186x` speedup) using SQLite hydration path.
- End-to-end online GHSA pass on 5k Nessus sample completed successfully with online prefetch (`25` CVEs queried) and `22` GHSA-attributed findings in output.
- Release-readiness validation run set executed successfully:
  - Focused regression suite: `39 passed`
  - 5k E2E full enrichment: completed successfully (`release_validation_full` artifacts)
  - 5k E2E reduced enrichment: completed successfully (`release_validation_reduced` artifacts)

### Fixed

- Executive markdown risk distribution rendering issue where template/code-like output could appear instead of resolved numeric values.
- Enrichment source status display in markdown reports now accurately reflects runtime enable/disable state for KEV, EPSS, Exploit-DB, NVD, and GHSA.
- ACI over-inference noise reduced with guardrails:
  - `remote_service`-only signals no longer imply `remote_execution` or `initial_access`.
  - protocol-only (`smb`/`ssh`/`rdp`/`rpc`) signals no longer imply `lateral_movement` by themselves.
  - generic `exposure` token removed from core-token mapping to reduce false information-disclosure inference.
- Zero-inference reporting clarity improved: reports now include explicit diagnostics and a mapping note when ranked findings exist but all entries are `None inferred` under current ACI thresholds.

- GHSA SQLite signature write path now matches PFH open/write API contract, preventing cache-init disablement under strict handler validation.
- GHSA test context fixture now roots cache paths under pytest temp roots, preventing false PFH root-policy failures during test runs.
- Defensive CSV parsing bug fix in Nessus CSV path: row iteration now stays inside file-handle context to avoid closed-file runtime errors under malformed input handling.

### Notes

- Release hardening completed without adding a newly bundled Nessus sample or a bundled Qualys sample artifact. Validation is based on targeted synthetic/adversarial fixtures, focused parser regression suites, and public-format references.

### Deferred

- NVD + GHSA SQLite consolidation into a single database (separate tables). Deferred to allow independent lifecycle tuning and minimise blast radius.

## [1.1.1] - 2026-04-05 Governance and Architecture Hardening

### Added

- Strict schema validation for all runtime config files (`config.yaml`, `scoring.json`, `tn_triage.json`) during config load.
- New configuration schemas: `core/schemas/config.schema.json`, `core/schemas/scoring.schema.json`.
- TopN soft no-op dependency artifact when `Scoring@1.0` is unavailable, including explicit error metadata.
- Pass dependency declarations and pipeline dependency/order validation in `PassRunner`.
- RunManifest TopN pass summary metrics now include skip status and error code when applicable.
- Governance guardrail docs: ADR workflow, architecture review checklist, and deprecation/versioning policy.
- Enrichment seam contract: implementation-ready boundary design with staged migration and rollback guidance (`Enrichment Seam Contract.md`).
- Config seam contract: implementation-ready boundary design with staged migration and rollback guidance (`Config Seam Contract.md`).
- Config seam architecture (4-stage refactor) with dedicated `ConfigSource`, `ConfigValidator`, `ConfigProjector` modules and ADR-0001 decision record.
- `--output_all BASENAME` now derives all output artifact paths from a single base name stem: `<base>.json`, `<base>.csv`, `<base>_summary.md`, `<base>_technical.md`, `<base>_runmanifest.json`. Individual output flags still override specific artifacts when provided alongside `--output_all`.

### Changed

- Parser lifecycle metadata now supports `stability` and deprecation markers in parser specs.
- Nessus/OpenVAS JSON parser specs are now explicitly marked as `experimental` and `deprecated`.
- Parser spec `formats` fields were normalized to tuple form for single-format entries.
- Enrichment source summary now reports `exploitdb` enablement truthfully instead of hardcoded true.
- Default global config now includes explicit `version: v1` marker.

### Fixed

- TopN pass contract behavior now remains pass-compatible on missing dependencies by returning a derived artifact rather than a scan object.
- Pass pipelines with missing or misordered declared dependencies now fail fast with explicit validation errors.
- `--output_all` CLI flag redefined as a `BASENAME` string argument; was incorrectly declared as a boolean store-true flag causing argparse to raise "expected one argument" when used.
- Removed spurious f-string with no interpolated variables in `markdown_report.py`.

## [1.1.0] - 2026-03-29 Auditability and Provenance Update

This release introduces comprehensive auditability and provenance tracking for VulnParse-Pin runs. The new Execution Framework captures detailed lifecycle events for each pass and enrichment phase, records input and configuration hashes, and produces a verifiable RunManifest artifact that allows offline integrity and schema validation of the run outputs.  

This ensures that every run can be independently verified for correctness, traceability, and tamper-evidence, providing security teams with confidence in the integrity of the prioritized vulnerability outputs.  

Incident Response, forensics, and compliance teams can now rely on the RunManifest to demonstrate exactly what occurred during a given run, what inputs were used, and how decisions were derived, without needing to rerun the processing pipeline.

### Added

- **RunManifest execution artifact** with embedded decision ledger output via `--output-runmanifest`.
  - Includes runtime metadata, input/config hashes, output references, enrichment summary, pass summaries, and verification block.
- **Decision ledger runtime service** (`LedgerService`) with append-only hash chaining.
  - Pass lifecycle events (`pass_start`, `pass_end`, `pass_error`) now captured during orchestration.
  - Enrichment lifecycle events (`phase_start`, `phase_end`) now captured in the pipeline.
- **RunManifest schema contract** (`core/schemas/runManifest.schema.json`) and runtime schema validation support.
- **RunManifest integrity verification** with chain continuity, entry hash recomputation, and manifest digest verification.
- **Standalone RunManifest verifier command**: `--verify-runmanifest <PATH>` for offline schema/integrity validation without rerunning scan processing.
- **RunManifest mode controls**: `--runmanifest-mode compact|expanded`.
  - `compact` remains default for bounded artifact size.
  - `expanded` emits richer decision detail in Scoring/TopN event emission paths.
- **Decision reason code registry** (`DecisionReasonCodes`) with stable reason identifiers for explainability.
- **Pass-phase metrics in runmanifest** now populated from real pass outputs (Scoring, TopN, Summary) rather than placeholders.
- **New documentation**:
  - `documentation/docs/RunManifest.md`
  - `documentation/docs/RunManifest_Technical.md`
  - Usage updates for generation, mode selection, and verification workflows.
- **RunManifest test suite** covering schema, integrity, tamper detection, reason-code presence, pass metrics, and file verification flows.

### Changed

- Demo output defaults now include `demo_runmanifest.json` when runmanifest output is requested in demo workflow.
- Output orchestration now writes RunManifest alongside JSON/CSV/Markdown artifacts when configured.
- Runtime services container extended with `ledger` and `runmanifest_mode` fields to support explainability and artifact controls.

### Fixed

- Fixed empty `pass_summaries[*].metrics` in RunManifest by deriving metrics from actual pass outputs.
- Reduced analyzer noise in verification flow by narrowing exception handling for verifier path.

## [1.0.3] - 2026-03-28

### Added

- **Derived Asset Criticality Architecture**: Moved asset criticality derivation from parser normalization to the `ScoringPass`, ensuring true derived characteristics are owned by appropriate pass phases.
  - `ScoringPass` now computes `asset_criticality` from risk-band thresholds (`Extreme`, `High`, `Medium`, `Low`).
  - Criticality threshold configuration added to `scoring.json` with sensible defaults.
  - Asset criticality persisted back to `ScanResult.assets[*].criticality` for downstream pass consumption.
  - Removed parser-layer criticality assignment from `NessusParser` and `OpenVASParser` (data normalization scope reduced per architecture principle).
- **TopN Pass Criticality Integration**: Updated asset ranking logic to prioritize current-scan derived criticality over stale index observations.
  - TopN asset ranking now merges current `ScanResult.assets[*].criticality` into parallel pipeline inference state.
  - Asset observations now inherit derived criticality for consistent exposure-management decisions.
- **Enhanced Markdown Reports**:
  - Executive report now includes "Recommended Asset Target List" table showing vulnerable assets with derived criticality, critical/high risk counts, and top CVE per asset.
  - Executive report now includes SLA recommendation note based on criticality distribution.
  - Technical report asset analysis table now displays criticality column for visibility.
  - Both reports now clearly leverage scored risk-band criticality (not scanner severity).
- **Presentation Overlay Criticality Storage**: Asset-level derived criticality and scored risk-band counts now materialized in presentation overlay for both `flatten` and `namespace` modes.
  - Overlay asset entries include: `criticality` (string), derived scoring context (risk-band thresholds and counts).
- **Exploit References Schema Compliance**: Fixed `exploit_references` field emission to conform to schema contract.
  - Changed from non-compliant `exploit_references: {}` object to schema-compliant `exploit_references: [{ "cve": "CVE-xxx" }, ...]` array of dicts.
  - Updated CSV exporter to support both new list-of-dicts format and legacy dict format for backward compatibility.
  - Added regression test (`test_exploit_references_shape.py`) to prevent backsliding.
- **Comprehensive JSON Schema for ScanResult**: Packaged as `core/schemas/scanResult.schema.json` with field-level descriptions, type constraints, and enum validation.
  - Added schema documentation artifact (`ScanResult_Schema.md`) with complete field reference, examples, validation instructions, and common Python patterns.
  - Schema validation included in `pyproject.toml` package resources for runtime contract enforcement.
- **Immutable post-enrichment indexing** (`PostEnrichmentIndex`) with O(1) pass-phase finding lookups.
- **Criticality predicate** (`criticality_is`) added to TopN inference engine for `extreme|high|medium|low` asset classification.
- **Bundled criticality-aware inference rule** (`critical_asset_hint`) in `tn_triage.json` applying +1 exposure weight for `extreme` and `high` criticality assets.
- **New CLI enrichment controls** with online-by-default semantics and explicit disable/source selection:
  - `--no-kev`, `--no-epss`, `--no-exploit`
  - `--kev-source`, `--epss-source`, `--exploit-source`
  - `--kev-feed`, `--epss-feed`
- **Graduated confidence scoring** in `NessusXMLParser.detect_file` and `OpenVASXMLParser.detect_file` returning `(float, list[tuple[str, str]])` instead of a plain `bool`.

### Fixed

- Fixed `asset.criticality` schema definition and documentation to match derived scoring logic (values: `Extreme|High|Medium|Low`).
- Fixed enrichment conditional precedence so KEV/EPSS enrichment execution is evaluated correctly.
- Fixed CSV exporter sentinel handling for `cvss_score`, `epss_score`, and `asset_avg_risk_score` — all now emit `-1.0` when no score data is available.
- Fixed `_sniff_format` to strip leading UTF-8 BOM before format detection so BOM-prefixed XML/JSON inputs are classified correctly.
- Fixed exploit references schema contract violation (now array of dicts, not bare object).

### Changed

- Removed legacy enrichment flags `--enrich-kev`, `--enrich-epss`, and `--enrich-exploit` (hard rename).
- Updated CLI matrix coverage and user documentation for the new enrichment flag model.
- Refactored asset criticality ownership: parser normalization no longer assigns criticality; derived passes own it.
- Updated markdown report generation to use derived scored risk-band criticality (not scanner severity) for asset prioritization and presentation.
- Validated the full OpenVAS XML pipeline against `tests_output/diverse_openvas_mixed.xml`; detection selected `openvas-xml` at `0.95` confidence and successfully generated JSON, CSV, executive Markdown, and technical Markdown artifacts.
- Schema validation on demo output confirmed zero schema errors (including exploit references shape fix).

## [1.0.2] - 2026-03-25

### Added

- Added `--demo` CLI flag for a one-command end-to-end run using a bundled Nessus sample.
- Added automatic demo behavior that forces online enrichment mode and enables all four output artifacts (JSON, CSV, executive Markdown, technical Markdown).
- Added packaged Nessus demo resource support (`resources/*.nessus`) so the demo sample resolves reliably in installed environments.
- Added generated 5k synthetic Nessus benchmark dataset support and tooling (`tests/generate_5k_nessus.py`) with reproducible 10-asset, 5,000-finding coverage.
- Added new value and scoring documentation artifacts: `docs/Value_Proof_Analysis.md`, `docs/CVSS_vs_VulnParse_Scoring_Comparison.md`, and `docs/Value_Proposition_One_Pager.md`.
- Added `--demo` usage instructions to `README.md` and `docs/Usage.md`.

### Fixed

- Fixed CLI summary banner output location rendering to display clean output filenames.

### Changed

- Updated Markdown report templates to clearly separate scanner severity from VulnParse-Pin derived risk bands.
- Updated executive and technical report risk tables with explicit "Primary Drivers" context (KEV, public exploit, EPSS threshold signals).
- Updated benchmark and performance documentation with the 5k demo-derived dataset and measured throughput/runtime snapshot.
- Updated `README.md`, `ROADMAP.md`, and overview docs to reflect demo workflow, prioritization messaging, and current documentation structure.

## [1.0.1] - 2026-03-22

### Added

- Added `ROADMAP.md` with planned milestones for v1.1.0, v1.2.0, and v1.3.0-1.5.0+.

### Fixed

- Fixed a minor documentation typo in `docs/Getting Started In 5 Minutes.md`.

### Changed

- Updated `CHANGELOG.md` with the new roadmap section and minor formatting adjustments.

## [1.0.0] - 2026-03-18

### Added

- CSV export sentinel value (`-1.0`) for findings with no numeric enrichment score, preventing `TypeError` on `round(None)`.
- Five TopN pass contract tests covering asset exhaustiveness, finding completeness, no cross-asset leakage, deterministic index sorting, and score-rank consistency.
- CLI aliases for `--forbid-symlinks_read` and `--forbid-symlinks_write` (underscore variants) alongside the canonical hyphenated forms.
- Stability tier documentation in `docs/Detection and Parsing.md` (XML paths stable, JSON paths experimental).
- Expanded deferred-scope list in `docs/Known Limitations.md` (Shodan enrichment, CVSS v2, extended enrichment, strict schema validation, JSON parser parity).

### Fixed

- CSV exporter no longer raises `TypeError` when exporting findings that have no CVE and therefore no numeric enrichment scores.
- Editable install no longer shadowed by stale `rc1` physical package copy in site-packages.

### Changed

- Removed two `TODO: VERIFY` uncertainty markers from `topn_pass.py` after contract tests confirmed correct behavior.
- `pyproject.toml` classifier updated from `Development Status :: 4 - Beta` to `Development Status :: 5 - Production/Stable`.

## [1.0.0-rc4] - 2026-03-15

### RC4 Added

- GitHub Pages documentation deployment workflow.
- GitHub Pages documentation updates and project favicon.

### RC4 Changed

- CLI argument wording and UX polish for clarity.

## [1.0.0-rc3] - 2026-03-13

### RC3 Fixed

- Packaging resource inclusion for release distributions.

## [1.0.0-rc2] - 2026-03-13

### RC2 Changed

- Release workflow and CI configuration fixes for RC publishing.
- Versioning/release metadata updates for the RC pipeline.

## [1.0.0-rc1] - 2026-03-11

### RC1 Added

- JSON Schema validation support for normalized `ScanResult` data.
- Canonical `asset_id` support on `Asset` objects.
- Post-normalization default schema validation.
- Additional unit tests for schema detection, schema validation, and pass contracts.
- Real-sample validation coverage for Nessus and OpenVAS parsing flows.
- Packaging metadata improvements in `pyproject.toml`.
- `CHANGELOG.md` for release tracking.

### RC1 Changed

- Refactored application startup and orchestration into focused modules under `vulnparse_pin.app`.
- Refactored CLI argument handling into `vulnparse_pin.cli.args`.
- Refactored TopN worker logic into a dedicated module without changing public contracts.
- Updated downstream processing to treat `Asset.asset_id` as the canonical source of truth.
- Improved parser-selection tie-breaking in `SchemaDetector` to honor confidence, priority, then parser name.

### RC1 Fixed

- Corrected XML parser exception handling to use the proper XML `ParseError`.
- Removed unintended dependency path caused by incorrect parse exception usage.
- Fixed asset-to-finding ID consistency issues in parser outputs.
- Fixed downstream scoring/reporting usage of asset identity to avoid relying on finding-level IDs.
- Resolved various unused import and unused variable issues in parser modules.

[Unreleased]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/VulnParse-Pin/VulnParse-Pin/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.2
[1.0.1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.1
[1.0.0]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0
[1.0.0-rc4]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc4
[1.0.0-rc3]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc3
[1.0.0-rc2]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc2
[1.0.0-rc1]: https://github.com/VulnParse-Pin/VulnParse-Pin/releases/tag/v1.0.0-rc1
