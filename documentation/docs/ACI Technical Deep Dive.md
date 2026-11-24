# ACI Technical Deep Dive

This deep dive documents `ACI@2.0` (`ACIV2Pass`) internals end to end: DuckDB SQL join enrichment, normalized `scanner_sig` token matching parity, Track B integration, confidence and uplift math, ledger persistence, and validation boundaries.

## Scope and Implementation Map

Primary implementation files:

- `src/vulnparse_pin/core/passes/ACI/aci_pass.py` (`ACIV2Pass` / `ACI@2.0`, `AttackCapabilityInferencePass` / `ACI@1.0`)
- `src/vulnparse_pin/core/passes/__init__.py` (`run_v2_duckdb_pipeline`)
- `src/vulnparse_pin/storage/schema.sql` (`aci_signals` table)
- `src/vulnparse_pin/core/passes/Scoring/scoringPass.py` (`ScoringV3Pass` Track A & Track B consumers)
- `src/vulnparse_pin/core/passes/Triage/triage_pass.py` (`TriageDecisionPass` SSVC & SAST corroboration consumers)
- `src/vulnparse_pin/core/passes/TopN/topn_pass.py` (`TopNV2Pass` tie-break consumer)
- `src/vulnparse_pin/core/passes/TopN/TN_triage_semantics.py` & `src/vulnparse_pin/core/schemas/topN.schema.json`
- `src/vulnparse_pin/reporting/renderer.py` & `src/vulnparse_pin/ui/app.py`

## Pass Lifecycle & DAG Position

In `run_v2_duckdb_pipeline()`, `ACI@2.0` runs **ahead of** scoring and triage:

1. `NmapAdapter@1.0` *(optional)*
2. `ACI@2.0` (`ACIV2Pass`, `requires_passes = ()`)
3. `Scoring@3.0` (`ScoringV3Pass`)
4. `Triage@2.0` (`TriageDecisionPass`, `requires_passes = ("Scoring@3.0", "ACI@2.0")`)
5. `TopN@2.0` (`TopNV2Pass`, `requires_passes = ("Triage@2.0",)`)
6. `Summary@2.0` (`SummaryV2Pass`)

This ordering allows `Scoring@3.0` Track B (`exposure_weakness`) to incorporate `aci_signals` directly into `raw_risk_score` and `operational_score` without a second scoring pass.

## DuckDB Storage & SQL Join Enrichment

### `aci_signals` Table (`schema.sql`)

```sql
CREATE TABLE IF NOT EXISTS aci_signals (
    run_id VARCHAR NOT NULL,
    finding_id VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    capabilities_json VARCHAR,
    chains_json VARCHAR,
    matched_tokens_json VARCHAR,
    confidence DOUBLE,
    uplift_score DOUBLE,
    PRIMARY KEY (run_id, finding_id)
);
```

### Multi-Table SQL Join Input Query

`_run_duckdb()` streams findings in `25,000`-row cursor chunks (`fetchmany(25_000)`) from a single SQL query joining:

1. `findings f`: `cwes_json`, `title`, `description`, `plugin_output`, `affected_port`, `tags_json`, `exploit_evidence`, `references_json`.
2. `enrichment_snapshots e_prim`: primary CVE `in_kev` and `verified_exploit`.
3. `finding_cves fc` + `enrichment_snapshots e` (`fc_agg` subquery): `BOOL_OR(COALESCE(e.in_kev, FALSE))` and `BOOL_OR(COALESCE(e.verified_exploit, FALSE))` across **all** CVEs linked to the finding, ensuring secondary-CVE KEV/exploit signals are never missed.
4. `finding_evidence` (`fe_sig` subquery): `LIST(DISTINCT scanner_sig ORDER BY scanner_sig)` aggregating every contributing scanner rule/template/plugin signature across deduplicated detections.

Results are written back to `aci_signals` inside an explicit transaction using `conn.appender("aci_signals")` in `25,000`-row batches.

## Signal Extraction & `scanner_sig` Matching Parity

`aci_pass.py` preserves exact parity between its fast-path memoized DuckDB evaluator and the single-record `_infer_single_record()` path:

- **Word-boundary short tokens (`_SHORT_BOUNDED_TOKEN_RES`):** Short ambiguous acronyms/protocols (`rce`, `sqli`, `lfi`, `smb`, `ssh`, `rdp`, `rpc`, `xss`) require `(?<![a-z0-9])<tok>(?![a-z0-9])` boundaries rather than raw substring matches.
- **Normalized `scanner_sig` matching (`_scan_sig`):**
  - Fast-skips pure numeric `nessus:<id>`, `qualys:<id>`, `openvas:<id>` signatures unless `scanner_prefix_or_digit_tokens` match.
  - Otherwise lowercases `scanner_sig`, normalizes separators (`[/._:-]+` → `" "`), and checks both `_STRUCTURED_TAG_SIGNALS` (excluding broad prose-only keys `exposure`, `secret`, `secrets` from signature matching) and `_effective_text_tokens(cfg)`.
- **Structured tags & CWEs (`_scan_tags`, `_scan_cwes`):** Extracts normalized CWEs (`CWE-<int>`) from `cwes_json` and `CWE-\d+` inside tags, mapping them via `_CWE_SIGNAL_MAP` (e.g., `CWE-78`, `CWE-89`, `CWE-94`, `CWE-287`, `CWE-306`, `CWE-502`, `CWE-798`, `CWE-918`).
- **Remote port & threat-intel signals:** Adds `remote_service` when `affected_port` is in `_REMOTE_PORT_SIGNALS`, `exploit` when `exploit_evidence` or `verified_exploit` is true, and `kev` when `in_kev` is true.
- **Memoization caches:** Uses bounded memo dictionaries (`text_field_memo`, `cwes_memo`, `tags_memo`, `sig_memo`, `refs_memo`, `eval_memo`) so 500k+ finding runs avoid redundant regex/substring scans on repeated plugin descriptions.

## Rule Evaluation, Guardrails, & Uplift Math

`_evaluate_aci_signals_to_result()` executes deterministically:

1. **Capability matching & guardrails:**
   - Iterates enabled `cfg.capability_rules`, retaining the maximum rule weight per matched capability.
   - **Remote-service guardrail:** `remote_execution` and `initial_access` are suppressed if the *only* matched signal is `remote_service`.
   - **Lateral-movement guardrail:** `lateral_movement` from protocol-only signals (`smb`, `ssh`, `rdp`, `rpc`) is suppressed unless `has_exploit`, `in_kev`, `_LATERAL_CONTEXT_SIGNALS`, or `_LATERAL_CONTEXT_KEYWORDS` are present.
   - In `merge` mode, `_EXTRA_CAPABILITY_SIGNALS` additionally scores `deserialization` (`0.80`), `ssrf` (`0.70`), `initial_access` via `ssrf`/`deserialization` (`0.70`), `panel`/`misconfig`/`exposure` (`0.50`), and `xss` (`0.55`).
2. **Confidence & exploit boost:**
   - `confidence_base = min(1.0, sum(capability_weight_max.values()))`
   - If `exploit_boost.enabled` and `has_exploit`: `exploit_bonus = min(max_bonus, weight * confidence_base)`
   - `confidence = min(1.0, confidence_base + exploit_bonus)`
   - Buckets: `high >= 0.8`, `medium >= 0.5`, else `low`.
3. **Chain inference:** Matches enabled `cfg.chain_rules` where `set(rule.requires_all).issubset(matched_capabilities)`.
4. **Rank uplift:**
   - If `confidence >= min_confidence`: `uplift = clamp(max_uplift * ((confidence - min_confidence) / (1.0 - min_confidence)), 0.0, max_uplift)`
   - Else `0.0`.

## Downstream Integration (Track B, Triage, TopN, Ledger, UI/Dossier)

- **`Scoring@3.0` Track B (`exposure_weakness`):** Non-CVE findings gain `+3.5` for high-impact ACI capabilities (or `+2.0` for general capabilities) and `+1.0` for `aci_chains` before `signal_reliability` weighting; `score_trace` records `aci_capabilities` and `aci_chains`.
- **`Triage@2.0`:** Consumes `aci_signals` for `bod-26-04` SSVC `exploitation=active` (reliable Track B active exposure), `automatable`, `technical_impact=total`, `P2` chain elevation, and `static_sast` P1-cap corroboration.
- **`TopN@2.0`:** Uses `aci.uplift_score DESC` as a deterministic tie-breaker in SQL `ORDER BY` / `ROW_NUMBER()` windows.
- **Decision Ledger (`ledger_events`):** `_emit_ledger()` appends `ACI_INFERENCE_SUMMARY` and up to 10 `ACI_FINDING_INFERRED` sample events when `finding_semantics` is populated (`<= 10,000` findings).
- **`vpp ui` & Reporting:** `repositories.get_finding_detail()` and `reporting/renderer.py` expose `capabilities`, `chains`, `matched_tokens`, `aci_confidence`, and `aci_uplift_score` to the TUI finding inspector and Decision Defense Dossier templates.

## Validation Boundaries

- **JSON Schema:** `topN.schema.json` enforces structure and numeric bounds on `aci.*`.
- **Semantic validation (`TN_triage_semantics._parse_aci`):** Enforces unique rule IDs, non-empty normalized signals, valid `token_mode` (`merge` or `replace`), valid capability references in `chain_rules`, and `0.0 <= min_confidence <= 1.0`.
- **Testing:** Covered by `tests/test_aci_pass.py` and `tests/test_aci_v2.py` (parity across DuckDB and `ScanResult`, non-CVE Nuclei/SAST Track B uplift, `scanner_sig` matching, and guardrail enforcement).

## Related Docs

- [ACI Feature Explanation](ACI%20Feature%20Explanation.md)
- [ACI Rule Authoring Tutorial](ACI%20Rule%20Authoring%20Tutorial.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [ScanResult & DuckDB Schema](ScanResult_Schema.md)
- [Output Interpretation](Output%20Interpretation.md)
