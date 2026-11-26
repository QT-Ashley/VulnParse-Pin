# Presentation Overlays

Presentation overlays let you shape derived pass output (`Scoring@3.0`, `Triage@2.0`, `ACI@2.0`) in normalized JSON exports without mutating core finding fields or `.vpp.db` storage semantics.

Overlay generation is implemented in `src/vulnparse_pin/utils/reportgen.py` (`export_duckdb_json` and `materialize_presentation`).

## Overlay Modes

### `namespace` (Recommended / Default for DuckDB JSON)

Derived pass outputs are grouped under a dedicated `derived` object per finding and per asset:

- **Finding `derived`:**
  - `derived["Scoring@3.0"]`: `raw_risk_score`, `operational_score`, `risk_band`, `score_trace`
  - `derived["Triage@2.0"]`: `profile`, `priority_tier`, `oal_compat`, `ssvc_action`, `sla_bucket`, `sla_days`, `decision_status`, `decision_id`, `assumed_state`, `rationale_summary`
  - `derived["ACI@2.0"]`: `capabilities`, `chains`, `matched_tokens`, `confidence`, `uplift_score`
- **Asset `derived`:**
  - `derived["Scoring@3.0"]`: `asset_criticality`

Best for API consumers, schema governance, and avoiding key collisions.

### `flatten`

Derived fields are promoted directly onto each finding and asset object for legacy consumers and flat JSON pipelines:

- **Finding top-level keys:** `raw_risk_score`, `operational_score`, `risk_score`, `risk_band`, `score_trace`, `priority_tier`, `oal_compat`, `ssvc_action`, `sla_bucket`, `sla_days`, `decision_status`, `decision_id`, `rationale_summary`, `aci_capabilities`, `aci_chains`, `aci_confidence`, `aci_uplift_score`.
- **Asset top-level keys:** `derived_criticality`, `criticality`.

## CLI Usage

```bash
# Default DuckDB JSON export via vpp scan (uses namespace overlay)
vpp scan scan.nessus --db workspace.vpp.db -o out/scan.json

# Flattened presentation JSON during vpp scan
vpp scan scan.nessus --db workspace.vpp.db -o out/scan_flat.json --presentation --overlay-mode flatten

# Export JSON from an existing .vpp.db workspace
vpp export --db workspace.vpp.db --format json --overlay-mode namespace -o out/export.json
vpp export --db workspace.vpp.db --format json --overlay-mode flatten -o out/export_flat.json
```

> [!NOTE]
> On `vpp scan`, `--overlay-mode` requires `--presentation` when set to `flatten`. On `vpp export --format json`, `--overlay-mode` defaults to `namespace`.

## Related Docs

- [Output Interpretation](Output%20Interpretation.md)
- [ScanResult & DuckDB Schema](ScanResult_Schema.md)
- [Usage](Usage.md)
