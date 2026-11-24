# ScanResult, DuckDB, and Context Schemas

VulnParse-Pin v2.0 (`Apache-2.0`) persists every scan run in a 12-table **DuckDB workspace (`.vpp.db`)** and validates JSON exports, asset inventories, triage decisions, and manifests with **JSON Schema Draft 2020-12** contracts under `src/vulnparse_pin/core/schemas/`.

---

## 1. DuckDB Workspace Schema (`.vpp.db` — 12 Tables)

Defined in `src/vulnparse_pin/storage/schema.sql` and managed by `VppDatabase` (`src/vulnparse_pin/storage/db.py`) and `src/vulnparse_pin/storage/repositories.py`:

| Table | Primary Key | Purpose |
| --- | --- | --- |
| `runs` | `run_id` | Run metadata (`created_at_utc`, `vpp_version`, `profile`, `config_sha256`, `assets_sha256`, `decisions_sha256`, `intel_metadata_json`, `manifest_digest`, `input_files_json`, `baseline_run_id`) |
| `assets` | `(run_id, asset_id)` | Canonicalized assets (`canonical_key`, `hostname`, `ip_address`, `target_uri`, `image_or_repo`, `os`, `declared_criticality`, `derived_criticality`, `internet_facing`, `owner`, `env_tags_json`, `inventory_status` [`matched` \| `unmatched_shadow`], `matched_rule_id`, `open_ports_json`) |
| `asset_aliases` | — | Resolved identity aliases (`run_id`, `asset_id`, `alias_type`, `alias_value`) |
| `findings` | `(run_id, finding_id)` | Deduplicated canonical findings (`scoring_track` [`cve_threat` \| `exposure_weakness`], `primary_cve`, `cves_json`, `cwes_json`, `ghsa_ids_json`, `title`, `description`, `solution`, `plugin_output`, `affected_port`, `protocol`, `service_name`, `location_uri`, `line_number`, `package_purl`, `scanner_severity`, `scanner_cvss_score`, `scanner_cvss_vector`, `detection_mode`, `signal_reliability`, `ingestion_confidence`, `fidelity_tier`, `source_format`, `references_json`, `tags_json`, `exploit_evidence`, `is_deduplicated`, `source_count`) |
| `finding_evidence` | — | Per-detection cross-scanner provenance (`run_id`, `finding_id`, `evidence_idx`, `source_format`, `scanner_sig`, `raw_severity`, `raw_cvss`, `raw_location`, `evidence_excerpt`) |
| `finding_cves` | `(run_id, finding_id, cve_id)` | Normalized many-to-many CVE links per finding |
| `enrichment_snapshots` | `(run_id, cve_id)` | Run-pinned CVE intel (`cvss_score`, `cvss_vector`, `cvss_version`, `cvss_provenance`, `epss_score`, `epss_percentile`, `epss_model_version`, `epss_date`, `in_kev`, `kev_date_added`, `kev_due_date`, `kev_ransomware`, `kev_required_action`, `verified_exploit`, `heuristic_exploit_mention`, `exploit_refs_json`, `ghsa_ids_json`, `osv_ids_json`, `enrichment_confidence`, `sources_json`) |
| `aci_signals` | `(run_id, finding_id)` | `ACI@2.0` inference (`asset_id`, `capabilities_json`, `chains_json`, `matched_tokens_json`, `confidence`, `uplift_score`) |
| `scores` | `(run_id, finding_id)` | `Scoring@3.0` dual-track scores (`asset_id`, `scoring_track`, `raw_risk_score`, `operational_score`, `risk_band`, `score_trace_json`) |
| `triage_decisions` | `(run_id, finding_id)` | `Triage@2.0` outputs (`asset_id`, `profile`, `priority_tier`, `oal_compat`, `ssvc_action`, `sla_bucket`, `sla_days`, `decision_status`, `decision_id`, `assumed_state_json`, `rationale_summary`) |
| `diff_events` | — | Persisted `DiffEngine` events (`diff_id`, `base_run_id`, `target_run_id`, `category`, `finding_id`, `asset_id`, `cve_id`, `details_json`) |
| `ledger_events` | `(run_id, seq)` | Append-only SHA-256 hash-chained events (`ts`, `component`, `event_type`, `subject_ref`, `why`, `evidence_digest`, `prev_hash`, `entry_hash`) |

---

## 2. Normalized DuckDB JSON Export (`schema_version: "2.0.0"`)

Produced by `export_duckdb_json()` (`src/vulnparse_pin/utils/reportgen.py`) via `vpp scan -o ...` or `vpp export --format json`:

```json
{
  "schema_version": "2.0.0",
  "run_id": "run_20261124T...",
  "generated_at_utc": "2026-11-24T...",
  "profile": "bod-26-04",
  "presentation": {
    "overlay_mode": "namespace",
    "operational_scale": "0-10",
    "streaming": true
  },
  "run": { "...": "runs table metadata" },
  "assets": [
    {
      "asset_id": "aid_v2_...",
      "canonical_key": "...",
      "hostname": "edge-gw-01.corp.local",
      "ip_address": "203.0.113.10",
      "internet_facing": true,
      "inventory_status": "matched",
      "derived": {
        "Scoring@3.0": { "asset_criticality": "Extreme" }
      },
      "findings": [
        {
          "finding_id": "fid_v2_...",
          "scoring_track": "cve_threat",
          "primary_cve": "CVE-2024-3094",
          "cves": ["CVE-2024-3094"],
          "detection_mode": "credentialed_host",
          "signal_reliability": 1.0,
          "enrichment": {
            "cvss_score": 10.0,
            "cvss_version": "3.1",
            "cvss_provenance": "NVD",
            "epss_score": 0.91,
            "epss_percentile": 0.99,
            "in_kev": true
          },
          "derived": {
            "Scoring@3.0": { "raw_risk_score": 16.0, "operational_score": 10.0, "risk_band": "Critical", "score_trace": {} },
            "Triage@2.0": { "profile": "bod-26-04", "priority_tier": "P1", "oal_compat": "OAL-1", "ssvc_action": "Act", "sla_bucket": "3-day + Forensic Triage", "sla_days": 3, "decision_status": "active" },
            "ACI@2.0": { "capabilities": ["remote_execution"], "chains": [], "matched_tokens": [], "confidence": 0.85, "uplift_score": 1.25 }
          }
        }
      ]
    }
  ]
}
```

See [Presentation Overlays](Presentation%20Overlays.md) for `namespace` vs `flatten` field layout.

---

## 3. `scanResult.schema.json` (In-Memory `ScanResult` Contract)

Location: `src/vulnparse_pin/core/schemas/scanResult.schema.json` (JSON Schema Draft 2020-12).

Top-level required properties:

- `scan_metadata` (`source`, `scan_date`, `asset_count`, `vulnerability_count`, optional `parsed_at`, `source_file`, `scan_name`)
- `assets` (array of `Asset` objects with `findings`)
- `derived` (`DerivedContext` holding pass outputs)

In v2.0, `scanResult.schema.json` `$defs.Finding` includes v2 metadata fields (`cwes`, `ghsa_ids`, `service_name`, `location_uri`, `line_number`, `package_purl`, `detection_mode`, `tags`, `scoring_track`, `primary_cve`, `signal_reliability`, `epss_percentile`, `cvss_provenance`, `cvss_version`, `triage_profile`, `ssvc_action`, `sla_bucket`, `sla_days`, `decision_status`, `decision_id`), `source_format`, `fidelity_tier` (`full|partial|minimal|high|medium|low`), `ingestion_confidence`, and expanded `cve_analysis` properties (`cvss_provenance`, `cvss_version`, `epss_percentile`, `epss_model_version`, `epss_date`, `kev_*`, `verified_exploit`, `heuristic_exploit_mention`, `ghsa_ids`, `osv_ids`).

Validate a `ScanResult` object in Python:

```python
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema

validate_scan_result_schema(my_scan_result)
```

---

## 4. `assets.schema.json` (`assets.yaml`)

Location: `src/vulnparse_pin/core/schemas/assets.schema.json` (Draft 2020-12, `additionalProperties: false`).

Defines pattern-based inventory context rules (`--assets assets.yaml`) used by `AssetContextMatcher` (`src/vulnparse_pin/core/assets_context.py`):

- **`version`**: `"v1"` or `"v2"`
- **`defaults`**: optional `criticality` (`critical|high|medium|low`), `internet_facing` (`boolean|null`), `owner`, `env` (string or list), `tags` (`{key: string}`)
- **`rules[]`** (`AssetRule`, `required: ["id"]`):
  - Identity / matchers: `id`, `asset_id`, `aliases[]`, `cidrs[]`, `hostnames[]`, `uris[]`, `images[]`, `repos[]`
  - Context attributes: `internet_facing`, `criticality`, `owner`, `env`, `tags`
  - Matching precedence: `alias`/`asset_id` → exact IP/FQDN/URI/image → longest-prefix CIDR → most-specific `fnmatchcase` glob → `unmatched_shadow`
- **`decisions[]`** *(optional inline `InlineDecisionEntry` list)*: same fields as `decisions.schema.json`

---

## 5. `decisions.schema.json` (`decisions.yaml`)

Location: `src/vulnparse_pin/core/schemas/decisions.schema.json` (Draft 2020-12, `additionalProperties: false`).

Defines explicit risk-acceptance, deferral, and mitigation records (`--decisions decisions.yaml` or `vpp defer`):

- **`version`**: `"v1"` or `"v2"`
- **`decisions[]`** (`DecisionEntry`, `required: ["id", "cve_or_rule_id", "status", "rationale"]`):
  - `id` (1–128 chars), `asset_id` (optional), `asset_pattern` (optional glob/ID), `cve_or_rule_id` (CVE ID or scanner rule/template ID)
  - `status`: `"deferred"` | `"accepted"` | `"mitigated"`
  - `rationale`, `owner`, `created_at`, `expires_at`
  - **`assumptions`** *(optional object, `additionalProperties: false`)*:
    - `in_kev` (`boolean|null`)
    - `max_epss` (`0.0–1.0`)
    - `max_epss_percentile` (`0.0–1.0`)
    - `internet_facing` (`boolean|null`)
    - `max_cvss` (`0.0–10.0`)

Any violated assumption flips the finding to `deferred_invalidated` / `accepted_invalidated` in `Triage@2.0` and triggers `DiffEngine` (`--fail-on stale-assumption`).

## Related Docs

- [Identity Contract](Identity%20Contract.md)
- [Output Interpretation](Output%20Interpretation.md)
- [Presentation Overlays](Presentation%20Overlays.md)
- [RunManifest Technical Deep Dive](RunManifest_Technical.md)
