# Nmap Context Deep Dive

This page is the technical reference for the Nmap context adapter feature (`NmapAdapterPass`). It covers how the adapter works, how it is implemented, what it affects, its operational and security implications, and how to configure it.

## Overview

VulnParse-Pin accepts Nmap XML scan output as optional supplementary context for vulnerability prioritization. Supplying a Nmap file does **not** alter the source vulnerability data — findings and assets derived from the primary scanner (Nessus, OpenVAS, Qualys, etc.) are never mutated. Instead, the adapter extracts confirmed open-port evidence and makes it available to downstream passes as a derived signal.

Two downstream effects are available:

1. **TopN ranking tiebreak** — equal-score findings and assets that have a confirmed Nmap open port sort above those without one.
2. **Optional scoring bonus** — a configurable raw-score addend applied when a finding's service port is confirmed open by Nmap (default `0.0`, opt-in).

Both effects are independently controlled by policy knobs in `config.yaml`.

---

## How it works

### Pass lifecycle

`NmapAdapterPass` runs as the **first derived pass** in the pipeline, before `Scoring@2.0`, `TopN@1.0`, and `Summary@1.0`. It is a pure read-and-derive step:

```
[NmapAdapterPass] → [Scoring@2.0] → [TopN@1.0] → [Summary@1.0]
```

The pass writes its result into the `DerivedContext` registry under the key `nmap_adapter@1.0`. Downstream passes retrieve this by key — no direct coupling.

### Asset identity join

The adapter maps Nmap hosts to scan assets using IP address and hostname tokens. It attempts:

1. Exact IP match against `asset.ip_address`
2. Hostname prefix/suffix matching against `asset.hostname`

A "join" is recorded when a Nmap host maps to at least one scan asset. Unmatched Nmap hosts are tracked in `unmatched_asset_ids` in the output for observability.

### Port extraction

For each matched host, the adapter collects all confirmed `open` TCP/UDP ports from the Nmap XML `<port>` elements. NSE script output is also scanned for CVE references when present.

The resulting per-asset port index is:

```python
asset_open_ports: dict[str, tuple[int, ...]]   # asset_id → (port, port, ...)
nse_cves_by_asset: dict[str, tuple[str, ...]]  # asset_id → ("CVE-XXXX-XXXX", ...)
```

### Downstream consumption

**ScoringPass** reads `asset_open_ports` via `_get_nmap_open_ports_by_asset()` on the `DerivedContext`. For each finding, it checks whether the finding's service port appears in the confirmed open ports for that asset. If a match is found, a `"nmap_open_port": True` signal is attached to the plugin attribute cache. If `scoring_port_bonus > 0.0`, this adds directly to `raw_score` before normalization.

**TopNPass** reads the same index. It injects an `nmap_hit` flag into all three sort key positions:

- `_rank_findings_for_asset`: `(-score, -nmap_hit, finding_id)`
- `_rank_assets`: `(-score, -crit_high, -crit_rank, -scorable_count, -nmap_confirmed, asset_id)`
- `_rank_global_findings`: `(-score, -nmap_hit, asset_id, finding_id)`

This ensures deterministic and operationally meaningful ordering without numeric score inflation.

---

## Status paths and ledger events

The pass always completes — it does not raise. Status is one of four values written to the `DerivedPassResult`:

| Status | Condition | Ledger reason code |
|---|---|---|
| `disabled` | `--nmap-ctx` was not supplied | `NMAP_CTX_DISABLED` |
| `enabled` | XML parsed and joined successfully | `NMAP_CTX_ENABLED` |
| `error` | File unreadable or XML parse failure | `NMAP_CTX_FAILED` |
| `invalid_format` | Root XML tag is not `nmaprun` | `NMAP_CTX_INVALID_FORMAT` |

All four paths emit a structured `LedgerService` decision event when a `LedgerService` is present in `ctx.services`. The `NMAP_CTX_ENABLED` event includes:

```json
{
  "status": "enabled",
  "source_file": "/path/to/nmap.xml",
  "host_count": 42,
  "matched_asset_count": 39,
  "unmatched_asset_count": 3,
  "join_rate": 0.9286
}
```

`join_rate` is `matched_asset_count / total_scan_assets`, rounded to 4 decimal places. A low join rate may indicate IP/hostname mismatch between the Nmap scan scope and the vulnerability scanner scope.

---

## Implementation files

| File | Role |
|---|---|
| `src/vulnparse_pin/core/passes/Nmap/nmap_adapter_pass.py` | Pass implementation |
| `src/vulnparse_pin/core/passes/Nmap/types.py` | `NmapAdapterPassOutput` dataclass |
| `src/vulnparse_pin/core/classes/decision_reasons.py` | `NMAP_CTX_*` reason codes |
| `src/vulnparse_pin/core/classes/scoring_pol.py` | `ScoringPolicyV1.nmap_port_bonus` |
| `src/vulnparse_pin/core/classes/dataclass.py` | `Services.nmap_ctx_config` |
| `src/vulnparse_pin/core/passes/Scoring/scoringPass.py` | `nmap_open_port` signal + bonus |
| `src/vulnparse_pin/core/passes/TopN/topn_pass.py` | Tiebreak wiring in all 3 sort paths |
| `src/vulnparse_pin/app/bootstrap.py` | CLI wiring and `Services` construction |
| `src/vulnparse_pin/app/runtime_helpers.py` | `load_score_policy(nmap_port_bonus=...)` |
| `src/vulnparse_pin/resources/config.yaml` | `nmap_ctx` config section defaults |
| `src/vulnparse_pin/core/schemas/config.schema.json` | Schema validation for `nmap_ctx` |

---

## Configuration

### Enabling Nmap context

Nmap context is opt-in. Pass the path to a Nmap XML file via `--nmap-ctx`:

```bash
vpp -f scan.nessus -o results.json --nmap-ctx nmap_results.xml
```

Short form:

```bash
vpp -f scan.nessus -o results.json -nmap nmap_results.xml
```

The argument requires a `.xml` extension and must be a readable file. If the file cannot be read or is not valid Nmap XML, the pass records the failure in the ledger and the pipeline continues normally — no findings are dropped.

### `config.yaml` — `nmap_ctx` section

```yaml
nmap_ctx:
  port_tiebreak_enabled: true
  scoring_port_bonus: 0.0
```

#### `port_tiebreak_enabled`

- **Type**: boolean
- **Default**: `true`
- **Effect**: when `true`, TopN ranking uses confirmed open ports as a secondary sort key for equal-score findings and assets. When `false`, the sort key reverts to finding/asset ID only.
- **Does not affect numeric scores.**

#### `scoring_port_bonus`

- **Type**: float, range `0.0–5.0`
- **Default**: `0.0`
- **Effect**: when `> 0`, this value is added to `raw_score` for any finding whose service port is confirmed open by Nmap. The addend is applied before operational score normalization.

Score impact example with default ceilings (`max_raw_risk: 15`, `max_op_risk: 10`):

| Bonus | Raw score delta | Approx operational score delta |
|---|---|---|
| `0.0` | +0.0 | +0.0 (tiebreak only) |
| `0.5` | +0.5 | ~+0.33 |
| `1.5` | +1.5 | ~+1.0 |
| `3.0` | +3.0 | ~+2.0 |
| `5.0` (max) | +5.0 | ~+3.33 |

The schema enforces a maximum of `5.0`. This cap limits the influence of network context to a supplementary signal rather than a dominant factor.

### Schema validation

`config.schema.json` validates both keys at startup:

```json
"nmap_ctx": {
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "port_tiebreak_enabled": { "type": "boolean" },
    "scoring_port_bonus": { "type": "number", "minimum": 0.0, "maximum": 5.0 }
  }
}
```

Unknown keys under `nmap_ctx` are rejected.

---

## What it affects

| Area | Effect when disabled | Effect when enabled (defaults) | Effect with bonus > 0 |
|---|---|---|---|
| Findings/assets data | No change | No change | No change |
| Numeric scores | No change | No change | `raw_score` increases by bonus amount |
| TopN finding order | ID-sorted tiebreak | Nmap-confirmed ports sort first at equal score | Same as defaults |
| TopN asset order | ID-sorted tiebreak | Nmap-confirmed assets rank higher at equal score | Same as defaults |
| RunManifest ledger | No nmap events | `NMAP_CTX_DISABLED` event | `NMAP_CTX_ENABLED` event with join stats |
| `derived.passes["nmap_adapter@1.0"]` | `status: disabled` | `status: enabled` with port index | `status: enabled` with port index |

---

## Operational implications

### When to use the tiebreak (default)

The tiebreak is the safest mode. It does not alter any numeric risk scores — it only promotes findings with confirmed open service ports within a group of otherwise equal-priority items. This is a signal of reachability: if two CVEs score identically but one's service port is confirmed reachable by Nmap, that finding gets surfaced first.

Use this when you want deterministic, operationally meaningful ordering at no risk of inflating scores.

### When to use a scoring bonus

Set `scoring_port_bonus > 0` when you want network reachability to explicitly lift findings above others on different assets. This is appropriate when:

- Confirmed open ports are a high-confidence indicator of exploitability in your environment.
- You are running both a vulnerability scanner and Nmap against the same scope with reliable overlap.
- You have validated the join rate is acceptable (e.g., `≥ 0.80`).

A small bonus (`0.5–1.5`) is generally sufficient to produce visible prioritization changes without drowning the CVSS/EPSS/KEV signal.

### Join rate interpretation

| Join rate | Implication |
|---|---|
| `≥ 0.90` | Strong overlap; Nmap context is highly reliable |
| `0.70–0.89` | Acceptable; some scope mismatch |
| `0.50–0.69` | Moderate mismatch; consider reviewing scan scopes |
| `< 0.50` | Significant mismatch; Nmap context may not be representative |

Join rate is visible in the RunManifest ledger under the `nmap_adapter` component event.

---

## Security considerations

- The Nmap XML file is read via `ctx.pfh.ensure_readable_file(...)` — all standard PFH path policy constraints apply (symlink policy, root-read enforcement, etc.).
- Parsing uses `defusedxml` to prevent XML external entity (XXE) and entity expansion attacks.
- `nse_cves_by_asset` CVE extraction applies the same `_is_valid_cve_id()` validator pattern used in GHSA to prevent malformed CVE strings from propagating into the output.
- A maliciously crafted Nmap XML file cannot alter finding scores beyond the configured `scoring_port_bonus` ceiling (schema-enforced `5.0`).
- The `NMAP_CTX_FAILED` and `NMAP_CTX_INVALID_FORMAT` events in the ledger provide a tamper-evidence trail if a supplied file is corrupt or unexpected.

---

## Testing coverage

| Test file | What it covers |
|---|---|
| `tests/test_nmap_adapter_pass.py` | Disabled path, enabled path, error path, invalid format path, TopN tiebreak integration |
| `tests/test_parallel_scoring.py` | `nmap_open_ports` arg forwarding in plugin cache build |
| `tests/test_pass_contracts.py` | Pass contract and pipeline ordering |
| `tests/test_config_schema_validation.py` | `nmap_ctx` schema acceptance and unknown-key rejection |

---

## Related pages

- [Pass Phases](Pass%20Phases.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Configs](Configs.md)
- [Usage](Usage.md)
- [Security Features](Security%20Features.md)
- [RunManifest Overview](RunManifest.md)
