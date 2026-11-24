# Nmap Context Deep Dive

This page is the technical reference for the Nmap context adapter (`NmapAdapterPass`, `nmap_adapter@1.0`). It covers streaming XML parsing, deterministic DuckDB host/port reconciliation, shadow-asset separation, downstream pass effects, and security controls.

## Overview

VulnParse-Pin accepts Nmap XML scan output (`--nmap` / `--nmap-ctx` / `-nmap`) as supplementary attack-surface context. Supplying an Nmap XML file never mutates primary scanner findings; instead, `NmapAdapterPass` extracts confirmed `open` ports, OS hints, and NSE CVE references, reconciles them deterministically against `.vpp.db` assets, and publishes `nmap_adapter@1.0` to `DerivedContext`.

Downstream effects:

1. **TopN ranking tiebreak** (default `port_tiebreak_enabled: true`) — equal-priority findings/assets with confirmed open ports sort ahead of unconfirmed ones.
2. **Optional scoring bonus** (`scoring_port_bonus`, default `0.0`, range `0.0–5.0`) — adds to raw risk when a finding's port is confirmed open by Nmap.
3. **Shadow-asset discovery & exposure inference** — Nmap hosts absent from the primary scan are recorded in `.vpp.db` as `unmatched_shadow` (unless matched by `assets.yaml`), and unmatched hosts infer `internet_facing` from public/test-net IP classification or exposed public service ports.

---

## How it works

### Pass lifecycle in v2.0

In `run_v2_duckdb_pipeline()`, `NmapAdapterPass` runs first:

```text
[NmapAdapterPass (nmap_adapter@1.0)] -> [ACI@2.0] -> [Scoring@3.0] -> [Triage@2.0] -> [TopN@2.0] -> [Summary@2.0]
```

### Streaming Nmap XML parsing

`_stream_nmap_hosts()` (`src/vulnparse_pin/core/passes/Nmap/nmap_adapter_pass.py`) reads the file through `ctx.pfh.open_for_read(...)` and streams `<nmaprun>` / `<host>` elements using `safe_iterparse()` + `prune_element()` from `src/vulnparse_pin/parsers/_xml_security.py` in O(1) memory per host:

- Validates root tag is `<nmaprun>` (otherwise emits `status="invalid_format"` and `NMAP_CTX_INVALID_FORMAT`).
- Extracts normalized IPv4/IPv6 addresses, normalized hostnames, OS match names, `open` ports, and valid `CVE-YYYY-NNNN+` IDs from `<script>` NSE outputs.

### Deterministic DuckDB reconciliation (`_reconcile_duckdb_hosts`)

When a DuckDB workspace (`db` + `run_id`) is active, `_reconcile_duckdb_hosts()` reconciles Nmap hosts deterministically against `assets` and `asset_aliases`:

1. **Deterministic DB read order:** Loads existing assets ordered by `ORDER BY asset_id ASC` and aliases ordered by `ORDER BY asset_id ASC, alias_type ASC, alias_value ASC`.
2. **Hostname-before-IP matching precedence:** For each Nmap host, candidate keys are checked in order `(*hostnames, *ips, *sorted(host["all_keys"]))` against `key_to_aid`, preferring hostname matches before IP matches; if unmatched, `AssetContextMatcher.resolve(ip=primary_ip, hostname=primary_host)` is consulted.
3. **Existing asset updates:** Merges newly confirmed `open_ports_json`, backfills missing `hostname`, `ip_address`, or `os`, and infers `internet_facing` for `unmatched_shadow` assets when `internet_facing IS NULL` (`_infer_unmatched_internet_facing`).
4. **Shadow-asset separation:** Nmap hosts that do not match any primary scan asset or `assets.yaml` rule are inserted into `assets` with `inventory_status = "unmatched_shadow"`, and `matched_asset_count` explicitly excludes `db_shadow_aids` so shadow hosts do not inflate join counts.
5. **Atomic DuckDB persistence:** Updates and new asset/alias rows are flushed via DuckDB `appender` (`_stg_nmap_upd`, `assets`, `asset_aliases`) inside a single transaction.

### Downstream consumption

- **`Scoring@3.0` / `ScoringPass`:** Checks whether a finding's `affected_port` appears in `asset_open_ports[asset_id]`; attaches `"nmap_open_port": True` to `score_trace` and applies `nmap_port_bonus` if configured `> 0.0`.
- **`TopN@2.0` / `TopNPass`:** Consumes `asset_open_ports` when `port_tiebreak_enabled: true`.

---

## Status paths and ledger events

`NmapAdapterPass` is non-blocking; errors do not drop findings.

| Status | Condition | Ledger reason code |
| --- | --- | --- |
| `disabled` | `--nmap` / `--nmap-ctx` not supplied | `NMAP_CTX_DISABLED` |
| `enabled` | XML parsed and reconciled | `NMAP_CTX_ENABLED` |
| `error` | File unreadable or XML/XXE error | `NMAP_CTX_FAILED` |
| `invalid_format` | Root XML tag is not `nmaprun` | `NMAP_CTX_INVALID_FORMAT` |

`join_rate` (`matched_asset_count / total_assets`, excluding shadow-only Nmap hosts from `matched_asset_count`) is recorded in the `NMAP_CTX_ENABLED` ledger event.

---

## Configuration and CLI usage

```bash
vpp scan scan.nessus --nmap nmap_results.xml -o results.json
```

Legacy aliases `--nmap-ctx` and `-nmap` remain supported. The file must have a `.xml` extension.

In `config.yaml`:

```yaml
nmap_ctx:
  port_tiebreak_enabled: true
  scoring_port_bonus: 0.0
```

`config.schema.json` enforces `additionalProperties: false` and `0.0 <= scoring_port_bonus <= 5.0`.

---

## Security considerations

- **PFH enforcement:** `--nmap` input is validated via `ctx.pfh.ensure_readable_file(...)` (`forbid_symlinks_read=True` by default, optional `--enforce-root-read`).
- **Hardened XML parsing (NO `defusedxml`):** `_stream_nmap_hosts()` uses `safe_iterparse()` (`src/vulnparse_pin/parsers/_xml_security.py`), which enforces `resolve_entities=False`, `no_network=True`, `load_dtd=False`, `dtd_validation=False`, `huge_tree=False`, 1 MiB XML prolog validation (including BOM-less UTF-16LE/BE), and full-subtree `etree.Entity` rejection.
- **CVE sanitization:** NSE script CVE tokens must match `^CVE-\d{4}-\d{4,7}$`.
- **Bounded bonus:** `scoring_port_bonus` is schema-capped at `5.0`.

---

## Related pages

- [Detection and Parsing](Detection%20and%20Parsing.md)
- [Pass Phases](Pass%20Phases.md)
- [Identity Contract](Identity%20Contract.md)
- [Scoring and Prioritization Deep Dive](Scoring%20and%20Prioritization%20Deep%20Dive.md)
- [Security Features](Security%20Features.md)
