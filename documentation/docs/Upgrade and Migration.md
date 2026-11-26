# Upgrade and Migration

This guide covers upgrading to **v2.0.0** from **`v1.2.x`** as well as historical `v1.0.x -> v1.1.x` migration notes.

---

## v1.2.x -> v2.0.0 Migration Guide

`v2.0.0` is a major platform upgrade introducing permissive `Apache-2.0` licensing, a persistent DuckDB workspace (`.vpp.db`), streaming XML/SARIF/Nuclei parsers, dual-track `Scoring@3.0`, `ACI@2.0`, `Triage@2.0` (`--profile bod-26-04`), scan-over-scan `vpp diff`, Decision Defense Dossiers, Executive Roadmaps, an optional Textual TUI (`vpp ui`), and a subcommand CLI.

### 1. Clean License Cut (`AGPL-3.0-or-later` -> `Apache-2.0`)

- **v2.0.0 and later** are licensed under the **Apache License, Version 2.0** (`Apache-2.0`) with zero copyleft Python runtime dependencies (`cvss` replaced by the clean-room Apache-2.0 CVSS v2.0/v3.x/v4.0 calculator in `src/vulnparse_pin/utils/cvss_utils.py`, and `defusedxml` replaced by hardened streaming `lxml`).
- Historical **`v1.0.0–v1.2.2`** releases remain under **`AGPL-3.0-or-later`**. See [Licensing](Licensing.md) for terms.

### 2. Packaging & Distribution Shift (PyInstaller Retired)

- Standalone PyInstaller `--onefile` binaries have been retired after `v1.2.2`.
- `v2.0.0+` ships as PEP 639 Python wheels and source distributions (with SLSA build provenance and CycloneDX SBOM verification).
- Install via `pipx install "vulnparse-pin[ui]"`, `uv tool install "vulnparse-pin[ui]"`, `pip`, or build a container locally using [Deployment Options](Deployment%20Options.md).

### 3. CLI Subcommand Migration

`v2.0.0` moves from top-level flags to purpose-built subcommands (`scan`, `demo`, `diff`, `ui`, `export`, `verify`, `defer`, `intel`). Top-level `v1.x` invocations still run through a compatibility shim with `[DEPRECATED]` stderr warnings, but all scripts and CI jobs should migrate:

| `v1.2.x` Invocation | `v2.0.0` Replacement | Notes |
| --- | --- | --- |
| `vpp -f scan.nessus -o out.json` | `vpp scan scan.nessus -o out.json` | Positional multi-file inputs supported (`vpp scan a.nessus b.sarif`) |
| `vpp -f scan.nessus --nmap-ctx nmap.xml -o out.json` | `vpp scan scan.nessus --nmap nmap.xml -o out.json` | `--nmap-ctx` remains an accepted alias inside `vpp scan` |
| `vpp --demo` | `vpp demo` (or `vpp demo --no-ui` in CI) | New 100% offline bundled multi-scanner demo pack (`<2s`) |
| `vpp --verify-runmanifest runmanifest.json` | `vpp verify runmanifest.json` | Strictly read-only by default (no `$HOME`/XDG writes unless custom `--log-file`) |
| `vpp --debug-path-policy` | `vpp scan --debug-path-policy` | Available on any subcommand |
| n/a | `vpp diff --fail-on stale-assumption` | Scan-over-scan delta & CI fail gate |
| n/a | `vpp ui --db .vpp.db` | Optional Textual TUI (`vulnparse-pin[ui]`) |
| n/a | `vpp export --format dossier-html` | Export Dossier, Roadmap, CSV, or JSON from `.vpp.db` |
| n/a | `vpp defer ...` | Upsert `decisions.yaml` deferral/acceptance/mitigation rules |
| n/a | `vpp intel status` / `vpp intel sync` | Cache integrity/freshness checks and feed syncing |

Additional CLI behavior changes:

- **`--no-csv-sanitize`** now **requires `--confirm-unsafe-csv`** on both `vpp scan` and `vpp export`, exiting with code `2` if omitted.
- **`--allow-large`** raises the input size cap from `500 MiB` to **`50 GiB`** across `FileInputValidator` and all streaming parsers.

### 4. Persistent DuckDB Store (`.vpp.db`) & Canonical v2 Identity (`aid_v2_` / `fid_v2_`)

- Scans now persist into `.vpp.db` (12 tables, `0o600` POSIX permissions, symlink-checked).
- Cross-scanner findings on the same host/service/CVE or non-CVE key are deduplicated deterministically while retaining all scanner-specific rows in `finding_evidence`.
- **Canonical v2 Identity**: Assets and findings in `.vpp.db` and v2 passes use `aid_v2_` and `fid_v2_` prefixes (`canonicalize_target_key()` normalizing IPs, FQDNs, URIs, and container images/repos). Legacy `aid_v1_` / `fid_v1_` helpers remain for in-memory `ScanResult` compatibility.

### 5. Pattern `assets.yaml` & `decisions.yaml`

Adopt structured asset inventory and decision governance files:

- **`assets.yaml`** (`assets.schema.json`): Map hosts, CIDRs, FQDNs, URIs, container images, and globs to `owner`, `criticality`, `internet_facing`, and `inventory_status`. Unmatched hosts are surfaced as `unmatched_shadow` alerts.
- **`decisions.yaml`** (`decisions.schema.json`): Record `deferred`, `accepted`, and `mitigated` entries with explicit assumption predicates (`expires_at`, `in_kev`, `max_epss`, `max_epss_percentile`, `internet_facing`, `max_cvss`). Manage via `vpp defer` or the `f` modal in `vpp ui`.

### 6. Scoring, EPSS v5, ACI@2.0, Triage@2.0 (`bod-26-04`) & `derived` Keys

Packaged configs advance to `version: v2` (`config.yaml`, `scoring.json`). Legacy `v1` config files continue loading with migration warnings during `v2.0.x`.

| Area | `v1.2.x` | `v2.0.0` |
| --- | --- | --- |
| Scoring Pass | `Scoring@2.0` | **`Scoring@3.0`**: Dual-track (`cve_threat` Track A + `exposure_weakness` Track B) weighted by `detection_mode` Signal Reliability (`1.0`, `0.90`, `0.85`, `0.55`) |
| EPSS Scoring | Linear scale in `Scoring@2.0` | **Monotonic EPSS v5 piecewise breakpoints** (`(0.0, 0.0)`, `(0.04, 1.8)`, `(0.10, 3.0)`, `(0.50, 4.2)`, `(1.0, 5.0)`) + FIRST percentile |
| CVSS Provenance | `NVD` / `GHSA` / `Scanner` | Unified `NVD > CNA > GHSA > OSV > Scanner-Supplied > Missing` including CVSS v4.0 (`cvssMetricV40`) |
| ACI Pass | `ACI@1.0` (opt-in) | **`ACI@2.0`** (default-enabled DuckDB pass across CVE & Track B findings) |
| Triage / SSVC | OAL lanes in reporting | **`Triage@2.0`**: `--profile default` or `--profile bod-26-04` (CISA BOD 26-04 SSVC `Act`/`Attend`/`Track*`/`Track`, SLAs `3-day + Forensic Triage`/`14-day`/`60-day`/`Fix on Upgrade`, SAST P1-cap guardrail, `decisions.yaml` reconciliation) |
| TopN & Summary | `TopN@1.0`, `Summary@1.0` | **`TopN@2.0`**, **`Summary@2.0`** |
| Reports | JSON, CSV, Executive/Technical MD | Adds **Decision Defense Dossiers** (`.html`/`.md`), **Executive Roadmaps** (`.html`/`.md`), and **Diff PR Comments** |

### 7. Recommended `v1.2.x -> v2.0.0` Upgrade Checklist

1. Upgrade installation (`pipx install "vulnparse-pin[ui]"` or `uv tool install "vulnparse-pin[ui]"`).
2. Run `vpp demo --no-ui` to verify DuckDB and offline reporting in your environment.
3. Update CI/cron scripts from `vpp -f ...` / `--verify-runmanifest` to `vpp scan ...` and `vpp verify ...`.
4. Add `--confirm-unsafe-csv` if any automation intentionally passes `--no-csv-sanitize` (prefer keeping default sanitization enabled).
5. Run `vpp intel status` (and `vpp intel sync --refresh` if enabling `VP_SQLITE_HMAC_KEY` or `VP_FEED_CACHE_HMAC_KEY` for the first time).
6. Check downstream JSON/automation consumers for `Scoring@3.0`, `ACI@2.0`, `Triage@2.0`, `TopN@2.0`, and `Summary@2.0`.

---

## Historical Reference: v1.0.x -> v1.1.x

> [!NOTE]
> The section below is retained for teams migrating older `v1.0.x` automation directly or auditing historical `v1.x` (`AGPL-3.0-or-later`) pipelines.

### Enrichment Flag Model Changed (`v1.1.x`)

Legacy positive-enable flags (`--enrich-kev`, `--enrich-epss`, `--enrich-exploit`) were removed in `v1.1.0` in favor of default-on enrichment with opt-out and source flags:

- `--no-kev`, `--no-epss`, `--no-exploit`, `--no-nvd`
- `--kev-source <online|offline>`, `--epss-source <online|offline>`, `--exploit-source <online|offline>`

### GHSA Activation Became CLI-Only

GHSA enrichment does not auto-activate from `config.yaml`; pass `--ghsa` (online) or `--ghsa <path>` (offline) at runtime. Token selection uses `enrichment.ghsa_token_env` (`VP_GHSA_TK`) with `GITHUB_TOKEN` fallback.

### Historical Before & After (`v1.0.x` vs `v1.1.x` vs `v2.0.0`)

```bash
# Legacy v1.0.x
vpp -f input.xml -o out.json --enrich-kev --enrich-epss --enrich-exploit

# Legacy v1.1.x
vpp -f input.xml -o out.json

# Current v2.0.0
vpp scan input.xml -o out.json --output-runmanifest out.runmanifest.json
vpp verify out.runmanifest.json
```

## Related Docs

- [Usage](Usage.md)
- [Deprecation and Versioning Policy](Deprecation%20and%20Versioning%20Policy.md)
- [Workflow Examples](Workflow%20Examples.md)
- [Deployment Options](Deployment%20Options.md)
- [RunManifest Overview](RunManifest.md)
- [Output Interpretation](Output%20Interpretation.md)
- [Troubleshooting](Troubleshooting.md)
