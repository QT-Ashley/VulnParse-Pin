# Getting Started In 5 Minutes

This guide gets you from zero to a persisted `.vpp.db` workspace, an audit-ready Decision Defense Dossier, an Executive Client Roadmap, an interactive Textual TUI workbench, and a verified `RunManifest` in VulnParse-Pin **v2.0.0** (`Apache-2.0`).

## 1) Install

Install VulnParse-Pin with optional interactive TUI support (`[ui]`):

```bash
pipx install "vulnparse-pin[ui]"
```

For headless CI/automation without the TUI:

```bash
pipx install vulnparse-pin
```

Or using `uv` / source editable install:

```bash
uv tool install "vulnparse-pin[ui]"
# Or from a local checkout:
pip install -e ".[ui]"
```

Verify the `vpp` CLI is ready:

```bash
vpp --version
vpp --help
```

See [Installation](Installation.md) for environment variables, virtual environments, and [Deployment Options](Deployment%20Options.md) for Docker, Kubernetes, and systemd setups.

## 2) Run the 2-Second Offline Demo (`vpp demo`)

Experience the full v2.0 pipeline 100% offline using the bundled multi-scanner demo pack (Nessus XML + Trivy SARIF + Nuclei JSONL + Semgrep SARIF + Nmap XML + `assets.yaml` + `decisions.yaml` + miniature threat-intel snapshot):

```bash
vpp demo
```

In headless shells or CI (skipping the interactive TUI launch):

```bash
vpp demo --no-ui
```

`vpp demo` automatically creates:

- `.vpp-demo.db`: DuckDB workspace containing both `demo-baseline` and `demo-current` runs
- `vpp_demo_output/dossier.html` and `vpp_demo_output/dossier.md`: Decision Defense Dossier
- `vpp_demo_output/executive_roadmap.html`: Executive Client Roadmap
- `vpp_demo_output/runmanifest.json`: Cryptographically digest-sealed `RunManifest` with hash-chained decision ledger

> [!NOTE]
> Single-pass `vpp demo` and `vpp scan --output-dossier ... --output-runmanifest ...` write `dossier.html` before `RunManifest` computes `output_hashes` (preventing a circular SHA-256 self-hash), so inline dossiers display `Pending post-export RunManifest seal (see runmanifest.json)`. To embed the sealed `sha256:...` digest directly inside `dossier.html`, re-export from `.vpp.db` / `.vpp-demo.db` after the scan:
>
> ```bash
> vpp export --db .vpp.db --format dossier-html -o out/dossier.html
> ```

## 3) Run Your First Scan (`vpp scan`)

Point `vpp scan` at one or more scanner reports (Nessus `.nessus`/`.xml`/`.csv`, OpenVAS `.xml`, Qualys `.xml`/`.csv`, SARIF 2.1.0 `.sarif`/`.json`, Nuclei `.jsonl`) plus optional Nmap context, asset inventory (`assets.yaml`), and triage decisions (`decisions.yaml`):

```bash
vpp scan scan.nessus trivy.sarif \
  --nmap nmap.xml \
  --assets assets.yaml \
  --decisions decisions.yaml \
  --profile bod-26-04 \
  --output-dossier out/dossier \
  --output-md out/executive_roadmap.md \
  --output-runmanifest out/runmanifest.json
```

To generate the complete artifact bundle (JSON, CSV, Executive Roadmap MD, Technical/Dossier MD, Decision Defense Dossier HTML/MD, and `RunManifest`) in one command:

```bash
vpp scan scan.nessus --output-all out/triage_report
```

This writes `.vpp.db` (owner-only `0o600` POSIX permissions) alongside `out/triage_report.json`, `out/triage_report.csv`, `out/triage_report_summary.md`, `out/triage_report_technical.md`, `out/triage_report_dossier.md`, `out/triage_report_dossier.html`, and `out/triage_report_runmanifest.json`. CSV output is formula-injection sanitized by default.

> [!TIP]
> Running in an air-gapped or restricted network environment? Add `--offline` (after syncing local caches with `vpp intel sync`), or add `--portable` when `$HOME` / `XDG_DATA_HOME` is read-only. See [Workflow Examples](Workflow%20Examples.md) for copy-pasteable MSSP, air-gapped, and scheduled drift scripts.

## 4) Triage Interactively (`vpp ui`)

Launch the Textual TUI workbench over your `.vpp.db` workspace (or inspect `.vpp-demo.db`):

```bash
vpp ui --db .vpp.db --decisions decisions.yaml
```

Key TUI shortcuts (`vpp ui`):

| Key | Action |
| --- | --- |
| `1` / `2` / `3` / `4` | Filter findings to priority tier `P1` / `P2` / `P3` / `P4` (auto-switches back to **Findings** if on **Diff**) |
| `0` | Clear all active filters (auto-switches back to **Findings** if on **Diff**) |
| `t` | Cycle scoring track (`cve_threat` / `exposure_weakness` / all; auto-switches to **Findings**) |
| `k` | Toggle CISA KEV filter (auto-switches to **Findings**) |
| `u` | Toggle unmatched shadow assets filter (auto-switches to **Findings**) |
| `/` | Focus search box (`Esc` returns to findings table) |
| `i` | Toggle focus between findings table and inspector pane (`Up`/`Down`/`PageDown` to scroll; `Esc` returns to table) |
| `[` / `]` | Previous / next page |
| `r` | Cycle across runs stored in `.vpp.db` |
| `d` | Switch to **Diff & Stale Assumptions** tab |
| `e` | Export Decision Defense Dossier for the selected finding |
| `E` | Export full-run Decision Defense Dossier |
| `f` | Open deferral / acceptance / mitigation modal (`Enter` moves Rationale -> Owner or submits) |
| `?` | Open keybinding help modal (`Esc`, `?`, or `Enter` closes) |
| `q` | Quit |

## 5) Diff Runs and Verify Evidence (`vpp diff` & `vpp verify`)

Compare two runs in `.vpp.db` (or two scan files directly) and fail CI (exit code `2`) when stale deferral assumptions or new P1/KEV findings appear:

```bash
vpp diff --db .vpp.db --decisions decisions.yaml --fail-on stale-assumption
```

Verify a `RunManifest` and its listed output artifact SHA-256 digests in read-only mode:

```bash
vpp verify out/runmanifest.json
```

## 6) Understand What Just Happened

The v2.0 DuckDB pipeline runs end-to-end:

1. **Validate & Sniff**: Enforce path/symlink policy (`PermFileHandler`) and classify input formats via bounded 64 KB sniffing (`SchemaDetector`).
2. **Stream & Normalize**: Stream findings in 10,000-row batches (`iter_batches`) into `.vpp.db` with canonical `aid_v2_` / `fid_v2_` identity and cross-scanner deduplication.
3. **Hydrate Threat Intel**: Populate `enrichment_snapshots` for scan-matched CVEs and PURLs from NVD (CVSS v4.0/v3.x/v2.0), EPSS v5, CISA KEV, Exploit-DB, and optional GHSA/OSV.
4. **Execute Pass DAG**: Run `NmapAdapter@1.0` (if `--nmap` supplied) → `ACI@2.0` → `Scoring@3.0` (dual-track `cve_threat` + `exposure_weakness`) → `Triage@2.0` (`default` or `bod-26-04` SSVC) → `TopN@2.0` → `Summary@2.0`.
5. **Persist, Diff & Export**: Store results in `.vpp.db`, compute scan-over-scan diffs (`--baseline-run-id`), and export Decision Defense Dossiers, Executive Roadmaps, JSON (`derived["Scoring@3.0"]`, `derived["ACI@2.0"]`, `derived["Triage@2.0"]`, `derived["TopN@2.0"]`, `derived["Summary@2.0"]`), CSV, and `RunManifest`.

## Next Steps

- [Operator Tutorial](Operator%20Tutorial.md) — End-to-end engineering walkthrough (multi-scanner fusion, 5-tier `assets.yaml`, `Scoring@3.0` + `BOD 26-04`, full `vpp ui` keymap, drift gates, dossiers, and air-gapped/container ops)
- [Usage](Usage.md) — Authoritative reference for all 8 subcommands, flags, and exit codes
- [Workflow Examples](Workflow%20Examples.md) — End-to-end MSSP, air-gapped, CI, and scheduled drift workflows
- [Deployment Options](Deployment%20Options.md) — Docker, Docker Compose, Kubernetes CronJob, and systemd units
- [Output Interpretation](Output%20Interpretation.md) — Reading Dossiers, Roadmaps, `score_trace`, SSVC paths, and `RunManifest`
- [Upgrade and Migration](Upgrade%20and%20Migration.md) — Upgrading from `v1.2.x` to `v2.0.0`
- [Troubleshooting](Troubleshooting.md) — Quick fixes for DuckDB permissions, offline caches, and TUI setup

## 5-Minute Checklist

- [ ] Install `vulnparse-pin[ui]` via `pipx` or `uv`
- [ ] Run `vpp demo` and explore `.vpp-demo.db` in `vpp ui`
- [ ] Run `vpp scan` on a real report to generate `.vpp.db`, a Decision Defense Dossier, and `runmanifest.json`
- [ ] Confirm `Scoring@3.0`, `ACI@2.0`, `Triage@2.0`, `TopN@2.0`, and `Summary@2.0` in JSON output or `vpp ui`
- [ ] Run `vpp verify` on your `runmanifest.json` and `vpp diff` between two runs
