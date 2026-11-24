# Workflow Examples

This guide provides seven end-to-end recipes for **VulnParse-Pin v2.0.0 (`vpp`)**, pairing the subcommand CLI (`scan`, `demo`, `diff`, `ui`, `export`, `verify`, `defer`, `intel`) with the runnable configs, CI pipelines, and shell workflows in [`examples/`](../../examples/README.md).

> **Honest Reachability Boundary:** `vpp` performs **Network & Operational Reachability** (Nmap open-port reconciliation, `assets.yaml` exposure rules, `ACI@2.0` capability inference, and `detection_mode` Signal Reliability weighting). It does **not** perform AST source-code call-graph reachability or eBPF kernel execution tracing.

---

## Recipe 1: 60-Second Offline `vpp demo` & Interactive `vpp ui`

Use `vpp demo` to evaluate VulnParse-Pin **100% offline** with bundled Nessus XML, Trivy SARIF, Nuclei JSONL, Semgrep SARIF, Nmap XML, pattern `assets.yaml`, `decisions.yaml`, and miniature EPSS v5 / KEV / NVD / GHSA snapshots—without touching your production cache.

```bash
# Install with interactive Textual TUI support
pipx install "vulnparse-pin[ui]"

# Run the offline walkthrough and open the Textual TUI
vpp demo --profile bod-26-04 --output-dir vpp_demo_output --db .vpp-demo.db
```

For headless terminals or CI validation without launching the TUI:

```bash
vpp demo --no-ui --profile bod-26-04 --output-dir vpp_demo_output --db .vpp-demo.db
vpp verify vpp_demo_output/runmanifest.json
```

### Exploring `.vpp-demo.db` in `vpp ui`

Re-open any workspace database directly with `vpp ui`:

```bash
vpp ui --db .vpp-demo.db --output-dir vpp_demo_output
```

Key bindings available inside `vpp ui`:

| Key | Action |
| --- | --- |
| `1` / `2` / `3` / `4` / `0` | Filter by priority tier (`P1`, `P2`, `P3`, `P4`) or `0` to clear filters |
| `t` | Cycle scoring track (`cve_threat` vs. `exposure_weakness`) |
| `k` | Toggle CISA KEV filter |
| `u` | Toggle `unmatched_shadow` assets filter |
| `/` | Focus search input (`Esc` returns to table) |
| `[` / `]` | Previous / next page |
| `d` | Switch to Diff tab (`demo-baseline` → `demo-current`) |
| `e` / `E` | Export Decision Defense Dossier for selected finding (`e`) or full run (`E`) |
| `f` | Open interactive deferral modal (`vpp defer`) |
| `q` | Quit |

---

## Recipe 2: Consultant / MSSP Multi-Scanner Assessment

Ingest infrastructure, container, DAST, and Nmap discovery files into a persistent engagement DuckDB workspace (`.vpp.db`), deliver offline HTML/Markdown reports, verify the `RunManifest`, and track remediation velocity on re-test.

- Runnable script: [`examples/workflows/mssp-assessment.sh`](../../examples/workflows/mssp-assessment.sh)
- Example configs: [`examples/configs/assets.example.yaml`](../../examples/configs/assets.example.yaml), [`examples/configs/decisions.example.yaml`](../../examples/configs/decisions.example.yaml)

```bash
# 1. Initial multi-scanner assessment
vpp scan scans/nessus.xml scans/trivy.sarif scans/nuclei.jsonl \
  --nmap scans/nmap.xml \
  --assets examples/configs/assets.example.yaml \
  --decisions examples/configs/decisions.example.yaml \
  --profile bod-26-04 \
  --run-id assessment-baseline \
  --db engagement.vpp.db \
  --output-dossier out/mssp/dossier \
  --output-runmanifest out/mssp/runmanifest.json \
  --runmanifest-mode expanded \
  --show-ingestion-summary

# 2. Export Executive Client Roadmaps (self-contained HTML + Markdown)
vpp export --db engagement.vpp.db --run-id assessment-baseline \
  --format roadmap-html --output out/mssp/executive_roadmap.html
vpp export --db engagement.vpp.db --run-id assessment-baseline \
  --format roadmap-md --output out/mssp/executive_roadmap.md

# 3. Verify RunManifest digest, hash-chained ledger, and output hashes (read-only)
vpp verify out/mssp/runmanifest.json

# 4. Re-test engagement & verify remediation velocity
vpp scan scans/retest_nessus.xml scans/retest_trivy.sarif \
  --nmap scans/nmap.xml \
  --assets examples/configs/assets.example.yaml \
  --decisions examples/configs/decisions.example.yaml \
  --profile bod-26-04 \
  --run-id assessment-retest \
  --baseline-run-id assessment-baseline \
  --db engagement.vpp.db \
  --output-dossier out/mssp/retest_dossier \
  --output-runmanifest out/mssp/retest_runmanifest.json

vpp diff assessment-baseline assessment-retest \
  --db engagement.vpp.db \
  --decisions examples/configs/decisions.example.yaml \
  --fail-on stale-assumption \
  --output-md out/mssp/retest_diff.md \
  --output-json out/mssp/retest_diff.json
```

---

## Recipe 3: Federal `--profile bod-26-04` SSVC & SLA Triage

Use `--profile bod-26-04` to activate CISA BOD 26-04 Stakeholder-Specific Vulnerability Categorization (`Triage@2.0`), mapping **Exposure**, **Exploitation** (`active`, `poc`, `none`), **Automatable**, **Technical Impact**, and **Signal Reliability** into SSVC actions (`Act`, `Attend`, `Track*`, `Track`) and SLA buckets (`3-day + Forensic Triage`, `14-day`, `60-day`, `Fix on Upgrade`).

```bash
# Score and triage with BOD 26-04 SSVC and Nmap port reconciliation
vpp scan scans/nessus.xml scans/trivy.sarif \
  --nmap scans/nmap.xml \
  --assets examples/configs/assets.example.yaml \
  --decisions examples/configs/decisions.example.yaml \
  --profile bod-26-04 \
  --db federal.vpp.db \
  --output-all out/federal/bod_26_04 \
  --output-dossier out/federal/dossier \
  --runmanifest-mode expanded

# Export audit-profile CSV (with formula-injection sanitization enabled by default)
vpp export --db federal.vpp.db --format csv --csv-profile audit \
  --output out/federal/bod_26_04_audit.csv

# Verify RunManifest and every hashed output artifact
vpp verify out/federal/bod_26_04_runmanifest.json
```

> **Static SAST Guardrail:** Under `config.yaml` (`triage.static_sast_p1_cap: true`), findings detected solely by `static_sast` (`signal_reliability = 0.55`) are capped below `P1` unless confirmed by higher-reliability runtime/host evidence or active exploitation context.

---

## Recipe 4: CI/CD Trivy SARIF PR Gate (GitHub Actions & GitLab CI)

Run Trivy to produce SARIF 2.1.0, triage with `vpp scan`, verify `RunManifest` integrity, and fail the build (`exit 2`) if any deferred finding breaks its underlying assumptions or introduces unreviewed risk.

- GitHub Actions template: [`examples/ci/github-actions-trivy-vpp.yml`](../../examples/ci/github-actions-trivy-vpp.yml)
- GitLab CI template: [`examples/ci/gitlab-ci-trivy-vpp.yml`](../../examples/ci/gitlab-ci-trivy-vpp.yml)

```bash
# 1. Produce Trivy SARIF (vuln + misconfig)
trivy fs . --scanners vuln,misconfig --format sarif --output trivy.sarif

# 2. Triage into cached .vpp.db workspace with Decision Defense Dossier & RunManifest
mkdir -p out
vpp scan trivy.sarif \
  --assets examples/configs/assets.example.yaml \
  --decisions examples/configs/decisions.example.yaml \
  --profile bod-26-04 \
  --db .vpp.db \
  --output-dossier out/dossier \
  --output-runmanifest out/runmanifest.json

# 3. Read-only RunManifest verification
vpp verify out/runmanifest.json

# 4. Evaluate PR delta & stale-assumption gate (exits 2 on breach)
vpp diff \
  --db .vpp.db \
  --decisions examples/configs/decisions.example.yaml \
  --fail-on stale-assumption \
  --output-pr-comment out/pr_comment.md
```

Available `--fail-on` modes on `vpp diff`: `p1`, `p2`, `kev`, `stale-assumption`, `none` (default).

---

## Recipe 5: Waiver Lifecycle with `vpp defer` + `vpp diff`

Record auditable deferrals, mitigations, and risk acceptances in `decisions.yaml` using `vpp defer`—including explicit falsifiable `assumptions`—and let `vpp diff` fail closed whenever reality invalidates a waiver.

```bash
# 1. Record or update a deferral with explicit threat-intel and exposure assumptions
vpp defer \
  --asset "*10.20.1.*" \
  --id CVE-2023-38545 \
  --status deferred \
  --rationale "Internal-only worker behind mTLS; SOCKS5 proxy disabled pending OS rebuild." \
  --owner "core-infra@example.org" \
  --expires "2027-06-01" \
  --in-kev false \
  --max-epss 0.04 \
  --max-epss-percentile 0.85 \
  --internet-facing false \
  --max-cvss 9.8 \
  --decisions decisions.yaml \
  --db .vpp.db

# 2. Later, after threat feeds update or exposure changes, run diff gate
vpp diff \
  --db .vpp.db \
  --decisions decisions.yaml \
  --fail-on stale-assumption \
  --output-md out/waiver_drift.md
```

`DecisionsRegistry` and `DiffEngine` automatically flag violated predicates:

- `expired` (`expires_at` has passed)
- `kev_flipped` (CVE entered CISA KEV when `in_kev: false` was assumed)
- `epss_exceeded` / `epss_percentile_exceeded` (EPSS probability or percentile rose above `max_epss` / `max_epss_percentile`)
- `exposure_flipped` (`assets.yaml` or scan exposure changed `internet_facing`)
- `cvss_exceeded` (effective CVSS rose above `max_cvss`)

---

## Recipe 6: Scheduled KEV / EPSS Drift Monitoring + Signed Webhook

Sync threat-intel feeds on a schedule (`cron`, `systemd` timer, or Kubernetes `CronJob`), evaluate `vpp diff --fail-on stale-assumption`, and separate operational failures (`exit 1`) from policy drift alerts (`exit 2`).

- Runnable script: [`examples/workflows/scheduled-kev-drift-check.sh`](../../examples/workflows/scheduled-kev-drift-check.sh)
- Scheduler templates: [`examples/deploy/k8s-cronjob-vpp-drift.yaml`](../../examples/deploy/k8s-cronjob-vpp-drift.yaml), [`examples/deploy/systemd/vpp-drift.service`](../../examples/deploy/systemd/vpp-drift.service)

```bash
export VP_FEED_CACHE_HMAC_KEY="replace-with-strong-random-secret"
export VP_SQLITE_HMAC_KEY="replace-with-strong-random-secret"
export VP_WEBHOOK_HMAC_KEY="replace-with-strong-random-secret"

# Optional: run script with fresh scan + signed webhook notification for P1 findings
SCAN_FILES="scans/trivy.sarif" \
DECISIONS_FILE="examples/configs/decisions.example.yaml" \
ASSETS_FILE="examples/configs/assets.example.yaml" \
VPP_WEBHOOK_URL="https://hooks.example.org/vpp" \
VPP_WEBHOOK_OAL_FILTER="P1" \
  ./examples/workflows/scheduled-kev-drift-check.sh
```

Direct CLI flags for webhook overrides on `vpp scan`:

```bash
vpp scan scans/trivy.sarif \
  --assets examples/configs/assets.example.yaml \
  --decisions examples/configs/decisions.example.yaml \
  --webhook-endpoint https://hooks.example.org/vpp \
  --webhook-oal-filter P1
```

See [Deployment Options — Signed Webhook Receiver Verification](Deployment%20Options.md#signed-webhook-receiver-verification) for validating `X-VPP-Signature`, `X-VPP-Timestamp`, and `X-VPP-Nonce`.

---

## Recipe 7: Air-Gapped Intel Transfer & Read-Only `vpp verify`

Prepare HMAC-signed threat-intelligence caches on a connected staging host, verify integrity metadata, transfer the bundle across the air gap, and scan strictly offline inside the enclave with `--portable --enforce-root-read`.

- Runnable script: [`examples/workflows/airgapped-sync-and-scan.sh`](../../examples/workflows/airgapped-sync-and-scan.sh)

```bash
# === On connected staging host ===
export VP_FEED_CACHE_HMAC_KEY="shared-staging-enclave-feed-secret"
export VP_SQLITE_HMAC_KEY="shared-staging-enclave-sqlite-secret"

./examples/workflows/airgapped-sync-and-scan.sh stage
# Produces vpp-intel-bundle.tar.gz + vpp-intel-bundle.tar.gz.sha256

# === On air-gapped enclave (same HMAC env vars exported) ===
sha256sum -c vpp-intel-bundle.tar.gz.sha256
export VP_FEED_CACHE_HMAC_KEY="shared-staging-enclave-feed-secret"
export VP_SQLITE_HMAC_KEY="shared-staging-enclave-sqlite-secret"

# Runs:
#   vpp intel status --portable --json
#   vpp scan <inputs...> --offline --kev-source offline --epss-source offline \
#     [--nvd ...] [--ghsa ...] [--osv ...] [--exploit-source offline --exploit-db ...] \
#     --portable --enforce-root-read --output-dossier ... --output-runmanifest ...
#   vpp verify out/airgapped/runmanifest.json --portable --enforce-root-read
./examples/workflows/airgapped-sync-and-scan.sh scan scans/nessus.xml scans/trivy.sarif
```

> **Note on `--exploit-source offline`:** `cli/args.py` requires `--exploit-db <PATH>` whenever `--exploit-source offline` is passed explicitly. When using the synced cache without a standalone Exploit-DB CSV path, `--offline` alone reads the cached `files_exploit.csv` under `cache/exploit_db/` if present.

---

## Related Documentation

- [Deployment Options](Deployment%20Options.md)
- [Usage Guide](Usage.md)
- [RunManifest Overview](RunManifest.md)
- [Output Interpretation](Output%20Interpretation.md)
- [Runnable Examples Index](../../examples/README.md)
