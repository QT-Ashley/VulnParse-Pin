# VulnParse-Pin v2.0.0 Runnable Examples

Ready-to-use configuration files, CI pipelines, workflow scripts, and deployment manifests for **VulnParse-Pin (`vpp`)**.

## Directory Map

| Path | Purpose |
| --- | --- |
| [`configs/assets.example.yaml`](configs/assets.example.yaml) | Pattern-based asset inventory rules covering all 5 resolution tiers (`asset_id`/`aliases`, exact IP/hostname/URI/image/repo, longest-prefix CIDR, globs) |
| [`configs/decisions.example.yaml`](configs/decisions.example.yaml) | Triage deferrals, mitigations, and acceptances with `assumptions` predicates (`in_kev`, `max_epss`, `max_epss_percentile`, `internet_facing`, `max_cvss`, `expires_at`) |
| [`ci/github-actions-trivy-vpp.yml`](ci/github-actions-trivy-vpp.yml) | 3-minute GitHub Actions Trivy SARIF + `vpp scan` + `vpp verify` + `vpp diff --fail-on stale-assumption` PR gate |
| [`ci/gitlab-ci-trivy-vpp.yml`](ci/gitlab-ci-trivy-vpp.yml) | GitLab CI Trivy SARIF + `vpp scan` + `vpp verify` + `vpp export` + `vpp diff` pipeline |
| [`workflows/mssp-assessment.sh`](workflows/mssp-assessment.sh) | Consultant/MSSP multi-scanner (`nessus` + `trivy` + `nuclei` + `--nmap`) engagement → Dossier + Executive Roadmap + `RunManifest` → `vpp verify` → re-test diff |
| [`workflows/airgapped-sync-and-scan.sh`](workflows/airgapped-sync-and-scan.sh) | Connected staging `vpp intel sync` + HMAC verification (`VP_FEED_CACHE_HMAC_KEY`, `VP_SQLITE_HMAC_KEY`) → bundle transfer → offline `--portable --enforce-root-read` scan & verify |
| [`workflows/scheduled-kev-drift-check.sh`](workflows/scheduled-kev-drift-check.sh) | Scheduled `vpp intel sync` + `vpp diff --re-enrich --fail-on stale-assumption` (when `SCAN_FILES` is empty) handling exit codes `0`/`1`/`2` and optional signed `--webhook-endpoint` (`VP_WEBHOOK_HMAC_KEY`) |
| Root [`../Dockerfile`](../Dockerfile) | Source-built multi-stage `python:3.12-slim` portable container (`uid=10001`, `--read-only` compatible; powers `ghcr.io/qt-ashley/vulnparse-pin`) |
| [`deploy/Dockerfile`](deploy/Dockerfile) | Standalone PyPI / offline-wheelhouse `python:3.12-slim` container (`uid=10001`, `--read-only` rootfs compatible) |
| [`deploy/docker-compose.yml`](deploy/docker-compose.yml) | Non-root Compose stack (`vpp-scan`, `vpp-drift`, interactive `vpp-ui` profile) |
| [`deploy/k8s-cronjob-vpp-drift.yaml`](deploy/k8s-cronjob-vpp-drift.yaml) | Hardened Kubernetes `CronJob` + `PVC` + `Secret` for daily KEV/EPSS drift checks |
| [`deploy/systemd/vpp-drift.service`](deploy/systemd/vpp-drift.service) | Hardened `systemd` oneshot service (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `UMask=0077`) |
| [`deploy/systemd/vpp-drift.timer`](deploy/systemd/vpp-drift.timer) | Daily `systemd` timer for `vpp-drift.service` |

## Operational Caveats

- **Sealed `RunManifest` Digest in `dossier.html`:** Single-pass `vpp scan --output-dossier ... --output-runmanifest ...` writes `dossier.html` before `RunManifest` computes `output_hashes` (preventing a circular SHA-256 self-hash), so inline dossiers display `Pending post-export RunManifest seal (see runmanifest.json)`. Run `vpp export --db .vpp.db --format dossier-html -o out/dossier.html` afterwards to embed the sealed `sha256:...` digest.
- **`--enforce-root-read` with `$PWD` Scans:** Always pair `--enforce-root-read` with `--portable` (`-P`) when scanning files under `$PWD` (as shown in `workflows/airgapped-sync-and-scan.sh`); without `--portable`, `root_dir` defaults to the OS user data directory and `$PWD` reads are rejected.
- **Scheduled Drift Checks (`--re-enrich`):** When `SCAN_FILES` is empty, `vpp diff --db .vpp.db --decisions decisions.yaml --re-enrich --fail-on stale-assumption` re-evaluates local KEV/EPSS/NVD caches in both 1-run and multi-run workspaces without mutating frozen historical `runs` rows.
- **Signed Webhooks (`--webhook-endpoint`):** Delivery requires `VP_WEBHOOK_HMAC_KEY` to be set (failing closed if missing/invalid), excludes validly deferred/accepted/mitigated findings, and logs a hash-chained `WEBHOOK_DELIVERY` event.

## Related Documentation

- [Workflow Examples](../documentation/docs/Workflow%20Examples.md)
- [Deployment Options](../documentation/docs/Deployment%20Options.md)
- [Usage Guide](../documentation/docs/Usage.md)
