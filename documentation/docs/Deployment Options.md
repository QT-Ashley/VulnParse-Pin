# Deployment Options

VulnParse-Pin (`vpp`) v2.0.0 is licensed under **Apache-2.0** with zero copyleft Python runtime dependencies, allowing unrestricted internal SOC, MSSP/consulting, CI/CD, and commercial enclave deployment.

## Deployment Matrix

| Option | Best For | Persistence | Non-Root / Hardening | Offline / Air-Gap | Template |
| --- | --- | --- | --- | --- | --- |
| **Isolated CLI (`pipx` / `uv tool`)** | Analyst workstations, MSSP laptops, `vpp ui` | Local `.vpp.db` + XDG or `./data` | `PermFileHandler` (`0o600`/`0o700`, symlink reject) | Supported via wheelhouse + `--offline` | [Installation](Installation.md) |
| **Container / Compose (`ghcr.io` or Local Build)** | Reproducible runners, isolated multi-user hosts | Host bind `/work` + volume `/cache` | `uid=10001`, `--read-only`, `cap_drop: ALL` | Supported via wheelhouse `--build-arg PIP_NO_INDEX=1` | [Root `Dockerfile`](../../Dockerfile), [`examples/deploy/Dockerfile`](../../examples/deploy/Dockerfile), [`docker-compose.yml`](../../examples/deploy/docker-compose.yml) |
| **CI/CD Runners** | PR priority gates, stale-assumption checks | CI cache for `.vpp.db` + artifact upload | Ephemeral runner + exit codes `0`/`1`/`2` | Supported with cached wheelhouse & feeds | [`github-actions`](../../examples/ci/github-actions-trivy-vpp.yml), [`gitlab-ci`](../../examples/ci/gitlab-ci-trivy-vpp.yml) |
| **Kubernetes `CronJob`** | Daily KEV/EPSS drift checks across clusters | `PersistentVolumeClaim` + `Secret` | `runAsNonRoot`, `readOnlyRootFilesystem`, `RuntimeDefault` | Supported via pre-seeded PVC & private registry | [`k8s-cronjob-vpp-drift.yaml`](../../examples/deploy/k8s-cronjob-vpp-drift.yaml) |
| **`systemd` Service & Timer** | Linux bastion / VM scheduled drift alerts | `/var/lib/vulnparse-pin` + `/var/cache/vulnparse-pin` | `ProtectSystem=strict`, `NoNewPrivileges=yes`, `UMask=0077` | Supported via `--offline` + synced cache | [`vpp-drift.service`](../../examples/deploy/systemd/vpp-drift.service), [`vpp-drift.timer`](../../examples/deploy/systemd/vpp-drift.timer) |
| **Air-Gapped Enclave** | Classified / isolated OT & SCIF networks | Portable `./data` bundle (`--portable`) | `--enforce-root-read`, HMAC sidecars, read-only `vpp verify` | First-class (`--offline`, wheelhouse) | [`airgapped-sync-and-scan.sh`](../../examples/workflows/airgapped-sync-and-scan.sh) |

---

## 1. Isolated CLI (`pipx` / `uv tool`)

For workstations and jump hosts, isolate `vpp` dependencies from the system Python:

```bash
# Using pipx (with interactive Textual TUI)
pipx install "vulnparse-pin[ui]"

# Using pipx (minimal headless CLI for automation/CI)
pipx install vulnparse-pin

# Using uv tool
uv tool install "vulnparse-pin[ui]"
# or headless:
uv tool install vulnparse-pin
```

Verify both entrypoints and runtime policy:

```bash
vpp --version
vpp scan --debug-path-policy
```

---

## 2. `AppPaths` (XDG vs `--portable`), File Policy & Read-Only `vpp verify`

### Path Resolution (`AppPaths.resolve`)

`src/vulnparse_pin/core/apppaths.py` supports two directory layouts:

1. **Default OS-native / XDG mode** (`platformdirs.user_data_dir("VulnParse-Pin", False)`):
   - Linux default: `~/.local/share/VulnParse-Pin/` (honors `XDG_DATA_HOME`)
   - Subdirectories:
     - `versions/<version>/config/` (`0o700` — `config.yaml`, `scoring.json`, `tn_triage.json`)
     - `cache/` (`0o700` — `kev/`, `epss/`, `exploit_db/`, `nvd/feeds/`, and `*_cache.sqlite3`)
     - `logs/` (`0o700` — `bootstrap.log` and per-run logs)
     - `versions/<version>/outputs/` (`0o750`)
2. **Portable mode** (`--portable` / `-P`, or `VULNPARSE_PIN_PORTABLE=1`):
   - Anchored to `./data/` under the current working directory (or executable directory if frozen):
     - `./data/versions/<version>/config/`
     - `./data/cache/` (`kev/`, `epss/`, `exploit_db/`, `nvd/feeds/`)
     - `./data/logs/`
     - `./data/versions/<version>/outputs/`

### POSIX Permission & Symlink Policy (`PermFileHandler`)

By default (`src/vulnparse_pin/app/bootstrap.py` & `src/vulnparse_pin/io/pfhandler.py`):

- Written files use **`0o600`** (`--file-mode`) and created directories use **`0o700`** (`--dir-mode`) on POSIX systems.
- **Symlinks are forbidden** on both read (`--forbid-symlinks-read`, default `True`; opt out with `--allow-symlinks-read`) and write (`--forbid-symlinks-write`, default `True`).
- **Write root confinement** (`--enforce-root-write`, default `True`) confines outputs to authorized workspace/application roots.
- **Read root confinement** (`--enforce-root-read`, default `False`) confines reads to `PermFileHandler.allowed_roots` (`paths.base_dir` + config/cache/log/output directories). **Important:** Without `--portable`, `paths.base_dir` is the OS user data directory (such as `~/.local/share/VulnParse-Pin/`), so `--enforce-root-read` rejects scan inputs under `$PWD`; combine `--enforce-root-read` with `--portable` (`-P`) whenever scanning or verifying files under `$PWD`.
- **DuckDB `.vpp.db`** enforces `0o600` POSIX creation mode and rejects symlinks on `.vpp.db` and `.vpp.db.wal` sidecars.

### Strictly Read-Only `vpp verify`

`vpp verify <runmanifest.json>` is designed for immutable audit verification and read-only mounts:

- Validates `RunManifest` v2 JSON schema, `verification.manifest_digest`, every `decision_ledger` entry SHA-256 hash chain (`prev_hash` → `entry_hash` → `chain_root`), and the SHA-256 digest of every non-null artifact listed in `outputs` / `output_hashes`.
- **Does not write log files or mutate directories** unless `--log-file` is explicitly passed to a custom path.
- Rejects symlinks by default (`--forbid-symlinks-read`); use `--enforce-root-read` to additionally confine manifest and output artifact reads to authorized roots, or `--allow-symlinks-read` only when required by immutable symlinked artifact stores.

```bash
vpp verify out/runmanifest.json --portable --enforce-root-read
```

---

## 3. Portable Container (`ghcr.io` & Docker Compose)

Tagged releases publish attested multi-arch (`linux/amd64`, `linux/arm64`) OCI images to `ghcr.io/qt-ashley/vulnparse-pin` via [`.github/workflows/release.yml`](../../.github/workflows/release.yml).

### Pull Official GHCR Image or Build from Source

```bash
# 1. Pull the multi-arch GHCR image
docker pull ghcr.io/qt-ashley/vulnparse-pin:2.0.0

# 2. Or build directly from this repository checkout (root Dockerfile)
docker build -t vulnparse-pin:2.0.0 .

# Minimal headless image without Textual TUI extras
docker build --build-arg EXTRAS="" -t vulnparse-pin:2.0.0-headless .

# Or build standalone from PyPI / offline wheelhouse without cloning repo source
docker build -t vulnparse-pin:2.0.0-pypi -f examples/deploy/Dockerfile .
```

The image runs as non-root `vpp` (`uid=10001`, `gid=10001`), sets `HOME=/work` and `XDG_*` under `/cache`, and operates cleanly with `--read-only` rootfs:

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid \
  -v "$PWD:/work" \
  -v "vpp-cache:/cache" \
  vulnparse-pin:2.0.0 demo --no-ui --output-dir /work/vpp_demo_output --db /work/.vpp-demo.db
```

### Docker Compose Stack

[`examples/deploy/docker-compose.yml`](../../examples/deploy/docker-compose.yml) defines three hardened non-root services sharing `/work` and `vpp-cache`:

- `vpp-scan`: Runs `vpp scan` with `--profile bod-26-04`, generating `.vpp.db`, `out/dossier`, and `out/runmanifest.json`.
- `vpp-drift`: Syncs `kev` and `epss` feeds and runs `vpp diff --re-enrich --fail-on stale-assumption` (no re-scan required).
- `vpp-ui` (`profiles: ["ui"]`): Interactive `vpp ui` TTY session over `/work/.vpp.db`.

```bash
export VP_FEED_CACHE_HMAC_KEY="$(openssl rand -hex 32)"
export VP_SQLITE_HMAC_KEY="$(openssl rand -hex 32)"

docker compose -f examples/deploy/docker-compose.yml run --rm vpp-scan
docker compose -f examples/deploy/docker-compose.yml run --rm vpp-drift
docker compose -f examples/deploy/docker-compose.yml --profile ui run --rm vpp-ui
```

---

## 4. CI/CD Runners & Exit Codes (`0` / `1` / `2`)

Copy-pasteable CI pipelines are provided in:

- [`examples/ci/github-actions-trivy-vpp.yml`](../../examples/ci/github-actions-trivy-vpp.yml)
- [`examples/ci/gitlab-ci-trivy-vpp.yml`](../../examples/ci/gitlab-ci-trivy-vpp.yml)

Both workflows restore `.vpp.db` from runner cache, scan Trivy SARIF with `--assets` and `--decisions`, verify `out/runmanifest.json` with `vpp verify`, export Decision Defense Dossiers, and gate PRs via `vpp diff --fail-on stale-assumption`.

### CLI Exit Code Contract

| Exit Code | Meaning | Common Triggers |
| --- | --- | --- |
| `0` | Success / gate passed | Scan, export, verify, intel sync, or `vpp diff` passed with zero policy violations |
| `1` | Runtime, I/O, or integrity failure | Missing/corrupt input file, `RunManifest` verification failure, DuckDB symlink/path-policy error, unhandled exception |
| `2` | Policy breach or invalid invocation | `vpp diff --fail-on <p1\|p2\|kev\|stale-assumption>` triggered; `--no-csv-sanitize` without `--confirm-unsafe-csv`; invalid CLI flags (`argparse`); `--offline` with HTTP feed URL |

---

## 5. Kubernetes `CronJob`

[`examples/deploy/k8s-cronjob-vpp-drift.yaml`](../../examples/deploy/k8s-cronjob-vpp-drift.yaml) provisions:

- `Secret` (`vpp-hmac-secrets`) holding `VP_FEED_CACHE_HMAC_KEY`, `VP_SQLITE_HMAC_KEY`, and `VP_WEBHOOK_HMAC_KEY`.
- `PersistentVolumeClaim` (`vpp-workspace-pvc`) persisting `.vpp.db`, `decisions.yaml`, outputs, and `/cache`.
- `CronJob` (`vpp-kev-drift-check`) with `runAsNonRoot: true`, `runAsUser: 10001`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities: {drop: ["ALL"]}`, `seccompProfile: {type: RuntimeDefault}`, and an `emptyDir` mounted at `/tmp`.

Using `ghcr.io/qt-ashley/vulnparse-pin:2.0.0` (or mirroring/pushing a local build from `Dockerfile` to a private enclave registry), update the `Secret` values, seed `.vpp.db` + `decisions.yaml` onto the PVC, and apply:

```bash
kubectl apply -f examples/deploy/k8s-cronjob-vpp-drift.yaml
```

---

## 6. `systemd` Service & Daily Timer

For dedicated Linux hosts, install [`examples/deploy/systemd/vpp-drift.service`](../../examples/deploy/systemd/vpp-drift.service), [`examples/deploy/systemd/vpp-drift.timer`](../../examples/deploy/systemd/vpp-drift.timer), and [`examples/workflows/scheduled-kev-drift-check.sh`](../../examples/workflows/scheduled-kev-drift-check.sh):

```bash
sudo useradd --system --home-dir /var/lib/vulnparse-pin --shell /usr/sbin/nologin vpp
sudo install -d -o vpp -g vpp -m 0700 /var/lib/vulnparse-pin /var/cache/vulnparse-pin /var/log/vulnparse-pin
sudo install -d -o root -g vpp -m 0750 /etc/vulnparse-pin
sudo install -m 0755 examples/workflows/scheduled-kev-drift-check.sh /usr/local/bin/scheduled-kev-drift-check.sh
sudo cp examples/deploy/systemd/vpp-drift.service /etc/systemd/system/
sudo cp examples/deploy/systemd/vpp-drift.timer /etc/systemd/system/
```

Create `/etc/vulnparse-pin/vpp.env` (`chmod 0640`, `root:vpp`):

```dotenv
VP_FEED_CACHE_HMAC_KEY=replace-with-32-byte-random-secret
VP_SQLITE_HMAC_KEY=replace-with-32-byte-random-secret
XDG_DATA_HOME=/var/cache/vulnparse-pin/data
XDG_CONFIG_HOME=/etc/vulnparse-pin/config
XDG_CACHE_HOME=/var/cache/vulnparse-pin/xdg
DB_PATH=/var/lib/vulnparse-pin/.vpp.db
DECISIONS_FILE=/etc/vulnparse-pin/decisions.yaml
OUT_DIR=/var/lib/vulnparse-pin/out
```

Enable and inspect the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vpp-drift.timer
systemctl list-timers vpp-drift.timer
```

Hardening enforced by `vpp-drift.service`: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `UMask=0077`, and explicit `ReadWritePaths`.

---

## 7. Air-Gapped Offline Wheelhouse & HMAC Feed Bundle Transfer

### Step A: Build an Offline Wheelhouse (Connected Host Matching Target OS/Python)

```bash
mkdir -p wheelhouse
python -m pip download "vulnparse-pin[ui]" -d ./wheelhouse
# Or headless CLI only:
# python -m pip download vulnparse-pin -d ./wheelhouse
```

On the air-gapped enclave:

```bash
python -m venv /opt/vpp-venv
/opt/vpp-venv/bin/pip install --no-index --find-links ./wheelhouse "vulnparse-pin[ui]"
```

### Step B: Sync & Verify HMAC-Signed Feed Bundles

`FeedCacheManager` signs feed integrity sidecars (`.integrity.json`) with **`VP_FEED_CACHE_HMAC_KEY`**, and SQLite enrichment stores (`nvd_cache.sqlite3`, `epss_cache.sqlite3`, `kev_cache.sqlite3`, `ghsa_cache.sqlite3`, `osv_cache.sqlite3`) sign `.sig.json` sidecars with **`VP_SQLITE_HMAC_KEY`**:

```bash
export VP_FEED_CACHE_HMAC_KEY="shared-enclave-feed-secret"
export VP_SQLITE_HMAC_KEY="shared-enclave-sqlite-secret"

# Staging sync + integrity check + archive (see examples/workflows/airgapped-sync-and-scan.sh)
./examples/workflows/airgapped-sync-and-scan.sh stage
```

Inside the enclave, extract `vpp-intel-bundle.tar.gz` into `./data/`, export the **exact same** `VP_FEED_CACHE_HMAC_KEY` and `VP_SQLITE_HMAC_KEY`, verify with `vpp intel status --portable --json`, and scan offline with `--portable --enforce-root-read`. Any tampered feed, missing sidecar, or mismatched HMAC key fails closed before scoring begins.

---

## 8. Signed Webhook Receiver Verification

When webhook delivery is configured in `config.yaml` (`webhook.enabled: true`) or overridden via `--webhook-endpoint` / `--webhook-oal-filter`, `src/vulnparse_pin/utils/webhook_delivery.py` emits canonical JSON payloads (`vpp.topn.summary`) over HTTPS (`allow_redirects=False`, `max_payload_bytes: 262144`, spooled to `webhook_spool/` on failure when `allow_spool: true`). In v2 scans:

- **Fail-closed signing secret:** `VP_WEBHOOK_HMAC_KEY` (or configured `signing_key_env`) is required; missing/invalid keys or misconfigured endpoints fail closed rather than silently succeeding.
- **Active & invalidated findings only:** Validly `deferred`, `accepted`, and `mitigated` findings are excluded; active prioritized findings and `DEFERRED_INVALIDATED` findings are dispatched with `priority_tier`, `oal`, `ssvc_action`, `sla_label`, `operational_score`, `in_kev`, `epss_score`, `decision_status`, and `invalidated_reasons`.
- **Ledger audit trail:** Every delivery attempt appends a hash-chained `WEBHOOK_DELIVERY` event (recording counts only, never secret material) to `ledger_events`.

### Request Headers

- `Content-Type: application/json`
- `X-VPP-Event: vpp.topn.summary`
- `X-VPP-Timestamp`: UTC ISO-8601 timestamp (`...Z`)
- `X-VPP-Nonce`: 32-character hex random nonce
- `X-VPP-Key-Id`: Configured key identifier (default `primary`)
- `X-VPP-Signature`: `sha256=<hex_hmac>`

### Verification Algorithm

Compute HMAC-SHA256 using the shared secret (`VP_WEBHOOK_HMAC_KEY` by default) over the raw UTF-8 request body prefixed with `<timestamp>.<nonce>.`:

```python
from datetime import datetime, timezone
import hashlib
import hmac


def verify_vpp_webhook(
    *,
    secret: str,
    headers: dict[str, str],
    raw_body: bytes,
    seen_nonces: set[str],
    replay_window_seconds: int = 300,
) -> bool:
    timestamp = headers["X-VPP-Timestamp"]
    nonce = headers["X-VPP-Nonce"]
    signature = headers["X-VPP-Signature"]

    # 1. Enforce replay window (default 300s in config.yaml)
    sent_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    age_s = abs((datetime.now(timezone.utc) - sent_at).total_seconds())
    if age_s > replay_window_seconds or nonce in seen_nonces:
        return False

    # 2. Recompute sha256=HMAC-SHA256(secret, "{timestamp}.{nonce}." + raw_body)
    signing_input = f"{timestamp}.{nonce}.".encode("utf-8") + raw_body
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), signing_input, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        return False

    seen_nonces.add(nonce)
    return True
```

Always compare `expected` and `X-VPP-Signature` in constant time (`hmac.compare_digest`), enforce the replay window (`replay_window_seconds`), and reject duplicate `X-VPP-Nonce` values.
