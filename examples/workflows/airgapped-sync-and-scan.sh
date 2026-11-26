#!/usr/bin/env bash
# Air-Gapped Threat-Intel Sync (Connected Staging) & Offline Enclave Scan + Verify
#
# Usage:
#   Connected staging host:
#     export VP_FEED_CACHE_HMAC_KEY="replace-with-32-byte-random-secret"
#     export VP_SQLITE_HMAC_KEY="replace-with-32-byte-random-secret"
#     ./examples/workflows/airgapped-sync-and-scan.sh stage
#
#   Transfer vpp-intel-bundle.tar.gz (+ optional NVD/GHSA/OSV dirs) to enclave, then:
#     export VP_FEED_CACHE_HMAC_KEY="same-secret-as-staging"
#     export VP_SQLITE_HMAC_KEY="same-secret-as-staging"
#     ./examples/workflows/airgapped-sync-and-scan.sh scan scans/nessus.xml scans/trivy.sarif
#
# Note: VulnParse-Pin FeedCacheManager reads VP_FEED_CACHE_HMAC_KEY and SQLite caches read VP_SQLITE_HMAC_KEY.
set -euo pipefail

VPP_BIN="${VPP_BIN:-vpp}"
BUNDLE_ARCHIVE="${BUNDLE_ARCHIVE:-vpp-intel-bundle.tar.gz}"
OUT_DIR="${OUT_DIR:-out/airgapped}"
DB_PATH="${DB_PATH:-airgapped.vpp.db}"
ASSETS_FILE="${ASSETS_FILE:-examples/configs/assets.example.yaml}"
DECISIONS_FILE="${DECISIONS_FILE:-examples/configs/decisions.example.yaml}"
PROFILE="${PROFILE:-bod-26-04}"

# Optional local enrichment archives inside ./data or mounted enclave media (must reside under $PWD when --enforce-root-read is enabled)
KEV_FEED="${KEV_FEED:-}"
EPSS_FEED="${EPSS_FEED:-}"
NVD_LOCAL_PATH="${NVD_LOCAL_PATH:-}"
GHSA_LOCAL_PATH="${GHSA_LOCAL_PATH:-}"
OSV_LOCAL_PATH="${OSV_LOCAL_PATH:-}"
EXPLOIT_DB_CSV="${EXPLOIT_DB_CSV:-}"

usage() {
  cat <<'EOF'
Usage:
  airgapped-sync-and-scan.sh stage
  airgapped-sync-and-scan.sh scan <scan-file> [<scan-file>...]
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

mode="$1"
shift

case "$mode" in
  stage)
    if [[ -z "${VP_FEED_CACHE_HMAC_KEY:-}" || -z "${VP_SQLITE_HMAC_KEY:-}" ]]; then
      echo "[WARN] VP_FEED_CACHE_HMAC_KEY and/or VP_SQLITE_HMAC_KEY not set; falling back to SHA-256-only sidecars." >&2
    fi

    echo "[1/3] Syncing threat-intel caches in portable mode (./data/cache)..."
    sync_args=(intel sync --feed all --portable)
    if [[ -n "$KEV_FEED" ]]; then
      sync_args+=(--kev-feed "$KEV_FEED")
    fi
    if [[ -n "$EPSS_FEED" ]]; then
      sync_args+=(--epss-feed "$EPSS_FEED")
    fi
    if [[ -n "$NVD_LOCAL_PATH" ]]; then
      sync_args+=(--nvd "$NVD_LOCAL_PATH")
    fi
    if [[ -n "$GHSA_LOCAL_PATH" ]]; then
      sync_args+=(--ghsa "$GHSA_LOCAL_PATH")
    fi
    if [[ -n "$OSV_LOCAL_PATH" ]]; then
      sync_args+=(--osv "$OSV_LOCAL_PATH")
    fi
    if [[ -n "$EXPLOIT_DB_CSV" ]]; then
      sync_args+=(--exploit-db "$EXPLOIT_DB_CSV")
    fi
    "$VPP_BIN" "${sync_args[@]}"

    echo "[2/3] Verifying feed integrity and SQLite HMAC sidecars..."
    mkdir -p "$OUT_DIR"
    "$VPP_BIN" intel status --portable --json | tee "${OUT_DIR}/intel-status-stage.json"

    echo "[3/3] Packaging portable cache bundle -> ${BUNDLE_ARCHIVE}..."
    tar -czf "$BUNDLE_ARCHIVE" -C data cache
    sha256sum "$BUNDLE_ARCHIVE" | tee "${BUNDLE_ARCHIVE}.sha256"

    cat <<EOF

Transfer instructions for the air-gapped enclave:
  1. Copy '${BUNDLE_ARCHIVE}' and '${BUNDLE_ARCHIVE}.sha256' (plus your wheelhouse & scan files) to enclave media.
  2. On the enclave host inside your working directory:
       sha256sum -c ${BUNDLE_ARCHIVE}.sha256
       mkdir -p data && tar -xzf ${BUNDLE_ARCHIVE} -C data
  3. Export the exact same VP_FEED_CACHE_HMAC_KEY and VP_SQLITE_HMAC_KEY secrets, then run:
       $0 scan <scan-file...>
EOF
    ;;

  scan)
    if [[ $# -lt 1 ]]; then
      echo "[ERROR] 'scan' mode requires at least one scan file under the portable working directory." >&2
      usage
      exit 1
    fi

    if [[ -f "$BUNDLE_ARCHIVE" && ! -d "data/cache" ]]; then
      echo "[0/3] Extracting ${BUNDLE_ARCHIVE} into ./data/cache..."
      mkdir -p data
      tar -xzf "$BUNDLE_ARCHIVE" -C data
    fi

    mkdir -p "$OUT_DIR"

    echo "[1/3] Checking offline feed cache & HMAC health..."
    "$VPP_BIN" intel status --portable --json | tee "${OUT_DIR}/intel-status-enclave.json"
    if grep -Eq '"health":[[:space:]]*"(tampered|world-writable|symlink|corrupt)"' "${OUT_DIR}/intel-status-enclave.json"; then
      echo "[ERROR] Offline threat-intel cache integrity check failed in ${OUT_DIR}/intel-status-enclave.json; refusing to start scan." >&2
      exit 1
    fi

    # Note: In --portable mode, CWD is an authorized root for --enforce-root-read.
    # Pass --exploit-source offline only when --exploit-db PATH is supplied (required by cli/args.py);
    # otherwise --offline automatically uses the cached Exploit-DB file under data/cache if present.
    scan_args=(
      scan "$@"
      --offline
      --kev-source offline
      --epss-source offline
      --portable
      --enforce-root-read
      --profile "$PROFILE"
      --db "$DB_PATH"
      --output-dossier "${OUT_DIR}/dossier"
      --output-runmanifest "${OUT_DIR}/runmanifest.json"
    )
    if [[ -f "$ASSETS_FILE" ]]; then
      scan_args+=(--assets "$ASSETS_FILE")
    fi
    if [[ -f "$DECISIONS_FILE" ]]; then
      scan_args+=(--decisions "$DECISIONS_FILE")
    fi
    if [[ -n "$NVD_LOCAL_PATH" ]]; then
      scan_args+=(--nvd "$NVD_LOCAL_PATH")
    fi
    if [[ -n "$GHSA_LOCAL_PATH" ]]; then
      scan_args+=(--ghsa "$GHSA_LOCAL_PATH")
    fi
    if [[ -n "$OSV_LOCAL_PATH" ]]; then
      scan_args+=(--osv "$OSV_LOCAL_PATH")
    fi
    if [[ -n "$EXPLOIT_DB_CSV" ]]; then
      scan_args+=(--exploit-source offline --exploit-db "$EXPLOIT_DB_CSV")
    fi

    echo "[2/3] Running 100% offline scan (--portable --enforce-root-read)..."
    "$VPP_BIN" "${scan_args[@]}"

    echo "[3/3] Verifying RunManifest and listed artifacts (strictly read-only)..."
    "$VPP_BIN" verify "${OUT_DIR}/runmanifest.json" --portable --enforce-root-read
    ;;

  *)
    echo "[ERROR] Unknown mode '$mode'." >&2
    usage
    exit 1
    ;;
esac
