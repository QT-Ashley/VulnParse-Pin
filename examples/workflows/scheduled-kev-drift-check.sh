#!/usr/bin/env bash
# Scheduled CISA KEV / EPSS Drift Check & Stale-Assumption Alerting
#
# Syncs threat-intel feeds, optionally re-ingests the latest scan artifacts,
# runs `vpp diff --fail-on stale-assumption`, and handles exit codes cleanly:
#   0 -> No stale-assumption drift
#   1 -> Runtime / operational error
#   2 -> Policy drift / invalidated deferral detected (alerts & exits 2)
#
# Optional signed webhook override:
#   export VP_WEBHOOK_HMAC_KEY="replace-with-strong-random-secret"
#   export VPP_WEBHOOK_URL="https://hooks.example.org/vpp"
#   export VPP_WEBHOOK_OAL_FILTER="P1"  # all | P1 | P1b | P2
set -euo pipefail

VPP_BIN="${VPP_BIN:-vpp}"
DB_PATH="${DB_PATH:-.vpp.db}"
DECISIONS_FILE="${DECISIONS_FILE:-examples/configs/decisions.example.yaml}"
ASSETS_FILE="${ASSETS_FILE:-examples/configs/assets.example.yaml}"
PROFILE="${PROFILE:-bod-26-04}"
OUT_DIR="${OUT_DIR:-out/drift}"

# Optional space-delimited scan files to ingest a fresh run before diffing.
# Leave empty to re-enrich and diff existing runs in $DB_PATH against updated decisions/intel.
SCAN_FILES="${SCAN_FILES:-}"
BASE_RUN_ID="${BASE_RUN_ID:-}"
TARGET_RUN_ID="${TARGET_RUN_ID:-}"

KEV_FEED="${KEV_FEED:-}"
EPSS_FEED="${EPSS_FEED:-}"
NVD_SOURCE="${NVD_SOURCE:-}"
NVD_YEARS="${NVD_YEARS:-}"
SKIP_INTEL_SYNC="${SKIP_INTEL_SYNC:-0}"

VPP_WEBHOOK_URL="${VPP_WEBHOOK_URL:-}"
VPP_WEBHOOK_OAL_FILTER="${VPP_WEBHOOK_OAL_FILTER:-P1}"

mkdir -p "$OUT_DIR"

if [[ "$SKIP_INTEL_SYNC" == "1" ]]; then
  echo "[1/3] Skipping threat-intel feed sync (SKIP_INTEL_SYNC=1)."
else
  echo "[1/3] Syncing CISA KEV, EPSS, and NVD feeds..."
  kev_sync_args=(intel sync --feed kev)
  if [[ -n "$KEV_FEED" ]]; then
    kev_sync_args+=(--kev-feed "$KEV_FEED")
  fi
  "$VPP_BIN" "${kev_sync_args[@]}"

  epss_sync_args=(intel sync --feed epss)
  if [[ -n "$EPSS_FEED" ]]; then
    epss_sync_args+=(--epss-feed "$EPSS_FEED")
  fi
  "$VPP_BIN" "${epss_sync_args[@]}"

  nvd_sync_args=(intel sync --feed nvd)
  if [[ -n "$NVD_SOURCE" ]]; then
    nvd_sync_args+=(--nvd "$NVD_SOURCE")
  fi
  if [[ -n "$NVD_YEARS" ]]; then
    nvd_sync_args+=(--years "$NVD_YEARS")
  fi
  "$VPP_BIN" "${nvd_sync_args[@]}"
fi

if [[ -n "$SCAN_FILES" ]]; then
  echo "[2/3] Running scheduled scan against updated threat intelligence..."
  read -r -a scan_inputs <<< "$SCAN_FILES"
  scan_args=(
    scan "${scan_inputs[@]}"
    --decisions "$DECISIONS_FILE"
    --profile "$PROFILE"
    --db "$DB_PATH"
    --output-dossier "${OUT_DIR}/dossier"
    --output-runmanifest "${OUT_DIR}/runmanifest.json"
  )
  if [[ -f "$ASSETS_FILE" ]]; then
    scan_args+=(--assets "$ASSETS_FILE")
  fi
  if [[ -n "$VPP_WEBHOOK_URL" ]]; then
    if [[ -z "${VP_WEBHOOK_HMAC_KEY:-}" ]]; then
      echo "[WARN] VPP_WEBHOOK_URL set without VP_WEBHOOK_HMAC_KEY; webhook signing requires VP_WEBHOOK_HMAC_KEY." >&2
    fi
    scan_args+=(--webhook-endpoint "$VPP_WEBHOOK_URL" --webhook-oal-filter "$VPP_WEBHOOK_OAL_FILTER")
  fi
  "$VPP_BIN" "${scan_args[@]}"
  "$VPP_BIN" verify "${OUT_DIR}/runmanifest.json"
else
  echo "[2/3] Skipping scan ingestion (SCAN_FILES not set; will re-enrich stored run via --re-enrich)."
fi

echo "[3/3] Evaluating stale-assumption drift gate (--fail-on stale-assumption)..."
diff_args=()
if [[ -n "$BASE_RUN_ID" && -n "$TARGET_RUN_ID" ]]; then
  diff_args+=("$BASE_RUN_ID" "$TARGET_RUN_ID")
fi
diff_args+=(
  --db "$DB_PATH"
  --decisions "$DECISIONS_FILE"
)
if [[ -z "$SCAN_FILES" ]]; then
  diff_args+=(--re-enrich)
fi
diff_args+=(
  --fail-on stale-assumption
  --output-md "${OUT_DIR}/drift_report.md"
  --output-json "${OUT_DIR}/drift_report.json"
)

set +e
"$VPP_BIN" diff "${diff_args[@]}"
diff_rc=$?
set -e

case "$diff_rc" in
  0)
    echo "[OK] No stale-assumption deferral drift detected."
    exit 0
    ;;
  2)
    echo "[ALERT] Stale-assumption policy drift detected (exit 2). Review ${OUT_DIR}/drift_report.md" >&2
    exit 2
    ;;
  *)
    echo "[ERROR] vpp diff encountered a runtime failure (exit ${diff_rc})." >&2
    exit "$diff_rc"
    ;;
esac
