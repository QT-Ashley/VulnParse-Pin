#!/usr/bin/env bash
# MSSP / Consultant Multi-Scanner Assessment -> Decision Defense Dossier + Roadmap + Re-test Diff
# Usage:
#   ./examples/workflows/mssp-assessment.sh
#   ENGAGEMENT_DB=client_acme.vpp.db ASSETS_FILE=examples/configs/assets.example.yaml \
#     DECISIONS_FILE=examples/configs/decisions.example.yaml ./examples/workflows/mssp-assessment.sh
set -euo pipefail

VPP_BIN="${VPP_BIN:-vpp}"
PROFILE="${PROFILE:-bod-26-04}"
ENGAGEMENT_DB="${ENGAGEMENT_DB:-engagement.vpp.db}"
OUT_DIR="${OUT_DIR:-out/mssp}"
ASSETS_FILE="${ASSETS_FILE:-examples/configs/assets.example.yaml}"
DECISIONS_FILE="${DECISIONS_FILE:-examples/configs/decisions.example.yaml}"

# Initial multi-scanner assessment inputs (override with client engagement files)
NESSUS_FILE="${NESSUS_FILE:-scans/nessus.xml}"
TRIVY_FILE="${TRIVY_FILE:-scans/trivy.sarif}"
NUCLEI_FILE="${NUCLEI_FILE:-scans/nuclei.jsonl}"
NMAP_FILE="${NMAP_FILE:-scans/nmap.xml}"

# Optional re-test scan inputs for velocity + stale-assumption diffing
RETEST_NESSUS_FILE="${RETEST_NESSUS_FILE:-}"
RETEST_TRIVY_FILE="${RETEST_TRIVY_FILE:-}"
RETEST_NUCLEI_FILE="${RETEST_NUCLEI_FILE:-}"

BASELINE_RUN_ID="${BASELINE_RUN_ID:-assessment-baseline}"
RETEST_RUN_ID="${RETEST_RUN_ID:-assessment-retest}"

mkdir -p "$OUT_DIR"

scan_inputs=()
for candidate in "$NESSUS_FILE" "$TRIVY_FILE" "$NUCLEI_FILE"; do
  if [[ -f "$candidate" ]]; then
    scan_inputs+=("$candidate")
  fi
done

if [[ ${#scan_inputs[@]} -eq 0 ]]; then
  echo "[ERROR] No scan input files found (checked: $NESSUS_FILE, $TRIVY_FILE, $NUCLEI_FILE)." >&2
  echo "Set NESSUS_FILE / TRIVY_FILE / NUCLEI_FILE to your engagement scan files." >&2
  exit 1
fi

nmap_args=()
if [[ -f "$NMAP_FILE" ]]; then
  nmap_args=(--nmap "$NMAP_FILE")
fi

echo "[1/5] Running multi-scanner assessment (${#scan_inputs[@]} input(s), profile=$PROFILE)..."
baseline_scan_args=(
  scan "${scan_inputs[@]}"
  ${nmap_args[@]+"${nmap_args[@]}"}
  --assets "$ASSETS_FILE"
  --decisions "$DECISIONS_FILE"
  --profile "$PROFILE"
  --run-id "$BASELINE_RUN_ID"
  --db "$ENGAGEMENT_DB"
  --output-dossier "${OUT_DIR}/dossier"
  --output-runmanifest "${OUT_DIR}/runmanifest.json"
  --runmanifest-mode expanded
  --show-ingestion-summary
)
"$VPP_BIN" "${baseline_scan_args[@]}"

echo "[2/5] Exporting Client Executive Remediation Roadmaps (HTML + Markdown)..."
"$VPP_BIN" export \
  --db "$ENGAGEMENT_DB" \
  --run-id "$BASELINE_RUN_ID" \
  --format roadmap-html \
  --output "${OUT_DIR}/executive_roadmap.html"

"$VPP_BIN" export \
  --db "$ENGAGEMENT_DB" \
  --run-id "$BASELINE_RUN_ID" \
  --format roadmap-md \
  --output "${OUT_DIR}/executive_roadmap.md"

echo "[3/5] Verifying RunManifest digest and hash-chained decision ledger (read-only)..."
"$VPP_BIN" verify "${OUT_DIR}/runmanifest.json"

retest_inputs=()
for candidate in "$RETEST_NESSUS_FILE" "$RETEST_TRIVY_FILE" "$RETEST_NUCLEI_FILE"; do
  if [[ -n "$candidate" && -f "$candidate" ]]; then
    retest_inputs+=("$candidate")
  fi
done

if [[ ${#retest_inputs[@]} -gt 0 ]]; then
  echo "[4/5] Running re-test scan against baseline '$BASELINE_RUN_ID'..."
  retest_scan_args=(
    scan "${retest_inputs[@]}"
    ${nmap_args[@]+"${nmap_args[@]}"}
    --assets "$ASSETS_FILE"
    --decisions "$DECISIONS_FILE"
    --profile "$PROFILE"
    --run-id "$RETEST_RUN_ID"
    --baseline-run-id "$BASELINE_RUN_ID"
    --db "$ENGAGEMENT_DB"
    --output-dossier "${OUT_DIR}/retest_dossier"
    --output-runmanifest "${OUT_DIR}/retest_runmanifest.json"
  )
  "$VPP_BIN" "${retest_scan_args[@]}"

  "$VPP_BIN" verify "${OUT_DIR}/retest_runmanifest.json"

  echo "[5/5] Evaluating re-test velocity and stale-assumption gate..."
  set +e
  "$VPP_BIN" diff "$BASELINE_RUN_ID" "$RETEST_RUN_ID" \
    --db "$ENGAGEMENT_DB" \
    --decisions "$DECISIONS_FILE" \
    --fail-on stale-assumption \
    --output-md "${OUT_DIR}/retest_diff.md" \
    --output-json "${OUT_DIR}/retest_diff.json"
  diff_rc=$?
  set -e

  if [[ $diff_rc -eq 2 ]]; then
    echo "[ALERT] Stale-assumption deferral invalidations detected in re-test diff (exit 2). See ${OUT_DIR}/retest_diff.md" >&2
    exit 2
  elif [[ $diff_rc -ne 0 ]]; then
    echo "[ERROR] vpp diff failed with exit code $diff_rc" >&2
    exit "$diff_rc"
  fi
else
  echo "[4/5] Skipping re-test scan (set RETEST_NESSUS_FILE / RETEST_TRIVY_FILE / RETEST_NUCLEI_FILE to enable)."
  echo "[5/5] Assessment deliverables written to ${OUT_DIR}/ (dossier.html, dossier.md, executive_roadmap.*, runmanifest.json)."
fi
