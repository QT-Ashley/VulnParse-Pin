# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from vulnparse_pin.core.assets_context import AssetContextMatcher, DecisionsRegistry
from vulnparse_pin.core.diff_engine import (
    DiffEngine,
    DiffReport,
    compare_run_metadata,
    compute_diff_id,
    evaluate_fail_gate,
    resolve_run_ids,
)
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    ensure_run,
    ingest_normalized_batches,
    upsert_enrichment_snapshots,
    upsert_scores,
    upsert_triage_decisions,
)


def _rec(
    *,
    ip: str,
    hostname: str,
    cves: List[str],
    scanner_sig: str,
    title: str,
    severity: str = "High",
    scanner_cvss_score: Optional[float] = 7.5,
    detection_mode: str = "credentialed_host",
    source_format: str = "nessus-xml",
) -> Dict[str, Any]:
    return {
        "ip_address": ip,
        "hostname": hostname,
        "target_uri": None,
        "image_or_repo": None,
        "os": "Ubuntu 24.04",
        "asset_metadata": {"credentialed": True, "open_ports": [443]},
        "source_format": source_format,
        "scanner_sig": scanner_sig,
        "title": title,
        "description": f"Description for {title}",
        "solution": "Apply vendor patch.",
        "plugin_output": "Detected vulnerable package.",
        "severity": severity,
        "cves": cves,
        "cwes": ["CWE-79"],
        "ghsa_ids": [],
        "affected_port": 443,
        "protocol": "tcp",
        "service_name": "https",
        "location_uri": None,
        "line_number": None,
        "package_purl": None,
        "scanner_cvss_score": scanner_cvss_score,
        "scanner_cvss_vector": None,
        "detection_mode": detection_mode,
        "fidelity_tier": "high",
        "ingestion_confidence": 0.95,
        "missing_fields": [],
        "degraded_input": False,
        "references": [],
        "tags": [],
        "exploit_evidence": False,
        "raw_evidence_excerpt": "version check",
    }


def _seed_comprehensive_runs(db: VppDatabase) -> Dict[str, Any]:
    """
    Seed a realistic base_run ('run-base') and target_run ('run-target') covering:
      - Newly introduced P1, P2, P3, and validly deferred P1
      - Threat intel escalations (KEV flip, EPSS <0.04->0.05, EPSS <0.10->0.15, pct 0.96,
        CVSS +1.0 float-tricky 6.8->7.8, Missing->NVD, internet_facing False->True, plus non-escalating control)
      - Verified remediated (asset_still_present=True vs False)
      - Explicit invalidated assumptions (decisions.yaml + DB deferred_invalidated / accepted_invalidated)
      - Implicit P3->P1 baseline drift
      - Valid deferrals NOT falsely flagged as invalidated
      - Shadow assets: newly observed in target, resolved matched in target, resolved absent in target
    """
    matcher_base = AssetContextMatcher(
        {
            "version": "v2",
            "defaults": {"criticality": "medium", "internet_facing": False},
            "rules": [
                {
                    "id": "web-prod",
                    "asset_id": "aid_web_prod",
                    "aliases": ["10.0.1.10", "web-01.corp.local"],
                    "criticality": "critical",
                    "internet_facing": True,
                },
                {
                    "id": "app-int",
                    "asset_id": "aid_app_int",
                    "aliases": ["10.0.2.20", "app-01.corp.local"],
                    "criticality": "high",
                    "internet_facing": False,
                },
                {
                    "id": "decomm-host",
                    "asset_id": "aid_decomm",
                    "aliases": ["10.0.3.30", "old-01.corp.local"],
                    "criticality": "low",
                    "internet_facing": False,
                },
            ],
        }
    )

    matcher_target = AssetContextMatcher(
        {
            "version": "v2",
            "defaults": {"criticality": "medium", "internet_facing": False},
            "rules": [
                {
                    "id": "web-prod",
                    "asset_id": "aid_web_prod",
                    "aliases": ["10.0.1.10", "web-01.corp.local"],
                    "criticality": "critical",
                    "internet_facing": True,
                },
                {
                    "id": "app-int",
                    "asset_id": "aid_app_int",
                    "aliases": ["10.0.2.20", "app-01.corp.local"],
                    "criticality": "high",
                    # Flipped False -> True in target!
                    "internet_facing": True,
                },
                {
                    "id": "shadow-now-onboarded",
                    "hostnames": ["shadow-onboarded.corp.local"],
                    "cidrs": ["192.168.99.10/32"],
                    "criticality": "medium",
                    "internet_facing": False,
                },
            ],
        }
    )

    ensure_run(
        db,
        "run-base",
        created_at_utc="2026-01-10T00:00:00Z",
        vpp_version="2.0.0",
        profile="bod-26-04",
        config_sha256="sha256:cfg_v1",
        assets_sha256="sha256:assets_v1",
        decisions_sha256="sha256:dec_v1",
        intel_metadata={
            "epss_model_version": "v2025.03.14",
            "epss_score_date": "2026-01-09",
            "kev_catalog_version": "2026.01.08",
            "kev_date_released": "2026-01-08",
        },
        input_files=["scan_base.nessus"],
    )
    ensure_run(
        db,
        "run-target",
        created_at_utc="2026-02-10T00:00:00Z",
        vpp_version="2.0.0",
        profile="bod-26-04",
        config_sha256="sha256:cfg_v2",
        assets_sha256="sha256:assets_v2",
        decisions_sha256="sha256:dec_v2",
        intel_metadata={
            "epss_model_version": "v2026.02.01",
            "epss_score_date": "2026-02-09",
            "kev_catalog_version": "2026.02.09",
            "kev_date_released": "2026-02-09",
        },
        input_files=["scan_target.nessus"],
        baseline_run_id="run-base",
    )

    base_records = [
        # Persisting on web-prod: KEV flip + explicit decisions.yaml invalidation
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1001"], scanner_sig="nessus:1001", title="Kev Flip & Broken Deferral"),
        # Persisting on web-prod: EPSS crosses 0.04 (0.03 -> 0.05), P3 -> P2 implicit drift
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1002"], scanner_sig="nessus:1002", title="EPSS 0.04 Cross"),
        # Persisting on web-prod: EPSS crosses 0.10 (0.06 -> 0.15) & pct 0.96, P3 -> P1 implicit drift
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1003"], scanner_sig="nessus:1003", title="EPSS 0.10 & P3->P1 Drift"),
        # Persisting on web-prod: CVSS 6.8 -> 7.8 (tricky IEEE-754 float +1.0)
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1004"], scanner_sig="nessus:1004", title="CVSS +1.0 Float"),
        # Persisting on web-prod: CVSS provenance Missing -> NVD
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1005"], scanner_sig="nessus:1005", title="CVSS Missing to NVD", scanner_cvss_score=None),
        # Persisting on web-prod: small change (CVSS +0.5, EPSS 0.05 -> 0.08) -> must NOT escalate
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1006"], scanner_sig="nessus:1006", title="Minor Noise Control"),
        # Persisting on web-prod: valid deferral that stays valid even though EPSS rises slightly within limit
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1007"], scanner_sig="nessus:1007", title="Validly Deferred Finding"),
        # Persisting on app-int: internet_facing flips False -> True
        _rec(ip="10.0.2.20", hostname="app-01.corp.local", cves=["CVE-2024-2001"], scanner_sig="nessus:2001", title="Exposure Flip Finding"),
        # Remediated on web-prod (host still present in target!)
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-3001"], scanner_sig="nessus:3001", title="Patched On Live Host"),
        # Remediated on decomm-host (host disappeared from target!)
        _rec(ip="10.0.3.30", hostname="old-01.corp.local", cves=["CVE-2024-3002"], scanner_sig="nessus:3002", title="Disappeared With Host"),
        # Shadow asset 1 in base -> onboarded/matched in target
        _rec(ip="192.168.99.10", hostname="shadow-onboarded.corp.local", cves=["CVE-2024-4001"], scanner_sig="nessus:4001", title="Onboarded Shadow Vuln"),
        # Shadow asset 2 in base -> absent in target
        _rec(ip="192.168.99.20", hostname="shadow-gone.corp.local", cves=["CVE-2024-4002"], scanner_sig="nessus:4002", title="Gone Shadow Vuln"),
    ]

    target_records = [
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1001"], scanner_sig="nessus:1001", title="Kev Flip & Broken Deferral"),
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1002"], scanner_sig="nessus:1002", title="EPSS 0.04 Cross"),
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1003"], scanner_sig="nessus:1003", title="EPSS 0.10 & P3->P1 Drift"),
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1004"], scanner_sig="nessus:1004", title="CVSS +1.0 Float"),
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1005"], scanner_sig="nessus:1005", title="CVSS Missing to NVD", scanner_cvss_score=None),
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1006"], scanner_sig="nessus:1006", title="Minor Noise Control"),
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2024-1007"], scanner_sig="nessus:1007", title="Validly Deferred Finding"),
        _rec(ip="10.0.2.20", hostname="app-01.corp.local", cves=["CVE-2024-2001"], scanner_sig="nessus:2001", title="Exposure Flip Finding"),
        _rec(ip="192.168.99.10", hostname="shadow-onboarded.corp.local", cves=["CVE-2024-4001"], scanner_sig="nessus:4001", title="Onboarded Shadow Vuln"),
        # Newly introduced P1 (KEV) on web-prod
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2025-9001"], scanner_sig="nessus:9001", title="New Active KEV P1", severity="Critical", scanner_cvss_score=9.8),
        # Newly introduced P2 (60-day) on web-prod
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2025-9002"], scanner_sig="nessus:9002", title="New P2 High", severity="High", scanner_cvss_score=7.8),
        # Newly introduced P4 (Fix on Upgrade) -> counted in newly_introduced_all ONLY
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2025-9003"], scanner_sig="nessus:9003", title="New Low Risk P4", severity="Low", scanner_cvss_score=2.5),
        # Newly introduced P1 validly deferred via decisions.yaml
        _rec(ip="10.0.1.10", hostname="web-01.corp.local", cves=["CVE-2025-9004"], scanner_sig="nessus:9004", title="New Deferred P1", severity="Critical", scanner_cvss_score=9.1),
        # Newly observed shadow asset in target
        _rec(ip="203.0.113.77", hostname="rogue-api.external.net", cves=["CVE-2025-9999"], scanner_sig="nuclei:rogue-rce", title="New Shadow Asset Vuln", severity="Critical", scanner_cvss_score=9.8, detection_mode="active_dast", source_format="nuclei-jsonl"),
    ]

    ingest_normalized_batches(db, "run-base", [base_records], asset_matcher=matcher_base)
    ingest_normalized_batches(db, "run-target", [target_records], asset_matcher=matcher_target)

    base_map = {
        r["title"]: r
        for r in db.execute(
            "SELECT finding_id, asset_id, primary_cve, title FROM findings WHERE run_id = 'run-base'"
        ).fetchall()
        for r in [{"finding_id": r[0], "asset_id": r[1], "primary_cve": r[2], "title": r[3]}]
    }
    target_map = {
        r["title"]: r
        for r in db.execute(
            "SELECT finding_id, asset_id, primary_cve, title FROM findings WHERE run_id = 'run-target'"
        ).fetchall()
        for r in [{"finding_id": r[0], "asset_id": r[1], "primary_cve": r[2], "title": r[3]}]
    }

    upsert_enrichment_snapshots(
        db,
        "run-base",
        [
            {"cve_id": "CVE-2024-1001", "cvss_score": 7.0, "cvss_provenance": "NVD", "epss_score": 0.05, "epss_percentile": 0.70, "in_kev": False},
            {"cve_id": "CVE-2024-1002", "cvss_score": 6.5, "cvss_provenance": "NVD", "epss_score": 0.03, "epss_percentile": 0.60, "in_kev": False},
            {"cve_id": "CVE-2024-1003", "cvss_score": 7.5, "cvss_provenance": "NVD", "epss_score": 0.06, "epss_percentile": 0.85, "in_kev": False},
            {"cve_id": "CVE-2024-1004", "cvss_score": 6.8, "cvss_provenance": "Scanner-Supplied", "epss_score": 0.02, "epss_percentile": 0.50, "in_kev": False},
            {"cve_id": "CVE-2024-1005", "cvss_score": None, "cvss_provenance": "Missing", "epss_score": 0.01, "epss_percentile": 0.40, "in_kev": False},
            {"cve_id": "CVE-2024-1006", "cvss_score": 7.0, "cvss_provenance": "Scanner-Supplied", "epss_score": 0.05, "epss_percentile": 0.80, "in_kev": False},
            {"cve_id": "CVE-2024-1007", "cvss_score": 7.0, "cvss_provenance": "NVD", "epss_score": 0.02, "epss_percentile": 0.50, "in_kev": False},
            {"cve_id": "CVE-2024-2001", "cvss_score": 7.5, "cvss_provenance": "NVD", "epss_score": 0.02, "epss_percentile": 0.55, "in_kev": False},
            {"cve_id": "CVE-2024-3001", "cvss_score": 9.8, "cvss_provenance": "NVD", "epss_score": 0.91, "epss_percentile": 0.99, "in_kev": True},
            {"cve_id": "CVE-2024-3002", "cvss_score": 7.0, "cvss_provenance": "NVD", "epss_score": 0.01, "epss_percentile": 0.30, "in_kev": False},
            {"cve_id": "CVE-2024-4001", "cvss_score": 6.5, "cvss_provenance": "NVD", "epss_score": 0.02, "epss_percentile": 0.45, "in_kev": False},
            {"cve_id": "CVE-2024-4002", "cvss_score": 5.0, "cvss_provenance": "NVD", "epss_score": 0.01, "epss_percentile": 0.25, "in_kev": False},
        ],
    )

    upsert_enrichment_snapshots(
        db,
        "run-target",
        [
            # 1001: in_kev flipped True, epss=0.45, cvss=9.5 -> violates in_kev, max_epss, max_cvss
            {"cve_id": "CVE-2024-1001", "cvss_score": 9.5, "cvss_provenance": "NVD", "epss_score": 0.45, "epss_percentile": 0.97, "in_kev": True},
            # 1002: epss crossed 0.04 (0.03 -> 0.05)
            {"cve_id": "CVE-2024-1002", "cvss_score": 6.5, "cvss_provenance": "NVD", "epss_score": 0.05, "epss_percentile": 0.72, "in_kev": False},
            # 1003: epss crossed 0.10 & pct crossed 0.95 (0.06/0.85 -> 0.15/0.96)
            {"cve_id": "CVE-2024-1003", "cvss_score": 7.5, "cvss_provenance": "NVD", "epss_score": 0.15, "epss_percentile": 0.96, "in_kev": False},
            # 1004: cvss 6.8 -> 7.8 (exact +1.0 IEEE-754 test)
            {"cve_id": "CVE-2024-1004", "cvss_score": 7.8, "cvss_provenance": "NVD", "epss_score": 0.02, "epss_percentile": 0.50, "in_kev": False},
            # 1005: Missing -> NVD (even small score 0.7)
            {"cve_id": "CVE-2024-1005", "cvss_score": 0.7, "cvss_provenance": "NVD", "epss_score": 0.01, "epss_percentile": 0.40, "in_kev": False},
            # 1006: minor noise (+0.5 CVSS, Scanner->NVD, EPSS 0.05->0.08) -> NO escalation
            {"cve_id": "CVE-2024-1006", "cvss_score": 7.5, "cvss_provenance": "NVD", "epss_score": 0.08, "epss_percentile": 0.85, "in_kev": False},
            # 1007: validly deferred (epss 0.02->0.06 stays <= max_epss=0.20, in_kev=False)
            {"cve_id": "CVE-2024-1007", "cvss_score": 7.0, "cvss_provenance": "NVD", "epss_score": 0.06, "epss_percentile": 0.75, "in_kev": False},
            # 2001: exposure flipped False -> True on app-int
            {"cve_id": "CVE-2024-2001", "cvss_score": 7.5, "cvss_provenance": "NVD", "epss_score": 0.02, "epss_percentile": 0.55, "in_kev": False},
            # 4001: persisted when shadow onboarded
            {"cve_id": "CVE-2024-4001", "cvss_score": 6.5, "cvss_provenance": "NVD", "epss_score": 0.02, "epss_percentile": 0.45, "in_kev": False},
            # Newly introduced
            {"cve_id": "CVE-2025-9001", "cvss_score": 9.8, "cvss_provenance": "NVD", "epss_score": 0.88, "epss_percentile": 0.99, "in_kev": True},
            {"cve_id": "CVE-2025-9002", "cvss_score": 7.8, "cvss_provenance": "NVD", "epss_score": 0.06, "epss_percentile": 0.91, "in_kev": False},
            {"cve_id": "CVE-2025-9003", "cvss_score": 2.5, "cvss_provenance": "NVD", "epss_score": 0.005, "epss_percentile": 0.20, "in_kev": False},
            {"cve_id": "CVE-2025-9004", "cvss_score": 9.1, "cvss_provenance": "NVD", "epss_score": 0.50, "epss_percentile": 0.97, "in_kev": True},
            {"cve_id": "CVE-2025-9999", "cvss_score": 9.8, "cvss_provenance": "NVD", "epss_score": 0.20, "epss_percentile": 0.96, "in_kev": False},
        ],
    )

    upsert_scores(
        db,
        "run-base",
        [
            {"finding_id": info["finding_id"], "asset_id": info["asset_id"], "scoring_track": "cve_threat", "raw_risk_score": 5.0, "operational_score": 3.5, "risk_band": "Low"}
            for info in base_map.values()
        ],
    )
    upsert_scores(
        db,
        "run-target",
        [
            {"finding_id": info["finding_id"], "asset_id": info["asset_id"], "scoring_track": "cve_threat", "raw_risk_score": 12.0, "operational_score": 7.5, "risk_band": "High"}
            for info in target_map.values()
        ],
    )

    upsert_triage_decisions(
        db,
        "run-base",
        [
            {"finding_id": base_map["Kev Flip & Broken Deferral"]["finding_id"], "asset_id": base_map["Kev Flip & Broken Deferral"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "deferred_valid", "decision_id": "dec-kev-flip"},
            {"finding_id": base_map["EPSS 0.04 Cross"]["finding_id"], "asset_id": base_map["EPSS 0.04 Cross"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "active"},
            {"finding_id": base_map["EPSS 0.10 & P3->P1 Drift"]["finding_id"], "asset_id": base_map["EPSS 0.10 & P3->P1 Drift"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "active"},
            {"finding_id": base_map["CVSS +1.0 Float"]["finding_id"], "asset_id": base_map["CVSS +1.0 Float"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "active"},
            {"finding_id": base_map["CVSS Missing to NVD"]["finding_id"], "asset_id": base_map["CVSS Missing to NVD"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P4", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "active"},
            {"finding_id": base_map["Minor Noise Control"]["finding_id"], "asset_id": base_map["Minor Noise Control"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "active"},
            {"finding_id": base_map["Validly Deferred Finding"]["finding_id"], "asset_id": base_map["Validly Deferred Finding"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "deferred_valid", "decision_id": "dec-still-valid"},
            {"finding_id": base_map["Exposure Flip Finding"]["finding_id"], "asset_id": base_map["Exposure Flip Finding"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "active"},
            {"finding_id": base_map["Patched On Live Host"]["finding_id"], "asset_id": base_map["Patched On Live Host"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P1", "sla_bucket": "3-day + Forensic Triage", "sla_days": 3, "ssvc_action": "Act", "decision_status": "active"},
            {"finding_id": base_map["Disappeared With Host"]["finding_id"], "asset_id": base_map["Disappeared With Host"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "active"},
        ],
    )

    upsert_triage_decisions(
        db,
        "run-target",
        [
            {"finding_id": target_map["Kev Flip & Broken Deferral"]["finding_id"], "asset_id": target_map["Kev Flip & Broken Deferral"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P1", "sla_bucket": "3-day + Forensic Triage", "sla_days": 3, "ssvc_action": "Act", "decision_status": "deferred_invalidated", "decision_id": "dec-kev-flip"},
            {"finding_id": target_map["EPSS 0.04 Cross"]["finding_id"], "asset_id": target_map["EPSS 0.04 Cross"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "active"},
            {"finding_id": target_map["EPSS 0.10 & P3->P1 Drift"]["finding_id"], "asset_id": target_map["EPSS 0.10 & P3->P1 Drift"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P1", "sla_bucket": "14-day", "sla_days": 14, "ssvc_action": "Act", "decision_status": "active"},
            {"finding_id": target_map["CVSS +1.0 Float"]["finding_id"], "asset_id": target_map["CVSS +1.0 Float"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "active"},
            {"finding_id": target_map["CVSS Missing to NVD"]["finding_id"], "asset_id": target_map["CVSS Missing to NVD"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P4", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "active"},
            {"finding_id": target_map["Minor Noise Control"]["finding_id"], "asset_id": target_map["Minor Noise Control"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "active"},
            # Even though EPSS moved into P2 range, valid deferral protects it from invalidation
            {"finding_id": target_map["Validly Deferred Finding"]["finding_id"], "asset_id": target_map["Validly Deferred Finding"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "deferred_valid", "decision_id": "dec-still-valid"},
            {"finding_id": target_map["Exposure Flip Finding"]["finding_id"], "asset_id": target_map["Exposure Flip Finding"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P1", "sla_bucket": "14-day", "sla_days": 14, "ssvc_action": "Act", "decision_status": "active"},
            {"finding_id": target_map["New Active KEV P1"]["finding_id"], "asset_id": target_map["New Active KEV P1"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P1", "sla_bucket": "3-day + Forensic Triage", "sla_days": 3, "ssvc_action": "Act", "decision_status": "active"},
            {"finding_id": target_map["New P2 High"]["finding_id"], "asset_id": target_map["New P2 High"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P2", "sla_bucket": "60-day", "sla_days": 60, "ssvc_action": "Attend", "decision_status": "active"},
            {"finding_id": target_map["New Low Risk P4"]["finding_id"], "asset_id": target_map["New Low Risk P4"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P4", "sla_bucket": "Fix on Upgrade", "ssvc_action": "Track", "decision_status": "active"},
            {"finding_id": target_map["New Deferred P1"]["finding_id"], "asset_id": target_map["New Deferred P1"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P1", "sla_bucket": "3-day + Forensic Triage", "sla_days": 3, "ssvc_action": "Act", "decision_status": "deferred_valid", "decision_id": "dec-new-p1"},
            {"finding_id": target_map["New Shadow Asset Vuln"]["finding_id"], "asset_id": target_map["New Shadow Asset Vuln"]["asset_id"], "profile": "bod-26-04", "priority_tier": "P1", "sla_bucket": "14-day", "sla_days": 14, "ssvc_action": "Act", "decision_status": "active"},
        ],
    )

    registry = DecisionsRegistry.from_dict(
        {
            "version": "v2",
            "decisions": [
                {
                    "id": "dec-kev-flip",
                    "asset_id": "aid_web_prod",
                    "cve_or_rule_id": "CVE-2024-1001",
                    "status": "deferred",
                    "rationale": "Mitigated while KEV=False, EPSS<=0.20, CVSS<=8.0.",
                    "expires_at": "2026-12-31",
                    "assumptions": {
                        "in_kev": False,
                        "max_epss": 0.20,
                        "max_cvss": 8.0,
                        "internet_facing": True,
                    },
                },
                {
                    "id": "dec-still-valid",
                    "asset_id": "aid_web_prod",
                    "cve_or_rule_id": "CVE-2024-1007",
                    "status": "deferred",
                    "rationale": "Valid deferral within limits.",
                    "expires_at": "2026-12-31",
                    "assumptions": {
                        "in_kev": False,
                        "max_epss": 0.20,
                        "internet_facing": True,
                    },
                },
                {
                    "id": "dec-new-p1",
                    "asset_id": "aid_web_prod",
                    "cve_or_rule_id": "CVE-2025-9004",
                    "status": "deferred",
                    "rationale": "Compensating WAF active and accepted KEV.",
                    "expires_at": "2026-12-31",
                    "assumptions": {
                        "in_kev": True,
                        "internet_facing": True,
                    },
                },
            ],
        }
    )

    return {"base_map": base_map, "target_map": target_map, "registry": registry}


def test_default_run_resolution_and_errors(tmp_path: Path) -> None:
    with VppDatabase(tmp_path / "resolve.vpp.db") as db:
        with pytest.raises(ValueError, match="At least 2 runs are required"):
            resolve_run_ids(db)

        ensure_run(db, "run-1", created_at_utc="2026-01-01T00:00:00Z")
        with pytest.raises(ValueError, match="At least 2 runs are required"):
            resolve_run_ids(db)

        ensure_run(db, "run-2", created_at_utc="2026-02-01T00:00:00Z")
        ensure_run(db, "run-3", created_at_utc="2026-03-01T00:00:00Z")

        # Omitted both -> two most recent runs ordered by created_at_utc DESC
        base_id, target_id = resolve_run_ids(db)
        assert (base_id, target_id) == ("run-2", "run-3")

        # Only target specified -> resolves preceding run
        assert resolve_run_ids(db, target_run_id="run-2") == ("run-1", "run-2")

        # Only base specified -> resolves newest distinct run
        assert resolve_run_ids(db, base_run_id="run-1") == ("run-1", "run-3")

        # Missing run fails clearly
        with pytest.raises(ValueError, match="does not exist"):
            resolve_run_ids(db, base_run_id="run-missing", target_run_id="run-3")


def test_diff_engine_4_deltas_shadow_assets_and_persistence(tmp_path: Path) -> None:
    db_path = tmp_path / "diff.vpp.db"
    with VppDatabase(db_path) as db:
        seeded = _seed_comprehensive_runs(db)
        engine = DiffEngine(
            db,
            decisions_registry=seeded["registry"],
            now_utc=datetime(2026, 2, 15, 0, 0, tzinfo=timezone.utc),
        )

        # persist=False should not write diff_events
        dry_report = engine.compare(persist=False)
        assert dry_report.base_run_id == "run-base"
        assert dry_report.target_run_id == "run-target"
        assert dry_report.persisted_events_count == 0
        assert db.execute("SELECT COUNT(*) FROM diff_events").fetchone()[0] == 0

        # persist=True writes deterministic diff_events
        report = engine.compare("run-base", "run-target", persist=True)
        assert isinstance(report, DiffReport)
        expected_diff_id = compute_diff_id("run-base", "run-target")
        assert report.diff_id == expected_diff_id
        assert report.persisted_events_count > 0

        # JSON serializable check
        serialized = json.dumps(report.to_dict())
        parsed = json.loads(serialized)
        assert parsed["diff_id"] == expected_diff_id

        # 1. newly_introduced_high_risk + newly_introduced_all
        assert report.newly_introduced_all == 5
        assert report.summary.newly_introduced_all == 5
        new_cves = {x.primary_cve for x in report.newly_introduced_high_risk}
        assert new_cves == {"CVE-2025-9001", "CVE-2025-9002", "CVE-2025-9004", "CVE-2025-9999"}
        assert "CVE-2025-9003" not in new_cves
        deferred_new = [x for x in report.newly_introduced_high_risk if x.primary_cve == "CVE-2025-9004"][0]
        assert deferred_new.is_active is False
        assert deferred_new.decision_status == "deferred_valid"

        # 2. threat_intel_escalated
        esc_by_cve = {x.primary_cve: x for x in report.threat_intel_escalated}
        assert set(esc_by_cve.keys()) == {
            "CVE-2024-1001",
            "CVE-2024-1002",
            "CVE-2024-1003",
            "CVE-2024-1004",
            "CVE-2024-1005",
            "CVE-2024-1007",
            "CVE-2024-2001",
        }
        assert "CVE-2024-1006" not in esc_by_cve  # minor noise control
        assert esc_by_cve["CVE-2024-1007"].is_active is False
        assert esc_by_cve["CVE-2024-1007"].decision_status == "deferred_valid"

        assert "in_kev_added" in esc_by_cve["CVE-2024-1001"].escalation_reasons
        assert "epss_score_crossed_0.04" in esc_by_cve["CVE-2024-1002"].escalation_reasons
        assert "epss_score_crossed_0.10" in esc_by_cve["CVE-2024-1003"].escalation_reasons
        assert "epss_percentile_crossed_0.95" in esc_by_cve["CVE-2024-1003"].escalation_reasons
        assert any(r.startswith("cvss_increased_") for r in esc_by_cve["CVE-2024-1004"].escalation_reasons)
        assert any(r.startswith("cvss_provenance_upgraded_Missing_to_NVD") for r in esc_by_cve["CVE-2024-1005"].escalation_reasons)
        assert "internet_facing_flipped_true" in esc_by_cve["CVE-2024-2001"].escalation_reasons

        # 3. verified_remediated (asset_still_present True vs False)
        rem_by_cve = {x.primary_cve: x for x in report.verified_remediated}
        assert set(rem_by_cve.keys()) == {"CVE-2024-3001", "CVE-2024-3002", "CVE-2024-4002"}
        assert rem_by_cve["CVE-2024-3001"].asset_still_present is True
        assert rem_by_cve["CVE-2024-3001"].remediation_status == "verified_patched"
        assert rem_by_cve["CVE-2024-3002"].asset_still_present is False
        assert rem_by_cve["CVE-2024-3002"].remediation_status == "asset_missing"

        # 4. invalidated_assumptions (explicit + implicit drift, valid deferrals NOT flagged)
        inv_by_cve = {x.primary_cve: x for x in report.invalidated_assumptions}
        assert "CVE-2024-1007" not in inv_by_cve
        assert "CVE-2025-9004" not in inv_by_cve
        assert "CVE-2024-1001" in inv_by_cve
        assert inv_by_cve["CVE-2024-1001"].invalidation_kind == "explicit+implicit"
        assert {"kev_flipped", "epss_exceeded", "cvss_exceeded"}.issubset(
            set(inv_by_cve["CVE-2024-1001"].violated_predicates)
        )
        assert "CVE-2024-1003" in inv_by_cve
        assert inv_by_cve["CVE-2024-1003"].invalidation_kind == "implicit"
        assert "CVE-2024-1002" in inv_by_cve  # P3 -> P2 due to EPSS drift
        assert "CVE-2024-2001" in inv_by_cve  # P3 -> P1 due to exposure flip

        # 5. shadow_assets_delta
        new_shadow_ips = {x.ip_address for x in report.shadow_assets_delta.newly_observed}
        assert new_shadow_ips == {"203.0.113.77"}
        resolved_map = {x.ip_address: x for x in report.shadow_assets_delta.resolved}
        assert set(resolved_map.keys()) == {"192.168.99.10", "192.168.99.20"}
        assert resolved_map["192.168.99.10"].delta_kind == "resolved_matched"
        assert resolved_map["192.168.99.20"].delta_kind == "resolved_absent"

        # Metadata delta
        meta = compare_run_metadata(db, "run-base", "run-target")
        assert meta.config_changed is True
        assert meta.assets_changed is True
        assert meta.decisions_changed is True
        assert meta.intel_changed is True
        assert meta.intel_changes["epss_model_version"] == {
            "base": "v2025.03.14",
            "target": "v2026.02.01",
        }
        assert meta.intel_changes["kev_date_released"] == {
            "base": "2026-01-08",
            "target": "2026-02-09",
        }

        # Idempotent deterministic persistence + raw DuckDB connection compatibility
        rows_first = db.execute(
            "SELECT diff_id, category, finding_id, asset_id, cve_id, details_json "
            "FROM diff_events ORDER BY category, asset_id, finding_id"
        ).fetchall()
        conn_engine = DiffEngine(
            db.conn,
            decisions_registry=seeded["registry"],
            now_utc=datetime(2026, 2, 15, 0, 0, tzinfo=timezone.utc),
        )
        report2 = conn_engine.compare("run-base", "run-target", persist=True)
        assert report2.diff_id == expected_diff_id
        rows_second = db.execute(
            "SELECT diff_id, category, finding_id, asset_id, cve_id, details_json "
            "FROM diff_events ORDER BY category, asset_id, finding_id"
        ).fetchall()
        assert rows_first == rows_second
        assert len(rows_first) == report.persisted_events_count


def test_explicit_decisions_yaml_predicates_and_valid_deferrals_isolated(tmp_path: Path) -> None:
    """
    Verify every decisions.yaml predicate (in_kev, max_epss, max_epss_percentile,
    internet_facing, max_cvss, expires_at) triggers exact violated_predicates,
    including non-CVE scanner_sig rules, while valid deferrals remain clean.
    """
    decisions_yaml = tmp_path / "decisions.yaml"
    decisions_yaml.write_text(
        """
version: v2
decisions:
  - id: dec-kev
    asset_id: aid_srv
    cve_or_rule_id: CVE-2024-5001
    status: deferred
    rationale: Wait until KEV changes.
    expires_at: 2026-12-31
    assumptions:
      in_kev: false
  - id: dec-epss
    asset_id: aid_srv
    cve_or_rule_id: CVE-2024-5002
    status: accepted
    rationale: Low EPSS accepted.
    expires_at: 2026-12-31
    assumptions:
      max_epss: 0.10
      max_epss_percentile: 0.80
  - id: dec-facing
    asset_id: aid_srv
    cve_or_rule_id: "nuclei:swagger-ui"
    status: deferred
    rationale: Internal only.
    expires_at: 2026-12-31
    assumptions:
      internet_facing: false
  - id: dec-expired
    asset_id: aid_srv
    cve_or_rule_id: CVE-2024-5004
    status: deferred
    rationale: Temporary window.
    expires_at: 2026-01-15
    assumptions:
      in_kev: false
  - id: dec-valid
    asset_id: aid_srv
    cve_or_rule_id: CVE-2024-5005
    status: deferred
    rationale: All predicates remain satisfied.
    expires_at: 2026-12-31
    assumptions:
      in_kev: false
      max_epss: 0.25
      internet_facing: true
      max_cvss: 9.0
""",
        encoding="utf-8",
    )

    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [
                {
                    "id": "srv-rule",
                    "asset_id": "aid_srv",
                    "aliases": ["10.10.5.5", "srv-01.corp.local"],
                    "criticality": "high",
                    "internet_facing": True,
                }
            ],
        }
    )

    with VppDatabase(tmp_path / "decisions_pred.vpp.db") as db:
        ensure_run(db, "r1", created_at_utc="2026-01-01T00:00:00Z")
        ensure_run(db, "r2", created_at_utc="2026-02-01T00:00:00Z")

        records = [
            _rec(ip="10.10.5.5", hostname="srv-01.corp.local", cves=["CVE-2024-5001"], scanner_sig="n:1", title="KEV Predicate"),
            _rec(ip="10.10.5.5", hostname="srv-01.corp.local", cves=["CVE-2024-5002"], scanner_sig="n:2", title="EPSS Predicate"),
            _rec(ip="10.10.5.5", hostname="srv-01.corp.local", cves=[], scanner_sig="nuclei:swagger-ui", title="Exposure Non-CVE Predicate", source_format="nuclei-jsonl", detection_mode="active_dast"),
            _rec(ip="10.10.5.5", hostname="srv-01.corp.local", cves=["CVE-2024-5004"], scanner_sig="n:4", title="Expiry Predicate"),
            _rec(ip="10.10.5.5", hostname="srv-01.corp.local", cves=["CVE-2024-5005"], scanner_sig="n:5", title="Valid Deferral"),
        ]
        ingest_normalized_batches(db, "r1", [records], asset_matcher=matcher)
        ingest_normalized_batches(db, "r2", [records], asset_matcher=matcher)

        upsert_enrichment_snapshots(
            db,
            "r1",
            [
                {"cve_id": "CVE-2024-5001", "cvss_score": 7.0, "epss_score": 0.05, "in_kev": False},
                {"cve_id": "CVE-2024-5002", "cvss_score": 7.0, "epss_score": 0.05, "epss_percentile": 0.60, "in_kev": False},
                {"cve_id": "CVE-2024-5004", "cvss_score": 7.0, "epss_score": 0.05, "in_kev": False},
                {"cve_id": "CVE-2024-5005", "cvss_score": 8.0, "epss_score": 0.05, "in_kev": False},
            ],
        )
        upsert_enrichment_snapshots(
            db,
            "r2",
            [
                {"cve_id": "CVE-2024-5001", "cvss_score": 7.0, "epss_score": 0.05, "in_kev": True},
                {"cve_id": "CVE-2024-5002", "cvss_score": 7.0, "epss_score": 0.35, "epss_percentile": 0.92, "in_kev": False},
                {"cve_id": "CVE-2024-5004", "cvss_score": 7.0, "epss_score": 0.05, "in_kev": False},
                {"cve_id": "CVE-2024-5005", "cvss_score": 8.5, "epss_score": 0.15, "in_kev": False},
            ],
        )

        # Also verify DB-seeded deferred_invalidated / accepted_invalidated without DecisionsRegistry
        r2_fids = {
            row[0]: row[1]
            for row in db.execute(
                "SELECT title, finding_id FROM findings WHERE run_id = 'r2'"
            ).fetchall()
        }
        upsert_triage_decisions(
            db,
            "r1",
            [
                {"finding_id": fid, "asset_id": "aid_srv", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "decision_status": "deferred_valid"}
                for fid in r2_fids.values()
            ],
        )
        upsert_triage_decisions(
            db,
            "r2",
            [
                {"finding_id": r2_fids["KEV Predicate"], "asset_id": "aid_srv", "priority_tier": "P1", "sla_bucket": "3-day + Forensic Triage", "decision_status": "deferred_valid"},
                {"finding_id": r2_fids["EPSS Predicate"], "asset_id": "aid_srv", "priority_tier": "P1", "sla_bucket": "14-day", "decision_status": "accepted_valid"},
                {"finding_id": r2_fids["Exposure Non-CVE Predicate"], "asset_id": "aid_srv", "priority_tier": "P2", "sla_bucket": "60-day", "decision_status": "deferred_valid"},
                {"finding_id": r2_fids["Expiry Predicate"], "asset_id": "aid_srv", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "decision_status": "deferred_valid"},
                {"finding_id": r2_fids["Valid Deferral"], "asset_id": "aid_srv", "priority_tier": "P1", "sla_bucket": "14-day", "decision_status": "deferred_valid"},
            ],
        )

        registry = DecisionsRegistry.from_file(decisions_yaml)
        engine = DiffEngine(db, decisions_registry=registry, now_utc="2026-02-01T00:00:00Z")
        report = engine.compare("r1", "r2")

        by_title = {x.title: x for x in report.invalidated_assumptions}
        assert "Valid Deferral" not in by_title
        assert "kev_flipped" in by_title["KEV Predicate"].violated_predicates
        assert {"epss_exceeded", "epss_percentile_exceeded"}.issubset(
            set(by_title["EPSS Predicate"].violated_predicates)
        )
        assert "exposure_flipped" in by_title["Exposure Non-CVE Predicate"].violated_predicates
        assert "expired" in by_title["Expiry Predicate"].violated_predicates

        # Check evaluate_fail_gate when only valid deferral exists vs invalidated
        assert evaluate_fail_gate(report, "stale-assumption") == 2
        assert evaluate_fail_gate(report, "kev") == 2
        assert evaluate_fail_gate(report, "p1") == 2
        assert evaluate_fail_gate(report, "p2") == 2
        assert evaluate_fail_gate(report, "none") == 0
        assert evaluate_fail_gate(report, None) == 0


def test_evaluate_fail_gate_exit_codes_and_fail_closed_validation(tmp_path: Path) -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "host", "asset_id": "aid_1", "aliases": ["10.1.1.1"], "internet_facing": True}],
        }
    )

    with VppDatabase(tmp_path / "gate.vpp.db") as db:
        ensure_run(db, "b", created_at_utc="2026-01-01T00:00:00Z")
        ensure_run(db, "t", created_at_utc="2026-02-01T00:00:00Z")

        # Scenario 1: Only validly deferred P1 KEV introduced + active P3 -> all gates 0
        recs_deferred_only = [
            _rec(ip="10.1.1.1", hostname="h1", cves=["CVE-2025-0001"], scanner_sig="s:1", title="Deferred P1 KEV"),
            _rec(ip="10.1.1.1", hostname="h1", cves=["CVE-2025-0002"], scanner_sig="s:2", title="Active P3"),
        ]
        ingest_normalized_batches(db, "t", [recs_deferred_only], asset_matcher=matcher)
        fids = {
            r[0]: r[1]
            for r in db.execute("SELECT title, finding_id FROM findings WHERE run_id = 't'").fetchall()
        }
        upsert_enrichment_snapshots(
            db,
            "t",
            [
                {"cve_id": "CVE-2025-0001", "cvss_score": 9.8, "epss_score": 0.9, "in_kev": True},
                {"cve_id": "CVE-2025-0002", "cvss_score": 4.0, "epss_score": 0.01, "in_kev": False},
            ],
        )
        upsert_triage_decisions(
            db,
            "t",
            [
                {"finding_id": fids["Deferred P1 KEV"], "asset_id": "aid_1", "priority_tier": "P1", "sla_bucket": "3-day + Forensic Triage", "decision_status": "deferred_valid"},
                {"finding_id": fids["Active P3"], "asset_id": "aid_1", "priority_tier": "P3", "sla_bucket": "Fix on Upgrade", "decision_status": "active"},
            ],
        )

        report_clean = DiffEngine(db).compare("b", "t")
        for flag in (None, "none", "p1", "p2", "kev", "stale-assumption"):
            assert evaluate_fail_gate(report_clean, flag) == 0

        # Scenario 2: Active P2 only -> p1=0, kev=0, stale-assumption=0, p2=2
        ensure_run(db, "t2", created_at_utc="2026-03-01T00:00:00Z")
        ingest_normalized_batches(
            db,
            "t2",
            [[_rec(ip="10.1.1.1", hostname="h1", cves=["CVE-2025-0003"], scanner_sig="s:3", title="Active P2")]],
            asset_matcher=matcher,
        )
        fid_p2 = db.execute("SELECT finding_id FROM findings WHERE run_id = 't2'").fetchone()[0]
        upsert_enrichment_snapshots(
            db, "t2", [{"cve_id": "CVE-2025-0003", "cvss_score": 7.5, "epss_score": 0.05, "in_kev": False}]
        )
        upsert_triage_decisions(
            db,
            "t2",
            [{"finding_id": fid_p2, "asset_id": "aid_1", "priority_tier": "P2", "sla_bucket": "60-day", "decision_status": "active"}],
        )
        report_p2 = DiffEngine(db).compare("b", "t2")
        assert evaluate_fail_gate(report_p2, "p1") == 0
        assert evaluate_fail_gate(report_p2, "kev") == 0
        assert evaluate_fail_gate(report_p2, "stale-assumption") == 0
        assert evaluate_fail_gate(report_p2, "p2") == 2

        # Scenario 3: DB-only accepted_invalidated without DecisionsRegistry triggers stale-assumption
        ensure_run(db, "t3", created_at_utc="2026-04-01T00:00:00Z")
        ingest_normalized_batches(
            db,
            "t3",
            [[_rec(ip="10.1.1.1", hostname="h1", cves=["CVE-2025-0004"], scanner_sig="s:4", title="DB Invalidated")]],
            asset_matcher=matcher,
        )
        fid_inv = db.execute("SELECT finding_id FROM findings WHERE run_id = 't3'").fetchone()[0]
        upsert_enrichment_snapshots(
            db, "t3", [{"cve_id": "CVE-2025-0004", "cvss_score": 7.5, "epss_score": 0.25, "in_kev": False}]
        )
        upsert_triage_decisions(
            db,
            "t3",
            [
                {
                    "finding_id": fid_inv,
                    "asset_id": "aid_1",
                    "priority_tier": "P2",
                    "sla_bucket": "60-day",
                    "decision_status": "accepted_invalidated",
                    "decision_id": "dec-db-only",
                    "assumed_state": {"max_epss": 0.05},
                }
            ],
        )
        report_inv = DiffEngine(db).compare("b", "t3")
        assert evaluate_fail_gate(report_inv, "stale-assumption") == 2
        assert report_inv.invalidated_assumptions[0].violated_predicates == ["epss_exceeded"]

        # Fail closed on unknown fail_on values
        for bad_flag in ("critical", "p3", "", "invalid-flag"):
            with pytest.raises(ValueError, match="Unknown fail_on mode"):
                evaluate_fail_gate(report_inv, bad_flag)


def test_read_only_db_metadata_fallback_and_60day_implicit_drift(tmp_path: Path) -> None:
    db_path = tmp_path / "ro.vpp.db"
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "h1", "asset_id": "aid_ro", "aliases": ["10.2.2.2"], "internet_facing": False}],
        }
    )

    with VppDatabase(db_path) as db:
        ensure_run(db, "r_base", created_at_utc="2026-01-01T00:00:00Z", profile="bod-26-04")
        ensure_run(db, "r_targ", created_at_utc="2026-02-01T00:00:00Z", profile="bod-26-04")
        rec = _rec(ip="10.2.2.2", hostname="ro-host", cves=["CVE-2024-7777"], scanner_sig="s:77", title="60-day to 14-day")
        ingest_normalized_batches(db, "r_base", [[rec]], asset_matcher=matcher)
        ingest_normalized_batches(db, "r_targ", [[rec]], asset_matcher=matcher)

        fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'r_base'").fetchone()[0]
        upsert_enrichment_snapshots(
            db,
            "r_base",
            [
                {
                    "cve_id": "CVE-2024-7777",
                    "cvss_score": 7.0,
                    "epss_score": 0.05,
                    "epss_model_version": "v2025.01",
                    "epss_date": "2026-01-01",
                    "in_kev": False,
                }
            ],
        )
        upsert_enrichment_snapshots(
            db,
            "r_targ",
            [
                {
                    "cve_id": "CVE-2024-7777",
                    "cvss_score": 7.0,
                    "epss_score": 0.25,
                    "epss_model_version": "v2026.02",
                    "epss_date": "2026-02-01",
                    "in_kev": True,
                }
            ],
        )
        upsert_triage_decisions(
            db,
            "r_base",
            [{"finding_id": fid, "asset_id": "aid_ro", "priority_tier": "P2", "sla_bucket": "60-day", "ssvc_action": "Attend", "decision_status": "active"}],
        )
        upsert_triage_decisions(
            db,
            "r_targ",
            [{"finding_id": fid, "asset_id": "aid_ro", "priority_tier": "P1", "sla_bucket": "14-day", "ssvc_action": "Act", "decision_status": "active"}],
        )

    # Query with read_only=True VppDatabase
    with VppDatabase(db_path, read_only=True) as ro_db:
        report = DiffEngine(ro_db).compare()
        assert len(report.invalidated_assumptions) == 1
        assert report.invalidated_assumptions[0].invalidation_kind == "implicit"
        assert {"kev_flipped", "epss_increased"}.issubset(set(report.invalidated_assumptions[0].violated_predicates))
        assert report.metadata_delta.intel_changed is True
        assert report.metadata_delta.intel_changes["epss_model_version"] == {
            "base": "v2025.01",
            "target": "v2026.02",
        }
        assert evaluate_fail_gate(report, "p1") == 2
        assert evaluate_fail_gate(report, "kev") == 2
        assert evaluate_fail_gate(report, "stale-assumption") == 2


def test_cross_db_deterministic_persistence_and_kev_only_gate(tmp_path: Path) -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "h1", "asset_id": "aid_det", "aliases": ["10.9.9.9"], "internet_facing": False}],
        }
    )

    def _build_and_persist(db_file: Path):
        with VppDatabase(db_file) as db:
            ensure_run(db, "run-a", created_at_utc="2026-01-01T00:00:00Z")
            ensure_run(db, "run-b", created_at_utc="2026-02-01T00:00:00Z")
            rec = _rec(ip="10.9.9.9", hostname="det-host", cves=["CVE-2024-8888"], scanner_sig="s:88", title="KEV Only Flip")
            ingest_normalized_batches(db, "run-a", [[rec]], asset_matcher=matcher)
            ingest_normalized_batches(db, "run-b", [[rec]], asset_matcher=matcher)
            fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'run-a'").fetchone()[0]
            upsert_enrichment_snapshots(db, "run-a", [{"cve_id": "CVE-2024-8888", "cvss_score": 7.0, "epss_score": 0.02, "in_kev": False}])
            upsert_enrichment_snapshots(db, "run-b", [{"cve_id": "CVE-2024-8888", "cvss_score": 7.0, "epss_score": 0.02, "in_kev": True}])
            # Stay at P2 in both runs so p1/p2 tier escalation is NOT triggered, ONLY kev gate
            upsert_triage_decisions(db, "run-a", [{"finding_id": fid, "asset_id": "aid_det", "priority_tier": "P2", "sla_bucket": "60-day", "decision_status": "active"}])
            upsert_triage_decisions(db, "run-b", [{"finding_id": fid, "asset_id": "aid_det", "priority_tier": "P2", "sla_bucket": "60-day", "decision_status": "active"}])

            rep = DiffEngine(db).compare("run-a", "run-b", persist=True)
            assert evaluate_fail_gate(rep, "p1") == 0
            assert evaluate_fail_gate(rep, "p2") == 0
            assert evaluate_fail_gate(rep, "stale-assumption") == 0
            assert evaluate_fail_gate(rep, "kev") == 2
            rows = db.execute(
                "SELECT diff_id, base_run_id, target_run_id, category, finding_id, asset_id, cve_id, details_json "
                "FROM diff_events ORDER BY category, asset_id, finding_id"
            ).fetchall()
            return rep.diff_id, rows

    id1, rows1 = _build_and_persist(tmp_path / "det1.vpp.db")
    id2, rows2 = _build_and_persist(tmp_path / "det2.vpp.db")
    assert id1 == id2
    assert rows1 == rows2

