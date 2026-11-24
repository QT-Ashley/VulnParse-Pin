# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import pytest

from vulnparse_pin.core.assets_context import DecisionsRegistry
from vulnparse_pin.core.classes.dataclass import AppPaths, RunContext, Services
from vulnparse_pin.core.passes import run_v2_duckdb_pipeline
from vulnparse_pin.core.passes.ACI.aci_pass import ACIV2Pass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringV3Pass
from vulnparse_pin.core.passes.Triage.triage_pass import TriageDecisionPass
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.utils.logger import LoggerWrapper


def _make_ctx(
    tmp_path: Path,
    db: VppDatabase,
    run_id: str,
    *,
    profile: Optional[str] = "bod-26-04",
    registry: Optional[DecisionsRegistry] = None,
) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "bod.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    svc = Services(db=db, run_id=run_id, decisions_registry=registry)
    ctx = RunContext(
        paths=AppPaths.resolve(portable=True),
        pfh=pfh,
        logger=logger,
        services=svc,
        db=db,
        run_id=run_id,
        decisions_registry=registry,
    )
    if profile is not None:
        object.__setattr__(ctx, "profile", profile)
    return ctx


def test_bod_26_04_all_ssvc_buckets_and_leaves(tmp_path: Path) -> None:
    db = VppDatabase(":memory:")
    run_id = "run-bod"
    db.execute(
        "INSERT INTO runs (run_id, created_at_utc, vpp_version, profile) VALUES (?, ?, ?, ?)",
        [run_id, "2026-11-24T00:00:00Z", "2.0.0", "bod-26-04"],
    )
    db.execute(
        "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, ip_address, internet_facing, declared_criticality, inventory_status) VALUES "
        "(?, 'a-pub', 'host:pub', 'edge.example.com', '203.0.113.20', TRUE, 'critical', 'matched'), "
        "(?, 'a-int', 'host:int', 'db.internal', '10.10.1.5', FALSE, 'high', 'matched')",
        [run_id, run_id],
    )

    findings = [
        # 1) 3-day + Forensic Triage: exposed + active (KEV)
        ("f-3day-kev", "a-pub", "cve_threat", "CVE-2024-9001", "[]", "Public KEV", "KEV", "Critical", 9.0, None, "credentialed_host", "[]"),
        # 2) 3-day + Forensic Triage via Track B: exposed + active_dast (rel>=0.90) + default-login/rce
        ("f-3day-dast", "a-pub", "exposure_weakness", None, "[]", "Default Login Panel RCE", "Default credentials on admin panel", "Critical", 9.0, None, "active_dast", '["default-login","rce"]'),
        # 3) 14-day: internal KEV (active, not exposed)
        ("f-14day-kev-int", "a-int", "cve_threat", "CVE-2024-9001", "[]", "Internal KEV", "KEV internal", "Critical", 9.0, None, "credentialed_host", "[]"),
        # 4) 14-day: exposed + automatable + total technical impact (CVSS AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
        ("f-14day-auto-total", "a-pub", "cve_threat", "CVE-2024-9002", "[]", "Exposed Auto Total", "Unauth RCE", "Critical", None, None, "credentialed_host", "[]"),
        # 5) 14-day: exposed + epss_percentile >= 0.95 (even partial impact, non-automatable)
        ("f-14day-epss95", "a-pub", "cve_threat", "CVE-2024-9003", "[]", "Exposed High EPSS Pct", "EPSS >= 95th", "Medium", None, None, "credentialed_host", "[]"),
        # 6) 14-day: exposed Track B reliable (>=0.85) + total impact (without active default-login/rce -> e.g. uncredentialed_banner 0.85 + sqli)
        ("f-14day-trackb", "a-pub", "exposure_weakness", None, '["CWE-89"]', "Exposed SQLi Banner", "SQL injection flaw", "High", 8.0, None, "uncredentialed_banner", '["sqli"]'),
        # 7) 60-day: internal epss >= 0.04 (or 90th pct)
        ("f-60day-epss", "a-int", "cve_threat", "CVE-2024-9004", "[]", "Internal EPSS 5%", "EPSS 0.05", "Medium", None, None, "credentialed_host", "[]"),
        # 8) 60-day: static_sast + technical_impact == total (internal)
        ("f-60day-sast-total", "a-int", "cve_threat", "CVE-2024-9002", "[]", "SAST Total Impact", "Total impact SAST", "High", None, None, "static_sast", "[]"),
        # 9) Fix on Upgrade: internal low risk partial
        ("f-fix-upgrade", "a-int", "cve_threat", "CVE-2024-9005", "[]", "Low Internal Local Bug", "Minor local issue", "Low", None, None, "credentialed_host", "[]"),
    ]
    for fid, aid, track, cve, cwes_j, title, desc, sev, cvss, vec, mode, tags_j in findings:
        cves_j = json.dumps([cve]) if cve else "[]"
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, primary_cve, cves_json, cwes_json, title, description, scanner_severity, scanner_cvss_score, scanner_cvss_vector, detection_mode, tags_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [run_id, fid, aid, track, cve, cves_j, cwes_j, title, desc, sev, cvss, vec, mode, tags_j],
        )
        if cve:
            db.execute("INSERT INTO finding_cves VALUES (?, ?, ?)", [run_id, fid, cve])

    db.execute(
        """
        INSERT INTO enrichment_snapshots (
            run_id, cve_id, cvss_score, cvss_vector, cvss_version, cvss_provenance,
            epss_score, epss_percentile, in_kev, verified_exploit
        ) VALUES
            (?, 'CVE-2024-9001', 8.5, 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N', '3.1', 'NVD', 0.02, 0.70, TRUE, TRUE),
            (?, 'CVE-2024-9002', 9.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', '3.1', 'NVD', 0.01, 0.40, FALSE, FALSE),
            (?, 'CVE-2024-9003', 5.5, 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', '3.1', 'NVD', 0.05, 0.96, FALSE, FALSE),
            (?, 'CVE-2024-9004', 5.5, 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', '3.1', 'NVD', 0.05, 0.85, FALSE, FALSE),
            (?, 'CVE-2024-9005', 3.1, 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', '3.1', 'NVD', 0.002, 0.20, FALSE, FALSE)
        """,
        [run_id, run_id, run_id, run_id, run_id],
    )

    ctx = _make_ctx(tmp_path, db=db, run_id=run_id, profile="bod-26-04")
    derived = run_v2_duckdb_pipeline(ctx, profile="bod-26-04")

    td = {
        r[0]: {
            "priority_tier": r[1],
            "oal_compat": r[2],
            "ssvc_action": r[3],
            "sla_bucket": r[4],
            "sla_days": r[5],
            "decision_status": r[6],
            "assumed_state": json.loads(r[7]),
        }
        for r in db.execute(
            "SELECT finding_id, priority_tier, oal_compat, ssvc_action, sla_bucket, sla_days, decision_status, assumed_state_json "
            "FROM triage_decisions WHERE run_id = ?",
            [run_id],
        ).fetchall()
    }

    assert (td["f-3day-kev"]["sla_bucket"], td["f-3day-kev"]["sla_days"], td["f-3day-kev"]["ssvc_action"], td["f-3day-kev"]["priority_tier"]) == ("3-day + Forensic Triage", 3, "Act", "P1")
    assert "exposed=True|exp=active|" in td["f-3day-kev"]["assumed_state"]["ssvc_path"]

    assert (td["f-3day-dast"]["sla_bucket"], td["f-3day-dast"]["sla_days"], td["f-3day-dast"]["ssvc_action"]) == ("3-day + Forensic Triage", 3, "Act")
    assert (td["f-14day-kev-int"]["sla_bucket"], td["f-14day-kev-int"]["sla_days"], td["f-14day-kev-int"]["ssvc_action"], td["f-14day-kev-int"]["priority_tier"]) == ("14-day", 14, "Act", "P1")
    assert (td["f-14day-auto-total"]["sla_bucket"], td["f-14day-auto-total"]["sla_days"], td["f-14day-auto-total"]["ssvc_action"]) == ("14-day", 14, "Act")
    assert (td["f-14day-epss95"]["sla_bucket"], td["f-14day-epss95"]["sla_days"]) == ("14-day", 14)
    assert (td["f-14day-trackb"]["sla_bucket"], td["f-14day-trackb"]["sla_days"]) == ("14-day", 14)

    assert (td["f-60day-epss"]["sla_bucket"], td["f-60day-epss"]["sla_days"], td["f-60day-epss"]["ssvc_action"], td["f-60day-epss"]["priority_tier"]) == ("60-day", 60, "Attend", "P2")
    assert (td["f-60day-sast-total"]["sla_bucket"], td["f-60day-sast-total"]["sla_days"]) == ("60-day", 60)

    assert (td["f-fix-upgrade"]["sla_bucket"], td["f-fix-upgrade"]["sla_days"], td["f-fix-upgrade"]["ssvc_action"], td["f-fix-upgrade"]["priority_tier"]) == ("Fix on Upgrade", None, "Track", "P4")
    assert all(v["decision_status"] == "active" for v in td.values())
    assert derived["Summary@2.0"].data["decision_trace_summary"]["ssvc_action_counts"]["Act"] == 6
    db.close()


def test_decisions_registry_reconciliation_statuses(tmp_path: Path) -> None:
    db = VppDatabase(":memory:")
    run_id = "run-dec"
    db.execute(
        "INSERT INTO runs (run_id, created_at_utc, vpp_version, profile) VALUES (?, ?, ?, ?)",
        [run_id, "2026-11-24T00:00:00Z", "2.0.0", "bod-26-04"],
    )
    db.execute(
        "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, ip_address, internet_facing, inventory_status) VALUES "
        "(?, 'a1', 'host:a1', 'app1.internal', '10.0.0.10', FALSE, 'matched')",
        [run_id],
    )
    cases = [
        ("f-active", "CVE-2024-7001"),
        ("f-def-valid", "CVE-2024-7002"),
        ("f-def-inv-kev", "CVE-2024-7003"),
        ("f-acc-valid", "CVE-2024-7004"),
        ("f-acc-inv-exp", "CVE-2024-7005"),
        ("f-mitigated", "CVE-2024-7006"),
    ]
    for fid, cve in cases:
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, primary_cve, cves_json, title, detection_mode) "
            "VALUES (?, ?, 'a1', 'cve_threat', ?, ?, 'Test finding', 'credentialed_host')",
            [run_id, fid, cve, json.dumps([cve])],
        )
        db.execute("INSERT INTO finding_cves VALUES (?, ?, ?)", [run_id, fid, cve])

    db.execute(
        """
        INSERT INTO enrichment_snapshots (run_id, cve_id, cvss_score, cvss_provenance, epss_score, epss_percentile, in_kev) VALUES
            (?, 'CVE-2024-7001', 5.0, 'NVD', 0.01, 0.40, FALSE),
            (?, 'CVE-2024-7002', 5.0, 'NVD', 0.02, 0.50, FALSE),
            (?, 'CVE-2024-7003', 5.0, 'NVD', 0.02, 0.50, TRUE),
            (?, 'CVE-2024-7004', 6.0, 'NVD', 0.02, 0.50, FALSE),
            (?, 'CVE-2024-7005', 6.0, 'NVD', 0.02, 0.50, FALSE),
            (?, 'CVE-2024-7006', 5.0, 'NVD', 0.01, 0.40, FALSE)
        """,
        [run_id] * 6,
    )

    registry = DecisionsRegistry.from_dict(
        {
            "version": "v2",
            "decisions": [
                {
                    "id": "DEC-DEF-OK",
                    "asset_id": "a1",
                    "cve_or_rule_id": "CVE-2024-7002",
                    "status": "deferred",
                    "rationale": "Patch scheduled",
                    "expires_at": "2027-01-01",
                    "assumptions": {"in_kev": False, "max_epss": 0.05},
                },
                {
                    "id": "DEC-DEF-KEV-FLIP",
                    "asset_id": "a1",
                    "cve_or_rule_id": "CVE-2024-7003",
                    "status": "deferred",
                    "rationale": "Assumed non-KEV",
                    "assumptions": {"in_kev": False},
                },
                {
                    "id": "DEC-ACC-OK",
                    "asset_id": "a1",
                    "cve_or_rule_id": "CVE-2024-7004",
                    "status": "accepted",
                    "rationale": "Low compensating controls",
                    "expires_at": "2027-01-01",
                    "assumptions": {"max_cvss": 7.0},
                },
                {
                    "id": "DEC-ACC-EXPIRED",
                    "asset_id": "a1",
                    "cve_or_rule_id": "CVE-2024-7005",
                    "status": "accepted",
                    "rationale": "Old acceptance",
                    "expires_at": "2025-01-01",
                },
                {
                    "id": "DEC-MITIGATED",
                    "asset_id": "a1",
                    "cve_or_rule_id": "CVE-2024-7006",
                    "status": "mitigated",
                    "rationale": "Mitigated via WAF rule",
                },
            ],
        }
    )

    ctx = _make_ctx(tmp_path, db=db, run_id=run_id, profile="bod-26-04", registry=registry)
    run_v2_duckdb_pipeline(
        ctx,
        profile="bod-26-04",
        decisions_registry=registry,
        now_utc="2026-11-24T00:00:00Z",
    )

    rows = {
        r[0]: (r[1], r[2], json.loads(r[3]))
        for r in db.execute(
            "SELECT finding_id, decision_status, decision_id, assumed_state_json "
            "FROM triage_decisions WHERE run_id = ?",
            [run_id],
        ).fetchall()
    }
    assert rows["f-active"][0] == "active"
    assert rows["f-def-valid"][0] == "deferred_valid"
    assert rows["f-def-inv-kev"][0] == "deferred_invalidated"
    assert "kev_flipped" in rows["f-def-inv-kev"][2]["violated_predicates"]
    assert rows["f-acc-valid"][0] == "accepted_valid"
    assert rows["f-acc-inv-exp"][0] == "accepted_invalidated"
    assert "expired" in rows["f-acc-inv-exp"][2]["violated_predicates"]
    assert rows["f-mitigated"][0] == "mitigated"
    db.close()
