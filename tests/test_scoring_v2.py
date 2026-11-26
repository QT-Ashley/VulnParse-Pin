# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

from vulnparse_pin.core.classes.dataclass import AppPaths, Asset, Finding, RunContext, ScanMetaData, ScanResult, Services
from vulnparse_pin.core.config_projector import ConfigProjector
from vulnparse_pin.core.passes import run_v2_duckdb_pipeline
from vulnparse_pin.core.passes.ACI.aci_pass import ACIV2Pass
from vulnparse_pin.core.passes.Nmap.nmap_adapter_pass import NmapAdapterPass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringV3Pass, _epss_v5_points, _ordinal, _resolve_best_cvss
from vulnparse_pin.core.passes.Summary.summary_pass import SummaryV2Pass
from vulnparse_pin.core.passes.TopN.topn_pass import TopNV2Pass
from vulnparse_pin.core.passes.Triage.triage_pass import TriageDecisionPass
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.utils.logger import LoggerWrapper


def _make_ctx(tmp_path: Path, db: Optional[VppDatabase] = None, run_id: Optional[str] = None, profile: Optional[str] = None) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "test.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    svc = Services(db=db, run_id=run_id)
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger, services=svc, db=db, run_id=run_id)
    if profile is not None:
        object.__setattr__(ctx, "profile", profile)
    return ctx


def _seed_basic_run(db: VppDatabase, run_id: str = "run-v2-test", profile: str = "default") -> None:
    db.execute(
        "INSERT INTO runs (run_id, created_at_utc, vpp_version, profile) VALUES (?, ?, ?, ?)",
        [run_id, "2026-11-24T00:00:00Z", "2.0.0", profile],
    )


def test_epss_v5_strict_monotonicity_dense_grid_and_edges() -> None:
    bps = ((0.0, 0.0), (0.04, 1.8), (0.10, 3.0), (0.50, 4.2), (1.0, 5.0))
    assert _epss_v5_points(0.0, None, bps) == pytest.approx(0.0)
    assert _epss_v5_points(0.04, None, bps) == pytest.approx(1.8)
    assert _epss_v5_points(0.10, None, bps) == pytest.approx(3.0)
    assert _epss_v5_points(0.50, None, bps) == pytest.approx(4.2)
    assert _epss_v5_points(1.0, None, bps) == pytest.approx(5.0)

    # Edge cases clamp safely
    assert _epss_v5_points(None, None, bps) == pytest.approx(0.0)
    assert _epss_v5_points(float("nan"), None, bps) == pytest.approx(0.0)
    assert _epss_v5_points(-0.25, None, bps) == pytest.approx(0.0)
    assert _epss_v5_points(float("-inf"), None, bps) == pytest.approx(0.0)
    assert _epss_v5_points(1.5, None, bps) == pytest.approx(5.0)
    assert _epss_v5_points(float("inf"), None, bps) == pytest.approx(5.0)

    # Dense grid 0.0 -> 1.0 step 0.001 strictly non-decreasing
    grid = [i / 1000.0 for i in range(1001)]
    vals = [_epss_v5_points(p, None, bps) for p in grid]
    for prev, nxt in zip(vals, vals[1:]):
        assert prev <= nxt

    assert _ordinal(1) == "1st"
    assert _ordinal(2) == "2nd"
    assert _ordinal(3) == "3rd"
    assert _ordinal(4) == "4th"
    assert _ordinal(11) == "11th"
    assert _ordinal(12) == "12th"
    assert _ordinal(13) == "13th"
    assert _ordinal(21) == "21st"
    assert _ordinal(92) == "92nd"


def test_authoritative_cvss_precedence() -> None:
    # Lower NVD score STILL overrides higher Scanner-Supplied score
    sc, ver, prov = _resolve_best_cvss(6.5, "3.1", "NVD", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert prov == "NVD"
    assert sc == pytest.approx(6.5)
    assert ver == "3.1"

    assert _resolve_best_cvss(7.2, "3.1", "CNA", 9.8)[2] == "CNA"
    assert _resolve_best_cvss(7.1, "3.1", "GHSA", 9.8)[2] == "GHSA"
    assert _resolve_best_cvss(7.0, "3.1", "OSV", 9.8)[2] == "OSV"
    sc_s, ver_s, prov_s = _resolve_best_cvss(
        None, None, "Missing", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert (sc_s, ver_s, prov_s) == (8.8, "3.1", "Scanner-Supplied")
    assert _resolve_best_cvss(None, None, "Missing", None) == (0.0, None, "Missing")


def test_track_a_kev_exploit_non_double_count_and_trace_fields(tmp_path: Path) -> None:
    db = VppDatabase(":memory:")
    run_id = "run-track-a"
    _seed_basic_run(db, run_id)

    db.execute(
        "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, ip_address, declared_criticality, internet_facing, inventory_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [run_id, "asset-ext", "host:web-01", "web-01", "203.0.113.10", "high", True, "matched"],
    )

    findings = [
        # f_kev_exp: KEV + Verified Exploit -> 4.5 + 0.5 (NOT 4.5 + 2.0)
        (run_id, "f_kev_exp", "asset-ext", "cve_threat", "CVE-2024-1001", '["CVE-2024-1001"]', "[]", "High", 9.8, "credentialed_host", False),
        # f_exp_only: Verified Exploit without KEV -> +2.0
        (run_id, "f_exp_only", "asset-ext", "cve_threat", "CVE-2024-1002", '["CVE-2024-1002"]', "[]", "High", 8.0, "credentialed_host", False),
        # f_heur: Heuristic mention only -> 0.0 exploit points, boolean preserved
        (run_id, "f_heur", "asset-ext", "cve_threat", "CVE-2024-1003", '["CVE-2024-1003"]', "[]", "High", 8.0, "credentialed_host", True),
        # f_multi: Multi-CVE stacked decay
        (run_id, "f_multi", "asset-ext", "cve_threat", "CVE-2024-1002", '["CVE-2024-1002","CVE-2024-1003"]', "[]", "High", None, "sca_container", False),
    ]
    for row in findings:
        fid = row[1]
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, primary_cve, cves_json, cwes_json, title, scanner_severity, scanner_cvss_score, detection_mode, exploit_evidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [row[0], fid, row[2], row[3], row[4], row[5], row[6], f"Title {fid}", row[7], row[8], row[9], row[10]],
        )
    db.execute("INSERT INTO finding_cves VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?), (?, ?, ?), (?, ?, ?)", [
        run_id, "f_kev_exp", "CVE-2024-1001",
        run_id, "f_exp_only", "CVE-2024-1002",
        run_id, "f_heur", "CVE-2024-1003",
        run_id, "f_multi", "CVE-2024-1002",
        run_id, "f_multi", "CVE-2024-1003",
    ])

    db.execute(
        """
        INSERT INTO enrichment_snapshots (
            run_id, cve_id, cvss_score, cvss_vector, cvss_version, cvss_provenance,
            epss_score, epss_percentile, epss_model_version, epss_date,
            in_kev, kev_date_added, kev_due_date, kev_ransomware,
            verified_exploit, heuristic_exploit_mention
        ) VALUES
            (?, 'CVE-2024-1001', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', '3.1', 'NVD',
             0.153, 0.92, 'v2025.03.14', '2026-11-20', TRUE, '2024-02-01', '2024-02-22', 'Known', TRUE, TRUE),
            (?, 'CVE-2024-1002', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', '3.1', 'CNA',
             0.10, 0.88, 'v2025.03.14', '2026-11-20', FALSE, NULL, NULL, NULL, TRUE, FALSE),
            (?, 'CVE-2024-1003', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', '3.1', 'GHSA',
             0.10, 0.88, 'v2025.03.14', '2026-11-20', FALSE, NULL, NULL, NULL, FALSE, TRUE)
        """,
        [run_id, run_id, run_id],
    )

    ctx = _make_ctx(tmp_path, db=db, run_id=run_id)
    ACIV2Pass().run(ctx)
    ScoringV3Pass().run(ctx)

    rows = {
        r[0]: (r[1], r[2], r[3], r[4], json.loads(r[5]))
        for r in db.execute(
            "SELECT finding_id, scoring_track, raw_risk_score, operational_score, risk_band, score_trace_json "
            "FROM scores WHERE run_id = ?",
            [run_id],
        ).fetchall()
    }

    # f_kev_exp: CVSS=7.5 (NVD overrides 9.8 scanner), EPSS(0.153), KEV=4.5, ExpWithKEV=0.5, Ext=1.25, High=0.5
    _, raw_ke, op_ke, _, tr_ke = rows["f_kev_exp"]
    assert tr_ke["cvss_provenance"] == "NVD"
    assert tr_ke["cvss_score"] == pytest.approx(7.5)
    assert tr_ke["epss_display"] == "15.3% / 92nd"
    assert tr_ke["in_kev"] is True
    assert tr_ke["verified_exploit"] is True
    assert tr_ke["breakdown"]["kev_points"] == pytest.approx(4.5)
    assert tr_ke["breakdown"]["verified_exploit_points"] == pytest.approx(0.5)
    expected_epss_153 = _epss_v5_points(0.153)
    expected_ke_pre = 7.5 + expected_epss_153 + 4.5 + 0.5 + 1.25 + 0.5
    assert tr_ke["breakdown"]["pre_clamp_raw_score"] == pytest.approx(expected_ke_pre, abs=1e-3)
    assert raw_ke == pytest.approx(min(16.0, expected_ke_pre), abs=1e-3)
    assert op_ke == pytest.approx(round(raw_ke / 16.0 * 10.0, 4), abs=1e-4)

    # Required rich trace keys present
    for key in (
        "scoring_track", "cvss_score", "cvss_version", "cvss_provenance",
        "epss_score", "epss_percentile", "epss_display", "epss_model_version",
        "epss_date", "in_kev", "kev_date_added", "kev_due_date",
        "kev_ransomware", "verified_exploit", "heuristic_exploit_mention",
        "aci_capabilities", "aci_chains", "detection_mode",
        "signal_reliability", "asset_inventory_status", "internet_facing",
        "declared_criticality", "breakdown",
    ):
        assert key in tr_ke

    # f_exp_only vs f_heur difference is exactly 2.0 verified_exploit_points
    _, raw_eo, _, _, tr_eo = rows["f_exp_only"]
    _, raw_hu, _, _, tr_hu = rows["f_heur"]
    assert tr_eo["breakdown"]["verified_exploit_points"] == pytest.approx(2.0)
    assert tr_hu["breakdown"]["verified_exploit_points"] == pytest.approx(0.0)
    assert tr_hu["breakdown"]["heuristic_exploit_points"] == pytest.approx(0.0)
    assert tr_hu["heuristic_exploit_mention"] is True
    assert (raw_eo - raw_hu) == pytest.approx(2.0, abs=1e-4)

    # f_multi stacks secondary CVE * 0.35 cleanly
    _, raw_mu, _, _, tr_mu = rows["f_multi"]
    assert tr_mu["breakdown"]["cve_count"] == 2
    assert tr_mu["breakdown"]["multi_cve_additional_points"] > 0.0
    assert raw_mu > raw_eo

    # Bulk update checks on assets & findings
    rel_map = dict(db.execute("SELECT finding_id, signal_reliability FROM findings WHERE run_id = ?", [run_id]).fetchall())
    assert rel_map["f_kev_exp"] == pytest.approx(1.0)
    assert rel_map["f_multi"] == pytest.approx(0.90)
    derived_crit = db.execute("SELECT derived_criticality FROM assets WHERE run_id = ? AND asset_id = 'asset-ext'", [run_id]).fetchone()[0]
    assert derived_crit in ("Extreme", "High")
    db.close()


def test_track_b_signal_reliability_and_sast_p1_cap_guardrail(tmp_path: Path) -> None:
    db = VppDatabase(":memory:")
    run_id = "run-track-b"
    _seed_basic_run(db, run_id, profile="default")

    db.execute(
        "INSERT INTO assets (run_id, asset_id, canonical_key, internet_facing, declared_criticality, inventory_status) VALUES "
        "(?, 'a-ext', 'host:ext', TRUE, 'critical', 'matched'), "
        "(?, 'a-int', 'host:int', FALSE, 'critical', 'matched')",
        [run_id, run_id],
    )

    # 1) active_dast (reliability 1.0) vs static_sast uncorroborated (0.55)
    # 2) static_sast uncorroborated critical -> capped at P2
    # 3) static_sast internal with CWE-89 -> capped at P2 (not internet_facing)
    # 4) static_sast external WITH CWE-89 (corroborated) + operational >= 8.5/high score -> P1 allowed
    findings = [
        ("f-dast", "a-ext", "[]", "SQL Injection Login Bypass", "Critical RCE sqli bypass", "Critical", 9.2, "active_dast", '["sqli","rce"]'),
        ("f-sast-unc", "a-ext", "[]", "High risk pattern match", "Potential issue", "Critical", 9.8, "static_sast", '[]'),
        ("f-sast-int", "a-int", '["CWE-89"]', "Internal SQL Query Issue", "Unsanitized SQL injection query", "Critical", 9.8, "static_sast", '["sqli"]'),
        ("f-sast-corr", "a-ext", '["CWE-89","CWE-78"]', "External SQLi Command Exec", "Remote command injection & SQL injection", "Critical", 9.8, "static_sast", '["sqli","rce"]'),
    ]
    for fid, aid, cwes_j, title, desc, sev, cvss, mode, tags_j in findings:
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, cwes_json, title, description, scanner_severity, scanner_cvss_score, detection_mode, tags_json) "
            "VALUES (?, ?, ?, 'exposure_weakness', ?, ?, ?, ?, ?, ?, ?)",
            [run_id, fid, aid, cwes_j, title, desc, sev, cvss, mode, tags_j],
        )

    ctx = _make_ctx(tmp_path, db=db, run_id=run_id)
    derived = run_v2_duckdb_pipeline(ctx, profile="default")

    assert "ACI@2.0" in derived
    assert "Scoring@3.0" in derived
    assert "Triage@2.0" in derived
    assert "TopN@2.0" in derived
    assert "Summary@2.0" in derived

    scores = {
        r[0]: (r[1], r[2])
        for r in db.execute(
            "SELECT finding_id, operational_score, score_trace_json FROM scores WHERE run_id = ?",
            [run_id],
        ).fetchall()
    }
    # active_dast (1.0) > static_sast (0.55)
    assert scores["f-dast"][0] > scores["f-sast-unc"][0]
    assert json.loads(scores["f-dast"][1])["signal_reliability"] == pytest.approx(1.0)
    assert json.loads(scores["f-sast-unc"][1])["signal_reliability"] == pytest.approx(0.55)

    triage = {
        r[0]: (r[1], r[2], r[3], json.loads(r[4]))
        for r in db.execute(
            "SELECT finding_id, priority_tier, oal_compat, rationale_summary, assumed_state_json "
            "FROM triage_decisions WHERE run_id = ?",
            [run_id],
        ).fetchall()
    }
    assert triage["f-dast"][0] == "P1"
    assert triage["f-dast"][1] == "OAL-1"
    # Uncorroborated static_sast capped -> never P1
    assert triage["f-sast-unc"][0] != "P1"
    # Even with critical CWE, internal static_sast (f-sast-int) cannot become P1; reliability 0.55 lowers op_score to ~5.09 -> P3
    assert triage["f-sast-int"][0] != "P1"
    assert triage["f-sast-int"][0] == "P3"
    assert derived["TopN@2.0"].data["global_top_findings"][0]["finding_id"] == "f-dast"
    assert derived["Summary@2.0"].data["overview"]["total_findings"] == 4
    db.close()


def test_sast_p1_cap_direct_high_score_behavior(tmp_path: Path) -> None:
    """Verify explicit SAST P1-cap guardrail caps uncorroborated SAST P1 candidates to P2, while allowing corroborated external CWE-89 P1."""
    db = VppDatabase(":memory:")
    run_id = "run-sast-cap"
    _seed_basic_run(db, run_id, profile="default")
    db.execute(
        "INSERT INTO assets (run_id, asset_id, canonical_key, internet_facing, declared_criticality, inventory_status) VALUES "
        "(?, 'a-ext', 'host:ext', TRUE, 'critical', 'matched'), (?, 'a-int', 'host:int', FALSE, 'critical', 'matched')",
        [run_id, run_id],
    )
    rows = [
        ("f-unc-kev", "a-ext", "CVE-2024-8001", "[]", "static_sast"),
        ("f-int-cwe", "a-int", "CVE-2024-8001", '["CWE-89"]', "static_sast"),
        ("f-ext-cwe", "a-ext", "CVE-2024-8001", '["CWE-89"]', "static_sast"),
    ]
    for fid, aid, cve, cwes_j, mode in rows:
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, primary_cve, cves_json, cwes_json, title, scanner_severity, detection_mode) "
            "VALUES (?, ?, ?, 'cve_threat', ?, ?, ?, 'SAST vuln', 'Critical', ?)",
            [run_id, fid, aid, cve, json.dumps([cve]), cwes_j, mode],
        )
        db.execute("INSERT INTO finding_cves VALUES (?, ?, ?)", [run_id, fid, cve])
    db.execute(
        "INSERT INTO enrichment_snapshots (run_id, cve_id, cvss_score, cvss_version, cvss_provenance, epss_score, epss_percentile, in_kev) "
        "VALUES (?, 'CVE-2024-8001', 9.0, '3.1', 'NVD', 0.25, 0.97, TRUE)",
        [run_id],
    )
    ctx = _make_ctx(tmp_path, db=db, run_id=run_id)
    ACIV2Pass().run(ctx)
    ScoringV3Pass().run(ctx)
    TriageDecisionPass(profile="default").run(ctx)

    tiers = {
        r[0]: (r[1], json.loads(r[2]))
        for r in db.execute(
            "SELECT finding_id, priority_tier, assumed_state_json FROM triage_decisions WHERE run_id = ?",
            [run_id],
        ).fetchall()
    }
    assert tiers["f-unc-kev"][0] == "P2"
    assert tiers["f-unc-kev"][1].get("sast_p1_capped") is True
    assert tiers["f-int-cwe"][0] == "P2"
    assert tiers["f-int-cwe"][1].get("sast_p1_capped") is True
    assert tiers["f-ext-cwe"][0] == "P1"
    assert tiers["f-ext-cwe"][1].get("sast_p1_capped") is None
    db.close()


def test_nmap_duckdb_reconciliation_and_unmatched_shadow(tmp_path: Path) -> None:
    db = VppDatabase(":memory:")
    run_id = "run-nmap"
    _seed_basic_run(db, run_id)
    db.execute(
        "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, ip_address, inventory_status, open_ports_json) "
        "VALUES (?, 'asset-known', 'host:known', 'app01.internal', '10.0.0.5', 'matched', '[22]')",
        [run_id],
    )
    nmap_xml = tmp_path / "scan.xml"
    nmap_xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="app01.internal" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="203.0.113.55" addrtype="ipv4"/>
    <hostnames><hostname name="shadow.example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    ctx = _make_ctx(tmp_path, db=db, run_id=run_id)
    res = NmapAdapterPass(nmap_source=nmap_xml).run(ctx)
    assert res.data["host_count"] == 2
    assert res.data["matched_asset_count"] == 1

    known_ports = json.loads(
        db.execute("SELECT open_ports_json FROM assets WHERE run_id = ? AND asset_id = 'asset-known'", [run_id]).fetchone()[0]
    )
    assert known_ports == [22, 80, 443]

    shadows = db.execute(
        "SELECT asset_id, ip_address, internet_facing, inventory_status, open_ports_json "
        "FROM assets WHERE run_id = ? AND inventory_status = 'unmatched_shadow'",
        [run_id],
    ).fetchall()
    assert len(shadows) == 1
    assert shadows[0][1] == "203.0.113.55"
    assert shadows[0][2] is True
    assert json.loads(shadows[0][4]) == [443]
    db.close()


def test_scoring_v3_vectorized_500k_scale_benchmark(tmp_path: Path) -> None:
    """Verify ScoringV3Pass processes 500,000 findings cleanly and fast in DuckDB."""
    db = VppDatabase(":memory:")
    run_id = "run-500k"
    _seed_basic_run(db, run_id)

    conn = db.conn
    asset_rows = [
        (run_id, f"a-{i}", f"host:{i}", i % 4 == 0, ("critical", "high", "medium", "low")[i % 4], "matched")
        for i in range(1000)
    ]
    conn.executemany(
        "INSERT INTO assets (run_id, asset_id, canonical_key, internet_facing, declared_criticality, inventory_status) VALUES (?, ?, ?, ?, ?, ?)",
        asset_rows,
    )
    conn.execute(
        """
        INSERT INTO enrichment_snapshots (
            run_id, cve_id, cvss_score, cvss_version, cvss_provenance,
            epss_score, epss_percentile, in_kev, verified_exploit
        )
        SELECT ?, 'CVE-2024-' || CAST(1000 + i AS VARCHAR),
               5.0 + (i % 5), '3.1', 'NVD',
               (i % 100) / 100.0, (i % 100) / 100.0, (i % 10 = 0), (i % 5 = 0)
        FROM range(50) t(i)
        """,
        [run_id],
    )
    conn.execute(
        """
        INSERT INTO findings (
            run_id, finding_id, asset_id, scoring_track, primary_cve,
            title, scanner_severity, scanner_cvss_score, detection_mode
        )
        SELECT
            ?,
            'f-' || CAST(i AS VARCHAR),
            'a-' || CAST(i % 1000 AS VARCHAR),
            CASE WHEN i % 5 = 0 THEN 'exposure_weakness' ELSE 'cve_threat' END,
            CASE WHEN i % 5 = 0 THEN NULL ELSE 'CVE-2024-' || CAST(1000 + (i % 50) AS VARCHAR) END,
            'Finding ' || CAST(i AS VARCHAR),
            CASE (i % 4) WHEN 0 THEN 'Critical' WHEN 1 THEN 'High' WHEN 2 THEN 'Medium' ELSE 'Low' END,
            7.5,
            CASE (i % 4) WHEN 0 THEN 'active_dast' WHEN 1 THEN 'credentialed_host' WHEN 2 THEN 'sca_container' ELSE 'static_sast' END
        FROM range(500000) t(i)
        """,
        [run_id],
    )

    ctx = _make_ctx(tmp_path, db=db, run_id=run_id)
    t0 = time.perf_counter()
    res = ScoringV3Pass().run(ctx)
    elapsed = time.perf_counter() - t0

    assert res.data["coverage"]["scored_findings"] == 500_000
    assert db.execute("SELECT COUNT(*) FROM scores WHERE run_id = ?", [run_id]).fetchone()[0] == 500_000
    assert elapsed < 4.0, f"500k scoring took {elapsed:.2f}s"
    db.close()
