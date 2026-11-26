# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from vulnparse_pin.core.assets_context import AssetContextMatcher, DecisionsRegistry
from vulnparse_pin.core.classes.dataclass import AppPaths, RunContext, Services
from vulnparse_pin.core.diff_engine import DiffEngine, evaluate_fail_gate
from vulnparse_pin.core.id import canonicalize_target_key, make_asset_id_v2
from vulnparse_pin.core.passes.ACI.aci_pass import ACIV2Pass, _normalize_cwe
from vulnparse_pin.core.passes.Nmap.nmap_adapter_pass import NmapAdapterPass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringV3Pass, _resolve_best_cvss
from vulnparse_pin.core.passes.Summary.summary_pass import SummaryV2Pass
from vulnparse_pin.core.passes.TopN import TN_triage_config
from vulnparse_pin.core.passes.Triage.triage_pass import TriageDecisionPass, _is_high_conf_sast_corroborated
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    ensure_run,
    get_finding_detail,
    get_run_summary_counts,
    get_shadow_assets,
    ingest_normalized_batches,
    query_findings_page,
    upsert_enrichment_snapshots,
    upsert_triage_decisions,
)
from vulnparse_pin.utils.logger import LoggerWrapper


def _ctx(tmp_path: Path, db: VppDatabase, run_id: str, *, registry: DecisionsRegistry | None = None, profile: str = "default") -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "iter1.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    svc = Services(db=db, run_id=run_id, decisions_registry=registry)
    ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger, services=svc, db=db, run_id=run_id, decisions_registry=registry)
    object.__setattr__(ctx, "profile", profile)
    return ctx


def _rec(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "ip_address": "10.0.0.10",
        "hostname": "app1.internal",
        "target_uri": None,
        "image_or_repo": None,
        "os": "Ubuntu 24.04",
        "asset_metadata": {"credentialed": True, "open_ports": [443]},
        "source_format": "nessus-xml",
        "scanner_sig": "nessus:100",
        "title": "Sample Finding",
        "description": "Sample description",
        "solution": "Sample solution",
        "plugin_output": "Sample output",
        "severity": "High",
        "cves": ["CVE-2024-1000"],
        "cwes": [],
        "ghsa_ids": [],
        "affected_port": 443,
        "protocol": "tcp",
        "service_name": "https",
        "location_uri": None,
        "line_number": None,
        "package_purl": None,
        "scanner_cvss_score": 7.5,
        "scanner_cvss_vector": None,
        "detection_mode": "credentialed_host",
        "fidelity_tier": "high",
        "ingestion_confidence": 0.95,
        "missing_fields": [],
        "degraded_input": False,
        "references": [],
        "tags": [],
        "exploit_evidence": False,
        "raw_evidence_excerpt": "excerpt",
    }
    base.update(overrides)
    return base


def test_diff_engine_authoritative_tier_oal_ssvc_over_sla_buckets(tmp_path: Path) -> None:
    matcher = AssetContextMatcher({
        "version": "v2",
        "rules": [{"id": "h1", "asset_id": "aid_1", "aliases": ["10.0.0.10"], "internet_facing": True}],
    })
    with VppDatabase(":memory:") as db:
        ensure_run(db, "b", created_at_utc="2026-01-01T00:00:00Z", profile="default")
        ensure_run(db, "t", created_at_utc="2026-02-01T00:00:00Z", profile="default")
        ingest_normalized_batches(db, "b", [[
            _rec(cves=["CVE-2024-1001"], scanner_sig="n:1", title="P2 to P1 Escalation"),
        ]], asset_matcher=matcher)
        ingest_normalized_batches(db, "t", [[
            _rec(cves=["CVE-2024-1001"], scanner_sig="n:1", title="P2 to P1 Escalation"),
            _rec(cves=["CVE-2024-1002"], scanner_sig="n:2", title="Default P2 14-day"),
            _rec(cves=["CVE-2024-1003"], scanner_sig="n:3", title="Default P3 60-day"),
        ]], asset_matcher=matcher)
        b_fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'b'").fetchone()[0]
        t_fids = dict(db.execute("SELECT title, finding_id FROM findings WHERE run_id = 't'").fetchall())

        upsert_triage_decisions(db, "b", [
            {"finding_id": b_fid, "asset_id": "aid_1", "priority_tier": "P2", "oal_compat": "OAL-2", "ssvc_action": "Attend", "sla_bucket": "14-day", "decision_status": "active"},
        ])
        upsert_triage_decisions(db, "t", [
            {"finding_id": t_fids["P2 to P1 Escalation"], "asset_id": "aid_1", "priority_tier": "P2", "oal_compat": "OAL-2", "ssvc_action": "Attend", "sla_bucket": "14-day", "decision_status": "active"},
            {"finding_id": t_fids["Default P2 14-day"], "asset_id": "aid_1", "priority_tier": "P2", "oal_compat": "OAL-2", "ssvc_action": "Attend", "sla_bucket": "14-day", "decision_status": "active"},
            {"finding_id": t_fids["Default P3 60-day"], "asset_id": "aid_1", "priority_tier": "P3", "oal_compat": "OAL-3", "ssvc_action": "Track*", "sla_bucket": "60-day", "decision_status": "active"},
        ])
        rep = DiffEngine(db).compare("b", "t")
        new_titles = {x.title for x in rep.newly_introduced_high_risk}
        assert new_titles == {"Default P2 14-day"}
        assert evaluate_fail_gate(rep, "p1") == 0
        assert evaluate_fail_gate(rep, "p2") == 2

        # Real P2 (14-day) -> P1 (14-day) escalation on target
        ensure_run(db, "t_esc", created_at_utc="2026-03-01T00:00:00Z", profile="default")
        ingest_normalized_batches(db, "t_esc", [[
            _rec(cves=["CVE-2024-1001"], scanner_sig="n:1", title="P2 to P1 Escalation"),
        ]], asset_matcher=matcher)
        upsert_enrichment_snapshots(db, "b", [{"cve_id": "CVE-2024-1001", "cvss_score": 7.0, "epss_score": 0.02, "in_kev": False}])
        upsert_enrichment_snapshots(db, "t_esc", [{"cve_id": "CVE-2024-1001", "cvss_score": 7.0, "epss_score": 0.25, "in_kev": True}])
        upsert_triage_decisions(db, "t_esc", [
            {"finding_id": b_fid, "asset_id": "aid_1", "priority_tier": "P1", "oal_compat": "OAL-1", "ssvc_action": "Act", "sla_bucket": "14-day", "decision_status": "active"},
        ])
        rep_esc = DiffEngine(db).compare("b", "t_esc")
        assert evaluate_fail_gate(rep_esc, "p1") == 2


def test_multi_cve_enrichment_join_across_diff_repos_and_summary(tmp_path: Path) -> None:
    matcher = AssetContextMatcher({
        "version": "v2",
        "rules": [{"id": "pub", "asset_id": "aid_pub", "aliases": ["203.0.113.10"], "internet_facing": True}],
    })
    with VppDatabase(":memory:") as db:
        ensure_run(db, "base", created_at_utc="2026-01-01T00:00:00Z", profile="bod-26-04")
        ensure_run(db, "targ", created_at_utc="2026-02-01T00:00:00Z", profile="bod-26-04")
        ingest_normalized_batches(db, "targ", [[
            _rec(ip_address="203.0.113.10", hostname=None, cves=["CVE-2020-0001", "CVE-2024-9999"], scanner_sig="trivy:multi"),
            _rec(ip_address="198.51.100.77", hostname="shadow-multi", cves=["CVE-2020-0001", "CVE-2024-9999"], scanner_sig="trivy:shadow"),
        ]], asset_matcher=matcher)
        upsert_enrichment_snapshots(db, "targ", [
            {"cve_id": "CVE-2020-0001", "cvss_score": 5.0, "cvss_provenance": "NVD", "epss_score": 0.01, "epss_percentile": 0.20, "in_kev": False, "verified_exploit": False},
            {"cve_id": "CVE-2024-9999", "cvss_score": 9.8, "cvss_provenance": "NVD", "epss_score": 0.85, "epss_percentile": 0.99, "in_kev": True, "verified_exploit": True},
        ])
        ctx = _ctx(tmp_path, db, "targ", profile="bod-26-04")
        ACIV2Pass().run(ctx)
        ScoringV3Pass().run(ctx)
        TriageDecisionPass(profile="bod-26-04").run(ctx)
        sum_res = SummaryV2Pass().run(ctx)

        rep = DiffEngine(db).compare("base", "targ")
        assert rep.newly_introduced_active_kev_count == 2
        assert all(item.in_kev is True for item in rep.newly_introduced_high_risk)
        assert evaluate_fail_gate(rep, "kev") == 2

        kev_rows, kev_total = query_findings_page(db, "targ", in_kev=True)
        assert kev_total == 2
        assert all(r["in_kev"] is True and r["verified_exploit"] is True for r in kev_rows)
        detail = get_finding_detail(db, "targ", kev_rows[0]["finding_id"])
        assert detail is not None and detail["in_kev"] is True and detail["verified_exploit"] is True

        counts = get_run_summary_counts(db, "targ")
        assert counts["kev_findings"] == 2
        shadows = get_shadow_assets(db, "targ")
        assert len(shadows) == 1 and shadows[0]["kev_count"] == 1
        assert sum_res.data["enrichment_metrics"]["kev_findings"] == 2
        assert sum_res.data["enrichment_metrics"]["verified_exploit_findings"] == 2

        # Also verify raw finding_cves BOOL_OR fallback when scores.score_trace_json is absent
        ensure_run(db, "targ_noscore", created_at_utc="2026-03-01T00:00:00Z", profile="bod-26-04")
        ingest_normalized_batches(db, "targ_noscore", [[
            _rec(ip_address="203.0.113.10", hostname=None, cves=["CVE-2020-0001", "CVE-2024-9999"], scanner_sig="trivy:multi"),
        ]], asset_matcher=matcher)
        upsert_enrichment_snapshots(db, "targ_noscore", [
            {"cve_id": "CVE-2020-0001", "cvss_score": 5.0, "cvss_provenance": "NVD", "epss_score": 0.01, "in_kev": False, "verified_exploit": False},
            {"cve_id": "CVE-2024-9999", "cvss_score": 9.8, "cvss_provenance": "NVD", "epss_score": 0.85, "in_kev": True, "verified_exploit": True},
        ])
        ns_rows, ns_total = query_findings_page(db, "targ_noscore", in_kev=True)
        assert ns_total == 1 and ns_rows[0]["in_kev"] is True and ns_rows[0]["verified_exploit"] is True
        assert get_run_summary_counts(db, "targ_noscore")["kev_findings"] == 1
        rep_ns = DiffEngine(db).compare("base", "targ_noscore")
        assert rep_ns.newly_introduced_active_kev_count == 1
        assert evaluate_fail_gate(rep_ns, "kev") == 2


def test_triage_and_aci_multi_sig_loading_and_specificity(tmp_path: Path) -> None:
    matcher = AssetContextMatcher({
        "version": "v2",
        "rules": [{"id": "srv", "asset_id": "aid_srv", "aliases": ["10.0.0.10"], "internet_facing": True}],
    })
    registry = DecisionsRegistry.from_dict({
        "version": "v2",
        "decisions": [
            {"id": "d-broad", "cve_or_rule_id": "Nessus:100", "status": "deferred", "rationale": "Broad"},
            {"id": "d-spec", "asset_id": "aid_srv", "cve_or_rule_id": "Semgrep:sql-inj", "status": "accepted", "rationale": "Specific"},
            {"id": "d-cve-sig", "asset_id": "aid_srv", "cve_or_rule_id": "CVE-2024-1111", "status": "deferred", "rationale": "Track B rule matching CVE ID"},
        ],
    })
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r1", created_at_utc="2026-01-01T00:00:00Z", profile="default")
        ensure_run(db, "r2", created_at_utc="2026-02-01T00:00:00Z", profile="default")
        recs = [
            _rec(cves=[], scanner_sig="Nessus:100", title="SQLi Finding", source_format="nessus-xml", detection_mode="active_dast"),
            _rec(cves=[], scanner_sig="Semgrep:sql-inj", title="SQLi Finding", source_format="sarif-2.1.0", detection_mode="active_dast"),
            _rec(cves=[], scanner_sig="CVE-2024-1111", title="Track B CVE Rule", source_format="nuclei-jsonl", detection_mode="active_dast"),
        ]
        # Force same dedup key on first two records
        recs[0]["location_uri"] = recs[1]["location_uri"] = "app.py"
        # Use same CVE so dedup keeps both scanner_sigs in finding_evidence
        recs[0]["cves"] = recs[1]["cves"] = ["CVE-2024-9000"]
        ingest_normalized_batches(db, "r2", [recs], asset_matcher=matcher)
        ctx = _ctx(tmp_path, db, "r2", registry=registry, profile="default")
        ACIV2Pass().run(ctx)
        ScoringV3Pass().run(ctx)
        TriageDecisionPass(profile="default", decisions_registry=registry).run(ctx)

        rows = {
            r[0]: (r[1], r[2])
            for r in db.execute(
                "SELECT f.title, td.decision_status, td.decision_id "
                "FROM triage_decisions td JOIN findings f ON f.run_id = td.run_id AND f.finding_id = td.finding_id "
                "WHERE td.run_id = 'r2'"
            ).fetchall()
        }
        assert rows["SQLi Finding"] == ("accepted_valid", "d-spec")
        assert rows["Track B CVE Rule"] == ("deferred_valid", "d-cve-sig")


def test_diff_engine_db_only_nested_assumed_state_and_expiry(tmp_path: Path) -> None:
    matcher = AssetContextMatcher({
        "version": "v2",
        "rules": [{"id": "srv", "asset_id": "aid_srv", "aliases": ["10.0.0.10"], "internet_facing": False}],
    })
    registry = DecisionsRegistry.from_dict({
        "version": "v2",
        "decisions": [
            {
                "id": "dec-exp",
                "asset_id": "aid_srv",
                "cve_or_rule_id": "CVE-2024-2222",
                "status": "deferred",
                "rationale": "Temporary",
                "expires_at": "2026-03-01",
                "assumptions": {"max_epss": 0.05},
            }
        ],
    })
    with VppDatabase(":memory:") as db:
        ensure_run(db, "b", created_at_utc="2026-01-01T00:00:00Z", profile="default")
        ensure_run(db, "t", created_at_utc="2026-02-01T00:00:00Z", profile="default")
        rec = _rec(cves=["CVE-2024-2222"], scanner_sig="n:2222", title="DB Deferred")
        ingest_normalized_batches(db, "b", [[rec]], asset_matcher=matcher)
        ingest_normalized_batches(db, "t", [[rec]], asset_matcher=matcher)
        upsert_enrichment_snapshots(db, "t", [{"cve_id": "CVE-2024-2222", "cvss_score": 5.0, "epss_score": 0.02, "in_kev": False}])
        ctx = _ctx(tmp_path, db, "t", registry=registry, profile="default")
        ACIV2Pass().run(ctx)
        ScoringV3Pass().run(ctx)
        TriageDecisionPass(profile="default", decisions_registry=registry, now_utc="2026-02-01T00:00:00Z").run(ctx)

        # DB-only DiffEngine without --decisions at later date catches expired deferred_valid
        rep = DiffEngine(db, now_utc="2026-06-01T00:00:00Z").compare("b", "t")
        assert len(rep.invalidated_assumptions) == 1
        assert rep.invalidated_assumptions[0].decision_status == "deferred_invalidated"
        assert "expired" in rep.invalidated_assumptions[0].violated_predicates
        assert evaluate_fail_gate(rep, "stale-assumption") == 2


def test_sast_p1_cap_bod_severity_and_word_boundary(tmp_path: Path) -> None:
    assert _is_high_conf_sast_corroborated(
        internet_facing=True, cwes=["CWE-78"], scanner_sig="semgrep:cmd", scanner_severity="Low", high_impact_aci=True
    ) is False
    assert _is_high_conf_sast_corroborated(
        internet_facing=True, cwes=[], scanner_sig="semgrep:aws-resource-tag", scanner_severity="Critical", high_impact_aci=False
    ) is False
    assert _is_high_conf_sast_corroborated(
        internet_facing=True, cwes=[], scanner_sig="semgrep:python-rce-check", scanner_severity="High", high_impact_aci=False
    ) is True

    matcher = AssetContextMatcher({
        "version": "v2",
        "rules": [{"id": "pub", "asset_id": "aid_pub", "aliases": ["203.0.113.10"], "internet_facing": True}],
    })
    with VppDatabase(":memory:") as db:
        ensure_run(db, "run-bod-sast", created_at_utc="2026-01-01T00:00:00Z", profile="bod-26-04")
        ingest_normalized_batches(db, "run-bod-sast", [[
            _rec(
                ip_address="203.0.113.10",
                hostname=None,
                cves=[],
                cwes=["CWE-78"],
                scanner_sig="semgrep:aws-resource-tag",
                title="Resource tag",
                severity="Low",
                scanner_cvss_score=None,
                detection_mode="static_sast",
                source_format="sarif-2.1.0",
            ),
        ]], asset_matcher=matcher)
        ctx = _ctx(tmp_path, db, "run-bod-sast", profile="bod-26-04")
        ACIV2Pass().run(ctx)
        ScoringV3Pass().run(ctx)
        TriageDecisionPass(profile="bod-26-04").run(ctx)
        row = db.execute(
            "SELECT priority_tier, sla_bucket, ssvc_action FROM triage_decisions WHERE run_id = 'run-bod-sast'"
        ).fetchone()
        assert row == ("P2", "60-day", "Attend")


def test_scoring_scanner_vector_only_and_no_scanner_snapshot_leak() -> None:
    # Scanner-Supplied snapshot does not override finding's own score or leak to other findings
    sc1, ver1, prov1 = _resolve_best_cvss(4.0, "3.1", "Scanner-Supplied", 9.0, None)
    assert (sc1, prov1) == (9.0, "Scanner-Supplied")
    sc2, ver2, prov2 = _resolve_best_cvss(4.0, "3.1", "Scanner-Supplied", None, None)
    assert (sc2, ver2, prov2) == (0.0, None, "Missing")

    # Vector-only CVSS in Track A and Track B
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    sc_v, ver_v, prov_v = _resolve_best_cvss(None, None, "Missing", None, vec)
    assert (sc_v, ver_v, prov_v) == (9.8, "3.1", "Scanner-Supplied")

    pass_v3 = ScoringV3Pass()
    _, _, _, trace_b = pass_v3._score_track_b(
        scanner_cvss_score=None,
        scanner_cvss_vector=vec,
        scanner_severity="Low",
        finding_exploit_evidence=False,
        cwes=(),
        aci_capabilities=(),
        aci_chains=(),
        detection_mode="active_dast",
        signal_reliability=1.0,
        asset_inventory_status="matched",
        internet_facing=False,
        declared_criticality="low",
    )
    assert trace_b["cvss_score"] == 9.8
    assert trace_b["cvss_provenance"] == "Scanner-Supplied"
    assert trace_b["breakdown"]["base_score"] == 9.8


def test_asset_matcher_ip_url_consistency() -> None:
    matcher = AssetContextMatcher({"version": "v2", "rules": []})
    ctx_matched = matcher.resolve(target_uri="https://192.0.2.10/login")
    ckey_direct = canonicalize_target_key(target_uri="https://192.0.2.10/login")
    assert ctx_matched.canonical_key == ckey_direct == "uri=https://192.0.2.10/login"
    assert ctx_matched.asset_id == make_asset_id_v2(ckey_direct)


def test_aci_scan_sig_cwe_boundaries_and_dict_init(tmp_path: Path) -> None:
    assert _normalize_cwe("CWE-79: XSS") == "CWE-79"
    aci = ACIV2Pass({"aci": {"enabled": True, "signal_aliases": [{"token": "nessus", "signal": "rce"}]}})
    assert aci.cfg.enabled is True

    with VppDatabase(":memory:") as db:
        ensure_run(db, "run-aci-edge", created_at_utc="2026-01-01T00:00:00Z")
        db.execute("INSERT INTO assets (run_id, asset_id, canonical_key, inventory_status) VALUES ('run-aci-edge', 'a1', 'host:a1', 'matched')")
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, cwes_json, title, description) VALUES "
            "('run-aci-edge', 'f-false-pos', 'a1', 'exposure_weakness', '[]', 'Open source library', 'Uses sqlite storage'), "
            "('run-aci-edge', 'f-sig-alias', 'a1', 'exposure_weakness', '[]', 'Generic title', 'Generic desc')"
        )
        db.execute(
            "INSERT INTO finding_evidence (run_id, finding_id, evidence_idx, source_format, scanner_sig) VALUES "
            "('run-aci-edge', 'f-false-pos', 0, 'sarif', 'trivy:sqlite'), "
            "('run-aci-edge', 'f-sig-alias', 0, 'nessus-xml', 'Nessus:12345')"
        )
        ctx = _ctx(tmp_path, db, "run-aci-edge")
        aci.run(ctx)
        caps = {
            r[0]: json.loads(r[1])
            for r in db.execute("SELECT finding_id, capabilities_json FROM aci_signals WHERE run_id = 'run-aci-edge'").fetchall()
        }
        assert "remote_execution" not in caps["f-false-pos"]
        assert "sql_injection" not in caps["f-false-pos"]
        assert "remote_execution" in caps["f-sig-alias"]
        assert "initial_access" in caps["f-sig-alias"]


def test_repositories_dedup_promotion_cumulative_assets_and_finding_cves(tmp_path: Path) -> None:
    with VppDatabase(":memory:") as db:
        ensure_run(db, "run-dedup", created_at_utc="2026-01-01T00:00:00Z")
        b1 = [
            _rec(
                cves=["CVE-2024-5555"],
                source_format="sarif-2.1.0",
                scanner_sig="trivy:1",
                title="Trivy Title",
                description="Trivy Desc",
                solution="Trivy Sol",
                plugin_output="Trivy Out",
                scanner_cvss_score=9.8,
                scanner_cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                detection_mode="sca_container",
                ingestion_confidence=0.90,
            ),
            _rec(
                cves=["CVE-2024-5555"],
                source_format="nessus-xml",
                scanner_sig="nessus:1",
                title="Nessus Title",
                description="Nessus Desc",
                solution="Nessus Sol",
                plugin_output="Nessus Out",
                scanner_cvss_score=10.0,
                scanner_cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                detection_mode="credentialed_host",
                ingestion_confidence=0.95,
            ),
        ]
        s1 = ingest_normalized_batches(db, "run-dedup", [b1])
        assert s1["assets_ingested"] == 1
        assert s1["cve_links_ingested"] == 1

        rows, _ = query_findings_page(db, "run-dedup")
        assert rows[0]["title"] == "Nessus Title"
        assert rows[0]["description"] == "Nessus Desc"
        assert rows[0]["solution"] == "Nessus Sol"
        assert rows[0]["plugin_output"] == "Nessus Out"
        assert rows[0]["scanner_cvss_score"] == 10.0

        # Incremental ingest of same finding + new asset -> cumulative assets_ingested == 2, zero duplicate finding_cves
        s2 = ingest_normalized_batches(db, "run-dedup", [[
            b1[1],
            _rec(ip_address="10.0.0.99", hostname="app2.internal", cves=["CVE-2024-6666"], scanner_sig="nessus:2"),
        ]])
        assert s2["assets_ingested"] == 2
        assert s2["cve_links_ingested"] == 1
        cnt = db.execute("SELECT COUNT(*) FROM finding_cves WHERE run_id = 'run-dedup' AND cve_id = 'CVE-2024-5555'").fetchone()[0]
        assert cnt == 1


def test_nmap_existing_shadow_counting_and_matched_null_exposure(tmp_path: Path) -> None:
    with VppDatabase(":memory:") as db:
        ensure_run(db, "run-nmap-shadow", created_at_utc="2026-01-01T00:00:00Z")
        db.execute(
            "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, ip_address, internet_facing, inventory_status, open_ports_json) VALUES "
            "('run-nmap-shadow', 'a-matched-null', 'host:matched', 'matched.internal', '10.0.0.10', NULL, 'matched', '[]'), "
            "('run-nmap-shadow', 'a-shadow', 'host:shadow', 'shadow.example', '203.0.113.50', NULL, 'unmatched_shadow', '[]')"
        )
        nmap_xml = tmp_path / "nmap.xml"
        nmap_xml.write_text(
            "<nmaprun>"
            "<host><status state='up'/><address addr='10.0.0.10' addrtype='ipv4'/><ports><port protocol='tcp' portid='443'><state state='open'/></port></ports></host>"
            "<host><status state='up'/><address addr='203.0.113.50' addrtype='ipv4'/><ports><port protocol='tcp' portid='443'><state state='open'/></port></ports></host>"
            "</nmaprun>",
            encoding="utf-8",
        )
        res = NmapAdapterPass(nmap_source=nmap_xml).run(_ctx(tmp_path, db, "run-nmap-shadow"))
        assert res.data["matched_asset_count"] == 1
        facing = dict(db.execute("SELECT asset_id, internet_facing FROM assets WHERE run_id = 'run-nmap-shadow'").fetchall())
        assert facing["a-matched-null"] is None
        assert facing["a-shadow"] is True


def test_fallback_aci_uses_importlib_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(TN_triage_config, "__file__", "/nonexistent/zipped.whl/vulnparse_pin/core/passes/TopN/TN_triage_config.py")
    cfg = TN_triage_config._fallback_aci_config()
    assert cfg.enabled is True
    assert len(cfg.capability_rules) > 0
