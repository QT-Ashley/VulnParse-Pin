# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import os
from pathlib import Path
import stat
import time

import pytest

from vulnparse_pin.core.assets_context import AssetContextMatcher
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    ensure_run,
    get_finding_detail,
    get_run_summary_counts,
    get_shadow_assets,
    ingest_normalized_batches,
    list_runs,
    query_findings_page,
    upsert_aci_signals,
    upsert_enrichment_snapshots,
    upsert_scores,
    upsert_triage_decisions,
)


def _sample_record(**overrides):
    rec = {
        "ip_address": "10.10.1.5",
        "hostname": "web-01.corp.local",
        "target_uri": None,
        "image_or_repo": None,
        "os": "Ubuntu 24.04",
        "asset_metadata": {"credentialed": True, "open_ports": [443]},
        "source_format": "nessus-xml",
        "scanner_sig": "nessus:10001",
        "title": "OpenSSL Remote Code Execution",
        "description": "Critical issue in OpenSSL.",
        "solution": "Upgrade OpenSSL.",
        "plugin_output": "Installed 3.0.1",
        "severity": "Critical",
        "cves": ["CVE-2024-1234"],
        "cwes": ["CWE-119"],
        "ghsa_ids": [],
        "affected_port": 443,
        "protocol": "tcp",
        "service_name": "https",
        "location_uri": None,
        "line_number": None,
        "package_purl": None,
        "scanner_cvss_score": 9.8,
        "scanner_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "detection_mode": "credentialed_host",
        "fidelity_tier": "high",
        "ingestion_confidence": 0.95,
        "missing_fields": [],
        "degraded_input": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        "tags": ["openssl"],
        "exploit_evidence": False,
        "raw_evidence_excerpt": "Installed version 3.0.1",
    }
    rec.update(overrides)
    return rec


def test_vpp_database_permissions_and_lifecycle(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "workspace.vpp.db"
    with VppDatabase(db_path) as db:
        assert db_path.exists()
        if os.name == "posix":
            mode = stat.S_IMODE(db_path.stat().st_mode)
            assert mode == 0o600
        tables = {
            r[0]
            for r in db.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
            ).fetchall()
        }
        expected_tables = {
            "runs",
            "assets",
            "asset_aliases",
            "findings",
            "finding_evidence",
            "finding_cves",
            "enrichment_snapshots",
            "aci_signals",
            "scores",
            "triage_decisions",
            "diff_events",
            "ledger_events",
        }
        assert expected_tables.issubset(tables)

    assert db.is_closed is True
    with pytest.raises(RuntimeError, match="already closed"):
        _ = db.conn

    # Refuse symlink DB path
    symlink_path = tmp_path / "link.vpp.db"
    symlink_path.symlink_to(db_path)
    with pytest.raises(ValueError, match="Refusing symlink"):
        VppDatabase(symlink_path)


def test_cross_scanner_cve_dedup_preserves_all_evidence_and_cves(tmp_path: Path) -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "defaults": {"criticality": "low", "internet_facing": False},
            "rules": [
                {
                    "id": "checkout-api",
                    "asset_id": "aid_v2_checkout_prod",
                    "aliases": [
                        "10.10.1.5",
                        "web-01.corp.local",
                        "https://checkout.example.com",
                        "ghcr.io/acme/checkout:1.4.0",
                    ],
                    "criticality": "critical",
                    "internet_facing": True,
                    "owner": "platform-sec",
                    "env": ["prod"],
                    "tags": {"tier": "0"},
                }
            ],
        }
    )

    batches = [
        [
            _sample_record(
                source_format="nessus-xml",
                scanner_sig="nessus:10001",
                ip_address="10.10.1.5",
                hostname="web-01.corp.local",
                cves=["CVE-2024-1234", "CVE-2024-5678"],
                detection_mode="credentialed_host",
                ingestion_confidence=0.95,
                raw_evidence_excerpt="Nessus local check",
            ),
            _sample_record(
                source_format="nuclei-jsonl",
                scanner_sig="nuclei:openssl-rce",
                ip_address=None,
                hostname=None,
                target_uri="https://checkout.example.com/api",
                cves=["CVE-2024-1234"],
                detection_mode="active_dast",
                ingestion_confidence=0.90,
                exploit_evidence=True,
                raw_location="https://checkout.example.com/api",
                raw_evidence_excerpt="curl -s https://checkout.example.com/api",
            ),
            _sample_record(
                source_format="sarif-2.1.0",
                scanner_sig="trivy:CVE-2024-1234",
                ip_address=None,
                hostname=None,
                image_or_repo="ghcr.io/acme/checkout:1.4.0",
                package_purl="pkg:deb/debian/openssl@3.0.1",
                cves=["CVE-2024-1234"],
                detection_mode="sca_container",
                ingestion_confidence=0.90,
                raw_location="usr/lib/libssl.so.3",
                raw_evidence_excerpt="Trivy container layer hit",
            ),
        ]
    ]

    with VppDatabase(tmp_path / "dedup.vpp.db") as db:
        ensure_run(db, "run-1", vpp_version="2.0.0", profile="bod_26_04", input_files=["a.nessus", "b.jsonl"])
        stats = ingest_normalized_batches(db, "run-1", batches, asset_matcher=matcher)

        assert stats["assets_ingested"] == 1
        assert stats["shadow_assets"] == 0
        assert stats["raw_findings_ingested"] == 3
        assert stats["unique_findings_ingested"] == 1
        assert stats["deduplicated_findings"] == 1
        assert stats["cve_links_ingested"] == 2

        rows, total = query_findings_page(db, "run-1")
        assert total == 1
        row = rows[0]
        assert row["asset_id"] == "aid_v2_checkout_prod"
        assert row["scoring_track"] == "cve_threat"
        assert row["primary_cve"] == "CVE-2024-1234"
        assert set(row["cves"]) == {"CVE-2024-1234", "CVE-2024-5678"}
        assert row["is_deduplicated"] is True
        assert row["source_count"] == 3
        assert row["exploit_evidence"] is True
        assert row["inventory_status"] == "matched"
        assert row["matched_rule_id"] == "checkout-api"

        detail = get_finding_detail(db, "run-1", row["finding_id"])
        assert detail is not None
        assert len(detail["evidence"]) == 3
        assert [e["source_format"] for e in detail["evidence"]] == [
            "nessus-xml",
            "nuclei-jsonl",
            "sarif-2.1.0",
        ]
        assert set(detail["finding_cves"]) == {"CVE-2024-1234", "CVE-2024-5678"}
        alias_vals = {a["alias_value"] for a in detail["asset_aliases"]}
        assert "10.10.1.5" in alias_vals
        assert "web-01.corp.local" in alias_vals
        assert "ghcr.io/acme/checkout:1.4.0" in alias_vals


def test_non_cve_preservation_and_incremental_ingest(tmp_path: Path) -> None:
    with VppDatabase(tmp_path / "noncve.vpp.db") as db:
        batch1 = [
            _sample_record(
                cves=[],
                scanner_sig="semgrep:python.sql-injection",
                title="SQL Injection in auth.py",
                location_uri="src/auth.py",
                line_number=42,
                affected_port=None,
                protocol=None,
                detection_mode="static_sast",
                source_format="sarif-2.1.0",
            ),
            _sample_record(
                cves=[],
                scanner_sig="semgrep:python.sql-injection",
                title="SQL Injection in auth.py",
                location_uri="src/auth.py",
                line_number=99,
                affected_port=None,
                protocol=None,
                detection_mode="static_sast",
                source_format="sarif-2.1.0",
            ),
            _sample_record(
                cves=[],
                scanner_sig="nuclei:exposed-git",
                title="Exposed .git repository",
                location_uri="https://web-01.corp.local/.git/HEAD",
                affected_port=443,
                protocol="tcp",
                detection_mode="active_dast",
                source_format="nuclei-jsonl",
            ),
        ]
        s1 = db.ingest_normalized_batches("run-inc", [batch1])
        assert s1["unique_findings_ingested"] == 3
        assert s1["deduplicated_findings"] == 0

        # Second incremental ingestion with duplicate of nuclei:exposed-git + new port on same host
        batch2 = [
            _sample_record(
                cves=[],
                scanner_sig="nuclei:exposed-git",
                title="Exposed .git repository",
                location_uri="https://web-01.corp.local/.git/HEAD",
                affected_port=8443,
                protocol="tcp",
                detection_mode="active_dast",
                source_format="nuclei-jsonl",
            ),
            _sample_record(
                cves=[],
                scanner_sig="nuclei:exposed-git",
                title="Exposed .git repository",
                location_uri="https://web-01.corp.local/.git/HEAD",
                affected_port=443,
                protocol="tcp",
                detection_mode="active_dast",
                source_format="nuclei-jsonl",
                raw_evidence_excerpt="Second scan confirmation",
            ),
        ]
        db.ingest_normalized_batches("run-inc", [batch2])

        rows, total = db.query_findings_page("run-inc", scoring_track="exposure_weakness")
        assert total == 4
        for r in rows:
            assert r["scoring_track"] == "exposure_weakness"
            assert r["primary_cve"] is None

        deduped = [r for r in rows if r["is_deduplicated"]]
        assert len(deduped) == 1
        assert deduped[0]["source_count"] == 2
        detail = db.get_finding_detail("run-inc", deduped[0]["finding_id"])
        assert len(detail["evidence"]) == 2
        assert 8443 in detail["open_ports"]
        assert 443 in detail["open_ports"]


def test_paged_queries_ordering_filtering_and_sql_injection_defense(tmp_path: Path) -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "defaults": {"criticality": "medium", "internet_facing": False},
            "rules": [
                {
                    "id": "known-db",
                    "cidrs": ["10.0.0.0/24"],
                    "criticality": "high",
                    "internet_facing": False,
                }
            ],
        }
    )

    with VppDatabase(tmp_path / "query.vpp.db") as db:
        ensure_run(db, "run-old", created_at_utc="2026-01-01T00:00:00Z", profile="legacy_oal")
        ensure_run(db, "run-new", created_at_utc="2026-02-01T00:00:00Z", profile="bod_26_04")

        records = [
            _sample_record(ip_address="10.0.0.10", hostname="db-1", cves=["CVE-2024-0001"], title="DB Vuln"),
            _sample_record(ip_address="203.0.113.5", hostname="shadow-edge", cves=["CVE-2024-0002"], title="Edge KEV Vuln"),
            _sample_record(ip_address="203.0.113.5", hostname="shadow-edge", cves=[], scanner_sig="nuclei:debug", title="Debug Panel"),
            _sample_record(ip_address="10.0.0.11", hostname="db-2", cves=["CVE-2024-0003"], title="Low Impact Vuln"),
        ]
        db.ingest_normalized_batches("run-new", [records], asset_matcher=matcher)

        rows_all, total_all = db.query_findings_page("run-new")
        assert total_all == 4
        by_title = {r["title"]: r for r in rows_all}

        upsert_enrichment_snapshots(
            db,
            "run-new",
            [
                {"cve_id": "CVE-2024-0001", "cvss_score": 8.0, "epss_score": 0.4, "in_kev": False},
                {"cve_id": "CVE-2024-0002", "cvss_score": 9.8, "epss_score": 0.95, "in_kev": True},
                {"cve_id": "CVE-2024-0003", "cvss_score": 4.0, "epss_score": 0.05, "in_kev": False},
            ],
        )
        upsert_scores(
            db,
            "run-new",
            [
                {"finding_id": by_title["DB Vuln"]["finding_id"], "asset_id": by_title["DB Vuln"]["asset_id"], "scoring_track": "cve_threat", "raw_risk_score": 11.0, "operational_score": 7.5, "risk_band": "High"},
                {"finding_id": by_title["Edge KEV Vuln"]["finding_id"], "asset_id": by_title["Edge KEV Vuln"]["asset_id"], "scoring_track": "cve_threat", "raw_risk_score": 18.0, "operational_score": 9.9, "risk_band": "Critical"},
                {"finding_id": by_title["Debug Panel"]["finding_id"], "asset_id": by_title["Debug Panel"]["asset_id"], "scoring_track": "exposure_weakness", "raw_risk_score": 6.0, "operational_score": 6.0, "risk_band": "Medium"},
                {"finding_id": by_title["Low Impact Vuln"]["finding_id"], "asset_id": by_title["Low Impact Vuln"]["asset_id"], "scoring_track": "cve_threat", "raw_risk_score": 4.0, "operational_score": 3.0, "risk_band": "Low"},
            ],
        )
        upsert_triage_decisions(
            db,
            "run-new",
            [
                {"finding_id": by_title["DB Vuln"]["finding_id"], "asset_id": by_title["DB Vuln"]["asset_id"], "profile": "bod_26_04", "priority_tier": "P2", "sla_bucket": "14-day", "sla_days": 14, "decision_status": "open"},
                {"finding_id": by_title["Edge KEV Vuln"]["finding_id"], "asset_id": by_title["Edge KEV Vuln"]["asset_id"], "profile": "bod_26_04", "priority_tier": "P1", "sla_bucket": "3-day", "sla_days": 3, "decision_status": "open"},
                {"finding_id": by_title["Debug Panel"]["finding_id"], "asset_id": by_title["Debug Panel"]["asset_id"], "profile": "bod_26_04", "priority_tier": "P1b", "sla_bucket": "14-day", "sla_days": 14, "decision_status": "open"},
                {"finding_id": by_title["Low Impact Vuln"]["finding_id"], "asset_id": by_title["Low Impact Vuln"]["asset_id"], "profile": "bod_26_04", "priority_tier": "P4", "sla_bucket": "60-day", "sla_days": 60, "decision_status": "deferred"},
            ],
        )
        upsert_aci_signals(
            db,
            "run-new",
            [
                {"finding_id": by_title["Debug Panel"]["finding_id"], "asset_id": by_title["Debug Panel"]["asset_id"], "capabilities": ["initial_access"], "chains": ["chain_x"], "confidence": 0.85, "uplift_score": 1.2}
            ],
        )

        # Deterministic ordering: P1 -> P1b -> P2 -> P4
        ordered_rows, ordered_total = db.query_findings_page("run-new")
        assert ordered_total == 4
        assert [r["priority_tier"] for r in ordered_rows] == ["P1", "P1b", "P2", "P4"]

        # Paging
        p1_rows, p1_total = db.query_findings_page("run-new", limit=2, offset=1)
        assert p1_total == 4
        assert [r["priority_tier"] for r in p1_rows] == ["P1b", "P2"]

        # Filters
        kev_rows, kev_total = db.query_findings_page("run-new", in_kev=True)
        assert kev_total == 1
        assert kev_rows[0]["title"] == "Edge KEV Vuln"

        shadow_rows, shadow_total = db.query_findings_page("run-new", inventory_status="unmatched_shadow")
        assert shadow_total == 2

        sla_rows, sla_total = db.query_findings_page("run-new", sla_bucket="14-day")
        assert sla_total == 2

        # SQL injection payloads must safely return 0 matches and leave DB intact
        for payload in ("'; DROP TABLE findings; --", "' OR '1'='1", "%"):
            inj_rows, inj_total = db.query_findings_page("run-new", search=payload)
            assert inj_total == 0
            assert inj_rows == []
        _, intact_total = db.query_findings_page("run-new", priority_tier="P1' OR '1'='1")
        assert intact_total == 0
        assert db.execute("SELECT COUNT(*) FROM findings WHERE run_id = 'run-new'").fetchone()[0] == 4

        # Summary counts & shadow assets & run listing
        summary = get_run_summary_counts(db, "run-new")
        assert summary["total_assets"] == 3
        assert summary["matched_assets"] == 2
        assert summary["shadow_assets"] == 1
        assert summary["kev_findings"] == 1
        assert summary["by_priority_tier"]["P1"] == 1

        shadows = get_shadow_assets(db, "run-new")
        assert len(shadows) == 1
        assert shadows[0]["hostname"] == "shadow-edge"
        assert shadows[0]["finding_count"] == 2
        assert shadows[0]["kev_count"] == 1

        runs = list_runs(db)
        assert [r["run_id"] for r in runs] == ["run-new", "run-old"]
        assert runs[0]["finding_count"] == 4


def test_bulk_ingestion_speed_100k_rows(tmp_path: Path) -> None:
    batch_size = 25_000
    total_rows = 100_000

    def _gen_batches():
        batch = []
        for i in range(total_rows):
            batch.append(
                {
                    "ip_address": f"10.1.{(i // 250) % 4}.{(i % 250) + 1}",
                    "hostname": f"host-{i % 1000}.corp.local",
                    "source_format": "nessus-xml",
                    "scanner_sig": f"nessus:{10000 + (i % 100)}",
                    "title": f"Vuln {i % 100}",
                    "description": "desc",
                    "solution": "sol",
                    "plugin_output": "out",
                    "severity": "High",
                    "cves": [f"CVE-2024-{1000 + (i % 100)}"],
                    "cwes": ["CWE-79"],
                    "ghsa_ids": [],
                    "affected_port": 443,
                    "protocol": "tcp",
                    "detection_mode": "credentialed_host",
                    "fidelity_tier": "high",
                    "ingestion_confidence": 0.95,
                    "references": [],
                    "tags": [],
                    "exploit_evidence": False,
                    "raw_evidence_excerpt": "excerpt",
                }
            )
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    with VppDatabase(tmp_path / "perf.vpp.db") as db:
        t0 = time.perf_counter()
        stats = db.ingest_normalized_batches("run-100k", _gen_batches())
        elapsed = time.perf_counter() - t0

    assert stats["raw_findings_ingested"] == 100_000
    assert stats["unique_findings_ingested"] == 1_000
    assert elapsed < 4.0, f"Bulk ingestion of 100k rows took {elapsed:.3f}s (expected < 4.0s)"
