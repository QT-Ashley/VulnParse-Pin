# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import csv
import json
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vulnparse_pin.core.assets_context import AssetContextMatcher, DecisionsRegistry
from vulnparse_pin.core.classes.dataclass import AppPaths, RunContext, Services
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.diff_engine import DiffEngine
from vulnparse_pin.core.passes import run_v2_duckdb_pipeline
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.reporting.renderer import (
    export_dossier_bundle,
    md_escape,
    render_diff_pr_comment,
    render_dossier_html,
    render_dossier_markdown,
    render_executive_roadmap_html,
    render_executive_roadmap_markdown,
)
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    ensure_run,
    ingest_normalized_batches,
    insert_ledger_events,
    upsert_enrichment_snapshots,
)
from vulnparse_pin.utils import reportgen
from vulnparse_pin.utils.csv_exporter import export_duckdb_csv
from vulnparse_pin.utils.reportgen import (
    _estimate_dict_size,
    _stream_json_dump,
    export_duckdb_json,
    materialize_presentation,
)
from vulnparse_pin.utils.runmanifest import (
    build_runmanifest_from_db,
    verify_runmanifest,
)


def _make_ctx(
    tmp_path: Path,
    db: VppDatabase,
    run_id: str,
    *,
    profile: str = "bod-26-04",
    registry: DecisionsRegistry | None = None,
    ledger: LedgerService | None = None,
) -> RunContext:
    logger = SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        debug=lambda *a, **k: None,
        error=lambda *a, **k: None,
        print_success=lambda *a, **k: None,
    )
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    svc = Services(db=db, run_id=run_id, decisions_registry=registry, ledger=ledger)
    ctx = RunContext(
        paths=AppPaths.resolve(portable=True),
        pfh=pfh,
        logger=logger,
        services=svc,
        db=db,
        run_id=run_id,
        decisions_registry=registry,
    )
    object.__setattr__(ctx, "profile", profile)
    return ctx


def _seed_v2_workspace(tmp_path: Path, *, xss_and_md_inject: bool = False) -> dict:
    db = VppDatabase(tmp_path / "vpp_reports.db")
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "defaults": {"criticality": "low", "internet_facing": False},
            "rules": [
                {
                    "id": "edge-api",
                    "asset_id": "aid_v2_edge_api",
                    "aliases": [
                        "203.0.113.10",
                        "edge-api.acme.test",
                        "ghcr.io/acme/edge-api:1.0.0",
                        "https://edge-api.acme.test",
                    ],
                    "criticality": "critical",
                    "internet_facing": True,
                    "owner": "platform-edge",
                    "env": ["prod"],
                },
                {
                    "id": "internal-db",
                    "asset_id": "aid_v2_internal_db",
                    "aliases": ["10.20.1.50", "db.internal.test"],
                    "criticality": "medium",
                    "internet_facing": False,
                    "owner": "core-data",
                    "env": ["prod"],
                },
            ],
        }
    )

    registry = DecisionsRegistry.from_dict(
        {
            "version": "v2",
            "decisions": [
                {
                    "id": "DEC-VALID-001",
                    "asset_id": "aid_v2_internal_db",
                    "cve_or_rule_id": "CVE-2024-7001",
                    "status": "deferred",
                    "rationale": "Compensating mTLS and network ACL enforced; low EPSS.",
                    "owner": "core-data",
                    "created_at": "2026-10-01",
                    "expires_at": "2099-12-31",
                    "assumptions": {
                        "in_kev": False,
                        "max_epss": 0.05,
                        "internet_facing": False,
                    },
                },
                {
                    "id": "DEC-STALE-002",
                    "asset_id": "aid_v2_internal_db",
                    "cve_or_rule_id": "CVE-2024-7002",
                    "status": "deferred",
                    "rationale": "Initially deferred prior to CISA KEV listing.",
                    "owner": "core-data",
                    "created_at": "2026-09-01",
                    "expires_at": "2099-12-31",
                    "assumptions": {
                        "in_kev": False,
                        "max_epss": 0.05,
                    },
                },
            ],
        }
    )

    evil_title = "OpenSSL RCE | <script>alert(1)</script>\r\n`rm -rf /`" if xss_and_md_inject else "Log4j2 Remote Code Execution"
    evil_excerpt = "pipe|char\n<img src=x onerror=alert(2)>\n`backtick`" if xss_and_md_inject else "Installed log4j-core 2.14.1"
    evil_host = "shadow|host<script>alert(3)</script>.evil.test" if xss_and_md_inject else "shadow-untracked.acme.test"

    # ---- Baseline Run (run-base) ----
    base_id = "run-base"
    ensure_run(
        db,
        base_id,
        created_at_utc="2026-11-20T00:00:00Z",
        vpp_version="2.0.0",
        profile="bod-26-04",
        config_sha256="sha256:cfg1",
        assets_sha256="sha256:assets1",
        decisions_sha256="sha256:dec1",
        intel_metadata={
            "epss_model_version": "v2025.03.14",
            "epss_score_date": "2026-11-01",
            "kev_catalog_version": "2026.11.01",
            "kev_date_released": "2026-11-01",
            "nvd_status": "local-cache",
            "ghsa_enabled": True,
            "osv_enabled": True,
        },
        input_files=["baseline.nessus"],
    )
    ingest_normalized_batches(
        db,
        base_id,
        [
            [
                {
                    "ip_address": "10.20.1.50",
                    "hostname": "db.internal.test",
                    "source_format": "nessus-xml",
                    "scanner_sig": "nessus:70002",
                    "title": "PostgreSQL Old Vulnerability (Now Escalated)",
                    "description": "Remote code execution via crafted query",
                    "solution": "Upgrade to 16.4",
                    "severity": "Medium",
                    "cves": ["CVE-2024-7002"],
                    "cwes": ["CWE-89"],
                    "affected_port": 5432,
                    "protocol": "tcp",
                    "detection_mode": "credentialed_host",
                    "ingestion_confidence": 0.95,
                },
                {
                    "ip_address": "10.20.1.50",
                    "hostname": "db.internal.test",
                    "source_format": "nessus-xml",
                    "scanner_sig": "nessus:70099",
                    "title": "Legacy OpenSSH Patched Issue",
                    "description": "Patched in target scan",
                    "solution": "Upgrade OpenSSH",
                    "severity": "High",
                    "cves": ["CVE-2024-7099"],
                    "affected_port": 22,
                    "protocol": "tcp",
                    "detection_mode": "credentialed_host",
                    "ingestion_confidence": 0.95,
                },
            ]
        ],
        asset_matcher=matcher,
    )
    upsert_enrichment_snapshots(
        db,
        base_id,
        [
            {
                "cve_id": "CVE-2024-7002",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvss_version": "3.1",
                "cvss_provenance": "NVD",
                "epss_score": 0.01,
                "epss_percentile": 0.30,
                "epss_model_version": "v2025.03.14",
                "epss_date": "2026-11-01",
                "in_kev": False,
                "verified_exploit": False,
            },
            {
                "cve_id": "CVE-2024-7099",
                "cvss_score": 7.8,
                "cvss_version": "3.1",
                "cvss_provenance": "NVD",
                "epss_score": 0.05,
                "epss_percentile": 0.91,
                "in_kev": False,
                "verified_exploit": False,
            },
        ],
    )
    run_v2_duckdb_pipeline(ctx=_make_ctx(tmp_path, db, base_id, registry=registry), profile="bod-26-04", decisions_registry=registry)

    # ---- Target Run (run-target) ----
    target_id = "run-target"
    ledger = LedgerService()
    ledger.append_event(
        component="Enrichment",
        event_type="phase_complete",
        subject_ref=f"run:{target_id}",
        reason_code="ENRICHMENT_COMPLETE",
        reason_text="Populated offline EPSS v5, KEV, and NVD snapshots.",
        factor_refs=["epss", "kev", "nvd"],
        evidence={"cves": 4},
    )
    ensure_run(
        db,
        target_id,
        created_at_utc="2026-11-24T00:00:00Z",
        vpp_version="2.0.0",
        profile="bod-26-04",
        config_sha256="sha256:cfg2",
        assets_sha256="sha256:assets2",
        decisions_sha256="sha256:dec2",
        intel_metadata={
            "epss_model_version": "v2025.03.14",
            "epss_score_date": "2026-11-24",
            "epss_sha256": "sha256:epss_file",
            "kev_catalog_version": "2026.11.24",
            "kev_date_released": "2026-11-24",
            "kev_sha256": "sha256:kev_file",
            "nvd_status": "local-cache",
            "ghsa_enabled": True,
            "osv_enabled": True,
        },
        input_files=["edge.nessus", "edge_trivy.sarif"],
        baseline_run_id=base_id,
    )

    batches = [
        [
            # 1) Prioritized P1 KEV (cross-scanner deduplicated Nessus + Trivy!)
            {
                "ip_address": "203.0.113.10",
                "hostname": "edge-api.acme.test",
                "asset_metadata": {"open_ports": [443, 8443]},
                "source_format": "nessus-xml",
                "scanner_sig": "nessus:156000",
                "title": evil_title,
                "description": "Remote code execution via JNDI lookup.",
                "solution": "Upgrade log4j-core to >= 2.17.1.",
                "plugin_output": evil_excerpt,
                "severity": "Critical",
                "cves": ["CVE-2021-44228"],
                "cwes": ["CWE-502"],
                "affected_port": 443,
                "protocol": "tcp",
                "service_name": "https",
                "scanner_cvss_score": 10.0,
                "detection_mode": "credentialed_host",
                "ingestion_confidence": 0.98,
                "raw_evidence_excerpt": evil_excerpt,
            },
            {
                "image_or_repo": "ghcr.io/acme/edge-api:1.0.0",
                "package_purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "source_format": "sarif-2.1.0",
                "scanner_sig": "trivy:CVE-2021-44228",
                "title": "Log4j2 RCE (Trivy Container)",
                "description": "Vulnerable Java dependency in container image",
                "solution": "Bump log4j-core to 2.17.1",
                "severity": "Critical",
                "cves": ["CVE-2021-44228"],
                "cwes": ["CWE-502"],
                "location_uri": "app/lib/log4j-core-2.14.1.jar",
                "detection_mode": "sca_container",
                "ingestion_confidence": 0.90,
                "raw_evidence_excerpt": "Container layer /app/lib/log4j-core-2.14.1.jar",
            },
            # 2) Track B exposure_weakness active_dast (non-CVE default-login!)
            {
                "target_uri": "https://edge-api.acme.test/admin",
                "source_format": "nuclei-jsonl",
                "scanner_sig": "nuclei:default-login",
                "title": "Exposed Admin Panel Default Login" if not xss_and_md_inject else "Admin Panel | <script>alert(1)</script>",
                "description": "Default credentials allow authentication bypass and RCE.",
                "solution": "Disable default account and restrict admin portal.",
                "severity": "Critical",
                "cves": [],
                "tags": ["default-login", "rce", "panel"],
                "affected_port": 8443,
                "protocol": "tcp",
                "detection_mode": "active_dast",
                "ingestion_confidence": 0.95,
                "raw_evidence_excerpt": "HTTP 200 admin/admin login accepted",
            },
            # 3) Validly deferred high-CVSS internal CVE (DEC-VALID-001)
            {
                "ip_address": "10.20.1.50",
                "hostname": "db.internal.test",
                "source_format": "nessus-xml",
                "scanner_sig": "nessus:70001",
                "title": "High CVSS Internal Lib Issue",
                "description": "Requires local privilege and high complexity.",
                "solution": "Apply vendor patch in next maintenance window.",
                "severity": "High",
                "cves": ["CVE-2024-7001"],
                "cwes": ["CWE-120"],
                "affected_port": 5432,
                "protocol": "tcp",
                "detection_mode": "credentialed_host",
                "ingestion_confidence": 0.95,
            },
            # 4) Invalidated deferral (DEC-STALE-002: KEV flipped True & EPSS exceeded!)
            {
                "ip_address": "10.20.1.50",
                "hostname": "db.internal.test",
                "source_format": "nessus-xml",
                "scanner_sig": "nessus:70002",
                "title": "PostgreSQL Old Vulnerability (Now Escalated)",
                "description": "Remote code execution via crafted query",
                "solution": "Upgrade to 16.4",
                "severity": "High",
                "cves": ["CVE-2024-7002"],
                "cwes": ["CWE-89"],
                "affected_port": 5432,
                "protocol": "tcp",
                "detection_mode": "credentialed_host",
                "ingestion_confidence": 0.95,
            },
            # 5) High-CVSS active finding deprioritized due to low EPSS / non-KEV / internal
            {
                "ip_address": "10.20.1.50",
                "hostname": "db.internal.test",
                "source_format": "nessus-xml",
                "scanner_sig": "nessus:70003",
                "title": "High CVSS Unexploited Internal Parser Bug",
                "description": "Theoretical crash with no public exploit.",
                "solution": "Update on next minor upgrade",
                "severity": "High",
                "cves": ["CVE-2024-7003"],
                "affected_port": 5432,
                "protocol": "tcp",
                "detection_mode": "credentialed_host",
                "ingestion_confidence": 0.95,
            },
            # 6) Unmatched Shadow Asset finding!
            {
                "ip_address": "198.51.100.77",
                "hostname": evil_host,
                "asset_metadata": {"open_ports": [80, 443]},
                "source_format": "nessus-xml",
                "scanner_sig": "nessus:80001",
                "title": "Shadow Host Exposed CVE",
                "description": "Uninventoried server running vulnerable service.",
                "solution": "Decommission or patch immediately.",
                "severity": "Critical",
                "cves": ["CVE-2021-44228"],
                "affected_port": 443,
                "protocol": "tcp",
                "detection_mode": "uncredentialed_banner",
                "ingestion_confidence": 0.85,
            },
        ]
    ]
    ingest_normalized_batches(db, target_id, batches, asset_matcher=matcher)
    upsert_enrichment_snapshots(
        db,
        target_id,
        [
            {
                "cve_id": "CVE-2021-44228",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cvss_version": "3.1",
                "cvss_provenance": "NVD",
                "epss_score": 0.153,
                "epss_percentile": 0.92,
                "epss_model_version": "v2025.03.14",
                "epss_date": "2026-11-24",
                "in_kev": True,
                "kev_date_added": "2021-12-10",
                "kev_due_date": "2021-12-24",
                "kev_ransomware": "Known",
                "kev_required_action": "Apply updates per vendor instructions.",
                "verified_exploit": True,
                "sources": ["nvd", "cisa_kev", "epss", "exploitdb"],
            },
            {
                "cve_id": "CVE-2024-7001",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H",
                "cvss_version": "3.1",
                "cvss_provenance": "CNA",
                "epss_score": 0.002,
                "epss_percentile": 0.12,
                "epss_model_version": "v2025.03.14",
                "epss_date": "2026-11-24",
                "in_kev": False,
                "verified_exploit": False,
                "sources": ["cna", "epss"],
            },
            {
                "cve_id": "CVE-2024-7002",
                "cvss_score": 8.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_version": "3.1",
                "cvss_provenance": "NVD",
                "epss_score": 0.25,
                "epss_percentile": 0.96,
                "epss_model_version": "v2025.03.14",
                "epss_date": "2026-11-24",
                "in_kev": True,
                "kev_date_added": "2026-11-20",
                "kev_due_date": "2026-12-11",
                "kev_ransomware": "Unknown",
                "verified_exploit": True,
                "sources": ["nvd", "cisa_kev", "epss"],
            },
            {
                "cve_id": "CVE-2024-7003",
                "cvss_score": 7.8,
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H",
                "cvss_version": "3.1",
                "cvss_provenance": "NVD",
                "epss_score": 0.003,
                "epss_percentile": 0.18,
                "epss_model_version": "v2025.03.14",
                "epss_date": "2026-11-24",
                "in_kev": False,
                "verified_exploit": False,
                "sources": ["nvd", "epss"],
            },
        ],
    )

    tctx = _make_ctx(tmp_path, db, target_id, registry=registry, ledger=ledger)
    run_v2_duckdb_pipeline(ctx=tctx, profile="bod-26-04", decisions_registry=registry)
    snap = ledger.snapshot()
    insert_ledger_events(
        db,
        target_id,
        [
            {
                "seq": e.seq,
                "ts": e.ts,
                "component": e.component,
                "event_type": e.event_type,
                "subject_ref": e.subject_ref,
                "why": {
                    "reason_code": e.why.reason_code,
                    "reason_text": e.why.reason_text,
                    "factor_refs": e.why.factor_refs,
                    "confidence": e.why.confidence,
                    "weight_context": e.why.weight_context,
                },
                "evidence_digest": e.evidence_digest,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in snap.entries
        ],
    )

    diff_report = DiffEngine(db, decisions_registry=registry).compare(base_id, target_id)
    rows = db.query_findings_page(target_id, limit=100)[0]
    by_cve = {r["primary_cve"] or r["title"]: r for r in rows}
    edge_log4j_row = next(
        r for r in rows if r["asset_id"] == "aid_v2_edge_api" and r["primary_cve"] == "CVE-2021-44228"
    )

    return {
        "db": db,
        "base_id": base_id,
        "target_id": target_id,
        "diff_report": diff_report,
        "by_cve": by_cve,
        "edge_log4j_id": edge_log4j_row["finding_id"],
        "ctx": tctx,
    }


def test_md_escape_neutralizes_table_injection_html_and_crlf() -> None:
    raw = "bad | pipe\r\n<script>alert(1)</script>\t`cmd`"
    escaped = md_escape(raw)
    assert "|" not in escaped or "\\|" in escaped
    assert "\n" not in escaped
    assert "\r" not in escaped
    assert "\t" not in escaped
    assert "<script>" not in escaped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in escaped
    assert "\\`cmd\\`" in escaped


def test_html_xss_autoescape_and_markdown_pipe_escape(tmp_path: Path) -> None:
    ws = _seed_v2_workspace(tmp_path, xss_and_md_inject=True)
    db = ws["db"]
    run_id = ws["target_id"]
    diff_report = ws["diff_report"]

    dossier_html = render_dossier_html(db, run_id, diff_report=diff_report)
    roadmap_html = render_executive_roadmap_html(db, run_id, diff_report=diff_report)
    for html_out in (dossier_html, roadmap_html):
        assert "<script>alert(1)</script>" not in html_out
        assert "<script>alert(3)</script>" not in html_out
        assert "<img src=x onerror=alert(2)>" not in html_out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out

    dossier_md = render_dossier_markdown(db, run_id, diff_report=diff_report)
    roadmap_md = render_executive_roadmap_markdown(db, run_id, diff_report=diff_report)
    pr_md = render_diff_pr_comment(diff_report)
    for md_out in (dossier_md, roadmap_md, pr_md):
        assert "<script>alert(1)</script>" not in md_out
        assert "<img src=x onerror=alert(2)>" not in md_out
    assert "OpenSSL RCE \\| &lt;script&gt;alert(1)&lt;/script&gt;" in dossier_md


def test_decision_defense_dossier_sections_and_single_finding_bundle(tmp_path: Path) -> None:
    ws = _seed_v2_workspace(tmp_path, xss_and_md_inject=False)
    db = ws["db"]
    run_id = ws["target_id"]
    diff_report = ws["diff_report"]

    dossier_md = render_dossier_markdown(db, run_id, diff_report=diff_report)
    dossier_html = render_dossier_html(db, run_id, diff_report=diff_report)

    for output in (dossier_md, dossier_html):
        assert "Why Prioritized" in output
        assert "Why Deprioritized / Deferred" in output
        assert "Shadow / Unmatched Asset Disclosure" in output
        assert "15.3% / 92nd" in output
        assert "2021-12-24" in output  # KEV due date
        assert "Known" in output  # KEV ransomware flag
        assert "3-day + Forensic Triage" in output
        assert "exposed=True|exp=active|auto=True|impact=total" in output
        assert "nessus-xml" in output
        assert "sarif-2.1.0" in output
        assert "CVE-2024-7001" in output
        assert "DEC-VALID-001" in output
        assert "CVE-2024-7002" in output
        assert "DEC-STALE-002" in output
        assert "deferred_invalidated" in output
        assert "kev_flipped" in output
        assert "CVE-2024-7003" in output  # high-CVSS deprioritized
        assert "198.51.100.77" in output  # shadow asset
        assert "PCI DSS v4.0.1" in output
        assert "CISA BOD 26-04" in output
        assert "sha256:" in output  # RunManifest digest / intel sha256

    # Single-finding mode + bundle export
    edge_log4j_id = ws["edge_log4j_id"]
    out_dir = tmp_path / "bundle_out"
    bundle = export_dossier_bundle(
        db,
        run_id,
        out_dir,
        finding_id=edge_log4j_id,
        diff_report=diff_report,
        pfh=ws["ctx"].pfh,
    )
    assert set(bundle.keys()) == {"markdown", "html"}
    assert bundle["markdown"].name == f"{edge_log4j_id}_dossier.md"
    assert bundle["html"].name == f"{edge_log4j_id}_dossier.html"
    assert bundle["markdown"].exists()
    assert bundle["html"].exists()
    assert "Log4j2 Remote Code Execution" in bundle["markdown"].read_text(encoding="utf-8")
    assert "CVE-2024-7003" not in bundle["markdown"].read_text(encoding="utf-8")

    # Full-run bundle export
    full_bundle = export_dossier_bundle(db, run_id, out_dir, diff_report=diff_report)
    assert full_bundle["markdown"].name == "dossier.md"
    assert full_bundle["html"].name == "dossier.html"


def test_executive_roadmap_offline_zero_cdn_and_velocity(tmp_path: Path) -> None:
    ws = _seed_v2_workspace(tmp_path, xss_and_md_inject=False)
    db = ws["db"]
    run_id = ws["target_id"]
    diff_report = ws["diff_report"]

    roadmap_md = render_executive_roadmap_markdown(db, run_id, diff_report=diff_report)
    roadmap_html = render_executive_roadmap_html(db, run_id, diff_report=diff_report)
    dossier_html = render_dossier_html(db, run_id, diff_report=diff_report)

    for text in (roadmap_md, roadmap_html):
        assert "BOD 26-04 / Priority SLA" in text
        assert "Owner-Grouped Remediation Batches" in text
        assert "platform-edge" in text
        assert "core-data" in text
        assert "Top Quick-Win Fixes" in text
        assert "Scan-over-Scan" in text
        assert "Shadow / Unmatched Asset Disclosure" in text

    for html_out in (roadmap_html, dossier_html):
        low = html_out.lower()
        assert "<style>" in low
        assert "@media print" in low
        assert "<script" not in low
        assert "<link" not in low
        assert "@import" not in low
        assert "cdn." not in low
        assert "fonts.googleapis" not in low
        assert "unpkg" not in low
        assert "jsdelivr" not in low
        assert not re.search(r"(?:src|href)\s*=\s*['\"]?https?://", low)
        assert not re.search(r"url\s*\(\s*['\"]?https?://", low)


def test_custom_template_dir_override_and_symlink_rejection(tmp_path: Path) -> None:
    ws = _seed_v2_workspace(tmp_path)
    db = ws["db"]
    run_id = ws["target_id"]

    tdir = tmp_path / "custom_templates"
    tdir.mkdir()
    (tdir / "dossier.md.j2").write_text(
        "CUSTOM DOSSIER {{ run.run_id | md_escape }} prio={{ prioritized_findings | length }}\n",
        encoding="utf-8",
    )

    custom_md = render_dossier_markdown(db, run_id, template_dir=tdir)
    assert custom_md.startswith(f"CUSTOM DOSSIER {run_id}")
    # Unoverridden template still loads from PackageLoader via ChoiceLoader
    fallback_html = render_dossier_html(db, run_id, template_dir=tdir)
    assert "VulnParse-Pin Decision Defense Dossier" in fallback_html

    sym_dir = tmp_path / "sym_templates"
    sym_dir.symlink_to(tdir)
    with pytest.raises(ValueError, match="Refusing symlink"):
        render_dossier_markdown(db, run_id, template_dir=sym_dir)


def test_diff_pr_comment_renders_all_four_deltas_and_stale_alerts(tmp_path: Path) -> None:
    ws = _seed_v2_workspace(tmp_path)
    pr_md = render_diff_pr_comment(ws["diff_report"])
    assert "Stale-Assumption Alerts" in pr_md
    assert "Newly Introduced High-Risk Findings" in pr_md
    assert "Threat-Intel Escalated Findings" in pr_md
    assert "Verified Remediated Findings" in pr_md
    assert "DEC-STALE-002" in pr_md
    assert "CVE-2024-7099" in pr_md
    assert "verified_patched" in pr_md


def test_reportgen_namespace_parity_and_streaming_without_full_ram_dumps(tmp_path: Path) -> None:
    ws = _seed_v2_workspace(tmp_path)
    db = ws["db"]
    run_id = ws["target_id"]

    # 1. materialize_presentation supports both 'namespace' and 'namespaced'
    scan_dict = {
        "assets": [{"asset_id": "a1", "findings": [{"finding_id": "f1"}]}],
        "derived": {
            "passes": {
                "Scoring@2.0": {
                    "data": {
                        "scored_findings": {
                            "f1": {"raw_score": 8.0, "operational_score": 5.0, "risk_band": "High", "reason": "test"}
                        },
                        "asset_criticality": {"a1": "High"},
                    }
                }
            }
        },
    }
    ns1 = materialize_presentation(scan_dict, overlay_mode="namespace")
    ns2 = materialize_presentation(scan_dict, overlay_mode="namespaced")
    assert ns1 == ns2
    assert ns1["presentation"]["overlay_mode"] == "namespace"

    # 2. _estimate_dict_size and _stream_json_dump must NOT call json.dumps() on the whole payload
    payload = {
        "schema": "test",
        "assets": [{"asset_id": f"a-{i}", "findings": [{"id": f"f-{i}"}]} for i in range(50)],
    }
    with patch.object(reportgen.json, "dumps", wraps=json.dumps) as spy_dumps:
        est = _estimate_dict_size(payload)
        assert est > 100
        assert spy_dumps.call_count == 0

    out_stream = tmp_path / "streamed.json"
    with out_stream.open("w", encoding="utf-8") as fh:
        with patch.object(reportgen.json, "dump", side_effect=AssertionError("full json.dump forbidden")):
            _stream_json_dump(payload, fh, indent=2)
    loaded = json.loads(out_stream.read_text(encoding="utf-8"))
    assert len(loaded["assets"]) == 50

    # 3. export_duckdb_json streams valid JSON for both 'namespace' and 'flatten'
    ns_json_path = tmp_path / "out_namespace.json"
    flat_json_path = tmp_path / "out_flatten.json"
    export_duckdb_json(db, run_id, ns_json_path, presentation="namespace", pfh=ws["ctx"].pfh)
    export_duckdb_json(db, run_id, flat_json_path, presentation="flatten")

    ns_data = json.loads(ns_json_path.read_text(encoding="utf-8"))
    flat_data = json.loads(flat_json_path.read_text(encoding="utf-8"))
    assert ns_data["run_id"] == run_id
    assert len(ns_data["assets"]) == 3
    total_ns_findings = sum(len(a["findings"]) for a in ns_data["assets"])
    assert total_ns_findings == 6
    sample_f = next(
        f
        for a in ns_data["assets"]
        if a["asset_id"] == "aid_v2_edge_api"
        for f in a["findings"]
        if f["primary_cve"] == "CVE-2021-44228"
    )
    assert "Scoring@3.0" in sample_f["derived"]
    assert "Triage@2.0" in sample_f["derived"]
    assert len(sample_f["evidence"]) == 2

    sample_flat = next(f for a in flat_data["assets"] for f in a["findings"] if f["primary_cve"] == "CVE-2021-44228")
    assert "priority_tier" in sample_flat
    assert "operational_score" in sample_flat


def test_duckdb_csv_and_empty_run_handling(tmp_path: Path) -> None:
    ws = _seed_v2_workspace(tmp_path, xss_and_md_inject=True)
    db = ws["db"]
    run_id = ws["target_id"]

    # Inject formula payload into solution for CSV sanitization check
    db.execute(
        "UPDATE findings SET solution = ? WHERE run_id = ? AND primary_cve = 'CVE-2021-44228'",
        ["=CMD|' /C calc'!A0", run_id],
    )
    csv_path = tmp_path / "export_v2.csv"
    res_path = export_duckdb_csv(db, run_id, csv_path, profile="full", pfh=ws["ctx"].pfh)
    assert res_path == csv_path.resolve()

    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames or []
        rows = list(reader)

    for required_col in (
        "epss_percentile",
        "cvss_provenance",
        "cvss_version",
        "scoring_track",
        "detection_mode",
        "signal_reliability",
        "priority_tier",
        "ssvc_action",
        "sla_bucket",
        "inventory_status",
        "owner",
        "decision_status",
    ):
        assert required_col in cols

    log4j_row = next(r for r in rows if r["primary_cve"] == "CVE-2021-44228")
    assert log4j_row["solution"].startswith("'=")
    assert log4j_row["cvss_provenance"] == "NVD"
    assert log4j_row["cvss_version"] == "3.1"

    # Empty run safety across all exporters & renderers
    empty_id = "run-empty"
    ensure_run(db, empty_id, created_at_utc="2026-11-24T01:00:00Z", vpp_version="2.0.0", profile="default")
    assert "Why Prioritized" in render_dossier_markdown(db, empty_id)
    assert "VulnParse-Pin Decision Defense Dossier" in render_dossier_html(db, empty_id)
    assert "Key Posture Indicators" in render_executive_roadmap_markdown(db, empty_id)
    assert "Executive Vulnerability Summary" in render_executive_roadmap_html(db, empty_id)

    empty_csv = tmp_path / "empty.csv"
    export_duckdb_csv(db, empty_id, empty_csv)
    assert empty_csv.exists()
    empty_json = tmp_path / "empty.json"
    export_duckdb_json(db, empty_id, empty_json)
    assert json.loads(empty_json.read_text(encoding="utf-8"))["assets"] == []

    manifest = build_runmanifest_from_db(db, run_id, mode="expanded")
    assert verify_runmanifest(manifest)["manifest_version"] == "2.0"
