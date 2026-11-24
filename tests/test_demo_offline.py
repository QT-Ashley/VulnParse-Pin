# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Offline demo bundle integrity and end-to-end `vpp demo` verification tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import types
from contextlib import ExitStack
from importlib import resources
from pathlib import Path

import pytest
import requests

from vulnparse_pin.core.diff_engine import DiffEngine
from vulnparse_pin.main import main
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    get_finding_detail,
    get_run_summary_counts,
    get_shadow_assets,
    list_runs,
    query_findings_page,
)


def test_demo_bundle_size_under_500kb_and_complete() -> None:
    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        files = [p for p in demo_dir.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
        total_bytes = sum(p.stat().st_size for p in files)
        assert total_bytes < 500_000, f"Demo pack exceeds 500 KB: {total_bytes} bytes"

        expected_rel = {
            "assets.yaml",
            "decisions.yaml",
            "demo_baseline.nessus",
            "demo.nessus",
            "demo_trivy.sarif",
            "demo_nuclei.jsonl",
            "demo_semgrep.sarif",
            "demo_nmap.xml",
            "intel_snapshot/epss.csv",
            "intel_snapshot/kev.json",
            "intel_snapshot/nvd.json",
            "intel_snapshot/exploitdb.csv",
            "intel_snapshot/ghsa/ghsa_demo.json",
        }
        actual_rel = {p.relative_to(demo_dir).as_posix() for p in files}
        missing = expected_rel - actual_rel
        assert not missing, f"Missing demo bundle files: {missing}"


def test_vpp_demo_runs_100_percent_offline_and_populates_showcase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _no_network(*_args, **_kwargs):
        raise AssertionError("vpp demo must run 100% offline with zero HTTP calls")

    monkeypatch.setattr(requests, "get", _no_network)
    monkeypatch.setattr(requests, "post", _no_network)
    monkeypatch.setattr(requests, "head", _no_network)
    monkeypatch.setattr(requests, "request", _no_network)
    monkeypatch.setattr(requests.Session, "request", _no_network)

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _no_network)

    demo_db = tmp_path / "demo.vpp.db"
    demo_out = tmp_path / "demo_out"

    rc = main(
        [
            "demo",
            "--db",
            str(demo_db),
            "--output-dir",
            str(demo_out),
            "--profile",
            "bod-26-04",
            "--no-ui",
        ]
    )
    assert rc == 0
    stdout = capsys.readouterr().out
    assert "VulnParse-Pin v2.0.0" in stdout
    assert "Shadow" in stdout or "SHADOW" in stdout
    assert demo_db.exists()
    assert (demo_out / "executive_roadmap.html").exists()
    assert (demo_out / "runmanifest.json").exists()
    assert any(demo_out.glob("*.md"))
    assert any(demo_out.glob("*.html"))

    with VppDatabase(demo_db, read_only=True) as db:
        runs = list_runs(db)
        run_ids = {r["run_id"] for r in runs}
        assert {"demo-baseline", "demo-current"}.issubset(run_ids)

        counts = get_run_summary_counts(db, "demo-current")
        assert counts["matched_assets"] >= 2
        assert counts["shadow_assets"] >= 1
        assert counts["cve_findings"] >= 1
        assert counts["exposure_findings"] >= 1
        assert counts["deduplicated_findings"] >= 1
        assert counts["kev_findings"] >= 1
        assert counts["by_priority_tier"].get("P1", 0) >= 1

        rows, total = query_findings_page(db, "demo-current", limit=200, offset=0)
        assert total == len(rows) and total >= 5

        # Cross-scanner dedup on CVE-2021-44228 across Nessus + Trivy
        log4j_rows = [r for r in rows if r.get("primary_cve") == "CVE-2021-44228" and r.get("source_count", 0) >= 2]
        assert log4j_rows, "Expected cross-scanner deduplicated CVE-2021-44228 finding"
        detail = get_finding_detail(db, "demo-current", log4j_rows[0]["finding_id"])
        assert detail is not None
        formats = {ev.get("source_format") for ev in (detail.get("evidence") or [])}
        assert len(formats) >= 2

        # Signal reliability / Track B coverage (Semgrep SAST = 0.55 reliability & P1 capped)
        tracks = {r.get("scoring_track") for r in rows}
        assert {"cve_threat", "exposure_weakness"}.issubset(tracks)
        sast_rows = [r for r in rows if abs(float(r.get("signal_reliability") or 0.0) - 0.55) < 0.01]
        assert sast_rows, "Expected Semgrep SAST finding with signal_reliability=0.55"
        assert all(r.get("priority_tier") != "P1" for r in sast_rows)

        # Shadow assets & invalidated deferral coverage
        shadows = get_shadow_assets(db, "demo-current")
        shadow_idents = {s.get("ip_address") or s.get("hostname") or s.get("canonical_key") for s in shadows}
        assert any("198.51.100" in str(x) for x in shadow_idents)

        statuses = {r.get("decision_status") for r in rows}
        assert "deferred_valid" in statuses
        assert "deferred_invalidated" in statuses

        # Diff deltas populated cleanly
        report = DiffEngine(db).compare("demo-baseline", "demo-current", persist=False)
        assert report.summary.newly_introduced_high_risk >= 1
        assert report.summary.threat_intel_escalated >= 1
        assert report.summary.verified_remediated >= 1
        assert report.summary.invalidated_assumptions >= 1
