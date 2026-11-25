# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Async Textual pilot tests for `vulnparse_pin.ui.app.VppApp`."""

from __future__ import annotations

import importlib.util
import shutil
import sys
import types
from contextlib import ExitStack
from importlib import resources
from pathlib import Path

import pytest
from textual.widgets import DataTable, Input, Static, TabbedContent

from vulnparse_pin.main import main
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import ensure_run, get_run_summary_counts, query_findings_page
from vulnparse_pin.ui.app import DeferralModal, VppApp


def _seed_demo_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    demo_db = tmp_path / "tui_demo.vpp.db"
    demo_out = tmp_path / "demo_out"
    decisions_copy = tmp_path / "decisions.yaml"
    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        shutil.copy2(demo_dir / "decisions.yaml", decisions_copy)
    rc = main(["demo", "--db", str(demo_db), "--output-dir", str(demo_out), "--profile", "bod-26-04", "--no-ui"])
    assert rc == 0
    return demo_db, decisions_copy, tmp_path / "tui_exports"


@pytest.mark.asyncio
async def test_tui_filters_pagination_inspector_diff_and_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path, monkeypatch)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=2,
    )

    async with app.run_test(size=(130, 42)) as pilot:
        await pilot.pause()

        kpi_text = str(app.query_one("#kpi-banner", Static).render())
        assert "demo-current" in kpi_text
        assert "SHADOW ASSETS:" in kpi_text
        assert "INVALIDATED DEFERRALS:" in kpi_text
        assert app.query_one("#kpi-banner", Static).region.y >= 1
        assert app.query_one("#filter-bar", Static).region.y >= 1
        assert app.query_one("#status-line", Static).region.y >= 1

        inspector_text = str(app.query_one("#finding-inspector", Static).render())
        assert "[Score Trace]" in inspector_text
        assert "[Merged Scanner Evidence" in inspector_text

        # Priority tier filter (1 -> P1, 0 -> clear)
        await pilot.press("1")
        await pilot.pause()
        assert app.filter_priority == "P1"
        assert app.current_rows
        assert all(r["priority_tier"] == "P1" for r in app.current_rows)

        await pilot.press("0")
        await pilot.pause()
        assert app.filter_priority is None

        # Track filter cycles None -> cve_threat -> exposure_weakness -> None
        await pilot.press("t")
        await pilot.pause()
        assert app.filter_track == "cve_threat"
        assert all(r["scoring_track"] == "cve_threat" for r in app.current_rows)

        await pilot.press("t")
        await pilot.pause()
        assert app.filter_track == "exposure_weakness"
        assert app.current_rows
        assert all(r["scoring_track"] == "exposure_weakness" for r in app.current_rows)

        await pilot.press("t")
        await pilot.pause()
        assert app.filter_track is None

        # KEV filter 'k'
        await pilot.press("k")
        await pilot.pause()
        assert app.filter_kev is True
        assert app.current_rows
        assert all(bool(r["in_kev"]) for r in app.current_rows)
        await pilot.press("k")
        await pilot.pause()

        # Unmatched Shadow Asset filter 'u'
        await pilot.press("u")
        await pilot.pause()
        assert app.filter_inventory == "unmatched_shadow"
        assert app.current_rows
        assert all(r["inventory_status"] == "unmatched_shadow" for r in app.current_rows)
        await pilot.press("u")
        await pilot.pause()

        # Pagination '[' / ']'
        assert app.page_offset == 0
        await pilot.press("]")
        await pilot.pause()
        assert app.page_offset == 2
        await pilot.press("[")
        await pilot.pause()
        assert app.page_offset == 0

        # Highlight next row updates inspector
        first_fid = app.selected_finding_id
        await pilot.press("down")
        await pilot.pause()
        assert app.selected_finding_id != first_fid
        updated_inspector = str(app.query_one("#finding-inspector", Static).render())
        assert str(app.selected_finding_id) in updated_inspector

        # Search '/' + Enter focuses table again
        await pilot.press("/")
        await pilot.pause()
        assert isinstance(app.focused, Input)
        await pilot.press("4", "4", "2", "2", "8", "enter")
        await pilot.pause()
        assert isinstance(app.focused, DataTable)
        assert app.current_rows
        assert any(r.get("primary_cve") == "CVE-2021-44228" for r in app.current_rows)

        await pilot.press("0")
        await pilot.pause()

        # Diff tab 'd'
        await pilot.press("d")
        await pilot.pause()
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-diff"
        diff_text = str(app.query_one("#diff-panel", Static).render())
        assert "Diff Report: demo-baseline -> demo-current" in diff_text
        assert "Invalidated Assumptions" in diff_text

        await pilot.press("d")
        await pilot.pause()
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-findings"

        # Export selected finding ('e') and full run ('E')
        await pilot.press("e")
        await pilot.pause()
        assert "[OK] Exported finding" in app.last_status_message
        assert any(export_dir.glob("*.html"))

        await pilot.press("E")
        await pilot.pause()
        assert "[OK] Exported run" in app.last_status_message
        assert any(export_dir.glob("*.md"))


@pytest.mark.asyncio
async def test_tui_deferral_modal_persists_yaml_and_updates_duckdb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path, monkeypatch)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=25,
    )

    async with app.run_test(size=(130, 42)) as pilot:
        await pilot.pause()
        # Focus Log4j finding via search
        await pilot.press("/")
        await pilot.press("4", "4", "2", "2", "8", "enter")
        await pilot.pause()
        target_fid = app.selected_finding_id
        assert target_fid is not None

        # Open DeferralModal with 'f'
        await pilot.press("f")
        await pilot.pause()
        assert isinstance(app.screen, DeferralModal)

        modal = app.screen
        modal.query_one("#defer-rationale", Input).value = "Isolated behind mTLS WAF control"
        modal.query_one("#defer-owner", Input).value = "tui-pilot@acme.test"
        modal.query_one("#defer-expires", Input).value = "2028-01-15"
        await pilot.click("#defer-save")
        await pilot.pause()

        assert not isinstance(app.screen, DeferralModal)
        assert "[OK] Saved deferred" in app.last_status_message
        yaml_text = decisions_path.read_text(encoding="utf-8")
        assert "Isolated behind mTLS WAF control" in yaml_text
        assert "tui-pilot@acme.test" in yaml_text

        with VppDatabase(demo_db, read_only=True) as db:
            rows, _ = query_findings_page(db, "demo-current", search="CVE-2021-44228", limit=50)
            matching = [r for r in rows if r["finding_id"] == target_fid]
            assert matching
            assert matching[0]["decision_status"] == "deferred_valid"


@pytest.mark.asyncio
async def test_tui_handles_missing_empty_and_zero_finding_db_safely(tmp_path: Path) -> None:
    # Missing DB
    missing_app = VppApp(db_path=tmp_path / "does_not_exist.db")
    async with missing_app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert "Workspace unavailable" in str(missing_app.query_one("#kpi-banner", Static).render())

    # Initialized DB with 1 empty run (0 findings)
    empty_db = tmp_path / "empty.vpp.db"
    with VppDatabase(empty_db) as db:
        ensure_run(db, "empty-run", profile="default")

    empty_app = VppApp(db_path=empty_db, run_id="empty-run")
    async with empty_app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert "[WARN] No finding selected" in empty_app.last_status_message
        assert "No findings match" in str(empty_app.query_one("#finding-inspector", Static).render())


@pytest.mark.asyncio
async def test_tui_skips_empty_latest_run_and_cycles_runs_with_r(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path, monkeypatch)
    with VppDatabase(demo_db, read_only=False) as db:
        ensure_run(
            db,
            "empty-latest-run",
            created_at_utc="2099-01-01T00:00:00Z",
            profile="default",
            overwrite=True,
        )

    app = VppApp(
        db_path=demo_db,
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=25,
    )
    async with app.run_test(size=(130, 42)) as pilot:
        await pilot.pause()
        # Skips empty-latest-run and opens demo-current with populated findings
        assert app.run_id == "demo-current"
        assert app.total_filtered > 0
        assert len(app.available_runs) == 3

        # Cycle backwards/next across runs with 'r'
        await pilot.press("r")
        await pilot.pause()
        assert app.run_id == "demo-baseline"
        assert app.total_filtered > 0

        await pilot.press("r")
        await pilot.pause()
        assert app.run_id == "empty-latest-run"
        assert app.total_filtered == 0
        assert "Workspace DB" in str(app.query_one("#finding-inspector", Static).render())

        await pilot.press("r")
        await pilot.pause()
        assert app.run_id == "demo-current"
        assert app.total_filtered > 0
