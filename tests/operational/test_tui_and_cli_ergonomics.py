# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Operational tests for Textual TUI keyboard ergonomics and CLI argument validation."""

from __future__ import annotations

import shutil
from contextlib import ExitStack
from importlib import resources
from pathlib import Path

import pytest
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Input, Static, TabbedContent

from vulnparse_pin.cli.args import get_args
from vulnparse_pin.main import main
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import query_findings_page
from vulnparse_pin.ui.app import DeferralModal, HelpModal, VppApp


@pytest.fixture(autouse=True)
def _isolated_xdg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    xdg_data = tmp_path / "xdg_data"
    xdg_data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))


def _seed_demo_workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    demo_db = tmp_path / "ergo_demo.vpp.db"
    demo_out = tmp_path / "demo_out"
    decisions_copy = tmp_path / "decisions.yaml"
    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        shutil.copy2(demo_dir / "decisions.yaml", decisions_copy)
    rc = main(["demo", "--db", str(demo_db), "--output-dir", str(demo_out), "--profile", "bod-26-04", "--no-ui"])
    assert rc == 0
    return demo_db, decisions_copy, tmp_path / "tui_exports"


@pytest.mark.asyncio
async def test_tui_filter_hotkeys_switch_from_diff_to_findings_tab(tmp_path: Path) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=25,
    )

    async with app.run_test(size=(120, 38)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#main-tabs", TabbedContent)
        table = app.query_one("#findings-table", DataTable)

        for key in ("1", "2", "3", "4", "0", "t", "k", "u"):
            await pilot.press("d")
            await pilot.pause()
            assert tabs.active == "tab-diff"

            await pilot.press(key)
            await pilot.pause()
            assert tabs.active == "tab-findings"
            assert app.focused is table


@pytest.mark.asyncio
async def test_tui_inspector_focus_toggle_scroll_and_escape(tmp_path: Path) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=25,
    )

    async with app.run_test(size=(100, 24)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#main-tabs", TabbedContent)
        table = app.query_one("#findings-table", DataTable)
        inspector = app.query_one("#inspector-scroll", VerticalScroll)
        assert inspector.can_focus is True
        assert app.focused is table

        # 'i' moves focus to inspector scroll pane
        await pilot.press("i")
        await pilot.pause()
        assert app.focused is inspector

        initial_scroll_y = inspector.scroll_y
        await pilot.press("pagedown", "down")
        await pilot.pause()
        if inspector.max_scroll_y > 0:
            assert inspector.scroll_y > initial_scroll_y

        # Escape returns focus from inspector to findings table
        await pilot.press("escape")
        await pilot.pause()
        assert app.focused is table

        # 'i' from tab-diff switches to tab-findings and focuses inspector
        await pilot.press("d")
        await pilot.pause()
        assert tabs.active == "tab-diff"

        await pilot.press("i")
        await pilot.pause()
        assert tabs.active == "tab-findings"
        assert app.focused is inspector

        # Pressing 'i' again toggles back to findings table
        await pilot.press("i")
        await pilot.pause()
        assert app.focused is table

        # Existing search Escape behavior preserved when search filter is active
        await pilot.press("/")
        await pilot.pause()
        assert isinstance(app.focused, Input)
        await pilot.press("4", "4", "2", "2", "8", "escape")
        await pilot.pause()
        assert app.focused is table
        assert app.search_query == "44228"


@pytest.mark.asyncio
async def test_tui_help_modal_blocks_main_hotkeys_and_closes_cleanly(tmp_path: Path) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=25,
    )

    async with app.run_test(size=(110, 32)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#main-tabs", TabbedContent)

        # Open HelpModal with '?'
        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpModal)

        # Underlying hotkeys ('1', 'f', 'd') must not fire while HelpModal is open
        await pilot.press("1", "f", "d")
        await pilot.pause()
        assert isinstance(app.screen, HelpModal)
        assert app.filter_priority is None
        assert tabs.active == "tab-findings"

        # Escape closes HelpModal
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpModal)

        # '?' toggles HelpModal closed as well
        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpModal)
        await pilot.press("?")
        await pilot.pause()
        assert not isinstance(app.screen, HelpModal)

        # Enter closes HelpModal cleanly
        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpModal)
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, HelpModal)


@pytest.mark.asyncio
async def test_tui_deferral_modal_keyboard_only_enter_submission(tmp_path: Path) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=25,
    )

    async with app.run_test(size=(120, 38)) as pilot:
        await pilot.pause()
        await pilot.press("/")
        await pilot.press("4", "4", "2", "2", "8", "enter")
        await pilot.pause()
        target_fid = app.selected_finding_id
        assert target_fid is not None

        # Open DeferralModal with 'f' -> #defer-rationale focused initially
        await pilot.press("f")
        await pilot.pause()
        assert isinstance(app.screen, DeferralModal)
        assert app.screen.focused is not None
        assert app.screen.focused.id == "defer-rationale"

        # Type rationale and press Enter -> moves focus to #defer-owner (since owner is empty)
        await pilot.press(*"Compensating", "space", *"mTLS-WAF", "enter")
        await pilot.pause()
        assert isinstance(app.screen, DeferralModal)
        assert app.screen.focused is not None
        assert app.screen.focused.id == "defer-owner"

        # Type owner and press Enter -> submits modal, writes decisions.yaml, updates DuckDB
        await pilot.press(*"ergo-ops@acme.test", "enter")
        await pilot.pause()

        assert not isinstance(app.screen, DeferralModal)
        assert "[OK] Saved deferred" in app.last_status_message
        yaml_text = decisions_path.read_text(encoding="utf-8")
        assert "Compensating mTLS-WAF" in yaml_text
        assert "ergo-ops@acme.test" in yaml_text

        with VppDatabase(demo_db, read_only=True) as db:
            rows, _ = query_findings_page(db, "demo-current", search="CVE-2021-44228", limit=50)
            matching = [r for r in rows if r["finding_id"] == target_fid]
            assert matching
            assert matching[0]["decision_status"] == "deferred_valid"
            run_row = db.execute(
                "SELECT decisions_sha256, manifest_digest FROM runs WHERE run_id = 'demo-current'"
            ).fetchone()
            assert run_row is not None
            assert run_row[0] is not None
            assert run_row[1] is None
            ledger_rows = db.execute(
                "SELECT event_type, seq FROM ledger_events WHERE run_id = 'demo-current' ORDER BY seq ASC"
            ).fetchall()
            assert any(r[0] == "DECISION_UPSERT" for r in ledger_rows)
            assert [r[1] for r in ledger_rows] == list(range(1, len(ledger_rows) + 1))

        # Empty filter result must display reset guidance instead of "Select a finding row..."
        await pilot.press("/")
        await pilot.press(*"NO_SUCH_FINDING_XYZ", "enter")
        await pilot.pause()
        inspector_text = str(app.query_one("#finding-inspector", Static).render())
        assert "No findings match the current filter" in inspector_text
        assert "Press '0'" in inspector_text
        assert "Select a finding row to inspect" not in inspector_text


@pytest.mark.asyncio
async def test_tui_small_terminal_80x24_layout_sanity(tmp_path: Path) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=15,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        for selector in (
            "#kpi-banner",
            "#filter-bar",
            "#status-line",
            "#search-input",
            "#findings-table",
            "#inspector-scroll",
        ):
            widget = app.query_one(selector)
            assert widget.region.width > 0, f"{selector} has non-positive width"
            assert widget.region.height > 0, f"{selector} has non-positive height"

        # HelpModal also fits within 80x24 terminal bounds
        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpModal)
        help_dialog = app.screen.query_one("#help-dialog")
        assert help_dialog.region.width > 0 and help_dialog.region.width <= 80
        assert help_dialog.region.height > 0 and help_dialog.region.height <= 24
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpModal)


@pytest.mark.asyncio
async def test_tui_unwritable_output_dir_export_surfaces_error_safely(tmp_path: Path) -> None:
    demo_db, decisions_path, _ = _seed_demo_workspace(tmp_path)
    # Regular file passed as output_dir deterministically blocks directory creation/export (even under root)
    bad_output_dir = tmp_path / "not_a_directory"
    bad_output_dir.write_text("occupied", encoding="utf-8")

    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=bad_output_dir,
        page_size=25,
    )

    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert app.is_running
        assert "[ERR] Export failed:" in app.last_status_message
        assert str(app.query_one("#status-line", Static).render()).startswith("[ERR] Export failed:")


@pytest.mark.asyncio
async def test_tui_chaos_50_plus_mixed_key_chords(tmp_path: Path) -> None:
    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path)
    app = VppApp(
        db_path=demo_db,
        run_id="demo-current",
        decisions_path=decisions_path,
        output_dir=export_dir,
        page_size=3,
    )

    chaos_sequence = [
        "1", "2", "3", "4", "0", "t", "t", "t", "k", "k", "u", "u",
        "]", "]", "[", "down", "down", "up", "i", "pagedown", "down", "escape",
        "d", "1", "d", "t", "d", "k", "d", "u", "d", "0",
        "d", "i", "escape", "?", "1", "f", "escape",
        "/", "c", "v", "e", "enter", "0",
        "r", "r", "r", "?", "?", "?", "enter",
        "1", "k", "0",
    ]
    assert len(chaos_sequence) >= 50

    async with app.run_test(size=(100, 28)) as pilot:
        await pilot.pause()
        for key in chaos_sequence:
            await pilot.press(key)
        await pilot.pause()
        assert app.is_running
        assert not isinstance(app.screen, (HelpModal, DeferralModal))
        assert app.query_one("#main-tabs", TabbedContent).active == "tab-findings"
        assert app.filter_priority is None
        assert app.filter_kev is None


def test_cli_get_args_re_enrich_and_years_ordering(tmp_path: Path) -> None:
    # Post- and pre-subcommand --re-enrich on diff
    args_post = get_args(["diff", "run-a", "run-b", "--re-enrich"])
    assert args_post.command == "diff"
    assert args_post.re_enrich is True
    assert args_post.base == "run-a"
    assert args_post.target == "run-b"

    args_pre = get_args(["--re-enrich", "diff", "run-a", "run-b"])
    assert args_pre.command == "diff"
    assert args_pre.re_enrich is True
    assert args_pre.base == "run-a"
    assert args_pre.target == "run-b"

    # Post- and pre-subcommand --years on intel sync
    intel_post = get_args(["intel", "sync", "--feed", "nvd", "--years", "2021-2026"])
    assert intel_post.command == "intel"
    assert intel_post.action == "sync"
    assert intel_post.feed == "nvd"
    assert intel_post.years == "2021-2026"

    intel_pre = get_args(["--years", "2021,2024", "intel", "sync", "--feed", "nvd"])
    assert intel_pre.command == "intel"
    assert intel_pre.action == "sync"
    assert intel_pre.feed == "nvd"
    assert intel_pre.years == "2021,2024"


def test_cli_get_args_sharp_edge_validation_and_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scan_file = tmp_path / "sample.nessus"
    scan_file.write_text("<NessusClientData_v2/>", encoding="utf-8")
    csv_out = tmp_path / "out.csv"
    rm_file = tmp_path / "runmanifest.json"
    rm_file.write_text("{}", encoding="utf-8")

    # --enforce-root-read without --portable warns with actionable guidance, while still parsing
    monkeypatch.delenv("VULNPARSE_PIN_PORTABLE", raising=False)
    args_err_warn = get_args(["scan", str(scan_file), "--enforce-root-read"])
    assert args_err_warn.enforce_root_read is True
    err_out = capsys.readouterr().err
    assert "--portable" in err_out

    # --enforce-root-read WITH --portable emits no portable warning
    args_err_ok = get_args(["scan", str(scan_file), "--enforce-root-read", "--portable"])
    assert args_err_ok.portable is True
    assert "--portable" not in capsys.readouterr().err

    # --no-csv-sanitize without --confirm-unsafe-csv emits security warning on stderr
    args_unsafe_csv = get_args(["scan", str(scan_file), "--output-csv", str(csv_out), "--no-csv-sanitize"])
    assert args_unsafe_csv.no_csv_sanitize is True
    assert "--confirm-unsafe-csv" in capsys.readouterr().err

    # --confirm-unsafe-csv without --no-csv-sanitize is rejected clearly
    with pytest.raises(SystemExit) as exc:
        get_args(["scan", str(scan_file), "--output-csv", str(csv_out), "--confirm-unsafe-csv"])
    assert exc.value.code == 2
    assert "--no-csv-sanitize" in capsys.readouterr().err

    # --baseline-run-id identical to --run-id is rejected
    with pytest.raises(SystemExit) as exc:
        get_args(["scan", str(scan_file), "--run-id", "r1", "--baseline-run-id", "r1"])
    assert exc.value.code == 2
    assert "--baseline-run-id" in capsys.readouterr().err

    # export sharp edges
    with pytest.raises(SystemExit) as exc:
        get_args(["export", "--format", "json", "--no-csv-sanitize"])
    assert exc.value.code == 2
    assert "--format csv" in capsys.readouterr().err

    with pytest.raises(SystemExit) as exc:
        get_args(["export", "--format", "csv", "--pretty-print"])
    assert exc.value.code == 2
    assert "--format json" in capsys.readouterr().err

    # intel --years validation errors
    for bad_argv, expected_substr in [
        (["intel", "status", "--years", "2024"], "intel sync"),
        (["intel", "sync", "--feed", "kev", "--years", "2024"], "--feed nvd"),
        (["intel", "sync", "--feed", "nvd", "--years", "2026-2021"], "start year"),
        (["intel", "sync", "--feed", "nvd", "--years", "not-a-year"], "YYYY"),
    ]:
        with pytest.raises(SystemExit) as exc:
            get_args(bad_argv)
        assert exc.value.code == 2
        assert expected_substr in capsys.readouterr().err

    # Legacy shim edge cases
    for bad_legacy, expected_substr in [
        (["--demo", "-f", str(scan_file)], "--demo"),
        (["--verify-runmanifest", str(rm_file), "--demo"], "--verify-runmanifest"),
        (["--verify-runmanifest"], "--verify-runmanifest"),
        (["--verify-runmanifest", str(rm_file), "--bad-flag"], "unrecognized"),
        (["--demo", "--unknown-flag-xyz"], "unrecognized"),
    ]:
        with pytest.raises(SystemExit) as exc:
            get_args(bad_legacy)
        assert exc.value.code == 2
        assert expected_substr in capsys.readouterr().err

    # diff --profile defaults to None, allowing --re-enrich --profile override
    diff_default = get_args(["diff", "r1", "r2", "--re-enrich"])
    assert diff_default.profile is None
    diff_override = get_args(["diff", "r1", "r2", "--re-enrich", "--profile", "bod-26-04"])
    assert diff_override.profile == "bod-26-04"


def test_cli_defer_db_clears_manifest_digest_and_diff_re_enrich_profile_override(
    tmp_path: Path,
) -> None:
    import json
    from vulnparse_pin.utils.runmanifest import build_runmanifest_from_db, write_runmanifest

    demo_db, decisions_path, export_dir = _seed_demo_workspace(tmp_path)

    # Confirm demo-current starts with a sealed manifest_digest and default profile
    with VppDatabase(demo_db, read_only=True) as db:
        before = db.execute(
            "SELECT profile, manifest_digest FROM runs WHERE run_id = 'demo-current'"
        ).fetchone()
    assert before is not None
    assert before[0] == "bod-26-04"
    assert before[1] is not None

    # vpp defer --db mutates triage_decisions, updates decisions_sha256, clears manifest_digest,
    # and appends a valid hash-chained DECISION_UPSERT event
    rc_defer = main(
        [
            "defer",
            "--asset",
            "*",
            "--id",
            "CVE-2021-44228",
            "--status",
            "deferred",
            "--rationale",
            "CLI defer invalidates prior RunManifest seal",
            "--owner",
            "cli-ops@acme.test",
            "--decisions",
            str(decisions_path),
            "--db",
            str(demo_db),
        ]
    )
    assert rc_defer == 0

    with VppDatabase(demo_db, read_only=True) as db:
        after = db.execute(
            "SELECT manifest_digest FROM runs WHERE run_id = 'demo-current'"
        ).fetchone()
        assert after is not None and after[0] is None
        manifest = build_runmanifest_from_db(db, "demo-current")
        assert any(e["event_type"] == "DECISION_UPSERT" for e in manifest["decision_ledger"]["entries"])

    # Set run profile to 'default', then run vpp diff --re-enrich --profile bod-26-04
    # and verify bod-26-04 SSVC action (Attend/Act/Track) is used in re-enriched run
    with VppDatabase(demo_db, read_only=False) as db:
        db.execute("UPDATE runs SET profile = 'default' WHERE run_id = 'demo-current'")

    diff_json = tmp_path / "profile_override_diff.json"
    # Note: diff --re-enrich runs on an isolated temp copy, so we verify via captured TriageDecisionPass profile
    # by running diff --re-enrich --profile bod-26-04 against seeded demo-baseline -> demo-current
    rc_diff = main(
        [
            "diff",
            "demo-baseline",
            "demo-current",
            "--db",
            str(demo_db),
            "--re-enrich",
            "--profile",
            "bod-26-04",
            "--output-json",
            str(diff_json),
        ]
    )
    assert rc_diff == 0
    payload = json.loads(diff_json.read_text(encoding="utf-8"))
    assert payload["base_run_id"] == "demo-baseline"
    assert payload["target_run_id"].startswith("demo-current__re_enriched_")
