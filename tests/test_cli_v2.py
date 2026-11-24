# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Comprehensive tests for VulnParse-Pin v2 subcommand CLI, security gates, and legacy shim."""

from __future__ import annotations

import builtins
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
from contextlib import ExitStack
from importlib import resources
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnparse_pin import __version__
from vulnparse_pin.app.bootstrap import initialize_runtime
from vulnparse_pin.app.io_resolution import resolve_io_paths_and_modes
from vulnparse_pin.cli.args import get_args
from vulnparse_pin.cli.errors import VppError
from vulnparse_pin.main import main
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import get_run_summary_counts, query_findings_page


@pytest.fixture(autouse=True)
def _isolated_xdg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep CLI app directories isolated to tmp_path instead of ~/.local/share."""
    xdg_data = tmp_path / "xdg_data"
    xdg_data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))


def test_lazy_tui_import_in_fresh_subprocess() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "src")
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, vulnparse_pin.main, vulnparse_pin.cli.args; assert 'textual' not in sys.modules",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}"


def test_version_banner_uses_dynamic_version_no_v1_rc(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert __version__ in out
    assert "v1.0-RC" not in out
    main_src = (Path(__file__).resolve().parents[1] / "src" / "vulnparse_pin" / "main.py").read_text(encoding="utf-8")
    assert "v1.0-RC" not in main_src


def test_cli_help_uses_prog_vpp(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--help"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "usage: vpp" in out
    for subcmd in ("scan", "demo", "diff", "ui", "export", "verify", "defer", "intel"):
        assert subcmd in out


def test_no_csv_sanitize_requires_explicit_confirm_without_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _forbid_input(*_args, **_kwargs):
        raise AssertionError("CLI must NEVER call blocking input()")

    monkeypatch.setattr(builtins, "input", _forbid_input)

    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        scan_src = tmp_path / "demo.nessus"
        shutil.copy2(demo_dir / "demo.nessus", scan_src)
        db_path = tmp_path / "gate.db"
        csv_path = tmp_path / "unsafe.csv"

        rc = main(
            [
                "scan",
                str(scan_src),
                "--db",
                str(db_path),
                "--output-csv",
                str(csv_path),
                "--offline",
                "--no-csv-sanitize",
            ]
        )
        err = capsys.readouterr().err
        assert rc == 2
        assert "--confirm-unsafe-csv" in err

        # Directly verify library helper raises VppError rather than SystemExit
        args = get_args(["-f", str(scan_src), "--output-csv", str(csv_path), "--no-csv-sanitize"])
        runtime = initialize_runtime(args, quiet_banner=True)
        with pytest.raises(VppError) as exc:
            resolve_io_paths_and_modes(args, runtime, "http://127.0.0.1/kev", "http://127.0.0.1/epss")
        assert exc.value.exit_code == 2

        # With --confirm-unsafe-csv, it runs cleanly without blocking
        rc_ok = main(
            [
                "scan",
                str(scan_src),
                "--db",
                str(db_path),
                "--output-csv",
                str(csv_path),
                "--offline",
                "--no-csv-sanitize",
                "--confirm-unsafe-csv",
            ]
        )
        assert rc_ok == 0


def test_scan_multi_file_explicit_paths_and_symlink_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        work = tmp_path / "ws"
        work.mkdir()
        nessus = work / "demo.nessus"
        trivy = work / "demo_trivy.sarif"
        nmap = work / "demo_nmap.xml"
        assets = work / "assets.yaml"
        decisions = work / "decisions.yaml"
        for src, dst in [
            (demo_dir / "demo.nessus", nessus),
            (demo_dir / "demo_trivy.sarif", trivy),
            (demo_dir / "demo_nmap.xml", nmap),
            (demo_dir / "assets.yaml", assets),
            (demo_dir / "decisions.yaml", decisions),
        ]:
            shutil.copy2(src, dst)

        out_dir = tmp_path / "custom_reports" / "nested"
        db_path = tmp_path / "custom_db" / "proj.vpp.db"
        csv_out = out_dir / "findings.csv"
        json_out = out_dir / "findings.json"
        dos_out = out_dir / "defense_dossier"
        rm_out = out_dir / "runmanifest.json"

        rc = main(
            [
                "scan",
                str(nessus),
                str(trivy),
                "--db",
                str(db_path),
                "--nmap",
                str(nmap),
                "--assets",
                str(assets),
                "--decisions",
                str(decisions),
                "--profile",
                "bod-26-04",
                "--offline",
                "--epss-feed",
                str(demo_dir / "intel_snapshot" / "epss.csv"),
                "--kev-feed",
                str(demo_dir / "intel_snapshot" / "kev.json"),
                "--nvd-source",
                str(demo_dir / "intel_snapshot" / "nvd.json"),
                "--exploit-db",
                str(demo_dir / "intel_snapshot" / "exploitdb.csv"),
                "--ghsa",
                str(demo_dir / "intel_snapshot" / "ghsa"),
                "--run-id",
                "run-explicit-1",
                "--output-csv",
                str(csv_out),
                "--output-json",
                str(json_out),
                "--output-dossier",
                str(dos_out),
                "--output-runmanifest",
                str(rm_out),
            ]
        )
        assert rc == 0
        # Explicit paths must be honored verbatim, not relocated into versions/<ver>/outputs/
        assert db_path.exists()
        assert csv_out.exists()
        assert json_out.exists()
        assert dos_out.with_suffix(".md").exists()
        assert dos_out.with_suffix(".html").exists()
        assert rm_out.exists()

        with VppDatabase(db_path, read_only=True) as db:
            counts = get_run_summary_counts(db, "run-explicit-1")
            assert counts["deduplicated_findings"] >= 1
            assert counts["shadow_assets"] >= 1

        # Verify vpp verify passes, and fails after tampering
        assert main(["verify", str(rm_out)]) == 0
        tampered = json.loads(rm_out.read_text(encoding="utf-8"))
        tampered["run_id"] = "tampered-run-id"
        rm_out.write_text(json.dumps(tampered), encoding="utf-8")
        assert main(["verify", str(rm_out)]) == 1

        # Symlink DB target must be blocked cleanly
        real_target = tmp_path / "real_target.db"
        real_target.write_text("dummy", encoding="utf-8")
        sym_db = tmp_path / "sym.db"
        sym_db.symlink_to(real_target)
        assert main(["scan", str(nessus), "--db", str(sym_db), "--offline"]) == 1


def test_diff_export_and_defer_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        db_path = tmp_path / "multi.vpp.db"
        decisions_copy = tmp_path / "decisions.yaml"
        shutil.copy2(demo_dir / "decisions.yaml", decisions_copy)
        assets_copy = tmp_path / "assets.yaml"
        shutil.copy2(demo_dir / "assets.yaml", assets_copy)

        rc1 = main(
            [
                "scan",
                str(demo_dir / "demo_baseline.nessus"),
                "--db",
                str(db_path),
                "--assets",
                str(assets_copy),
                "--decisions",
                str(decisions_copy),
                "--offline",
                "--epss-feed",
                str(demo_dir / "intel_snapshot" / "epss.csv"),
                "--kev-feed",
                str(demo_dir / "intel_snapshot" / "kev.json"),
                "--nvd-source",
                str(demo_dir / "intel_snapshot" / "nvd.json"),
                "--run-id",
                "run-base",
            ]
        )
        assert rc1 == 0

        rc2 = main(
            [
                "scan",
                str(demo_dir / "demo.nessus"),
                str(demo_dir / "demo_trivy.sarif"),
                "--db",
                str(db_path),
                "--assets",
                str(assets_copy),
                "--decisions",
                str(decisions_copy),
                "--offline",
                "--epss-feed",
                str(demo_dir / "intel_snapshot" / "epss.csv"),
                "--kev-feed",
                str(demo_dir / "intel_snapshot" / "kev.json"),
                "--nvd-source",
                str(demo_dir / "intel_snapshot" / "nvd.json"),
                "--run-id",
                "run-curr",
            ]
        )
        assert rc2 == 0

        diff_json = tmp_path / "diff.json"
        diff_md = tmp_path / "diff.md"
        diff_pr = tmp_path / "pr.md"
        assert (
            main(
                [
                    "diff",
                    "run-base",
                    "run-curr",
                    "--db",
                    str(db_path),
                    "--decisions",
                    str(decisions_copy),
                    "--fail-on",
                    "none",
                    "--output-json",
                    str(diff_json),
                    "--output-md",
                    str(diff_md),
                    "--output-pr-comment",
                    str(diff_pr),
                ]
            )
            == 0
        )
        assert diff_json.exists() and diff_md.exists() and diff_pr.exists()
        assert (
            main(["diff", "run-base", "run-curr", "--db", str(db_path), "--decisions", str(decisions_copy), "--fail-on", "p1"])
            == 2
        )
        assert (
            main(
                [
                    "diff",
                    "run-base",
                    "run-curr",
                    "--db",
                    str(db_path),
                    "--decisions",
                    str(decisions_copy),
                    "--fail-on",
                    "stale-assumption",
                ]
            )
            == 2
        )

        # Export formats directly from DuckDB
        for fmt, ext in [
            ("dossier-md", ".md"),
            ("dossier-html", ".html"),
            ("roadmap-md", ".roadmap.md"),
            ("roadmap-html", ".roadmap.html"),
            ("csv", ".csv"),
            ("json", ".json"),
        ]:
            out_file = tmp_path / f"exp_{fmt}{ext}"
            assert main(["export", "--db", str(db_path), "--run-id", "run-curr", "--format", fmt, "--output", str(out_file)]) == 0
            assert out_file.exists() and out_file.stat().st_size > 0

        # Defer command updates YAML and refreshes DuckDB triage status
        rc_def = main(
            [
                "defer",
                "--asset",
                "198.51.100.77",
                "--id",
                "CVE-2021-44228",
                "--status",
                "accepted",
                "--rationale",
                "Compensating WAF isolation verified in CI test",
                "--owner",
                "secops@acme.test",
                "--expires",
                "2027-06-01",
                "--in-kev",
                "true",
                "--decisions",
                str(decisions_copy),
                "--db",
                str(db_path),
            ]
        )
        assert rc_def == 0
        assert "Compensating WAF isolation verified in CI test" in decisions_copy.read_text(encoding="utf-8")


def test_ui_missing_textual_exits_cleanly_with_install_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db_path = tmp_path / "dummy.db"
    db_path.write_text("", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "textual", None)
    rc = main(["ui", "--db", str(db_path)])
    err = capsys.readouterr().err
    assert rc == 1
    assert 'pip install "vulnparse-pin[ui]"' in err


def test_intel_status_and_legacy_alias_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["intel", "status", "--json"]) == 0
    intel_payload = json.loads(capsys.readouterr().out)
    assert {"nvd", "epss", "kev", "exploit_db", "ghsa", "osv"}.issubset(intel_payload.keys())

    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        db_legacy = tmp_path / "legacy.db"
        rc_scan = main(["-f", str(demo_dir / "demo.nessus"), "--db", str(db_legacy), "--offline"])
        err_scan = capsys.readouterr().err
        assert rc_scan == 0
        assert "deprecated" in err_scan.lower()

        demo_out = tmp_path / "legacy_demo_out"
        demo_db = tmp_path / "legacy_demo.db"
        rc_demo = main(["--demo", "--db", str(demo_db), "--output-dir", str(demo_out)])
        err_demo = capsys.readouterr().err
        assert rc_demo == 0
        assert "deprecated" in err_demo.lower()

        rm_file = demo_out / "runmanifest.json"
        if rm_file.exists():
            rc_ver = main(["--verify-runmanifest", str(rm_file)])
            err_ver = capsys.readouterr().err
            assert rc_ver == 0
            assert "deprecated" in err_ver.lower()

        assert main(["--debug-path-policy"]) == 0
