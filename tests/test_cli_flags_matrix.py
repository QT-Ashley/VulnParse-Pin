from __future__ import annotations

import sys
from pathlib import Path

import pytest

from vulnparse_pin.cli.args import get_args


CLI_FLAG_CASES: list[tuple[str, list[str]]] = [
    ("no-kev", ["--no-kev"]),
    ("no-epss", ["--no-epss"]),
    ("no-exploit", ["--no-exploit"]),
    ("kev-source-online", ["--kev-source", "online"]),
    ("kev-source-offline", ["--kev-source", "offline"]),
    ("epss-source-online", ["--epss-source", "online"]),
    ("epss-source-offline", ["--epss-source", "offline"]),
    ("kev-feed-url", ["--kev-feed", "https://example.org/kev.json"]),
    ("epss-feed-url", ["--epss-feed", "https://example.org/epss.csv.gz"]),
    ("output-json", ["--output", "out.json"]),
    ("pretty-print", ["--pretty-print"]),
    ("log-file", ["--log-file", "test.log"]),
    ("log-level-debug", ["--log-level", "DEBUG"]),
    ("exploit-source-online", ["--exploit-source", "online"]),
    ("exploit-source-offline-with-db", ["--exploit-source", "offline", "--exploit-db", "exploit.csv", "--no-kev", "--no-epss"]),
    ("exploit-db", ["--exploit-db", "exploit.csv"]),
    ("refresh-cache", ["--refresh-cache"]),
    ("allow-regen", ["--allow_regen"]),
    ("no-nvd", ["--no-nvd"]),
    ("output-csv", ["--output-csv", "out.csv"]),
    ("output-md", ["--output-md", "summary.md"]),
    ("output-md-technical", ["--output-md-technical", "technical.md"]),
    ("allow-large", ["--allow-large"]),
    ("no-csv-sanitize-with-output", ["--output-csv", "out.csv", "--no-csv-sanitize"]),
    ("forbid-symlinks-read", ["--forbid-symlinks_read"]),
    ("forbid-symlinks-write", ["--forbid-symlinks_write"]),
    ("enforce-root-read", ["--enforce-root-read"]),
    ("enforce-root-write", ["--enforce-root-write"]),
    ("file-mode", ["--file-mode", "0o700"]),
    ("dir-mode", ["--dir-mode", "0o760"]),
    ("debug-path-policy", ["--debug-path-policy"]),
    ("portable", ["--portable"]),
    ("presentation", ["--presentation"]),
    ("overlay-mode-namespace", ["--presentation", "--overlay-mode", "namespace"]),
]


def _build_base_argv(tmp_path: Path) -> list[str]:
    scan_file = tmp_path / "scan.json"
    scan_file.write_text("{}", encoding="utf-8")

    return [
        "--file",
        str(scan_file),
    ]


def _materialize_paths(tmp_path: Path, fragment: list[str]) -> list[str]:
    result: list[str] = []
    for token in fragment:
        if token in {"out.json", "test.log", "out.csv", "summary.md", "technical.md", "exploit.csv"}:
            if token == "exploit.csv":
                (tmp_path / token).write_text("id,cve\n1,CVE-2024-0001\n", encoding="utf-8")
            token = str(tmp_path / token)
        result.append(token)
    return result


@pytest.mark.parametrize("case_name,fragment", CLI_FLAG_CASES, ids=[c[0] for c in CLI_FLAG_CASES])
def test_each_cli_flag_parses_in_online_and_offline_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_name: str,
    fragment: list[str],
) -> None:
    argv = _build_base_argv(tmp_path) + _materialize_paths(tmp_path, fragment)

    # get_args() enforces several cross-flag constraints using sys.argv.
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin", *argv])

    args = get_args(argv)

    assert args.file.exists(), case_name
    assert args.no_kev in (True, False), case_name
    assert args.no_epss in (True, False), case_name
    assert args.no_exploit in (True, False), case_name

    if "--file-mode" in fragment:
        assert args.file_mode == 0o700

    if "--dir-mode" in fragment:
        assert args.dir_mode == 0o760


def test_version_flag_exits_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--version"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin", *argv])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 0


def test_overlay_mode_requires_presentation_without_sys_argv_dependency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--overlay-mode", "namespace"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin"])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 2


def test_no_csv_sanitize_requires_output_csv_without_sys_argv_dependency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--no-csv-sanitize"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin"])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 2


def test_offline_exploit_source_requires_exploit_db_without_sys_argv_dependency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--exploit-source", "offline"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin"])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 2
