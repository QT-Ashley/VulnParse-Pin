from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from importlib import resources
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnparse_pin.cli.args import get_args
from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import RunContext
from vulnparse_pin.core.classes.pass_classes import PassRunner
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.ACI.aci_pass import AttackCapabilityInferencePass
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser
from vulnparse_pin.utils.logger import LoggerWrapper


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
    ("ghsa-online", ["--ghsa"]),
    ("ghsa-online-with-budget", ["--ghsa", "--ghsa-budget", "12"]),
    ("nmap-ctx", ["--nmap-ctx", "nmap.xml"]),
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
    ("csv-profile-analyst", ["--output-csv", "out.csv", "--csv-profile", "analyst"]),
    ("output-md", ["--output-md", "summary.md"]),
    ("output-md-technical", ["--output-md-technical", "technical.md"]),
    ("webhook-endpoint", ["--webhook-endpoint", "https://hooks.example.org/vpp"]),
    ("webhook-oal-filter", ["--webhook-endpoint", "https://hooks.example.org/vpp", "--webhook-oal-filter", "P1"]),
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
    ("strict-ingestion", ["--strict-ingestion"]),
    ("no-allow-degraded-input", ["--no-allow-degraded-input"]),
    ("show-ingestion-summary", ["--show-ingestion-summary"]),
    ("min-ingestion-confidence", ["--min-ingestion-confidence", "0.65"]),
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
        if token in {"out.json", "test.log", "out.csv", "summary.md", "technical.md", "exploit.csv", "ghsa.json", "nmap.xml", "nmap.txt"}:
            if token == "exploit.csv":
                (tmp_path / token).write_text("id,cve\n1,CVE-2024-0001\n", encoding="utf-8")
            elif token == "ghsa.json":
                (tmp_path / token).write_text("[]", encoding="utf-8")
            elif token == "nmap.xml":
                (tmp_path / token).write_text("<nmaprun></nmaprun>", encoding="utf-8")
            elif token == "nmap.txt":
                (tmp_path / token).write_text("not xml", encoding="utf-8")
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


def test_csv_profile_requires_output_csv_without_sys_argv_dependency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--csv-profile", "analyst"]
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


def test_ghsa_flag_without_value_enables_online_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--ghsa"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin", *argv])

    args = get_args(argv)

    assert args.ghsa == "online"
    assert args.ghsa_budget is None


def test_ghsa_flag_with_path_enables_offline_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text("[]", encoding="utf-8")
    argv = _build_base_argv(tmp_path) + ["--ghsa", str(ghsa_path)]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin", *argv])

    args = get_args(argv)

    assert args.ghsa == ghsa_path


def test_ghsa_budget_requires_online_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ghsa_path = tmp_path / "ghsa.json"
    ghsa_path.write_text("[]", encoding="utf-8")
    argv = _build_base_argv(tmp_path) + ["--ghsa", str(ghsa_path), "--ghsa-budget", "5"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin"])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 2


def test_nmap_adapter_requires_xml_extension(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + _materialize_paths(tmp_path, ["--nmap-ctx", "nmap.txt"])
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin"])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 2


def test_min_ingestion_confidence_must_be_between_zero_and_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--min-ingestion-confidence", "1.2"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin"])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 2


def test_webhook_endpoint_requires_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = _build_base_argv(tmp_path) + ["--webhook-endpoint", "http://hooks.example.org/vpp"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin"])

    with pytest.raises(SystemExit) as excinfo:
        get_args(argv)

    assert excinfo.value.code == 2


def test_demo_mode_wires_openvas_nmap_and_ghsa_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    openvas_sample = tmp_path / "openvas_demo.xml"
    nmap_sample = tmp_path / "base_test_nmap.xml"
    openvas_sample.write_text("<report><report><results></results></report></report>", encoding="utf-8")
    nmap_sample.write_text("<nmaprun></nmaprun>", encoding="utf-8")

    argv = ["--demo"]
    monkeypatch.setattr(sys, "argv", ["vulnparse-pin", *argv])

    with patch("vulnparse_pin.cli.args._resolve_demo_inputs", return_value=(openvas_sample, nmap_sample)):
        args = get_args(argv)

    assert args.file == openvas_sample
    assert args.nmap_ctx == nmap_sample
    assert args.ghsa == "online"
    assert args.ghsa_budget == 25
    assert args.output_all == "demo_output"
    assert args.output_runmanifest == "demo_runmanifest.json"


def test_packaged_demo_openvas_sample_has_scaled_floor() -> None:
    ref = resources.files("vulnparse_pin.resources").joinpath("openvas_updated_test.xml")
    with resources.as_file(ref) as sample_path:
        root = ET.parse(sample_path).getroot()

    results = root.findall(".//result")
    hosts = {
        host
        for host in (r.findtext("host", "").strip().split()[0] for r in results)
        if host
    }

    # Parser canonical key is asset + scanner_sig(oid) + proto/port + kind(name).
    # Enforce uniqueness per asset so finding IDs remain unique after parsing.
    parser_keys: list[tuple[str, str, str, str]] = []
    cves_by_host: dict[str, set[str]] = {}
    for result in results:
        host = (result.findtext("host", "").strip().split()[0] if result.findtext("host", "").strip() else "")
        nvt = result.find("nvt")
        oid = (nvt.get("oid", "") if nvt is not None else "")
        name = (nvt.findtext("name", "").strip() if nvt is not None else "")
        port = result.findtext("port", "").strip()
        parser_keys.append((host, oid, port, name))

        host_cves = cves_by_host.setdefault(host, set())
        if nvt is not None:
            for ref_node in nvt.findall(".//refs/ref"):
                if (ref_node.get("type", "").lower() == "cve"):
                    cve = (ref_node.get("id", "") or "").strip()
                    if cve:
                        host_cves.add(cve)

    assert len(results) >= 2000
    assert len(hosts) >= 15
    assert len(parser_keys) == len(set(parser_keys))

    sorted_hosts = sorted(cves_by_host.keys())
    for idx, host_a in enumerate(sorted_hosts):
        for host_b in sorted_hosts[idx + 1 :]:
            assert cves_by_host[host_a].isdisjoint(cves_by_host[host_b])


def test_packaged_demo_openvas_sample_exposes_aci_chain_artifacts(tmp_path: Path) -> None:
    ref = resources.files("vulnparse_pin.resources").joinpath("openvas_updated_test.xml")
    with resources.as_file(ref) as sample_path:
        logger = LoggerWrapper(log_file=str(tmp_path / "demo-aci-contract.log"))
        pfh = PermFileHandler(
            logger,
            root_dir=tmp_path,
            allowed_roots=[tmp_path],
            enforce_roots_on_read=False,
            enforce_roots_on_write=False,
        )
        ctx = RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)
        scan = OpenVASXMLParser(ctx, filepath=str(sample_path)).parse()

    policy = ScoringPolicyV1(
        epss_scale=1.0,
        epss_min=0.0,
        epss_max=1.0,
        kev_evd=1.0,
        exploit_evd=1.0,
        band_critical=10.0,
        band_high=7.0,
        band_medium=4.0,
        band_low=1.0,
        asset_aggregation="max",
        w_epss_high=1.0,
        w_epss_medium=1.0,
        w_kev=1.0,
        w_exploit=1.0,
        max_raw_risk=10.0,
        max_op_risk=10.0,
    )

    cfg = _safe_fallback_config()
    out = PassRunner([ScoringPass(policy), AttackCapabilityInferencePass(cfg.aci)]).run_all(ctx, scan)
    metrics = out.derived.passes["ACI@1.0"].data.get("metrics", {})

    assert int(metrics.get("inferred_findings", 0) or 0) > 0
    assert len(metrics.get("capabilities_detected", {}) or {}) > 0
    assert len(metrics.get("chain_candidates_detected", {}) or {}) > 0
