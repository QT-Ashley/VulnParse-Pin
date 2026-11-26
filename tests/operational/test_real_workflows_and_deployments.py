# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import hmac
from importlib import resources
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from vulnparse_pin.app.output import export_v2_outputs
from vulnparse_pin.cli.commands import (
    _parse_nvd_years,
    run_diff_command,
    run_intel_command,
    run_scan_command,
)
from vulnparse_pin.cli.errors import VppError
from vulnparse_pin.main import main
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.utils.runmanifest import verify_runmanifest_file


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / "examples" / "workflows"
DEPLOY_DIR = REPO_ROOT / "examples" / "deploy"


def _write_vpp_shim(bin_dir: Path, *, scan_offline_feeds: Dict[str, Path] | None = None) -> Path:
    """Create an executable `vpp` wrapper script invoking this repo's `vulnparse_pin.main`."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    shim_path = bin_dir / "vpp"

    offline_snippet = ""
    if scan_offline_feeds:
        extra = [
            "--offline",
            "--kev-feed",
            str(scan_offline_feeds["kev"]),
            "--epss-feed",
            str(scan_offline_feeds["epss"]),
            "--nvd",
            str(scan_offline_feeds["nvd"]),
            "--exploit-db",
            str(scan_offline_feeds["exploitdb"]),
        ]
        offline_snippet = (
            "if len(sys.argv) > 1 and sys.argv[1] == 'scan':\n"
            f"    sys.argv.extend({extra!r})\n"
        )

    shim_path.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"src_dir = {str(REPO_ROOT / 'src')!r}\n"
        "if src_dir not in sys.path:\n"
        "    sys.path.insert(0, src_dir)\n"
        f"{offline_snippet}"
        "from vulnparse_pin.main import main\n"
        "raise SystemExit(main(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    shim_path.chmod(0o755)
    return shim_path


def _base_env(tmp_path: Path, extra: Dict[str, str] | None = None) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    env["HOME"] = str(tmp_path / "home")
    env["XDG_DATA_HOME"] = str(tmp_path / "xdg_data")
    env["XDG_CONFIG_HOME"] = str(tmp_path / "xdg_config")
    env["XDG_CACHE_HOME"] = str(tmp_path / "xdg_cache")
    env["TMPDIR"] = str(tmp_path / "tmp")
    for k in ("HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR"):
        Path(env[k]).mkdir(parents=True, exist_ok=True)
    if extra:
        env.update(extra)
    return env


def _copy_demo_fixtures(dst_dir: Path) -> Dict[str, Path]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        demo_dir = stack.enter_context(resources.as_file(resources.files("vulnparse_pin.resources.demo")))
        files = {}
        for name in (
            "demo_baseline.nessus",
            "demo.nessus",
            "demo_trivy.sarif",
            "demo_nuclei.jsonl",
            "demo_nmap.xml",
            "assets.yaml",
            "decisions.yaml",
        ):
            target = dst_dir / name
            shutil.copy2(demo_dir / name, target)
            files[name] = target

        intel_dst = dst_dir / "intel_snapshot"
        shutil.copytree(demo_dir / "intel_snapshot", intel_dst, dirs_exist_ok=True)
        files["kev"] = intel_dst / "kev.json"
        files["epss"] = intel_dst / "epss.csv"
        files["nvd"] = intel_dst / "nvd.json"
        files["exploitdb"] = intel_dst / "exploitdb.csv"
        files["ghsa"] = intel_dst / "ghsa"
        return files


def _write_clean_kev_json(path: Path) -> Path:
    payload = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities (Pre-Flip)",
        "catalogVersion": "2026.10.01",
        "dateReleased": "2026-10-01T00:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 RCE",
                "dateAdded": "2021-12-10",
                "shortDescription": "Log4j2 JNDI RCE",
                "requiredAction": "Update Log4j2.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _write_clean_epss_csv(path: Path) -> Path:
    path.write_text(
        "\n".join(
            [
                "#model_version:v2025.03.14,score_date:2026-10-01T00:00:00+0000",
                "cve,epss,percentile",
                "CVE-2021-44228,0.97210,0.99990",
                "CVE-2024-3094,0.00500,0.10000",
                "CVE-2024-1709,0.91200,0.99850",
                "CVE-2023-26136,0.15300,0.92100",
                "CVE-2023-38545,0.00850,0.65000",
                "CVE-2023-4863,0.01500,0.72000",
                "CVE-2025-99001,0.00200,0.28000",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_mssp_assessment_workflow_end_to_end(tmp_path: Path) -> None:
    work = tmp_path / "mssp_ws"
    fixtures = _copy_demo_fixtures(work / "fixtures")
    vpp_shim = _write_vpp_shim(
        tmp_path / "bin",
        scan_offline_feeds={
            "kev": fixtures["kev"],
            "epss": fixtures["epss"],
            "nvd": fixtures["nvd"],
            "exploitdb": fixtures["exploitdb"],
        },
    )

    out_dir = work / "out"
    db_path = work / "engagement.vpp.db"
    env = _base_env(
        tmp_path,
        {
            "VPP_BIN": str(vpp_shim),
            "ENGAGEMENT_DB": str(db_path),
            "OUT_DIR": str(out_dir),
            "ASSETS_FILE": str(fixtures["assets.yaml"]),
            "DECISIONS_FILE": str(fixtures["decisions.yaml"]),
            "NESSUS_FILE": str(fixtures["demo_baseline.nessus"]),
            "TRIVY_FILE": str(fixtures["demo_trivy.sarif"]),
            "NUCLEI_FILE": str(fixtures["demo_nuclei.jsonl"]),
            "NMAP_FILE": str(fixtures["demo_nmap.xml"]),
            "RETEST_NESSUS_FILE": str(fixtures["demo.nessus"]),
        },
    )

    proc = subprocess.run(
        ["bash", str(WORKFLOWS_DIR / "mssp-assessment.sh")],
        cwd=str(work),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    # Demo decisions.yaml defers CVE-2024-3094 (in_kev=false), while demo intel_snapshot KEV includes CVE-2024-3094 -> exit 2
    assert proc.returncode == 2, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert (out_dir / "dossier.md").is_file()
    assert (out_dir / "dossier.html").is_file()
    assert (out_dir / "executive_roadmap.html").is_file()
    assert (out_dir / "executive_roadmap.md").is_file()
    assert (out_dir / "runmanifest.json").is_file()
    assert (out_dir / "retest_dossier.md").is_file()
    assert (out_dir / "retest_runmanifest.json").is_file()
    assert (out_dir / "retest_diff.md").is_file()
    assert (out_dir / "retest_diff.json").is_file()

    verify_runmanifest_file(out_dir / "runmanifest.json")
    verify_runmanifest_file(out_dir / "retest_runmanifest.json")
    diff_data = json.loads((out_dir / "retest_diff.json").read_text(encoding="utf-8"))
    assert diff_data["summary"]["invalidated_assumptions"] >= 1


def test_airgapped_sync_and_scan_workflow_hmac_and_root_jail(tmp_path: Path) -> None:
    staging_dir = tmp_path / "staging"
    enclave_dir = tmp_path / "enclave"
    staging_fixtures = _copy_demo_fixtures(staging_dir / "fixtures")
    enclave_fixtures = _copy_demo_fixtures(enclave_dir / "fixtures")
    vpp_shim = _write_vpp_shim(tmp_path / "bin")

    hmac_feed_key = "stage-feed-secret-key-0123456789"
    hmac_sqlite_key = "stage-sqlite-secret-key-0123456789"

    stage_env = _base_env(
        tmp_path,
        {
            "VPP_BIN": str(vpp_shim),
            "VP_FEED_CACHE_HMAC_KEY": hmac_feed_key,
            "VP_SQLITE_HMAC_KEY": hmac_sqlite_key,
            "KEV_FEED": str(staging_fixtures["kev"]),
            "EPSS_FEED": str(staging_fixtures["epss"]),
            "NVD_LOCAL_PATH": str(staging_fixtures["nvd"]),
            "GHSA_LOCAL_PATH": str(staging_fixtures["ghsa"]),
            "EXPLOIT_DB_CSV": str(staging_fixtures["exploitdb"]),
        },
    )

    stage_proc = subprocess.run(
        ["bash", str(WORKFLOWS_DIR / "airgapped-sync-and-scan.sh"), "stage"],
        cwd=str(staging_dir),
        env=stage_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert stage_proc.returncode == 0, f"stdout={stage_proc.stdout}\nstderr={stage_proc.stderr}"
    bundle_path = staging_dir / "vpp-intel-bundle.tar.gz"
    bundle_sha = staging_dir / "vpp-intel-bundle.tar.gz.sha256"
    assert bundle_path.is_file()
    assert bundle_sha.is_file()

    stage_status = json.loads((staging_dir / "out/airgapped/intel-status-stage.json").read_text(encoding="utf-8"))
    assert stage_status["kev"]["health"] == "valid"
    assert stage_status["kev"]["sqlite"]["health"] == "valid"
    assert stage_status["epss"]["health"] == "valid"
    assert stage_status["epss"]["sqlite"]["health"] == "valid"
    assert stage_status["nvd"]["health"] == "valid"

    kev_integrity = json.loads((staging_dir / "data/cache/kev/kev_cache.json.integrity.json").read_text(encoding="utf-8"))
    assert kev_integrity["mode"] == "hmac-sha256"
    kev_sqlite_sig = json.loads((staging_dir / "data/cache/kev_cache.sqlite3.sig.json").read_text(encoding="utf-8"))
    assert kev_sqlite_sig["mode"] == "hmac-sha256"

    # Transfer bundle to air-gapped enclave
    shutil.copy2(bundle_path, enclave_dir / "vpp-intel-bundle.tar.gz")
    shutil.copy2(bundle_sha, enclave_dir / "vpp-intel-bundle.tar.gz.sha256")

    enclave_env = _base_env(
        tmp_path,
        {
            "VPP_BIN": str(vpp_shim),
            "VP_FEED_CACHE_HMAC_KEY": hmac_feed_key,
            "VP_SQLITE_HMAC_KEY": hmac_sqlite_key,
            "ASSETS_FILE": "fixtures/assets.yaml",
            "DECISIONS_FILE": "fixtures/decisions.yaml",
        },
    )
    scan_proc = subprocess.run(
        [
            "bash",
            str(WORKFLOWS_DIR / "airgapped-sync-and-scan.sh"),
            "scan",
            "fixtures/demo.nessus",
            "fixtures/demo_trivy.sarif",
        ],
        cwd=str(enclave_dir),
        env=enclave_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert scan_proc.returncode == 0, f"stdout={scan_proc.stdout}\nstderr={scan_proc.stderr}"
    assert (enclave_dir / "out/airgapped/dossier.md").is_file()
    assert (enclave_dir / "out/airgapped/dossier.html").is_file()
    assert (enclave_dir / "out/airgapped/runmanifest.json").is_file()
    verify_runmanifest_file(enclave_dir / "out/airgapped/runmanifest.json")

    # Outside-CWD path must be rejected under --portable --enforce-root-read
    outside_scan = tmp_path / "outside.nessus"
    shutil.copy2(enclave_fixtures["demo.nessus"], outside_scan)
    outside_proc = subprocess.run(
        [
            "bash",
            str(WORKFLOWS_DIR / "airgapped-sync-and-scan.sh"),
            "scan",
            str(outside_scan),
        ],
        cwd=str(enclave_dir),
        env=enclave_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert outside_proc.returncode != 0

    # Tampering with cached KEV JSON must be reported as tampered read-only AND rejected fail-closed
    # even when .meta.json is deleted (no self-resigning) and on subsequent runs after quarantine.
    kev_cached = enclave_dir / "data/cache/kev/kev_cache.json"
    kev_meta = enclave_dir / "data/cache/kev/kev_cache.json.meta.json"
    if kev_meta.exists():
        kev_meta.unlink()
    kev_cached.write_text('{"vulnerabilities":[]}', encoding="utf-8")
    tampered_proc = subprocess.run(
        [
            "bash",
            str(WORKFLOWS_DIR / "airgapped-sync-and-scan.sh"),
            "scan",
            "fixtures/demo.nessus",
        ],
        cwd=str(enclave_dir),
        env=enclave_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tampered_proc.returncode != 0
    tampered_status = json.loads((enclave_dir / "out/airgapped/intel-status-enclave.json").read_text(encoding="utf-8"))
    assert tampered_status["kev"]["health"] == "tampered"

    # Second run after quarantine must STILL fail closed rather than scanning without KEV
    second_tampered_proc = subprocess.run(
        [
            "bash",
            str(WORKFLOWS_DIR / "airgapped-sync-and-scan.sh"),
            "scan",
            "fixtures/demo.nessus",
        ],
        cwd=str(enclave_dir),
        env=enclave_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert second_tampered_proc.returncode != 0


def _seed_workspace_db(
    *,
    tmp_path: Path,
    db_path: Path,
    fixtures: Dict[str, Path],
    clean_kev_path: Path,
    clean_epss_path: Path,
    run_count: int,
    env: Dict[str, str],
) -> List[str]:
    """Run real `vpp scan` calls against clean pre-flip KEV/EPSS to seed 1-run or 2-run .vpp.db."""
    old_env = {k: os.environ.get(k) for k in env}
    try:
        os.environ.update(env)
        run_ids = ["seed-run-1"] if run_count == 1 else ["seed-run-1", "seed-run-2"]
        for idx, rid in enumerate(run_ids):
            scan_file = fixtures["demo_baseline.nessus"] if idx == 0 else fixtures["demo.nessus"]
            rc = main(
                [
                    "scan",
                    str(scan_file),
                    "--db",
                    str(db_path),
                    "--assets",
                    str(fixtures["assets.yaml"]),
                    "--decisions",
                    str(fixtures["decisions.yaml"]),
                    "--profile",
                    "bod-26-04",
                    "--offline",
                    "--kev-feed",
                    str(clean_kev_path),
                    "--epss-feed",
                    str(clean_epss_path),
                    "--nvd",
                    str(fixtures["nvd"]),
                    "--exploit-db",
                    str(fixtures["exploitdb"]),
                    "--run-id",
                    rid,
                ]
            )
            assert rc == 0
        return run_ids
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.mark.parametrize("run_count", [1, 2])
def test_scheduled_kev_drift_check_empty_scan_files_re_enriches_and_exits_2(
    tmp_path: Path, run_count: int
) -> None:
    work = tmp_path / f"drift_ws_{run_count}"
    fixtures = _copy_demo_fixtures(work / "fixtures")
    clean_kev = _write_clean_kev_json(work / "clean_kev.json")
    clean_epss = _write_clean_epss_csv(work / "clean_epss.csv")
    db_path = work / ".vpp.db"
    vpp_shim = _write_vpp_shim(tmp_path / "bin")

    hmac_feed_key = "drift-feed-secret-0123456789abcdef"
    hmac_sqlite_key = "drift-sqlite-secret-0123456789abcdef"
    env = _base_env(
        tmp_path,
        {
            "VPP_BIN": str(vpp_shim),
            "VP_FEED_CACHE_HMAC_KEY": hmac_feed_key,
            "VP_SQLITE_HMAC_KEY": hmac_sqlite_key,
        },
    )

    seeded_runs = _seed_workspace_db(
        tmp_path=tmp_path,
        db_path=db_path,
        fixtures=fixtures,
        clean_kev_path=clean_kev,
        clean_epss_path=clean_epss,
        run_count=run_count,
        env=env,
    )

    with VppDatabase(db_path, read_only=True) as db:
        before_runs = db.execute(
            "SELECT run_id, created_at_utc, intel_metadata_json FROM runs ORDER BY run_id"
        ).fetchall()
        before_kev = db.execute(
            "SELECT run_id, cve_id, in_kev FROM enrichment_snapshots WHERE cve_id = 'CVE-2024-3094' ORDER BY run_id"
        ).fetchall()
    assert len(before_runs) == run_count
    assert all(row[2] is False for row in before_kev)

    # First verify exit 0 when KEV still does not include CVE-2024-3094 and EPSS <= 0.02
    clean_out = work / "out_clean"
    clean_env = dict(
        env,
        DB_PATH=str(db_path),
        DECISIONS_FILE=str(fixtures["decisions.yaml"]),
        ASSETS_FILE=str(fixtures["assets.yaml"]),
        OUT_DIR=str(clean_out),
        SCAN_FILES="",
        KEV_FEED=str(clean_kev),
        EPSS_FEED=str(clean_epss),
        NVD_SOURCE=str(fixtures["nvd"]),
    )
    clean_proc = subprocess.run(
        ["bash", str(WORKFLOWS_DIR / "scheduled-kev-drift-check.sh")],
        cwd=str(work),
        env=clean_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert clean_proc.returncode == 0, f"stdout={clean_proc.stdout}\nstderr={clean_proc.stderr}"

    # Now CVE-2024-3094 enters KEV and EPSS spikes -> must trigger invalidated_assumptions & exit 2
    drift_out = work / "out_drift"
    drift_env = dict(
        clean_env,
        OUT_DIR=str(drift_out),
        KEV_FEED=str(fixtures["kev"]),
        EPSS_FEED=str(fixtures["epss"]),
    )
    drift_proc = subprocess.run(
        ["bash", str(WORKFLOWS_DIR / "scheduled-kev-drift-check.sh")],
        cwd=str(work),
        env=drift_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert drift_proc.returncode == 2, f"stdout={drift_proc.stdout}\nstderr={drift_proc.stderr}"
    report_json = drift_out / "drift_report.json"
    assert report_json.is_file()
    assert (drift_out / "drift_report.md").is_file()
    report_payload = json.loads(report_json.read_text(encoding="utf-8"))
    assert report_payload["summary"]["invalidated_assumptions"] >= 1
    assert any(
        item["primary_cve"] == "CVE-2024-3094" and "kev_flipped" in item["violated_predicates"]
        for item in report_payload["invalidated_assumptions"]
    )

    # Historical frozen runs rows & snapshots must remain completely unmutated
    with VppDatabase(db_path, read_only=True) as db:
        after_runs = db.execute(
            "SELECT run_id, created_at_utc, intel_metadata_json FROM runs ORDER BY run_id"
        ).fetchall()
        after_kev = db.execute(
            "SELECT run_id, cve_id, in_kev FROM enrichment_snapshots WHERE cve_id = 'CVE-2024-3094' ORDER BY run_id"
        ).fetchall()
    assert after_runs == before_runs
    assert after_kev == before_kev
    assert [r[0] for r in after_runs] == seeded_runs

    # Tampered local SQLite cache must fail closed under --re-enrich
    kev_sqlite = Path(env["XDG_DATA_HOME"]) / "VulnParse-Pin" / "cache" / "kev_cache.sqlite3"
    assert kev_sqlite.exists()
    kev_sqlite.write_bytes(b"corrupted-sqlite-bytes")
    tamper_env = dict(drift_env, SKIP_INTEL_SYNC="1")
    tamper_proc = subprocess.run(
        ["bash", str(WORKFLOWS_DIR / "scheduled-kev-drift-check.sh")],
        cwd=str(work),
        env=tamper_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tamper_proc.returncode == 1


def test_simulated_readonly_container_env_contract(tmp_path: Path) -> None:
    dockerfile_text = (DEPLOY_DIR / "Dockerfile").read_text(encoding="utf-8")
    compose_text = (DEPLOY_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    k8s_text = (DEPLOY_DIR / "k8s-cronjob-vpp-drift.yaml").read_text(encoding="utf-8")
    service_text = (DEPLOY_DIR / "systemd" / "vpp-drift.service").read_text(encoding="utf-8")

    for var_name in ("HOME=", "XDG_DATA_HOME=", "XDG_CONFIG_HOME=", "XDG_CACHE_HOME=", "TMPDIR="):
        assert var_name in dockerfile_text
    assert "--re-enrich" in compose_text
    assert "--re-enrich" in k8s_text
    assert "SCAN_FILES=" in service_text

    # Simulate container mounts: /work (rw), /cache/{data,config,xdg} (rw), /tmp (rw), read-only root dir
    ro_root = tmp_path / "ro_root"
    ro_root.mkdir()
    work_dir = tmp_path / "work"
    cache_dir = tmp_path / "cache"
    tmp_dir = tmp_path / "tmp"
    for d in (work_dir, cache_dir / "data", cache_dir / "config", cache_dir / "xdg", tmp_dir):
        d.mkdir(parents=True, exist_ok=True)
    ro_root.chmod(0o555)
    try:
        env = dict(
            os.environ,
            PYTHONPATH=str(REPO_ROOT / "src"),
            HOME=str(work_dir),
            XDG_DATA_HOME=str(cache_dir / "data"),
            XDG_CONFIG_HOME=str(cache_dir / "config"),
            XDG_CACHE_HOME=str(cache_dir / "xdg"),
            TMPDIR=str(tmp_dir),
        )
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "vulnparse_pin.main",
                "demo",
                "--no-ui",
                "--db",
                str(work_dir / ".vpp-demo.db"),
                "--output-dir",
                str(work_dir / "vpp_demo_output"),
            ],
            cwd=str(work_dir),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
        assert (work_dir / ".vpp-demo.db").is_file()
        assert (work_dir / "vpp_demo_output" / "runmanifest.json").is_file()
    finally:
        ro_root.chmod(stat.S_IRWXU)


def test_v2_signed_webhook_delivery_filtering_spooling_and_fail_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures = _copy_demo_fixtures(tmp_path / "fixtures")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))

    # Create a decisions.yaml that validly defers CVE-2023-38545 AND invalidates CVE-2024-3094
    dec_path = tmp_path / "decisions.yaml"
    dec_path.write_text(
        """version: v2
decisions:
  - id: dec-valid-curl
    asset_pattern: "*10.20.1.50*"
    cve_or_rule_id: CVE-2023-38545
    status: deferred
    rationale: "Validly deferred internal service."
    owner: secops@acme.test
    expires_at: "2028-01-01"
    assumptions:
      in_kev: false
      max_epss: 0.99
  - id: dec-invalidated-xz
    asset_pattern: "*203.0.113.10*"
    cve_or_rule_id: CVE-2024-3094
    status: deferred
    rationale: "Invalidated because KEV flipped."
    owner: secops@acme.test
    expires_at: "2028-01-01"
    assumptions:
      in_kev: false
""",
        encoding="utf-8",
    )

    # 1. Missing VP_WEBHOOK_HMAC_KEY must fail closed
    monkeypatch.delenv("VP_WEBHOOK_HMAC_KEY", raising=False)
    db_fail = tmp_path / "fail.vpp.db"
    rc_missing = main(
        [
            "scan",
            str(fixtures["demo.nessus"]),
            "--db",
            str(db_fail),
            "--assets",
            str(fixtures["assets.yaml"]),
            "--decisions",
            str(dec_path),
            "--profile",
            "bod-26-04",
            "--offline",
            "--kev-feed",
            str(fixtures["kev"]),
            "--epss-feed",
            str(fixtures["epss"]),
            "--nvd",
            str(fixtures["nvd"]),
            "--exploit-db",
            str(fixtures["exploitdb"]),
            "--webhook-endpoint",
            "https://hooks.example.org/vpp",
            "--webhook-oal-filter",
            "P1",
        ]
    )
    assert rc_missing == 2
    assert not db_fail.exists()

    # 2. Valid key: delivers signed payload excluding validly deferred CVE-2023-38545, including active/invalidated P1s
    secret = "webhook-super-secret-key-999"
    monkeypatch.setenv("VP_WEBHOOK_HMAC_KEY", secret)
    captured: List[Dict[str, Any]] = []

    class _Resp:
        status_code = 202
        url = "https://hooks.example.org/vpp"

        def raise_for_status(self) -> None:
            return None

    def _fake_post(url, data=None, headers=None, timeout=None, allow_redirects=None):
        captured.append({"url": url, "data": data, "headers": headers, "allow_redirects": allow_redirects})
        return _Resp()

    monkeypatch.setattr("vulnparse_pin.utils.webhook_delivery.requests.post", _fake_post)

    db_ok = tmp_path / "ok.vpp.db"
    rm_path = tmp_path / "out" / "runmanifest.json"
    rc_ok = main(
        [
            "scan",
            str(fixtures["demo.nessus"]),
            "--db",
            str(db_ok),
            "--assets",
            str(fixtures["assets.yaml"]),
            "--decisions",
            str(dec_path),
            "--profile",
            "bod-26-04",
            "--offline",
            "--kev-feed",
            str(fixtures["kev"]),
            "--epss-feed",
            str(fixtures["epss"]),
            "--nvd",
            str(fixtures["nvd"]),
            "--exploit-db",
            str(fixtures["exploitdb"]),
            "--webhook-endpoint",
            "https://hooks.example.org/vpp",
            "--webhook-oal-filter",
            "P1",
            "--output-runmanifest",
            str(rm_path),
        ]
    )
    assert rc_ok == 0
    assert len(captured) == 1
    req = captured[0]
    assert req["allow_redirects"] is False
    hdrs = req["headers"]
    expected_mac = hmac.new(
        secret.encode("utf-8"),
        f"{hdrs['X-VPP-Timestamp']}.{hdrs['X-VPP-Nonce']}.".encode("utf-8") + req["data"],
        sha256,
    ).hexdigest()
    assert hdrs["X-VPP-Signature"] == f"sha256={expected_mac}"

    payload = json.loads(req["data"].decode("utf-8"))
    assert payload["oal_filter_applied"] == "P1"
    dispatched_titles = {item["title"] for item in payload["top_findings"]}
    assert any("XZ" in t or "Log4j" in t for t in dispatched_titles)
    with VppDatabase(db_ok, read_only=True) as db:
        suppressed_ids = {
            r[0]
            for r in db.execute(
                "SELECT finding_id FROM triage_decisions WHERE decision_status = 'deferred_valid'"
            ).fetchall()
        }
        invalidated_ids = {
            r[0]
            for r in db.execute(
                "SELECT finding_id FROM triage_decisions WHERE decision_status = 'deferred_invalidated'"
            ).fetchall()
        }
    dispatched_ids = {item["finding_id"] for item in payload["top_findings"]}
    assert suppressed_ids
    assert invalidated_ids
    assert dispatched_ids.isdisjoint(suppressed_ids)
    assert invalidated_ids.issubset(dispatched_ids)

    manifest = verify_runmanifest_file(rm_path)
    event_types = [e["event_type"] for e in manifest["decision_ledger"]["entries"]]
    assert "WEBHOOK_DELIVERY" in event_types
    assert secret not in rm_path.read_text(encoding="utf-8")

    # 3. Network failure spools payload cleanly and records WEBHOOK_EMIT_SPOOLED_FOR_RETRY
    def _failing_post(*_args, **_kwargs):
        raise RuntimeError("simulated webhook outage")

    monkeypatch.setattr("vulnparse_pin.utils.webhook_delivery.requests.post", _failing_post)
    db_spool = tmp_path / "spool.vpp.db"
    rm_spool = tmp_path / "out_spool" / "runmanifest.json"
    rc_spool = main(
        [
            "scan",
            str(fixtures["demo.nessus"]),
            "--db",
            str(db_spool),
            "--assets",
            str(fixtures["assets.yaml"]),
            "--decisions",
            str(dec_path),
            "--profile",
            "bod-26-04",
            "--offline",
            "--kev-feed",
            str(fixtures["kev"]),
            "--epss-feed",
            str(fixtures["epss"]),
            "--nvd",
            str(fixtures["nvd"]),
            "--exploit-db",
            str(fixtures["exploitdb"]),
            "--webhook-endpoint",
            "https://hooks.example.org/vpp",
            "--webhook-oal-filter",
            "P1",
            "--output-runmanifest",
            str(rm_spool),
        ]
    )
    assert rc_spool == 0
    spool_files = list((tmp_path / "xdg_data" / "VulnParse-Pin").rglob("webhook_*.json"))
    assert spool_files
    spool_manifest = verify_runmanifest_file(rm_spool)
    spool_reasons = [e["why"]["reason_code"] for e in spool_manifest["decision_ledger"]["entries"]]
    assert "WEBHOOK_EMIT_SPOOLED_FOR_RETRY" in spool_reasons


def test_intel_sync_nvd_years_parsing_and_policy_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _parse_nvd_years("2024") == {2024}
    assert _parse_nvd_years("2021-2026") == {2021, 2022, 2023, 2024, 2025, 2026}
    assert _parse_nvd_years("2021, 2023-2025") == {2021, 2023, 2024, 2025}

    for bad in ("", "2026-2021", "abc", "1999", "2021,,2022"):
        with pytest.raises(VppError) as exc:
            _parse_nvd_years(bad)
        assert exc.value.exit_code == 2

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))

    recorded_years: List[Any] = []

    def _fake_refresh(self, *, config, feed_cache, refresh_cache, offline, years=None, include_modified=True, target_cves=None):
        recorded_years.append(years)

    monkeypatch.setattr("vulnparse_pin.utils.nvdcacher.NVDFeedCache.refresh", _fake_refresh)

    # Default (--years None) uses full policy range (2002..end_year)
    rc_def = run_intel_command(
        SimpleNamespace(
            action="sync",
            feed="nvd",
            refresh=False,
            allow_regen=False,
            years=None,
            nvd_source=None,
            no_nvd=False,
            portable=False,
            log_level="INFO",
        )
    )
    assert rc_def == 0
    assert len(recorded_years) == 1
    assert 2002 in recorded_years[0]
    assert len(recorded_years[0]) > 1

    # Explicit --years range
    rc_explicit = run_intel_command(
        SimpleNamespace(
            action="sync",
            feed="nvd",
            refresh=False,
            allow_regen=False,
            years="2021,2023-2025",
            nvd_source=None,
            no_nvd=False,
            portable=False,
            log_level="INFO",
        )
    )
    assert rc_explicit == 0
    assert recorded_years[1] == {2021, 2023, 2024, 2025}


def test_phase1_webhook_v2_fields_and_ssrf_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vulnparse_pin.cli.args import valid_https_url
    from vulnparse_pin.core.config_validator import ConfigValidator, validate_webhook_https_url
    from vulnparse_pin.core.classes.dataclass import WebhookEndpointConfig, WebhookRuntimeConfig
    from vulnparse_pin.utils.webhook_delivery import emit_configured_webhooks

    # 1. SSRF URL rejections across validator layers
    for bad_url in (
        "https://127.0.0.1/hook",
        "https://[::1]/hook",
        "https://10.0.0.5/hook",
        "https://172.16.0.10/hook",
        "https://192.168.1.20/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/hook",
        "https://metadata.google.internal/computeMetadata",
        "https://service.local/hook",
    ):
        with pytest.raises(ValueError):
            validate_webhook_https_url(bad_url)
        with pytest.raises(Exception):
            valid_https_url(bad_url)
        with pytest.raises(RuntimeError):
            ConfigValidator._validate_webhook_config(
                {
                    "webhook": {
                        "enabled": True,
                        "connect_timeout_seconds": 3,
                        "read_timeout_seconds": 5,
                        "timeout_seconds": 5,
                        "endpoints": [{"url": bad_url, "enabled": True}],
                    }
                }
            )

    # 2. Webhook v2 payload preserves documented triage/intel fields
    fixtures = _copy_demo_fixtures(tmp_path / "fixtures")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))
    monkeypatch.setenv("VP_WEBHOOK_HMAC_KEY", "phase1-webhook-secret")

    dec_path = tmp_path / "decisions.yaml"
    dec_path.write_text(
        """version: v2
decisions:
  - id: dec-inv-xz
    asset_pattern: "*203.0.113.10*"
    cve_or_rule_id: CVE-2024-3094
    status: deferred
    rationale: "Invalidated because KEV flipped."
    owner: secops@acme.test
    expires_at: "2028-01-01"
    assumptions:
      in_kev: false
""",
        encoding="utf-8",
    )

    captured: List[Dict[str, Any]] = []

    class _Resp:
        status_code = 202
        url = "https://hooks.example.org/vpp"

        def raise_for_status(self) -> None:
            return None

    def _fake_post(url, data=None, headers=None, timeout=None, allow_redirects=None):
        captured.append({"url": url, "data": data, "headers": headers})
        return _Resp()

    monkeypatch.setattr("vulnparse_pin.utils.webhook_delivery.requests.post", _fake_post)

    rc = main(
        [
            "scan",
            str(fixtures["demo.nessus"]),
            "--db",
            str(tmp_path / "wh_v2.vpp.db"),
            "--assets",
            str(fixtures["assets.yaml"]),
            "--decisions",
            str(dec_path),
            "--profile",
            "bod-26-04",
            "--offline",
            "--kev-feed",
            str(fixtures["kev"]),
            "--epss-feed",
            str(fixtures["epss"]),
            "--nvd",
            str(fixtures["nvd"]),
            "--exploit-db",
            str(fixtures["exploitdb"]),
            "--webhook-endpoint",
            "https://hooks.example.org/vpp",
            "--webhook-oal-filter",
            "P1",
        ]
    )
    assert rc == 0
    assert len(captured) == 1
    payload = json.loads(captured[0]["data"].decode("utf-8"))
    assert payload["top_findings"]
    for item in payload["top_findings"]:
        for key in (
            "priority_tier",
            "oal",
            "ssvc_action",
            "sla_label",
            "operational_score",
            "in_kev",
            "epss_score",
            "decision_status",
            "invalidated_reasons",
        ):
            assert key in item
    inv_items = [it for it in payload["top_findings"] if it["decision_status"] == "deferred_invalidated"]
    assert inv_items
    assert inv_items[0]["invalidated_reasons"]

    # Transport layer also blocks SSRF target if constructed directly
    bad_cfg = WebhookRuntimeConfig(
        enabled=True,
        allow_spool=False,
        endpoints=(WebhookEndpointConfig(url="https://127.0.0.1/ssrf", oal_filter="all"),),
    )
    from tests.test_webhook_delivery import _make_ctx as _wh_ctx, _make_scan as _wh_scan

    wh_res = emit_configured_webhooks(
        ctx=_wh_ctx(tmp_path / "wh_direct", bad_cfg),
        scan_result=_wh_scan(),
        scanner_input=Path("scan.nessus"),
        output_paths={},
    )
    assert wh_res["failed"] == 1
    assert wh_res["sent"] == 0


def test_phase1_sqlite_and_nvd_feed_fail_closed_and_years_synthesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip
    from datetime import datetime, timezone
    from vulnparse_pin.app.bootstrap import initialize_runtime
    from vulnparse_pin.utils.feed_cache import FeedChecksumError
    from vulnparse_pin.utils.nvdcacher import NVDFeedCache

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))
    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "phase1-sqlite-key")
    monkeypatch.setenv("VP_FEED_CACHE_HMAC_KEY", "phase1-feed-key")

    fixtures = _copy_demo_fixtures(tmp_path / "fixtures")

    # 1. Bound validation rejects > now_year + 1
    too_far_year = str(datetime.now(timezone.utc).year + 2)
    with pytest.raises(VppError) as exc_y:
        _parse_nvd_years(too_far_year)
    assert exc_y.value.exit_code == 2

    # 2. NVDFeedCache.refresh(years=...) synthesizes years outside config start_year..end_year
    args = SimpleNamespace(portable=False, log_level="INFO", no_nvd=False)
    rt = initialize_runtime(args, quiet_banner=True)
    next_year = datetime.now(timezone.utc).year + 1
    requested = {2019, next_year}
    seen_keys: List[str] = []

    class _StubFC:
        def resolve_nvd_feed(self, *, key, ttl_hours, refresh_cache, offline):
            seen_keys.append(key)
            raise FileNotFoundError(key)

    rt.nvd_cache.refresh(
        config={"feed_cache": {"feeds": {"nvd": {"enabled": True, "start_year": 2024, "end_year": 2025}}}},
        feed_cache=_StubFC(),
        refresh_cache=False,
        offline=True,
        years=requested,
        include_modified=True,
    )
    assert "nvd.year.2019" in seen_keys
    assert f"nvd.year.{next_year}" in seen_keys
    assert "nvd.modified" in seen_keys

    # 3. FeedCacheManager.resolve_nvd_feed fails closed when cached NVD .json.gz is tampered
    gz_bytes = gzip.compress(b'{"vulnerabilities": []}')
    nvd_path = rt.feed_cache.write_atomic(
        "nvd.year.2024",
        gz_bytes,
        source_url="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz",
        mode="Online",
        validated=True,
        checksum_src="nvd.meta.sha256",
    )
    nvd_path.write_bytes(gzip.compress(b'{"vulnerabilities": [{"cve": {"id": "CVE-2024-9999"}}]}'))
    with pytest.raises(FeedChecksumError):
        rt.feed_cache.resolve_nvd_feed(key="nvd.year.2024", ttl_hours=24, refresh_cache=False, offline=True)

    # 4. Tampered SQLite cache fails closed BEFORE initialize_runtime on vpp scan and vpp intel sync
    kev_sqlite = rt.paths.cache_dir / "kev_cache.sqlite3"
    # Ensure kev_cache.sqlite3 exists signed first, then tamper it
    from vulnparse_pin.utils.enricher import KEVFeedCache
    KEVFeedCache(rt.ctx)
    assert kev_sqlite.exists()
    kev_sqlite.write_bytes(b"tampered-sqlite-payload")

    rc_scan = main(["scan", str(fixtures["demo.nessus"]), "--db", str(tmp_path / "fail.db"), "--offline"])
    assert rc_scan == 1
    assert not any(p.name.startswith("kev_cache.sqlite3.tampered.") for p in rt.paths.cache_dir.iterdir())

    with pytest.raises(VppError) as exc_sync:
        run_intel_command(
            SimpleNamespace(
                action="sync",
                feed="kev",
                refresh=False,
                allow_regen=False,
                years=None,
                portable=False,
                log_level="INFO",
            )
        )
    assert exc_sync.value.exit_code == 1
    assert not any(p.name.startswith("kev_cache.sqlite3.tampered.") for p in rt.paths.cache_dir.iterdir())


def test_phase1_re_enrich_secondary_cve_and_vector_cvss_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))

    fixtures = _copy_demo_fixtures(tmp_path / "fixtures")
    db_path = tmp_path / "sec_cve.vpp.db"
    clean_kev = _write_clean_kev_json(tmp_path / "clean_kev.json")
    clean_epss = _write_clean_epss_csv(tmp_path / "clean_epss.csv")

    rc = main(
        [
            "scan",
            str(fixtures["demo_baseline.nessus"]),
            "--db",
            str(db_path),
            "--assets",
            str(fixtures["assets.yaml"]),
            "--profile",
            "default",
            "--offline",
            "--kev-feed",
            str(clean_kev),
            "--epss-feed",
            str(clean_epss),
            "--nvd",
            str(fixtures["nvd"]),
            "--run-id",
            "run-sec-1",
        ]
    )
    assert rc == 0

    # 1. Attach secondary CVE (CVE-2024-3094) to CVE-2023-38545 with in_kev=False
    # 2. Set scanner_cvss_score=NULL + scanner_cvss_vector=9.8 on CVE-2023-4863 (not in nvd.json) with max_cvss=8.0
    with VppDatabase(db_path, read_only=False) as db:
        row_sec = db.execute(
            "SELECT finding_id FROM findings WHERE run_id = 'run-sec-1' AND UPPER(COALESCE(primary_cve, '')) = 'CVE-2023-38545' LIMIT 1"
        ).fetchone()
        row_vec = db.execute(
            "SELECT finding_id FROM findings WHERE run_id = 'run-sec-1' AND UPPER(COALESCE(primary_cve, '')) = 'CVE-2023-4863' LIMIT 1"
        ).fetchone()
        assert row_sec is not None and row_vec is not None
        fid_sec = row_sec[0]
        fid_vec = row_vec[0]

        db.execute(
            "INSERT INTO finding_cves (run_id, finding_id, cve_id) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            ["run-sec-1", fid_sec, "CVE-2024-3094"],
        )
        db.execute(
            "UPDATE triage_decisions SET decision_status = 'deferred_valid', decision_id = 'dec-sec-cve', "
            "assumed_state_json = ? WHERE run_id = 'run-sec-1' AND finding_id = ?",
            [json.dumps({"decision_id": "dec-sec-cve", "assumed_state": {"in_kev": False}}), fid_sec],
        )

        db.execute(
            "UPDATE findings SET scanner_cvss_score = NULL, scanner_cvss_vector = ? "
            "WHERE run_id = 'run-sec-1' AND finding_id = ?",
            ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", fid_vec],
        )
        db.execute(
            "UPDATE triage_decisions SET decision_status = 'deferred_valid', decision_id = 'dec-vec-cvss', "
            "assumed_state_json = ? WHERE run_id = 'run-sec-1' AND finding_id = ?",
            [json.dumps({"decision_id": "dec-vec-cvss", "assumed_state": {"max_cvss": 8.0}}), fid_vec],
        )

    # Re-enrich against fixtures["kev"] (which includes CVE-2024-3094) without --decisions:
    # must invalidate fid_sec via secondary CVE KEV flip AND fid_vec via CVSS vector fallback (> 8.0)
    from vulnparse_pin.utils.enricher import load_epss, load_kev
    from vulnparse_pin.app.bootstrap import initialize_runtime

    rt = initialize_runtime(SimpleNamespace(portable=False, log_level="INFO", no_nvd=True), quiet_banner=True)
    load_kev(rt.ctx, str(fixtures["kev"]), force_refresh=True, allow_regen=True)
    load_epss(rt.ctx, path_url=str(fixtures["epss"]), force_refresh=True, allow_regen=True)

    diff_json = tmp_path / "sec_diff.json"
    rc_diff = main(
        [
            "diff",
            "--db",
            str(db_path),
            "--re-enrich",
            "--fail-on",
            "stale-assumption",
            "--output-json",
            str(diff_json),
        ]
    )
    assert rc_diff == 2
    diff_data = json.loads(diff_json.read_text(encoding="utf-8"))
    assert diff_data["summary"]["invalidated_assumptions"] >= 2
    inv_sec = next(it for it in diff_data["invalidated_assumptions"] if it["finding_id"] == fid_sec)
    inv_vec = next(it for it in diff_data["invalidated_assumptions"] if it["finding_id"] == fid_vec)
    assert "kev_flipped" in inv_sec["violated_predicates"]
    assert "cvss_exceeded" in inv_vec["violated_predicates"]


def test_phase2_webhook_non_canonical_ipv4_metadata_and_dns_ssrf_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket
    from vulnparse_pin.core.classes.dataclass import WebhookEndpointConfig, WebhookRuntimeConfig
    from vulnparse_pin.core.config_validator import (
        validate_webhook_https_url,
        validate_webhook_resolved_dns,
    )
    from vulnparse_pin.utils.webhook_delivery import emit_configured_webhooks
    from tests.test_webhook_delivery import _make_ctx as _wh_ctx, _make_scan as _wh_scan

    monkeypatch.delenv("VP_WEBHOOK_ALLOW_PRIVATE", raising=False)

    # 1. Non-canonical IPv4 literals and cloud metadata hostnames must be rejected
    for bad_url in (
        "https://2130706433/vpp",
        "https://0x7f000001/vpp",
        "https://0177.0.0.1/vpp",
        "https://127.1/vpp",
        "https://metadata.aws.internal/latest/meta-data",
        "https://instance-data.ec2.internal/latest/meta-data",
        "https://metadata.azure.internal/metadata/instance",
        "https://metadata.internal/v1",
    ):
        with pytest.raises(ValueError):
            validate_webhook_https_url(bad_url)

    # Schema-contract allowed internal test host must remain accepted
    assert validate_webhook_https_url("https://hooks.example.internal/vpp") == "https://hooks.example.internal/vpp"

    # 2. Delivery-time DNS resolution blocking before requests.post
    monkeypatch.setenv("VP_WEBHOOK_HMAC_KEY", "phase2-dns-ssrf-secret")
    post_calls: List[Any] = []

    def _unexpected_post(*args, **kwargs):
        post_calls.append((args, kwargs))
        raise AssertionError("requests.post must not be called when DNS resolves to disallowed IP")

    monkeypatch.setattr("vulnparse_pin.utils.webhook_delivery.requests.post", _unexpected_post)

    for resolved_ip in ("127.0.0.1", "169.254.169.254"):
        def _mock_getaddrinfo(host, port, *args, _ip=resolved_ip, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ip, int(port or 443)))]

        monkeypatch.setattr("vulnparse_pin.core.config_validator.socket.getaddrinfo", _mock_getaddrinfo)

        with pytest.raises(ValueError):
            validate_webhook_resolved_dns("https://rebind.example.org/vpp")

        cfg = WebhookRuntimeConfig(
            enabled=True,
            allow_spool=False,
            endpoints=(WebhookEndpointConfig(url="https://rebind.example.org/vpp", oal_filter="all"),),
        )
        res = emit_configured_webhooks(
            ctx=_wh_ctx(tmp_path / f"wh_{resolved_ip}", cfg),
            scan_result=_wh_scan(),
            scanner_input=Path("scan.nessus"),
            output_paths={},
        )
        assert res["failed"] == 1
        assert res["sent"] == 0
        assert post_calls == []


def test_phase2_override_sqlite_fail_close_and_nvd_missing_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip
    from vulnparse_pin.app.bootstrap import initialize_runtime
    from vulnparse_pin.utils.enricher import KEVFeedCache
    from vulnparse_pin.utils.feed_cache import FeedChecksumError

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg_config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg_cache"))
    monkeypatch.delenv("VP_FEED_CACHE_HMAC_KEY", raising=False)
    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "phase2-sqlite-key")

    fixtures = _copy_demo_fixtures(tmp_path / "fixtures")
    rt = initialize_runtime(SimpleNamespace(portable=False, log_level="INFO", no_nvd=False), quiet_banner=True)
    KEVFeedCache(rt.ctx)

    nvd_sqlite = rt.paths.cache_dir / "nvd_cache.sqlite3"
    kev_sqlite = rt.paths.cache_dir / "kev_cache.sqlite3"
    assert nvd_sqlite.exists()
    assert kev_sqlite.exists()

    # 1. Tampered kev_cache.sqlite3 with --kev-feed override must fail closed without auto-quarantine
    kev_orig = kev_sqlite.read_bytes()
    kev_sqlite.write_bytes(b"tampered-kev-sqlite")
    rc_kev = main(
        [
            "scan",
            str(fixtures["demo.nessus"]),
            "--db",
            str(tmp_path / "fail_kev.db"),
            "--offline",
            "--kev-feed",
            str(fixtures["kev"]),
        ]
    )
    assert rc_kev == 1
    assert not any(p.name.startswith("kev_cache.sqlite3.tampered.") for p in rt.paths.cache_dir.iterdir())

    # Restore kev_cache.sqlite3, then tamper nvd_cache.sqlite3 with --nvd override
    kev_sqlite.write_bytes(kev_orig)
    nvd_sqlite.write_bytes(b"tampered-nvd-sqlite")
    rc_nvd = main(
        [
            "scan",
            str(fixtures["demo.nessus"]),
            "--db",
            str(tmp_path / "fail_nvd.db"),
            "--offline",
            "--nvd",
            str(fixtures["nvd"]),
        ]
    )
    assert rc_nvd == 1
    assert not any(p.name.startswith("nvd_cache.sqlite3.tampered.") for p in rt.paths.cache_dir.iterdir())

    # 2. Deleting .sha256 + .integrity.json on cached NVD .json.gz (with .meta.json intact and HMAC unset) fails closed
    gz_bytes = gzip.compress(b'{"vulnerabilities": []}')
    nvd_path = rt.feed_cache.write_atomic(
        "nvd.year.2024",
        gz_bytes,
        source_url="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz",
        mode="Online",
        validated=True,
        checksum_src="nvd.meta.sha256",
    )
    _, sha_path, meta_path = rt.feed_cache.resolve("nvd.year.2024")
    integrity_path = rt.feed_cache._feed_integrity_path(nvd_path)
    assert meta_path is not None and meta_path.exists()
    assert sha_path is not None and sha_path.exists()
    assert integrity_path.exists()

    sha_path.unlink()
    integrity_path.unlink()

    with pytest.raises(FeedChecksumError):
        rt.feed_cache.resolve_nvd_feed(key="nvd.year.2024", ttl_hours=24, refresh_cache=False, offline=True)


def test_root_dockerfile_dockerignore_and_release_ghcr_contract() -> None:
    from ruamel.yaml import YAML

    root_dockerfile = REPO_ROOT / "Dockerfile"
    deploy_dockerfile = DEPLOY_DIR / "Dockerfile"
    dockerignore = REPO_ROOT / ".dockerignore"
    release_yml = REPO_ROOT / ".github" / "workflows" / "release.yml"

    assert root_dockerfile.is_file()
    assert deploy_dockerfile.is_file()
    assert dockerignore.is_file()
    assert release_yml.is_file()

    root_df_text = root_dockerfile.read_text(encoding="utf-8")
    for expected in (
        "FROM python:3.12-slim AS builder",
        "FROM python:3.12-slim AS runtime",
        'ARG EXTRAS="ui"',
        "COPY pyproject.toml README.md LICENSE NOTICE ./",
        "COPY src/ ./src/",
        'HOME="/work"',
        'XDG_DATA_HOME="/cache/data"',
        'XDG_CONFIG_HOME="/cache/config"',
        'XDG_CACHE_HOME="/cache/xdg"',
        'TMPDIR="/tmp"',
        'TERM="xterm-256color"',
        "USER 10001:10001",
        'ENTRYPOINT ["vpp"]',
        'org.opencontainers.image.licenses="Apache-2.0"',
    ):
        assert expected in root_df_text, f"Root Dockerfile missing contract item: {expected}"

    deploy_df_text = deploy_dockerfile.read_text(encoding="utf-8")
    assert 'TERM="xterm-256color"' in deploy_df_text
    assert "USER 10001:10001" in deploy_df_text
    assert 'ENTRYPOINT ["vpp"]' in deploy_df_text

    ignore_lines = {
        line.strip()
        for line in dockerignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    for req_ignore in (
        ".git/",
        ".venv*",
        "*.vpp.db*",
        "*.sqlite3*",
        "tests/",
        "documentation/",
        "examples/",
        ".env*",
        "*.key",
    ):
        assert req_ignore in ignore_lines, f".dockerignore missing exclusion: {req_ignore}"

    yaml = YAML(typ="safe")
    release_data = yaml.load(release_yml.read_text(encoding="utf-8"))
    jobs = release_data["jobs"]
    assert "publish-ghcr" in jobs
    ghcr_job = jobs["publish-ghcr"]
    assert set(ghcr_job["needs"]) >= {"validation-gate", "test-matrix", "build"}
    assert ghcr_job["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }

    steps = ghcr_job["steps"]
    step_uses = {str(step.get("uses", "")) for step in steps if step.get("uses")}
    assert any(u.startswith("docker/setup-qemu-action@") for u in step_uses)
    assert any(u.startswith("docker/setup-buildx-action@") for u in step_uses)
    assert any(u.startswith("docker/login-action@") for u in step_uses)
    assert any(u.startswith("docker/build-push-action@") for u in step_uses)
    assert any(u.startswith("actions/attest-build-provenance@") for u in step_uses)

    meta_run = next(step["run"] for step in steps if step.get("id") == "meta")
    assert "GITHUB_REPOSITORY,," in meta_run
    # Execute the actual release metadata script against both GA and pre-release tags
    for tag, expect_latest in (("v2.0.0", True), ("v2.1.0-rc.1", False)):
        out_file = REPO_ROOT / ".pytest_cache" / f"ghcr_meta_{tag}.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                ["bash", "-c", meta_run],
                env={
                    **os.environ,
                    "GITHUB_REPOSITORY": "QT-Ashley/VulnParse-Pin",
                    "RELEASE_TAG": tag,
                    "GITHUB_OUTPUT": str(out_file),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            out_text = out_file.read_text(encoding="utf-8")
            assert "image_name=ghcr.io/qt-ashley/vulnparse-pin" in out_text
            assert ("ghcr.io/qt-ashley/vulnparse-pin:latest" in out_text) is expect_latest
        finally:
            if out_file.exists():
                out_file.unlink()

    smoke_run = next(step["run"] for step in steps if "Smoke-test container" in str(step.get("name", "")))
    assert "--read-only" in smoke_run
    assert "--cap-drop=ALL" in smoke_run
    assert "demo --no-ui" in smoke_run
    assert "verify /work/demo_out/runmanifest.json" in smoke_run

    push_step = next(step for step in steps if step.get("id") == "push")
    assert push_step["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert push_step["with"]["push"] is True
    assert push_step["with"]["sbom"] is True
    assert push_step["with"]["provenance"] == "mode=max"


