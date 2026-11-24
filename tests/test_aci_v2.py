# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest

from vulnparse_pin.core.classes.dataclass import AppPaths, Asset, Finding, RunContext, ScanMetaData, ScanResult, Services
from vulnparse_pin.core.config_source import ConfigSource
from vulnparse_pin.core.passes.ACI.aci_pass import ACIV2Pass
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import validate_and_normalize_semantics
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.utils.logger import LoggerWrapper


def _make_ctx(tmp_path: Path, db: VppDatabase | None = None, run_id: str | None = None) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "aci.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    svc = Services(db=db, run_id=run_id)
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger, services=svc, db=db, run_id=run_id)


def test_aci_enabled_by_default_in_packaged_config() -> None:
    raw = json.loads(resources.files("vulnparse_pin.resources").joinpath("tn_triage.json").read_text(encoding="utf-8"))
    assert raw["aci"]["enabled"] is True
    assert ACIV2Pass().cfg.enabled is True


def test_aci_v2_duckdb_cwe_nuclei_sarif_and_lateral_movement_fix(tmp_path: Path) -> None:
    db = VppDatabase(":memory:")
    run_id = "run-aci-v2"
    db.execute(
        "INSERT INTO runs (run_id, created_at_utc, vpp_version, profile) VALUES (?, ?, ?, ?)",
        [run_id, "2026-11-24T00:00:00Z", "2.0.0", "default"],
    )
    db.execute(
        "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, inventory_status) VALUES (?, 'a1', 'host:a1', 'srv1', 'matched')",
        [run_id],
    )

    rows = [
        # Nuclei tags: default-login + panel
        ("f-nuclei-login", "[]", "Admin Panel Login", "Exposed dashboard", None, None, '["default-login","panel"]', "nuclei/http-default-login"),
        # CWEs: CWE-89 SQLi + CWE-78 command exec + CWE-918 SSRF + CWE-502 deserialization
        ("f-cwe-sqli", '["CWE-89","CWE-78"]', "App Input Handler", "Generic description", None, None, "[]", "sarif/rule-1"),
        ("f-cwe-ssrf", '["CWE-918","CWE-502"]', "Webhook Fetcher", "Generic description", None, None, "[]", "sarif/rule-2"),
        # Lateral movement KEEP when SMB/SSH + lateral/credential context exists
        ("f-lat-keep", "[]", "SMB Relay Credential Reuse", "Attacker can pivot using pass-the-hash over smb with credential", None, 445, "[]", "nessus/1001"),
        # Bare port banner on SSH/SMB without lateral/credential/exec context -> suppress lateral_movement!
        ("f-lat-drop", "[]", "SSH Protocol Version Banner", "OpenSSH banner observed over tcp", "SSH-2.0-OpenSSH_8.9", 22, "[]", "nessus/1002"),
    ]
    for fid, cwes_j, title, desc, p_out, port, tags_j, sig in rows:
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, cwes_json, title, description, plugin_output, affected_port, tags_json) "
            "VALUES (?, ?, 'a1', 'exposure_weakness', ?, ?, ?, ?, ?, ?)",
            [run_id, fid, cwes_j, title, desc, p_out, port, tags_j],
        )
        db.execute(
            "INSERT INTO finding_evidence (run_id, finding_id, evidence_idx, source_format, scanner_sig) VALUES (?, ?, 0, 'sarif', ?)",
            [run_id, fid, sig],
        )

    ctx = _make_ctx(tmp_path, db=db, run_id=run_id)
    out = ACIV2Pass().run(ctx)
    assert out.meta.name == "ACI"
    assert out.meta.version == "2.0"

    signals = {
        r[0]: (json.loads(r[1]), json.loads(r[2]), float(r[3]), float(r[4]))
        for r in db.execute(
            "SELECT finding_id, capabilities_json, chains_json, confidence, uplift_score FROM aci_signals WHERE run_id = ?",
            [run_id],
        ).fetchall()
    }

    assert {"auth_bypass", "panel", "initial_access", "exposure", "information_disclosure"}.issubset(
        set(signals["f-nuclei-login"][0])
    )
    assert {"sql_injection", "command_execution"}.issubset(set(signals["f-cwe-sqli"][0]))
    assert {"ssrf", "deserialization", "remote_execution", "initial_access"}.issubset(set(signals["f-cwe-ssrf"][0]))

    # Fixed cap_lateral_movement guardrail
    assert "lateral_movement" in signals["f-lat-keep"][0]
    assert "lateral_movement" not in signals["f-lat-drop"][0]
    db.close()


def test_aci_asset_uplift_not_double_multiplied() -> None:
    defaults = ConfigSource.load_packaged_defaults()
    tn_cfg, issues = validate_and_normalize_semantics(defaults.topn_config)
    assert tn_cfg is not None and not issues
    assert tn_cfg.aci.enabled is True
    assert tn_cfg.aci.asset_uplift_weight == pytest.approx(0.5)
    topn = TopNPass(tn_cfg)
    # precomputed asset rank_uplift=1.2 with asset_uplift_weight=0.5 should NOT multiply by 0.5 a second time
    uplift = topn._compute_asset_aci_uplift({"rank_uplift": 1.2, "weighted_confidence": 0.9})
    assert uplift == pytest.approx(1.2)
