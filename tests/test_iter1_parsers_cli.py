# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import sqlite3
import stat
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from vulnparse_pin.app.bootstrap import build_pfh
from vulnparse_pin.app.io_resolution import resolve_io_paths_and_modes
from vulnparse_pin.app.output import invoke_duckdb_json_export
from vulnparse_pin.cli.args import get_args
from vulnparse_pin.cli.commands import _check_feed_health, _inspect_sqlite_health, run_verify_command
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.io.pfhandler import FilePathError
from vulnparse_pin.main import main
from vulnparse_pin.parsers._xml_security import safe_iterparse
from vulnparse_pin.parsers.base_parser import make_asset_id
from vulnparse_pin.parsers.nessusXML_parser import NessusXMLParser
from vulnparse_pin.parsers.nessus_csv_parser import NessusCSVParser
from vulnparse_pin.parsers.nuclei_jsonl_parser import NucleiJSONLParser
from vulnparse_pin.parsers.qualys_csv_parser import QualysCSVParser
from vulnparse_pin.parsers.qualys_parser import QualysXMLParser
from vulnparse_pin.parsers.sarif_parser import SarifParser, _FastSarifStreamReader
from vulnparse_pin.reporting.renderer import (
    _build_roadmap_context,
    md_escape,
    render_dossier_markdown,
    render_executive_roadmap_markdown,
)
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import ensure_run, insert_ledger_events, upsert_scores
from vulnparse_pin.ui.app import DeferralModal, _format_score_trace_lines, VppApp
from vulnparse_pin.utils.markdown_report import _generate_executive_report, _generate_technical_report
from vulnparse_pin.utils.runmanifest import (
    build_runmanifest_from_db,
    verify_runmanifest,
    verify_runmanifest_integrity,
    write_runmanifest,
)
from vulnparse_pin.utils.validations import FileInputValidator


def _dummy_ctx(pfh=None):
    return SimpleNamespace(
        logger=MagicMock(),
        pfh=pfh,
        args=SimpleNamespace(file=None),
    )


def test_xml_security_bomless_utf16_and_entity_outside_tag(tmp_path: Path) -> None:
    ctx = _dummy_ctx()

    # Validator rejects BOM-less UTF-16LE XML cleanly and defaults to 500 MiB max size
    u16le_path = tmp_path / "bomless_u16le.nessus"
    u16le_path.write_bytes('<?xml version="1.0"?><NessusClientData_v2/>'.encode("utf-16-le"))
    validator = FileInputValidator(ctx, str(u16le_path))
    assert validator.max_size_bytes == 500 * 1024 * 1024
    with pytest.raises(ValueError, match="UTF-16"):
        validator._validate_xml_stream()

    # BOM-less UTF-16BE XXE fails closed in NessusXMLParser
    u16be_xxe = (
        '<?xml version="1.0" encoding="UTF-16BE"?>'
        '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        '<NessusClientData_v2/>'
    ).encode("utf-16-be")
    xxe_path = tmp_path / "xxe_u16be.nessus"
    xxe_path.write_bytes(u16be_xxe)
    parser = NessusXMLParser(ctx=ctx, filepath=str(xxe_path))
    with pytest.raises(ValueError):
        list(parser._stream_batches(xxe_path, batch_size=10))

    # Entity declarations outside target tag filter are still intercepted by safe_iterparse
    with pytest.raises(ValueError):
        list(
            safe_iterparse(
                io.BytesIO(b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "v">]><r><other>&e;</other></r>'),
                events=("end",),
                tag=("ReportItem",),
            )
        )


def test_validator_streams_csv_nul_bytes_beyond_64kib(tmp_path: Path) -> None:
    ctx = _dummy_ctx()
    csv_path = tmp_path / "nul_late.csv"
    with csv_path.open("wb") as fh:
        fh.write(b"col1,col2\n")
        fh.write(b"a,b\n" * 20000)
        fh.write(b"evil,\x00bad\n")
    v = FileInputValidator(ctx, str(csv_path))
    with pytest.raises(ValueError, match="NUL"):
        v._validate_csv_stream()


def test_sarif_stream_numeric_split_trailing_artifacts_and_bad_indices(tmp_path: Path) -> None:
    reader = _FastSarifStreamReader(io.BytesIO(b'{"a": 123.45, "b": 1e+10}'), chunk_bytes=7)
    assert reader._decode_value() == {"a": 123.45, "b": 1e10}

    ctx = _dummy_ctx()
    sarif_small = tmp_path / "small.sarif"
    sarif_small.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Tool", "rules": [{"id": "R1"}]}},
                        "results": [
                            {
                                "ruleId": "R1",
                                "ruleIndex": True,
                                "level": "error",
                                "message": {"text": "m1"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"index": 0},
                                            "region": {"startLine": 12.0},
                                        }
                                    }
                                ],
                            }
                        ],
                        "artifacts": [{"location": {"uri": "late.py"}}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    sp = SarifParser(ctx=ctx, filepath=str(sarif_small))
    items = [r for b in sp._stream_batches(sarif_small, batch_size=10) for r in b]
    assert len(items) == 1
    assert "late.py" in str(items[0])

    sarif_large = tmp_path / "large.sarif"
    sarif_large.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Tool", "rules": [{"id": "R1"}]}},
                        "results": [
                            {
                                "ruleId": "R1",
                                "level": "warning",
                                "message": {"text": f"m{i}"},
                                "locations": [{"physicalLocation": {"artifactLocation": {"index": 0}}}],
                            }
                            for i in range(4105)
                        ],
                        "artifacts": [{"location": {"uri": "trailing_large.py"}}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    sp_large = SarifParser(ctx=ctx, filepath=str(sarif_large))
    items_large = [r for b in sp_large._stream_batches(sarif_large, batch_size=1000) for r in b]
    assert len(items_large) == 4105
    assert "trailing_large.py" in str(items_large[0])
    assert "trailing_large.py" in str(items_large[-1])


def test_qualys_nested_host_and_empty_asset_id_match(tmp_path: Path) -> None:
    ctx = _dummy_ctx()
    q_path = tmp_path / "qualys.xml"
    q_path.write_text(
        """<?xml version="1.0"?>
<SCAN>
  <ASSET>
    <IP>10.8.8.8</IP>
  </ASSET>
  <ASSET>
    <HOST>10.9.9.9</HOST>
    <VULN><QID>1001</QID><SEVERITY>3</SEVERITY><TITLE>NestedV</TITLE></VULN>
  </ASSET>
</SCAN>
""",
        encoding="utf-8",
    )
    parser = QualysXMLParser(ctx=ctx, filepath=str(q_path))
    parsed = parser.parse()
    expected_empty_id = make_asset_id(ip="10.8.8.8", hostname="10.8.8.8")
    assert any(getattr(a, "asset_id", None) == expected_empty_id for a in parsed.assets)
    assert any(getattr(a, "ip_address", None) == "10.9.9.9" for a in parsed.assets)


def test_csv_large_fields_and_nuclei_ipv6(tmp_path: Path) -> None:
    ctx = _dummy_ctx()
    big_text = "A" * 200_000

    ncsv = tmp_path / "nessus.csv"
    with ncsv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Plugin ID", "CVE", "CVSS v2.0 Base Score", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Description", "Solution"])
        w.writerow(["101", "CVE-2024-0001", "7.5", "High", "10.0.0.5", "tcp", "443", "Big", "Syn", big_text, "Sol"])
    nb = list(NessusCSVParser(ctx=ctx, filepath=str(ncsv))._stream_batches(ncsv, batch_size=10))
    assert len(nb[0][0]["description"]) == 200_000

    qcsv = tmp_path / "qualys.csv"
    with qcsv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["IP", "DNS", "QID", "Title", "Severity", "Port", "Protocol", "Results"])
        w.writerow(["10.0.0.6", "q.local", "202", "BigQ", "4", "443", "tcp", big_text])
    qb = list(QualysCSVParser(ctx=ctx, filepath=str(qcsv))._stream_batches(qcsv, batch_size=10))
    assert len(qb) == 1 and len(qb[0]) == 1

    nuc = tmp_path / "nuclei.jsonl"
    nuc.write_text(
        "\n".join(
            [
                json.dumps({"template-id": "t1", "info": {"name": "T1", "severity": "high"}, "host": "2001:db8::1"}),
                json.dumps({"template-id": "t2", "info": {"name": "T2", "severity": "high"}, "host": "[2001:db8::2]"}),
                json.dumps({"template-id": "t3", "info": {"name": "T3", "severity": "high"}, "host": "[2001:db8::3]:8443"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rows = list(NucleiJSONLParser(ctx=ctx, filepath=str(nuc))._stream_batches(nuc, batch_size=10))[0]
    assert rows[0]["ip_address"] == "2001:db8::1" and (rows[0].get("affected_port") or 0) == 0
    assert rows[1]["ip_address"] == "2001:db8::2" and (rows[1].get("affected_port") or 0) == 0
    assert rows[2]["ip_address"] == "2001:db8::3" and rows[2]["affected_port"] == 8443


def test_duckdb_symlinks_and_0600_perms(tmp_path: Path) -> None:
    dangling = tmp_path / "dangling.vpp.db"
    dangling.symlink_to(tmp_path / "target.vpp.db")
    with pytest.raises(ValueError):
        VppDatabase(dangling)

    wal_sym_base = tmp_path / "wal_sym.vpp.db"
    Path(f"{wal_sym_base}.wal").symlink_to(tmp_path / "evil.wal")
    with pytest.raises(ValueError):
        VppDatabase(wal_sym_base)

    real_dir = tmp_path / "real"
    real_dir.mkdir()
    sym_dir = tmp_path / "sym"
    sym_dir.symlink_to(real_dir)
    with pytest.raises(ValueError):
        VppDatabase(sym_dir / "nested.vpp.db")

    old_u = os.umask(0o000)
    try:
        good_db = real_dir / "good.vpp.db"
        db = VppDatabase(good_db)
        assert stat.S_IMODE(os.lstat(good_db).st_mode) == 0o600
        with db.transaction():
            pass
        db.close()
        assert stat.S_IMODE(os.lstat(good_db).st_mode) == 0o600
    finally:
        os.umask(old_u)


def test_pfh_defaults_offline_feeds_and_cli_args(tmp_path: Path) -> None:
    args_default = get_args(["intel", "status"])
    assert args_default.forbid_symlinks_read is True
    assert args_default.file_mode == 0o600
    assert args_default.dir_mode == 0o700

    reordered = get_args(["--feed", "nvd", "intel", "status"])
    assert reordered.command == "intel" and reordered.feed == "nvd"

    rm = tmp_path / "rm.json"
    rm.write_text("{}", encoding="utf-8")
    vrm = get_args(["--verify-runmanifest", str(rm), "--log-level", "DEBUG", "-Lf", str(tmp_path / "l.log"), "-P"])
    assert vrm.command == "verify" and vrm.log_level == "DEBUG" and vrm.portable is True

    paths = SimpleNamespace(
        base_dir=tmp_path,
        config_dir=tmp_path / "cfg",
        cache_dir=tmp_path / "cache",
        log_dir=tmp_path / "log",
        output_dir=tmp_path / "out",
    )
    paths.cache_dir.mkdir(parents=True, exist_ok=True)
    pfh = build_pfh(paths, MagicMock(), SimpleNamespace())
    assert pfh.forbid_symlinks_read is True
    assert pfh.file_mode == 0o600
    assert pfh.dir_mode == 0o700

    scan_f = tmp_path / "scan.json"
    scan_f.write_text("{}", encoding="utf-8")
    fc = SimpleNamespace(resolve=lambda k: (paths.cache_dir / f"{k}.dat", None, None))
    ctx_obj = SimpleNamespace(logger=MagicMock(), pfh=pfh, services=SimpleNamespace(feed_cache=fc))
    rt = SimpleNamespace(paths=paths, pfh=pfh, logger=MagicMock(), ctx=ctx_obj)

    args_off = SimpleNamespace(
        file=scan_f,
        output=None,
        output_csv=None,
        output_md=None,
        output_md_technical=None,
        output_runmanifest=None,
        no_csv_sanitize=False,
        no_exploit=True,
        no_kev=False,
        kev_source="online",
        kev_feed=None,
        no_epss=True,
        epss_source="online",
        epss_feed=None,
        offline=True,
    )
    with pytest.raises(FileNotFoundError):
        resolve_io_paths_and_modes(args_off, rt, "https://x/kev.json", "https://x/epss.csv.gz")

    real_kev = tmp_path / "real_kev.json"
    real_kev.write_text("{}", encoding="utf-8")
    sym_kev = tmp_path / "sym_kev.json"
    sym_kev.symlink_to(real_kev)
    args_sym = SimpleNamespace(**vars(args_off))
    args_sym.offline = False
    args_sym.kev_feed = str(sym_kev)
    with pytest.raises(FilePathError):
        resolve_io_paths_and_modes(args_sym, rt, "https://x/kev.json", "https://x/epss.csv.gz")


def test_intel_status_readonly_and_hmac_checks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["intel", "status", "--portable", "--json"]) == 0
    assert json.loads(buf.getvalue()).keys() >= {"nvd", "epss", "kev", "exploit_db", "ghsa", "osv"}
    assert not list(tmp_path.rglob("*.sqlite3"))

    sq = tmp_path / "nvd_cache.sqlite3"
    conn = sqlite3.connect(str(sq))
    conn.execute("CREATE TABLE nvd_records (cve_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO nvd_records VALUES ('CVE-2024-0001')")
    conn.commit()
    conn.close()
    os.chmod(sq, 0o600)

    assert _inspect_sqlite_health(sq, "nvd_records")["health"] == "no-signature"
    assert not Path(f"{sq}.sig.json").exists()

    digest = hashlib.sha256(sq.read_bytes()).hexdigest()
    sig_p = Path(f"{sq}.sig.json")
    sig_p.write_text(json.dumps({"mode": "sha256", "digest": digest, "signature": digest}), encoding="utf-8")
    os.chmod(sig_p, 0o600)

    monkeypatch.delenv("VP_SQLITE_HMAC_KEY", raising=False)
    res_ok = _inspect_sqlite_health(sq, "nvd_records")
    assert res_ok["health"] == "valid" and res_ok["rows"] == 1

    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "secret-key")
    assert _inspect_sqlite_health(sq, "nvd_records")["health"] == "tampered"

    mac = hmac.new(b"secret-key", digest.encode("utf-8"), hashlib.sha256).hexdigest()
    sig_p.write_text(json.dumps({"mode": "hmac-sha256", "digest": digest, "signature": mac}), encoding="utf-8")
    assert _inspect_sqlite_health(sq, "nvd_records")["health"] == "valid"

    os.chmod(sq, 0o666)
    assert _inspect_sqlite_health(sq, "nvd_records")["health"] == "world-writable"

    sym_sq = tmp_path / "sym.sqlite3"
    sym_sq.symlink_to(sq)
    assert _inspect_sqlite_health(sym_sq, "nvd_records")["health"] == "symlink"

    # _check_feed_health maps PermissionError -> world-writable
    feed_file = tmp_path / "feed.csv"
    feed_file.write_text("a,b\n", encoding="utf-8")
    fc_mock = SimpleNamespace(
        resolve=lambda k: (feed_file, tmp_path / "feed.sha256", None),
        load_meta=lambda k: {},
        is_fresh=lambda k: True,
        ensure_feed_checksum=MagicMock(side_effect=PermissionError("world-writable")),
    )
    assert _check_feed_health(fc_mock, "epss")["health"] == "world-writable"


def test_runmanifest_and_verify_outputs_and_pretty_json(tmp_path: Path) -> None:
    f1 = tmp_path / "scan1.nessus"
    f2 = tmp_path / "scan2.sarif"
    f1.write_text("a", encoding="utf-8")
    f2.write_text("b", encoding="utf-8")
    out_csv = tmp_path / "out.csv"
    out_csv.write_text("h1,h2\nv1,v2\n", encoding="utf-8")

    db_p = tmp_path / "rm.vpp.db"
    with VppDatabase(db_p) as db:
        ensure_run(db, "r1", profile="default", input_files=[str(f1), str(f2)])
        ledger = LedgerService()
        ledger.append_event(
            component="Scoring",
            event_type="decision",
            subject_ref="s:1",
            reason_code="RC1",
            reason_text="ok",
        )
        snap = ledger.snapshot()
        insert_ledger_events(
            db,
            "r1",
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

        m = build_runmanifest_from_db(db, "r1", outputs={"csv": str(out_csv)})
        assert str(m["inputs"]["target_sha256"]).startswith("sha256:")
        assert len(m["inputs"]["input_files_sha256"]) == 2
        assert m["output_hashes"]["csv"].startswith("sha256:")
        verify_runmanifest(m)

        bad_cnt = json.loads(json.dumps(m))
        bad_cnt["decision_ledger"]["entry_count"] = 42
        with pytest.raises(ValueError, match="entry_count"):
            verify_runmanifest_integrity(bad_cnt)

        rm_file = tmp_path / "rm.json"
        write_runmanifest(None, m, rm_file)
        assert run_verify_command(SimpleNamespace(runmanifest=str(rm_file))) == 0
        out_csv.write_text("tampered", encoding="utf-8")
        assert run_verify_command(SimpleNamespace(runmanifest=str(rm_file))) == 1

        db.execute("UPDATE ledger_events SET prev_hash = NULL, entry_hash = NULL WHERE run_id = 'r1'")
        tampered_m = build_runmanifest_from_db(db, "r1")
        with pytest.raises(ValueError):
            verify_runmanifest(tampered_m)

    json_out = tmp_path / "pretty.json"
    invoke_duckdb_json_export(
        lambda _db, _rid, p, *, presentation="namespace", pfh=None: Path(p).write_text('{"a":1}\n', encoding="utf-8"),
        None,
        "r1",
        json_out,
        presentation="namespace",
        pfh=None,
        pretty_print=True,
    )
    assert "\n    " in json_out.read_text(encoding="utf-8")


def test_markdown_escaping_and_sql_join_alignment(tmp_path: Path) -> None:
    assert md_escape("a\\|b `c` [l](u) ![i](x) <script>\r\ny") == "a\\\\\\|b \\`c\\` \\[l\\](u) \\!\\[i\\](x) &lt;script&gt; y"

    db_path = tmp_path / "join.vpp.db"
    with VppDatabase(db_path) as db:
        ensure_run(db, "r-join", profile="default")
        db.execute(
            "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, ip_address, owner, internet_facing) "
            "VALUES ('r-join', 'a1', '10.0.0.1', 'host-1', '10.0.0.1', 'secops', TRUE)"
        )
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, primary_cve, cves_json, title, description, solution, scanner_severity, source_format) "
            "VALUES ('r-join', 'f1', 'a1', 'cve_threat', 'CVE-2024-0001', '[\"CVE-2024-0001\", \"CVE-2024-8888\", \"CVE-2024-9999\"]', "
            "'Test | [Bad](https://evil.test)', 'Desc', 'Upgrade', 'High', 'nessus-xml')"
        )
        db.execute(
            "INSERT INTO finding_cves (run_id, finding_id, cve_id) VALUES "
            "('r-join', 'f1', 'CVE-2024-0001'), ('r-join', 'f1', 'CVE-2024-8888'), ('r-join', 'f1', 'CVE-2024-9999')"
        )
        db.execute(
            "INSERT INTO enrichment_snapshots (run_id, cve_id, cvss_score, epss_score, in_kev, verified_exploit) VALUES "
            "('r-join', 'CVE-2024-0001', 5.0, 0.01, FALSE, FALSE), "
            "('r-join', 'CVE-2024-9999', 9.8, 0.92, FALSE, TRUE), "
            "('r-join', 'CVE-2024-8888', 7.5, 0.50, TRUE, FALSE)"
        )
        upsert_scores(
            db,
            "r-join",
            [
                {
                    "finding_id": "f1",
                    "asset_id": "a1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 9.5,
                    "operational_score": 9.5,
                    "risk_band": "Critical",
                    "score_trace": {"primary_cve": "CVE-2024-9999", "verified_exploit": True},
                }
            ],
        )
        db.execute(
            "INSERT INTO triage_decisions (run_id, finding_id, asset_id, profile, priority_tier, sla_bucket, sla_days, decision_status) "
            "VALUES ('r-join', 'f1', 'a1', 'default', 'P1', '3-day', 3, 'active')"
        )
        ctx_rm = _build_roadmap_context(db, "r-join")
        assert ctx_rm["kpis"]["verified_exploit_findings"] == 1
        assert ctx_rm["sla_roadmap"][0]["kev_count"] == 1
        assert ctx_rm["quick_wins"][0]["in_kev"] is True
        assert ctx_rm["quick_wins"][0]["fix_key"] == "CVE-2024-9999"

        dos_md = render_dossier_markdown(db, "r-join")
        rm_md = render_executive_roadmap_markdown(db, "r-join")
        assert "\\[Bad\\](https://evil.test)" in dos_md
        assert "CVE-2024-9999" in rm_md

    # Legacy markdown_report functions escape untrusted titles/hosts
    scan_stub = SimpleNamespace(
        assets=[],
        derived=SimpleNamespace(passes={}),
    )
    summary_stub = SimpleNamespace(
        overview={
            "total_assets": 1,
            "total_findings": 1,
            "average_asset_risk": 8.0,
            "exploitable_findings": 0,
            "kev_listed_findings": 0,
            "scan_timestamp": "2026-01-01 | <bad>",
        },
        asset_summary={
            "total_assets": 1,
            "assets": [
                {
                    "asset_id": "a|1",
                    "ip": "10.0.0.1",
                    "hostname": "host|[1]",
                    "criticality": "high",
                    "total_findings": 1,
                    "risk_score": 8.0,
                    "critical_findings": 1,
                    "high_findings": 0,
                    "top_cve": "CVE-2024-1",
                }
            ],
        },
        finding_summary={"total": 1, "by_severity": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}},
        risk_distribution={"total_scored": 1, "by_risk_band": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}},
        top_risks=[],
        remediation_priorities={"immediate_action": 0, "high_priority": 0, "medium_priority": 0, "immediate_cves": []},
        enrichment_metrics={"total_findings": 1, "total_cves": 1, "enriched_findings": 1, "enrichment_coverage": 1.0},
        decision_trace_summary={},
    )
    exec_md = _generate_executive_report(_scan=scan_stub, summary=summary_stub)
    tech_md = _generate_technical_report(_scan=scan_stub, summary=summary_stub)
    assert "a\\|1" in exec_md and "&lt;bad&gt;" in exec_md
    assert "host\\|\\[1\\]" in tech_md


def test_ui_formatting_and_export_error_handling(tmp_path: Path) -> None:
    lines = _format_score_trace_lines({"operational_score": None, "cvss_score": 0.0, "verified_exploit": True})
    text = "\n".join(lines)
    assert "OpScore: 0.00" in text
    assert "CVSS: 0.0 " in text
    assert "Verified Exploit: True" in text

    app_obj = VppApp.__new__(VppApp)
    app_obj.run_id = "r1"
    db_file = tmp_path / "ui.db"
    db_file.write_text("x", encoding="utf-8")
    app_obj.db_path = db_file
    app_obj.selected_finding_id = "f1"
    app_obj.output_dir = tmp_path / "out"
    app_obj.diff_report = None
    app_obj.template_dir = None
    app_obj._ensure_pfh = MagicMock(side_effect=PermissionError("denied"))
    statuses = []
    app_obj._set_status = lambda s: statuses.append(s)
    app_obj._export_dossier(finding_id=None)
    assert statuses and "[ERR] Export failed: denied" in statuses[0]

    # Invalid calendar date like 2026-02-30 must be rejected by DeferralModal
    modal = DeferralModal.__new__(DeferralModal)
    err_widget = MagicMock()
    widgets = {
        "#defer-asset": SimpleNamespace(value="*"),
        "#defer-id": SimpleNamespace(value="CVE-2024-1"),
        "#defer-status": SimpleNamespace(value="deferred"),
        "#defer-rationale": SimpleNamespace(value="reason"),
        "#defer-owner": SimpleNamespace(value="secops"),
        "#defer-expires": SimpleNamespace(value="2026-02-30"),
        "#defer-error": err_widget,
    }
    modal.query_one = lambda sel, *_a: widgets[sel]
    modal.dismiss = MagicMock()
    modal.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="defer-save")))
    assert modal.dismiss.call_count == 0
    assert err_widget.update.call_count == 1
    assert "Invalid calendar expiry date" in err_widget.update.call_args[0][0]


def test_duckdb_export_pretty_csv_unsanitized_and_validator_json(tmp_path: Path) -> None:
    from vulnparse_pin.utils.csv_exporter import export_duckdb_csv
    from vulnparse_pin.utils.reportgen import export_duckdb_json

    ctx = _dummy_ctx()
    sarif_ok = tmp_path / "ok.sarif"
    sarif_ok.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
    assert FileInputValidator(ctx, str(sarif_ok)).is_valid_extension_structure() is True

    csv_ok = tmp_path / "ok.csv"
    csv_ok.write_text("col1,col2\n1,2\n", encoding="utf-8")
    assert FileInputValidator(ctx, str(csv_ok)).is_valid_extension_structure() is True

    db_path = tmp_path / "exp.vpp.db"
    with VppDatabase(db_path) as db:
        ensure_run(db, "r-exp", profile="default")
        db.execute(
            "INSERT INTO assets (run_id, asset_id, canonical_key, hostname, ip_address) "
            "VALUES ('r-exp', 'a1', '10.0.0.1', 'host-1', '10.0.0.1')"
        )
        db.execute(
            "INSERT INTO findings (run_id, finding_id, asset_id, scoring_track, primary_cve, cves_json, title, scanner_severity, source_format) "
            "VALUES ('r-exp', 'f1', 'a1', 'cve_threat', 'CVE-2024-0001', "
            "'[\"CVE-2024-0001\", \"CVE-2024-9999\"]', '=HYPERLINK(\"http://evil.test\",\"Click\")', 'High', 'nessus-xml')"
        )
        db.execute(
            "INSERT INTO finding_cves (run_id, finding_id, cve_id) VALUES "
            "('r-exp', 'f1', 'CVE-2024-0001'), ('r-exp', 'f1', 'CVE-2024-9999')"
        )
        db.execute(
            "INSERT INTO enrichment_snapshots (run_id, cve_id, cvss_score, epss_score, in_kev, verified_exploit) VALUES "
            "('r-exp', 'CVE-2024-0001', 4.0, 0.01, FALSE, FALSE), "
            "('r-exp', 'CVE-2024-9999', 9.8, 0.90, TRUE, TRUE)"
        )
        upsert_scores(
            db,
            "r-exp",
            [
                {
                    "finding_id": "f1",
                    "asset_id": "a1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 9.2,
                    "operational_score": 9.2,
                    "risk_band": "Critical",
                    "score_trace": {"primary_cve": "CVE-2024-9999", "in_kev": True, "verified_exploit": True},
                }
            ],
        )

        safe_csv = tmp_path / "safe.csv"
        export_duckdb_csv(db, "r-exp", safe_csv, profile="full", csv_sanitization=True)
        safe_rows = list(csv.DictReader(safe_csv.open("r", encoding="utf-8", newline="")))
        assert len(safe_rows) == 1
        assert safe_rows[0]["title"].startswith("'=")
        assert safe_rows[0]["cisa_kev"] == "True"
        assert safe_rows[0]["verified_exploit"] == "True"

        unsafe_csv = tmp_path / "unsafe.csv"
        export_duckdb_csv(db, "r-exp", unsafe_csv, profile="full", csv_sanitization=False)
        unsafe_rows = list(csv.DictReader(unsafe_csv.open("r", encoding="utf-8", newline="")))
        assert unsafe_rows[0]["title"] == '=HYPERLINK("http://evil.test","Click")'

        pretty_json = tmp_path / "pretty_native.json"
        export_duckdb_json(db, "r-exp", pretty_json, presentation="namespace", pretty_print=True)
        pretty_txt = pretty_json.read_text(encoding="utf-8")
        assert "\n    \"assets\": [" in pretty_txt
        parsed_json = json.loads(pretty_txt)
        enr = parsed_json["assets"][0]["findings"][0]["enrichment"]
        assert enr["in_kev"] is True and enr["verified_exploit"] is True
        assert enr["cvss_score"] == 9.8
