# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import asyncio
import csv
import gzip
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from vulnparse_pin.app.output import export_v2_outputs
from vulnparse_pin.cli.commands import _print_v2_summary, run_verify_command
from vulnparse_pin.main import main as cli_main
from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.assets_context import AssetContextMatcher
from vulnparse_pin.core.classes.dataclass import FeedCachePolicy, FeedSpec, RunContext
from vulnparse_pin.core.diff_engine import DiffEngine, evaluate_fail_gate
from vulnparse_pin.core.passes.ACI.aci_pass import (
    AttackCapabilityInferencePass,
    _effective_text_tokens,
    _infer_single_record,
)
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringV3Pass
from vulnparse_pin.core.passes.Summary.summary_pass import SummaryV2Pass
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.reporting.renderer import (
    _fetch_dossier_findings,
    _validate_template_dir,
    export_dossier_bundle,
    render_dossier_html,
    render_dossier_markdown,
    render_executive_roadmap_html,
    render_executive_roadmap_markdown,
)
from vulnparse_pin.storage.db import VppDatabase
from vulnparse_pin.storage.repositories import (
    ensure_run,
    get_finding_detail,
    get_run_summary_counts,
    ingest_normalized_batches,
    query_findings_page,
    upsert_enrichment_snapshots,
    upsert_scores,
    upsert_triage_decisions,
)
from vulnparse_pin.ui.app import (
    VppApp,
    _build_silent_ui_pfh,
    _format_finding_inspector,
    _format_score_trace_lines,
)
from vulnparse_pin.utils.csv_exporter import export_duckdb_csv
from vulnparse_pin.utils.feed_cache import MAX_NVD_META_BYTES, FeedCacheManager
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.markdown_report import _write_markdown_output
from vulnparse_pin.utils.reportgen import export_duckdb_json
from vulnparse_pin.utils.runmanifest import build_runmanifest_from_db, write_runmanifest


def _make_runtime_ctx(
    tmp_path: Path,
    *,
    monkeypatch: Optional[pytest.MonkeyPatch] = None,
    db: Any = None,
    run_id: Optional[str] = None,
) -> RunContext:
    root = tmp_path / "rt"
    root.mkdir(parents=True, exist_ok=True)
    if monkeypatch is not None:
        monkeypatch.chdir(root)
        paths = AppPaths.resolve(portable=True)
    else:
        old_cwd = Path.cwd()
        os.chdir(root)
        try:
            paths = AppPaths.resolve(portable=True)
        finally:
            os.chdir(old_cwd)
    paths.ensure_dirs()
    logger = LoggerWrapper(log_file=str(paths.log_dir / "iter2.log"), log_level="INFO")
    pfh = PermFileHandler(
        logger=logger,
        root_dir=paths.base_dir,
        allowed_roots=[paths.base_dir, paths.config_dir, paths.cache_dir, paths.log_dir, paths.output_dir, tmp_path],
        forbid_symlinks_read=True,
        forbid_symlinks_write=True,
        enforce_roots_on_read=False,
        enforce_roots_on_write=True,
        file_mode=0o600,
        dir_mode=0o700,
    )
    return RunContext(paths=paths, pfh=pfh, logger=logger, services=None, db=db, run_id=run_id)


def _rec(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "ip_address": "10.10.0.10",
        "hostname": "app-01.corp.local",
        "target_uri": None,
        "image_or_repo": None,
        "os": "Ubuntu 24.04",
        "asset_metadata": {"credentialed": True, "open_ports": [443]},
        "source_format": "nessus-xml",
        "scanner_sig": "nessus:1001",
        "title": "Sample Finding",
        "description": "Sample finding description",
        "solution": "Upgrade component",
        "plugin_output": "Detected vulnerable version",
        "severity": "High",
        "cves": ["CVE-2024-1001"],
        "cwes": ["CWE-79"],
        "ghsa_ids": [],
        "affected_port": 443,
        "protocol": "tcp",
        "service_name": "https",
        "location_uri": None,
        "line_number": None,
        "package_purl": None,
        "scanner_cvss_score": None,
        "scanner_cvss_vector": None,
        "detection_mode": "credentialed_host",
        "fidelity_tier": "high",
        "ingestion_confidence": 0.95,
        "missing_fields": [],
        "degraded_input": False,
        "references": [],
        "tags": [],
        "exploit_evidence": False,
        "raw_evidence_excerpt": "version check",
    }
    base.update(overrides)
    return base


class _FakeResp:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
        raw_bytes: bytes = b"",
        chunks: Optional[List[bytes]] = None,
        use_raw: bool = False,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url
        self.content = raw_bytes
        self._chunks = chunks
        self.raw = io.BytesIO(raw_bytes) if use_raw else None
        self.closed = False

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.close()
        return False

    def close(self) -> None:
        self.closed = True

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size: int = 1024) -> Any:
        if self._chunks is not None:
            for ch in self._chunks:
                yield ch
            return
        for i in range(0, len(self.content), max(1, chunk_size)):
            yield self.content[i : i + max(1, chunk_size)]


def test_feed_cache_epss_nvd_https_redirect_and_meta_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import vulnparse_pin.utils.feed_cache as fc_mod

    ctx = _make_runtime_ctx(tmp_path)
    specs = {"epss": FeedSpec(key="epss", filename="epss.csv", label="EPSS")}
    fcm = FeedCacheManager.from_ctx(ctx, specs=specs, policy=FeedCachePolicy(default_ttl_hours=24, ttl_hours={}))

    # 1. EPSS HTTP downgrade redirect blocked BEFORE following target
    calls: List[Dict[str, Any]] = []

    def _epss_downgrade(url: str, **kwargs: Any) -> _FakeResp:
        calls.append({"url": url, "kwargs": dict(kwargs)})
        if url.startswith("http://"):
            raise AssertionError("HTTP redirect target must never be requested")
        return _FakeResp(
            status_code=302,
            headers={"Location": "http://evil.example/epss.csv.gz"},
            url=url,
        )

    monkeypatch.setattr(fc_mod.requests, "get", _epss_downgrade)
    with pytest.raises(RuntimeError, match="non-HTTPS URL"):
        fcm.write_atomic_stream_gunzip(
            "epss",
            source_url="https://epss.example/epss.csv.gz",
            mode="online",
            validated=False,
            checksum_src="none",
        )
    assert len(calls) == 1
    assert calls[0]["kwargs"].get("allow_redirects") is False
    assert calls[0]["kwargs"].get("stream") is True

    # 2. EPSS HTTPS -> HTTPS redirect succeeds safely with allow_redirects=False
    gz_payload = gzip.compress(b"#model_version:v2025.03.14,score_date:2026-02-01T00:00:00Z\ncve,epss,percentile\nCVE-2024-1,0.5,0.9\n")

    def _epss_https_redir(url: str, **kwargs: Any) -> _FakeResp:
        assert kwargs.get("allow_redirects") is False
        assert kwargs.get("stream") is True
        if url == "https://epss.example/start.csv.gz":
            return _FakeResp(status_code=302, headers={"Location": "https://cdn.example/final.csv.gz"}, url=url)
        return _FakeResp(status_code=200, url="https://cdn.example/final.csv.gz", raw_bytes=gz_payload, use_raw=True)

    monkeypatch.setattr(fc_mod.requests, "get", _epss_https_redir)
    epss_path = fcm.write_atomic_stream_gunzip(
        "epss",
        source_url="https://epss.example/start.csv.gz",
        mode="online",
        validated=False,
        checksum_src="none",
    )
    assert "CVE-2024-1" in epss_path.read_text(encoding="utf-8")

    # 3. NVD .meta > 1 MiB (without Content-Length) aborts cleanly
    def _nvd_oversized_meta(url: str, **kwargs: Any) -> _FakeResp:
        assert kwargs.get("allow_redirects") is False
        assert kwargs.get("stream") is True
        return _FakeResp(
            status_code=200,
            url=url,
            chunks=[b"a" * (MAX_NVD_META_BYTES // 2 + 1), b"b" * (MAX_NVD_META_BYTES // 2 + 16)],
        )

    monkeypatch.setattr(fc_mod.requests, "get", _nvd_oversized_meta)
    with pytest.raises(RuntimeError, match="size limit"):
        fcm.resolve_nvd_feed(key="nvd.year.2024", ttl_hours=24, refresh_cache=True, offline=False)

    # 4. NVD .meta HTTP redirect fails closed even if local cache exists
    data_path, _, _ = fcm.resolve("nvd.year.2024")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_bytes(b"{}")

    def _nvd_meta_http_redir(url: str, **kwargs: Any) -> _FakeResp:
        assert kwargs.get("allow_redirects") is False
        return _FakeResp(status_code=302, headers={"Location": "http://insecure.example/nvd.meta"}, url=url)

    monkeypatch.setattr(fc_mod.requests, "get", _nvd_meta_http_redir)
    with pytest.raises(RuntimeError, match="non-HTTPS URL"):
        fcm.resolve_nvd_feed(key="nvd.year.2024", ttl_hours=24, refresh_cache=True, offline=False)

    # 5. NVD .json.gz HTTP redirect blocked before following
    valid_meta = b"lastModifiedDate:2026-02-01T00:00:00-05:00\nsha256:" + (b"0" * 64) + b"\n"

    def _nvd_feed_http_redir(url: str, **kwargs: Any) -> _FakeResp:
        assert kwargs.get("allow_redirects") is False
        assert kwargs.get("stream") is True
        if url.endswith(".meta"):
            return _FakeResp(status_code=200, url=url, raw_bytes=valid_meta)
        return _FakeResp(status_code=302, headers={"Location": "http://insecure.example/nvdcve.json.gz"}, url=url)

    monkeypatch.setattr(fc_mod.requests, "get", _nvd_feed_http_redir)
    with pytest.raises(RuntimeError, match="non-HTTPS URL"):
        fcm.resolve_nvd_feed(key="nvd.year.2024", ttl_hours=24, refresh_cache=True, offline=False)


def test_non_pfh_export_ancestor_symlinks_umask_and_ui_pfh(tmp_path: Path) -> None:
    db_path = tmp_path / "sec.vpp.db"
    with VppDatabase(db_path) as db:
        ensure_run(db, "r-sec", created_at_utc="2026-02-01T00:00:00Z", profile="default")

        real_dir = tmp_path / "real_target"
        real_dir.mkdir(parents=True, exist_ok=True)
        sym_ancestor = tmp_path / "sym_ancestor"
        sym_ancestor.symlink_to(real_dir, target_is_directory=True)

        # Multi-level non-existent paths under ancestor symlink must all fail closed
        with pytest.raises(ValueError, match="symlink"):
            export_duckdb_json(db, "r-sec", sym_ancestor / "sub1" / "sub2" / "out.json", pfh=None)
        with pytest.raises(ValueError, match="symlink"):
            export_duckdb_csv(db, "r-sec", sym_ancestor / "sub1" / "sub2" / "out.csv", pfh=None)
        with pytest.raises(ValueError, match="symlink"):
            export_dossier_bundle(db, "r-sec", sym_ancestor / "sub1" / "sub2", pfh=None)
        with pytest.raises(ValueError, match="symlink"):
            _write_markdown_output(sym_ancestor / "sub1" / "sub2" / "rep.md", "# hi", pfh=None)

        manifest = build_runmanifest_from_db(db, "r-sec")
        with pytest.raises(ValueError, match="symlink"):
            write_runmanifest(None, manifest, sym_ancestor / "sub1" / "sub2" / "rm.json")
        with pytest.raises(ValueError, match="symlink"):
            _validate_template_dir(sym_ancestor / "tpl")

        # Broken leaf symlink must also be rejected
        broken_leaf = tmp_path / "broken.json"
        broken_leaf.symlink_to(tmp_path / "does_not_exist.json")
        with pytest.raises(ValueError, match="symlink"):
            export_duckdb_json(db, "r-sec", broken_leaf, pfh=None)

        # Permissive process umask must still produce 0o700 dirs and 0o600 files
        old_umask = os.umask(0o002)
        try:
            json_out = tmp_path / "perm_json" / "nested" / "out.json"
            csv_out = tmp_path / "perm_csv" / "nested" / "out.csv"
            bundle_dir = tmp_path / "perm_bundle" / "nested"
            md_out = tmp_path / "perm_md" / "nested" / "out.md"
            rm_out = tmp_path / "perm_rm" / "nested" / "rm.json"

            export_duckdb_json(db, "r-sec", json_out, pfh=None)
            export_duckdb_csv(db, "r-sec", csv_out, pfh=None)
            bundle = export_dossier_bundle(db, "r-sec", bundle_dir, pfh=None)
            _write_markdown_output(md_out, "# ok\n", pfh=None)
            write_runmanifest(None, manifest, rm_out)
        finally:
            os.umask(old_umask)

        for d in (json_out.parent, csv_out.parent, bundle_dir, md_out.parent, rm_out.parent):
            assert stat.S_IMODE(d.stat().st_mode) == 0o700
        for f in (json_out, csv_out, Path(bundle["markdown"]), Path(bundle["html"]), md_out, rm_out):
            assert stat.S_IMODE(f.stat().st_mode) == 0o600

    # VppApp._build_silent_ui_pfh & VppApp._ensure_pfh ancestor guard
    silent_pfh = _build_silent_ui_pfh(tmp_path)
    assert silent_pfh.forbid_symlinks_read is True
    assert silent_pfh.forbid_symlinks_write is True
    assert silent_pfh.file_mode == 0o600
    assert silent_pfh.dir_mode == 0o700

    sym_db_dir = tmp_path / "sym_db_dir"
    sym_db_dir.symlink_to(tmp_path / "real_target", target_is_directory=True)
    app = VppApp(db_path=sym_db_dir / "nested" / "app.vpp.db")
    with pytest.raises(ValueError, match="symlink"):
        app._ensure_pfh()


def test_cvss_provenance_missing_does_not_override_scanner_and_no_zero_missing(tmp_path: Path) -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": True}],
        }
    )
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-base", created_at_utc="2026-01-01T00:00:00Z", profile="default")
        ensure_run(db, "r-cvss", created_at_utc="2026-02-01T00:00:00Z", profile="default")

        rec_scan = _rec(
            cves=["CVE-2024-5001"],
            scanner_sig="nessus:5001",
            title="Scanner CVSS With KEV Snapshot",
            scanner_cvss_score=9.8,
            scanner_cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        rec_miss = _rec(
            cves=["CVE-2024-5002"],
            scanner_sig="nessus:5002",
            title="Truly Missing CVSS",
            scanner_cvss_score=None,
            scanner_cvss_vector=None,
        )
        ingest_normalized_batches(db, "r-base", [[rec_scan, rec_miss]], asset_matcher=matcher)
        ingest_normalized_batches(db, "r-cvss", [[rec_scan, rec_miss]], asset_matcher=matcher)

        fids_b = dict(db.execute("SELECT title, finding_id FROM findings WHERE run_id = 'r-base'").fetchall())
        fids_t = dict(db.execute("SELECT title, finding_id FROM findings WHERE run_id = 'r-cvss'").fetchall())

        upsert_enrichment_snapshots(
            db,
            "r-base",
            [
                {"cve_id": "CVE-2024-5001", "cvss_score": None, "cvss_provenance": "Missing", "epss_score": 0.1, "in_kev": False},
                {"cve_id": "CVE-2024-5002", "cvss_score": None, "cvss_provenance": "Missing", "epss_score": 0.01, "in_kev": False},
            ],
        )
        upsert_enrichment_snapshots(
            db,
            "r-cvss",
            [
                {"cve_id": "CVE-2024-5001", "cvss_score": None, "cvss_provenance": "Missing", "epss_score": 0.5, "in_kev": True},
                {"cve_id": "CVE-2024-5002", "cvss_score": None, "cvss_provenance": "Missing", "epss_score": 0.01, "in_kev": False},
            ],
        )
        upsert_scores(
            db,
            "r-base",
            [
                {
                    "finding_id": fids_b["Scanner CVSS With KEV Snapshot"],
                    "asset_id": "aid_1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 11.0,
                    "operational_score": 7.0,
                    "risk_band": "High",
                    "score_trace": {
                        "primary_cve": "CVE-2024-5001",
                        "cvss_score": 9.8,
                        "cvss_version": "3.1",
                        "cvss_provenance": "Scanner-Supplied",
                    },
                },
                {
                    "finding_id": fids_b["Truly Missing CVSS"],
                    "asset_id": "aid_1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 1.0,
                    "operational_score": 1.0,
                    "risk_band": "Low",
                    "score_trace": {"primary_cve": "CVE-2024-5002", "cvss_score": 0.0, "cvss_provenance": "Missing"},
                },
            ],
        )
        upsert_scores(
            db,
            "r-cvss",
            [
                {
                    "finding_id": fids_t["Scanner CVSS With KEV Snapshot"],
                    "asset_id": "aid_1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 15.0,
                    "operational_score": 9.5,
                    "risk_band": "Critical",
                    "score_trace": {
                        "primary_cve": "CVE-2024-5001",
                        "cvss_score": 9.8,
                        "cvss_version": "3.1",
                        "cvss_provenance": "Scanner-Supplied",
                    },
                },
                {
                    "finding_id": fids_t["Truly Missing CVSS"],
                    "asset_id": "aid_1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 1.0,
                    "operational_score": 1.0,
                    "risk_band": "Low",
                    "score_trace": {"primary_cve": "CVE-2024-5002", "cvss_score": 0.0, "cvss_provenance": "Missing"},
                },
            ],
        )
        upsert_triage_decisions(
            db,
            "r-cvss",
            [
                {"finding_id": fids_t["Scanner CVSS With KEV Snapshot"], "asset_id": "aid_1", "priority_tier": "P1", "oal_compat": "OAL-1", "ssvc_action": "Act", "sla_bucket": "3-day + Forensic Triage", "decision_status": "active"},
                {"finding_id": fids_t["Truly Missing CVSS"], "asset_id": "aid_1", "priority_tier": "P4", "oal_compat": "OAL-3", "ssvc_action": "Track", "sla_bucket": "Fix on Upgrade", "decision_status": "active"},
            ],
        )

        # Dossier MD & HTML
        dos_md = render_dossier_markdown(db, "r-cvss")
        dos_html = render_dossier_html(db, "r-cvss")
        assert "9.8 (Scanner-Supplied" in dos_md
        assert "9.8 (Scanner-Supplied" in dos_html
        assert "0.0 (Missing)" not in dos_md
        assert "0.0 (Missing)" not in dos_html

        # CSV
        csv_path = tmp_path / "cvss.csv"
        export_duckdb_csv(db, "r-cvss", csv_path, profile="full", pfh=None)
        with csv_path.open("r", encoding="utf-8") as fh:
            csv_rows = {r["title"]: r for r in csv.DictReader(fh)}
        assert float(csv_rows["Scanner CVSS With KEV Snapshot"]["cvss_score"]) == 9.8
        assert csv_rows["Scanner CVSS With KEV Snapshot"]["cvss_provenance"] == "Scanner-Supplied"
        assert csv_rows["Truly Missing CVSS"]["cvss_score"] == ""
        assert csv_rows["Truly Missing CVSS"]["cvss_provenance"] == "Missing"

        # JSON
        json_path = tmp_path / "cvss.json"
        export_duckdb_json(db, "r-cvss", json_path, presentation="namespace", pfh=None)
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        j_findings = {f["title"]: f for f in payload["assets"][0]["findings"]}
        assert j_findings["Scanner CVSS With KEV Snapshot"]["enrichment"]["cvss_score"] == 9.8
        assert j_findings["Scanner CVSS With KEV Snapshot"]["enrichment"]["cvss_provenance"] == "Scanner-Supplied"
        assert j_findings["Truly Missing CVSS"]["enrichment"]["cvss_score"] is None
        assert j_findings["Truly Missing CVSS"]["enrichment"]["cvss_provenance"] == "Missing"

        # Repositories & TUI score trace
        page_rows, _ = query_findings_page(db, "r-cvss")
        p_map = {r["title"]: r for r in page_rows}
        assert p_map["Scanner CVSS With KEV Snapshot"]["cvss_provenance"] == "Scanner-Supplied"
        assert p_map["Scanner CVSS With KEV Snapshot"]["cvss_score"] == 9.8
        assert p_map["Truly Missing CVSS"]["cvss_score"] is None
        assert p_map["Truly Missing CVSS"]["cvss_provenance"] == "Missing"

        d_scan = get_finding_detail(db, "r-cvss", fids_t["Scanner CVSS With KEV Snapshot"])
        d_miss = get_finding_detail(db, "r-cvss", fids_t["Truly Missing CVSS"])
        assert d_scan is not None and d_miss is not None
        scan_lines = "\n".join(_format_score_trace_lines(d_scan))
        miss_lines = "\n".join(_format_score_trace_lines(d_miss))
        assert "CVSS: 9.8 (3.1, prov=Scanner-Supplied)" in scan_lines
        assert "CVSS: n/a (n/a, prov=Missing)" in miss_lines
        assert "CVSS: 0.0" not in miss_lines

        # Bare trace without cvss_provenance retains explicit 0.0 compatibility
        bare_lines = "\n".join(
            _format_score_trace_lines({"score_trace": {"operational_score": None, "cvss_score": 0.0}})
        )
        assert "CVSS: 0.0 " in bare_lines

        # DiffEngine must not report Scanner-Supplied 9.8 as Missing
        diff_rep = DiffEngine(db).compare("r-base", "r-cvss")
        esc = {e.primary_cve: e for e in diff_rep.threat_intel_escalated}
        assert esc["CVE-2024-5001"].target_cvss_score == 9.8
        assert esc["CVE-2024-5001"].target_cvss_provenance == "Scanner-Supplied"


def test_dossier_default_profile_p3_60day_deprioritized_while_bod_p2_prioritized() -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": False}],
        }
    )
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-default", created_at_utc="2026-01-01T00:00:00Z", profile="default")
        ensure_run(db, "r-bod", created_at_utc="2026-02-01T00:00:00Z", profile="bod-26-04")
        rec_p3 = _rec(cves=["CVE-2024-6001"], scanner_sig="n:6001", title="Active Default P3 Track* 60-day")
        rec_p2 = _rec(cves=["CVE-2024-6002"], scanner_sig="n:6002", title="Active Default P2 14-day")
        rec_bod = _rec(cves=["CVE-2024-6003"], scanner_sig="n:6003", title="Active BOD P2 Attend 60-day")

        ingest_normalized_batches(db, "r-default", [[rec_p3, rec_p2]], asset_matcher=matcher)
        ingest_normalized_batches(db, "r-bod", [[rec_bod]], asset_matcher=matcher)

        def_fids = dict(db.execute("SELECT title, finding_id FROM findings WHERE run_id = 'r-default'").fetchall())
        bod_fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'r-bod'").fetchone()[0]

        upsert_scores(
            db,
            "r-default",
            [
                {"finding_id": def_fids["Active Default P3 Track* 60-day"], "asset_id": "aid_1", "scoring_track": "cve_threat", "raw_risk_score": 4.0, "operational_score": 3.0, "risk_band": "Low"},
                {"finding_id": def_fids["Active Default P2 14-day"], "asset_id": "aid_1", "scoring_track": "cve_threat", "raw_risk_score": 9.0, "operational_score": 7.0, "risk_band": "High"},
            ],
        )
        upsert_scores(
            db,
            "r-bod",
            [{"finding_id": bod_fid, "asset_id": "aid_1", "scoring_track": "cve_threat", "raw_risk_score": 8.0, "operational_score": 6.0, "risk_band": "Medium"}],
        )
        upsert_triage_decisions(
            db,
            "r-default",
            [
                {"finding_id": def_fids["Active Default P3 Track* 60-day"], "asset_id": "aid_1", "profile": "default", "priority_tier": "P3", "oal_compat": "OAL-3", "ssvc_action": "Track*", "sla_bucket": "60-day", "decision_status": "active"},
                {"finding_id": def_fids["Active Default P2 14-day"], "asset_id": "aid_1", "profile": "default", "priority_tier": "P2", "oal_compat": "OAL-2", "ssvc_action": "Attend", "sla_bucket": "14-day", "decision_status": "active"},
            ],
        )
        upsert_triage_decisions(
            db,
            "r-bod",
            [{"finding_id": bod_fid, "asset_id": "aid_1", "profile": "bod-26-04", "priority_tier": "P2", "oal_compat": "OAL-2", "ssvc_action": "Attend", "sla_bucket": "60-day", "decision_status": "active"}],
        )

        _, prio_def, _, _, dep_def = _fetch_dossier_findings(db, "r-default", {})
        assert [f["title"] for f in prio_def] == ["Active Default P2 14-day"]
        assert [f["title"] for f in dep_def] == ["Active Default P3 Track* 60-day"]

        dos_default = render_dossier_markdown(db, "r-default")
        prio_part = dos_default.split("## Why Deprioritized / Deferred")[0]
        dep_part = dos_default.split("### Threat-Evidence & Exposure Deprioritized Findings")[1]
        assert "Active Default P2 14-day" in prio_part
        assert "CVE-2024-6001" not in prio_part
        assert "CVE-2024-6001" in dep_part

        _, prio_bod, _, _, dep_bod = _fetch_dossier_findings(db, "r-bod", {})
        assert [f["title"] for f in prio_bod] == ["Active BOD P2 Attend 60-day"]
        assert dep_bod == []
        dos_bod = render_dossier_markdown(db, "r-bod")
        bod_prio_part = dos_bod.split("## Why Deprioritized / Deferred")[0]
        assert "Active BOD P2 Attend 60-day" in bod_prio_part


def test_runmanifest_multicve_kev_counts_match_summary_and_repos(tmp_path: Path) -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": True}],
        }
    )
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-kev", created_at_utc="2026-02-01T00:00:00Z", profile="default")
        rec_multi = _rec(
            cves=["CVE-2020-0001", "CVE-2024-9999"],
            scanner_sig="trivy:multi",
            title="Multi CVE Secondary KEV",
        )
        rec_trace_only = _rec(
            cves=["CVE-2021-1111"],
            scanner_sig="trivy:trace",
            title="Score Trace KEV Only",
        )
        ingest_normalized_batches(db, "r-kev", [[rec_multi, rec_trace_only]], asset_matcher=matcher)
        fids = dict(db.execute("SELECT title, finding_id FROM findings WHERE run_id = 'r-kev'").fetchall())
        upsert_enrichment_snapshots(
            db,
            "r-kev",
            [
                {"cve_id": "CVE-2020-0001", "cvss_score": 5.0, "in_kev": False},
                {"cve_id": "CVE-2024-9999", "cvss_score": 6.5, "in_kev": True, "kev_date_added": "2025-01-10"},
                {"cve_id": "CVE-2021-1111", "cvss_score": 7.0, "in_kev": False},
            ],
        )
        upsert_scores(
            db,
            "r-kev",
            [
                {
                    "finding_id": fids["Multi CVE Secondary KEV"],
                    "asset_id": "aid_1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 10.0,
                    "operational_score": 7.0,
                    "risk_band": "High",
                    "score_trace": {"primary_cve": "CVE-2020-0001", "in_kev": True},
                },
                {
                    "finding_id": fids["Score Trace KEV Only"],
                    "asset_id": "aid_1",
                    "scoring_track": "cve_threat",
                    "raw_risk_score": 10.0,
                    "operational_score": 7.0,
                    "risk_band": "High",
                    "score_trace": {"primary_cve": "CVE-2021-1111", "in_kev": True},
                },
            ],
        )
        upsert_triage_decisions(
            db,
            "r-kev",
            [
                {"finding_id": fids["Multi CVE Secondary KEV"], "asset_id": "aid_1", "priority_tier": "P1", "decision_status": "active"},
                {"finding_id": fids["Score Trace KEV Only"], "asset_id": "aid_1", "priority_tier": "P1", "decision_status": "active"},
            ],
        )

        ctx = _make_runtime_ctx(tmp_path, db=db, run_id="r-kev")
        sum_res = SummaryV2Pass().run(ctx, scan=None)
        counts = get_run_summary_counts(db, "r-kev")
        rm = build_runmanifest_from_db(db, "r-kev")
        rm_summary = [s for s in rm["pass_summaries"] if s["name"] == "Summary"][0]["metrics"]
        assert counts["kev_findings"] == 2
        assert sum_res.data["enrichment_metrics"]["kev_findings"] == 2
        assert rm_summary["kev_findings"] == 2


def test_diff_engine_option_b_60day_implicit_drift_contract_preserved() -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": False}],
        }
    )
    with VppDatabase(":memory:") as db:
        ensure_run(db, "b-optb", created_at_utc="2026-01-01T00:00:00Z", profile="bod-26-04")
        ensure_run(db, "t-optb", created_at_utc="2026-02-01T00:00:00Z", profile="bod-26-04")
        rec = _rec(cves=["CVE-2024-7777"], scanner_sig="s:7777", title="BOD 60-day to 14-day")
        ingest_normalized_batches(db, "b-optb", [[rec]], asset_matcher=matcher)
        ingest_normalized_batches(db, "t-optb", [[rec]], asset_matcher=matcher)
        fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'b-optb'").fetchone()[0]
        upsert_enrichment_snapshots(db, "b-optb", [{"cve_id": "CVE-2024-7777", "cvss_score": 7.0, "epss_score": 0.05, "in_kev": False}])
        upsert_enrichment_snapshots(db, "t-optb", [{"cve_id": "CVE-2024-7777", "cvss_score": 7.0, "epss_score": 0.30, "in_kev": True}])
        upsert_triage_decisions(db, "b-optb", [{"finding_id": fid, "asset_id": "aid_1", "priority_tier": "P2", "sla_bucket": "60-day", "ssvc_action": "Attend", "decision_status": "active"}])
        upsert_triage_decisions(db, "t-optb", [{"finding_id": fid, "asset_id": "aid_1", "priority_tier": "P1", "sla_bucket": "14-day", "ssvc_action": "Act", "decision_status": "active"}])

        rep = DiffEngine(db).compare("b-optb", "t-optb")
        assert len(rep.invalidated_assumptions) == 1
        assert rep.invalidated_assumptions[0].invalidation_kind == "implicit"
        assert evaluate_fail_gate(rep, "stale-assumption") == 2


def test_runmanifest_digest_pre_export_vs_post_export_consistency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "digest.vpp.db"
    matcher = AssetContextMatcher(
        {"version": "v2", "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": True}]}
    )
    with VppDatabase(db_path) as db:
        ensure_run(db, "r-dig", created_at_utc="2026-02-01T00:00:00Z", profile="default")
        ingest_normalized_batches(db, "r-dig", [[_rec(scanner_sig="n:1111")]], asset_matcher=matcher)
        fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'r-dig'").fetchone()[0]
        upsert_scores(db, "r-dig", [{"finding_id": fid, "asset_id": "aid_1", "scoring_track": "cve_threat", "raw_risk_score": 9.0, "operational_score": 7.0, "risk_band": "High"}])
        upsert_triage_decisions(db, "r-dig", [{"finding_id": fid, "asset_id": "aid_1", "priority_tier": "P2", "sla_bucket": "14-day", "ssvc_action": "Attend", "decision_status": "active"}])

        # Pre-export reports (runs.manifest_digest is NULL): must show pending seal text, not a mismatched sha256
        pre_dos_md = render_dossier_markdown(db, "r-dig")
        pre_dos_html = render_dossier_html(db, "r-dig")
        pre_rm_md = render_executive_roadmap_markdown(db, "r-dig")
        pre_rm_html = render_executive_roadmap_html(db, "r-dig")
        pending_msg = "Pending post-export RunManifest seal (see runmanifest.json)"
        for out in (pre_dos_md, pre_dos_html, pre_rm_md, pre_rm_html):
            assert pending_msg in out

        # Export bundle + runmanifest (seals runs.manifest_digest)
        ctx = _make_runtime_ctx(tmp_path, monkeypatch=monkeypatch, db=db, run_id="r-dig")
        stem = str(ctx.paths.output_dir / "digest_bundle")
        args = SimpleNamespace(
            output_all=stem,
            output=None,
            output_csv=None,
            output_md=None,
            output_md_technical=None,
            output_html=None,
            output_dossier=None,
            output_runmanifest=None,
            template_dir=None,
            csv_profile="full",
            no_csv_sanitize=False,
            confirm_unsafe_csv=False,
            overlay_mode="namespace",
            pretty_print=False,
            runmanifest_mode="compact",
        )
        written = export_v2_outputs(
            ctx=ctx,
            db=db,
            run_id="r-dig",
            args=args,
            config_hashes={"config_sha256": "sha256:" + "1" * 64},
        )
        rm_payload = json.loads(Path(written["runmanifest"]).read_text(encoding="utf-8"))
        sealed_digest = rm_payload["verification"]["manifest_digest"]
        assert sealed_digest.startswith("sha256:")
        assert db.execute("SELECT manifest_digest FROM runs WHERE run_id = 'r-dig'").fetchone()[0] == sealed_digest

    # Subsequent export reads sealed digest matching runmanifest.json byte-for-byte
    post_dos_md = ctx.paths.output_dir / "post_dossier.md"
    rc = cli_main(["export", "--portable", "--db", str(db_path), "--run-id", "r-dig", "--format", "dossier-md", "--output", str(post_dos_md)])
    assert rc == 0
    assert sealed_digest in post_dos_md.read_text(encoding="utf-8")


def test_cross_component_primary_cve_p1b_mitigated_invalidated_and_secondary_kev(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    matcher = AssetContextMatcher(
        {"version": "v2", "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": True}]}
    )
    xcomp_db_path = tmp_path / "xcomp.vpp.db"
    with VppDatabase(xcomp_db_path) as db:
        ensure_run(db, "r-prev", created_at_utc="2026-01-01T00:00:00Z", profile="default")
        ensure_run(db, "r-xcomp", created_at_utc="2026-02-01T00:00:00Z", profile="default")

        rec_multi = _rec(
            cves=["CVE-2020-0001", "CVE-2024-8888", "CVE-2024-9999"],
            scanner_sig="nessus:8001",
            title="Multi CVE Winner + Secondary KEV",
        )
        rec_p1b = _rec(
            cves=["CVE-2024-7001"],
            scanner_sig="nessus:8002",
            title="P1B Immediate Escalation",
        )
        rec_mit = _rec(
            cves=["CVE-2024-7002"],
            scanner_sig="nessus:8003",
            title="Mitigated Invalidated Finding",
        )
        ingest_normalized_batches(db, "r-xcomp", [[rec_multi, rec_p1b, rec_mit]], asset_matcher=matcher)
        fids = dict(db.execute("SELECT title, finding_id FROM findings WHERE run_id = 'r-xcomp'").fetchall())

        # Notice primary_cve DB column was ordered CVE-2020-0001 (non-KEV, kev_ransomware='false'),
        # CVE-2024-9999 wins highest raw score (non-KEV), and CVE-2024-8888 provides secondary KEV!
        upsert_enrichment_snapshots(
            db,
            "r-xcomp",
            [
                {"cve_id": "CVE-2020-0001", "cvss_score": 4.0, "cvss_provenance": "NVD", "epss_score": 0.01, "in_kev": False, "kev_ransomware": "false"},
                {"cve_id": "CVE-2024-9999", "cvss_score": 9.8, "cvss_provenance": "NVD", "epss_score": 0.90, "in_kev": False, "kev_ransomware": "false"},
                {"cve_id": "CVE-2024-8888", "cvss_score": 6.0, "cvss_provenance": "NVD", "epss_score": 0.05, "in_kev": True, "kev_date_added": "2025-01-10", "kev_due_date": "2025-01-31", "kev_ransomware": "Known"},
                {"cve_id": "CVE-2024-7001", "cvss_score": 9.0, "cvss_provenance": "NVD", "epss_score": 0.20, "in_kev": False},
                {"cve_id": "CVE-2024-7002", "cvss_score": 7.5, "cvss_provenance": "NVD", "epss_score": 0.30, "in_kev": False},
            ],
        )

        # Verify ScoringV3Pass picks CVE-2024-9999 as primary_cve AND propagates CVE-2024-8888 KEV metadata
        ctx_score = _make_runtime_ctx(tmp_path, db=db, run_id="r-xcomp")
        ScoringV3Pass().run(ctx_score, scan=None)
        multi_trace_raw = db.execute(
            "SELECT score_trace_json FROM scores WHERE run_id = 'r-xcomp' AND finding_id = ?",
            [fids["Multi CVE Winner + Secondary KEV"]],
        ).fetchone()[0]
        multi_trace = json.loads(multi_trace_raw)
        assert multi_trace["primary_cve"] == "CVE-2024-9999"
        assert multi_trace["in_kev"] is True
        assert multi_trace["kev_date_added"] == "2025-01-10"
        assert multi_trace["kev_due_date"] == "2025-01-31"
        assert multi_trace["kev_ransomware"] == "Known"

        # Also test SQL fc_agg fallback by clearing KEV metadata keys from score_trace for Multi CVE finding
        stripped_trace = dict(multi_trace)
        stripped_trace.pop("kev_date_added", None)
        stripped_trace.pop("kev_due_date", None)
        stripped_trace.pop("kev_ransomware", None)
        db.execute(
            "UPDATE scores SET score_trace_json = ? WHERE run_id = 'r-xcomp' AND finding_id = ?",
            [json.dumps(stripped_trace), fids["Multi CVE Winner + Secondary KEV"]],
        )

        upsert_triage_decisions(
            db,
            "r-xcomp",
            [
                {"finding_id": fids["Multi CVE Winner + Secondary KEV"], "asset_id": "aid_1", "priority_tier": "P1", "oal_compat": "OAL-1", "ssvc_action": "Act", "sla_bucket": "3-day + Forensic Triage", "decision_status": "active"},
                {"finding_id": fids["P1B Immediate Escalation"], "asset_id": "aid_1", "priority_tier": "P1B", "oal_compat": "OAL-1", "ssvc_action": "Act", "sla_bucket": "14-day", "decision_status": "active"},
                {"finding_id": fids["Mitigated Invalidated Finding"], "asset_id": "aid_1", "priority_tier": "P2", "oal_compat": "OAL-2", "ssvc_action": "Attend", "sla_bucket": "14-day", "decision_status": "mitigated_invalidated", "decision_id": "dec-mit-1"},
            ],
        )

        # SummaryV2Pass: immediate_action includes P1 + P1B (2), invalidated_decisions includes mitigated_invalidated (1),
        # and top_risks / immediate_cves use winning primary_cve CVE-2024-9999
        sum_out = SummaryV2Pass().run(ctx_score, scan=None)
        assert sum_out.data["remediation_priorities"]["immediate_action"] == 2
        assert sum_out.data["remediation_priorities"]["invalidated_decisions"] == 1
        assert "CVE-2024-9999" in sum_out.data["remediation_priorities"]["immediate_cves"]
        assert "CVE-2024-7001" in sum_out.data["remediation_priorities"]["immediate_cves"]
        assert "CVE-2020-0001" not in sum_out.data["remediation_priorities"]["immediate_cves"]
        top_by_fid = {r["finding_id"]: r for r in sum_out.data["top_risks"]}
        assert top_by_fid[fids["Multi CVE Winner + Secondary KEV"]]["primary_cve"] == "CVE-2024-9999"

        # Dossier & Roadmap
        dos_md = render_dossier_markdown(db, "r-xcomp")
        rm_md = render_executive_roadmap_markdown(db, "r-xcomp")
        assert "CVE-2024-9999" in dos_md
        assert "CVE-2024-9999" in rm_md

        # CSV
        csv_path = tmp_path / "xcomp.csv"
        export_duckdb_csv(db, "r-xcomp", csv_path, profile="full", pfh=None)
        with csv_path.open("r", encoding="utf-8") as fh:
            csv_by_title = {r["title"]: r for r in csv.DictReader(fh)}
        row_m = csv_by_title["Multi CVE Winner + Secondary KEV"]
        assert row_m["primary_cve"] == "CVE-2024-9999"
        assert row_m["kev_date_added"] == "2025-01-10"
        assert row_m["kev_due_date"] == "2025-01-31"
        assert row_m["kev_ransomware"] == "Known"

        # JSON
        json_path = tmp_path / "xcomp.json"
        export_duckdb_json(db, "r-xcomp", json_path, presentation="namespace", pfh=None)
        j_payload = json.loads(json_path.read_text(encoding="utf-8"))
        j_by_title = {f["title"]: f for f in j_payload["assets"][0]["findings"]}
        jm = j_by_title["Multi CVE Winner + Secondary KEV"]
        assert jm["primary_cve"] == "CVE-2024-9999"
        assert jm["enrichment"]["kev_date_added"] == "2025-01-10"
        assert jm["enrichment"]["kev_due_date"] == "2025-01-31"
        assert jm["enrichment"]["kev_ransomware"] == "Known"

        # Repositories & TUI formatting
        page, _ = query_findings_page(db, "r-xcomp", search="CVE-2024-9999")
        assert len(page) == 1 and page[0]["primary_cve"] == "CVE-2024-9999"
        assert page[0]["kev_date_added"] == "2025-01-10"
        detail = get_finding_detail(db, "r-xcomp", fids["Multi CVE Winner + Secondary KEV"])
        assert detail is not None
        assert detail["primary_cve"] == "CVE-2024-9999"
        assert detail["kev_date_added"] == "2025-01-10"
        assert detail["kev_due_date"] == "2025-01-31"
        assert detail["kev_ransomware"] == "Known"
        inspector = _format_finding_inspector(detail, has_findings=True)
        assert "Primary CVE  : CVE-2024-9999" in inspector
        assert "added=2025-01-10, due=2025-01-31, ransomware=Known" in inspector

        # DiffEngine winning primary_cve
        diff_rep = DiffEngine(db).compare("r-prev", "r-xcomp")
        new_by_fid = {n.finding_id: n for n in diff_rep.newly_introduced_high_risk}
        assert new_by_fid[fids["Multi CVE Winner + Secondary KEV"]].primary_cve == "CVE-2024-9999"

        # CLI summary prints P1B
        _print_v2_summary(db, "r-xcomp", profile="default")
        out_txt = capsys.readouterr().out
        assert "P1=1  P1B=1" in out_txt

    # TUI KPI banner renders P1B alongside P1
    from textual.widgets import Static

    async def _check_tui_banner() -> str:
        app = VppApp(db_path=xcomp_db_path, run_id="r-xcomp", pfh=_build_silent_ui_pfh(tmp_path))
        async with app.run_test() as pilot:
            await pilot.pause()
            return str(app.query_one("#kpi-banner", Static).render())

    banner_txt = asyncio.run(_check_tui_banner())
    assert "P1=1 P1B=1" in banner_txt


def test_cli_export_pretty_print_and_unsafe_csv_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    port_root = tmp_path / "port"
    port_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(port_root)
    paths = AppPaths.resolve(portable=True)
    paths.ensure_dirs()
    db_path = port_root / "export_cli.vpp.db"
    matcher = AssetContextMatcher(
        {"version": "v2", "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": True}]}
    )
    with VppDatabase(db_path) as db:
        ensure_run(db, "r-exp", created_at_utc="2026-02-01T00:00:00Z", profile="default")
        ingest_normalized_batches(
            db,
            "r-exp",
            [[_rec(scanner_sig="n:9001", title="=HYPERLINK(\"http://evil\",\"click\")")]],
            asset_matcher=matcher,
        )
        fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'r-exp'").fetchone()[0]
        upsert_scores(db, "r-exp", [{"finding_id": fid, "asset_id": "aid_1", "scoring_track": "cve_threat", "raw_risk_score": 8.0, "operational_score": 6.0, "risk_band": "Medium"}])
        upsert_triage_decisions(db, "r-exp", [{"finding_id": fid, "asset_id": "aid_1", "priority_tier": "P2", "sla_bucket": "14-day", "decision_status": "active"}])

    out_json = paths.output_dir / "pretty.json"
    rc_json = cli_main(
        ["export", "--portable", "--db", str(db_path), "--format", "json", "--pretty-print", "--output", str(out_json)]
    )
    assert rc_json == 0
    json_txt = out_json.read_text(encoding="utf-8")
    assert "\n    \"" in json_txt

    unsafe_csv = paths.output_dir / "unsafe.csv"
    rc_blocked = cli_main(
        ["export", "--portable", "--db", str(db_path), "--format", "csv", "--no-csv-sanitize", "--output", str(unsafe_csv)]
    )
    assert rc_blocked == 2
    assert not unsafe_csv.exists()

    rc_csv = cli_main(
        ["export", "--portable", "--db", str(db_path), "--format", "csv", "--no-csv-sanitize", "--confirm-unsafe-csv", "--output", str(unsafe_csv)]
    )
    assert rc_csv == 0
    with unsafe_csv.open("r", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["title"].startswith("=HYPERLINK(")


def test_aci_scan_sig_fast_skip_prefix_plus_digits_alias_parity(tmp_path: Path) -> None:
    aci_pass = AttackCapabilityInferencePass(
        aci_config={
            "enabled": True,
            "token_mode": "merge",
            "signal_aliases": [{"token": "nessus 12345", "signal": "rce"}],
        }
    )
    cfg = aci_pass.cfg
    text_tokens = _effective_text_tokens(cfg)
    single_match = _infer_single_record(
        cfg=cfg,
        text_tokens=text_tokens,
        disabled_tokens=set(),
        title="Plugin match",
        description="",
        plugin_output="",
        references=[],
        tags=[],
        scanner_sig="Nessus:12345",
        affected_port=None,
        cwe_ids=(),
        scanner_sigs=["Nessus:12345"],
        has_exploit=False,
        in_kev=False,
    )
    single_miss = _infer_single_record(
        cfg=cfg,
        text_tokens=text_tokens,
        disabled_tokens=set(),
        title="Plugin miss",
        description="",
        plugin_output="",
        references=[],
        tags=[],
        scanner_sig="Nessus:99999",
        affected_port=None,
        cwe_ids=(),
        scanner_sigs=["Nessus:99999"],
        has_exploit=False,
        in_kev=False,
    )

    matcher = AssetContextMatcher(
        {"version": "v2", "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": True}]}
    )
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-aci", created_at_utc="2026-02-01T00:00:00Z")
        ingest_normalized_batches(
            db,
            "r-aci",
            [[
                _rec(cves=[], scanner_sig="Nessus:12345", title="Plugin match", description="", solution="", plugin_output="", cwes=[]),
                _rec(cves=[], scanner_sig="Nessus:99999", title="Plugin miss", description="", solution="", plugin_output="", cwes=[]),
            ]],
            asset_matcher=matcher,
        )
        ctx = _make_runtime_ctx(tmp_path, db=db, run_id="r-aci")
        AttackCapabilityInferencePass(aci_config=cfg).run(ctx, scan=None)
        rows = {
            r[0]: (tuple(json.loads(r[1])), tuple(json.loads(r[2])), tuple(json.loads(r[3])))
            for r in db.execute(
                "SELECT f.title, aci.capabilities_json, aci.chains_json, aci.matched_tokens_json "
                "FROM findings f JOIN aci_signals aci ON aci.run_id = f.run_id AND aci.finding_id = f.finding_id "
                "WHERE f.run_id = 'r-aci'"
            ).fetchall()
        }

    assert rows["Plugin match"][0] == single_match[0]
    assert rows["Plugin match"][1] == single_match[1]
    assert "nessus 12345" in rows["Plugin match"][2]
    assert rows["Plugin miss"][0] == single_miss[0] == ()


def test_output_all_roadmap_summary_and_dossier_markdown_in_runmanifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matcher = AssetContextMatcher(
        {"version": "v2", "rules": [{"id": "web", "asset_id": "aid_1", "aliases": ["10.10.0.10"], "internet_facing": True}]}
    )
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-all", created_at_utc="2026-02-01T00:00:00Z", profile="default")
        ingest_normalized_batches(db, "r-all", [[_rec(scanner_sig="n:777")]], asset_matcher=matcher)
        fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'r-all'").fetchone()[0]
        upsert_scores(db, "r-all", [{"finding_id": fid, "asset_id": "aid_1", "scoring_track": "cve_threat", "raw_risk_score": 8.0, "operational_score": 6.5, "risk_band": "High"}])
        upsert_triage_decisions(db, "r-all", [{"finding_id": fid, "asset_id": "aid_1", "priority_tier": "P2", "sla_bucket": "14-day", "decision_status": "active"}])

        ctx = _make_runtime_ctx(tmp_path, monkeypatch=monkeypatch, db=db, run_id="r-all")
        stem = str(ctx.paths.output_dir / "bundle")
        args = SimpleNamespace(
            output_all=stem,
            output=None,
            output_csv=None,
            output_md=None,
            output_md_technical=None,
            output_html=None,
            output_dossier=None,
            output_runmanifest=None,
            template_dir=None,
            csv_profile="full",
            no_csv_sanitize=False,
            confirm_unsafe_csv=False,
            overlay_mode="namespace",
            pretty_print=False,
            runmanifest_mode="compact",
        )
        written = export_v2_outputs(ctx=ctx, db=db, run_id="r-all", args=args)

        summary_md = Path(written["executive_markdown"]).read_text(encoding="utf-8")
        tech_md = Path(written["technical_markdown"]).read_text(encoding="utf-8")
        dos_md = Path(written["dossier_markdown"]).read_text(encoding="utf-8")
        assert "Executive Vulnerability Summary" in summary_md
        assert "Decision Defense Dossier" in tech_md
        assert "Decision Defense Dossier" in dos_md

        rm_path = Path(written["runmanifest"])
        rm = json.loads(rm_path.read_text(encoding="utf-8"))
        assert rm["outputs"]["dossier_markdown"] == str(written["dossier_markdown"])
        assert "dossier_markdown" in rm["output_hashes"]
        expected_hash = f"sha256:{sha256(Path(written['dossier_markdown']).read_bytes()).hexdigest()}"
        assert rm["output_hashes"]["dossier_markdown"] == expected_hash

        # vpp verify passes, then fails when *_dossier.md is tampered
        assert cli_main(["verify", "--portable", str(rm_path)]) == 0
        Path(written["dossier_markdown"]).write_text("tampered dossier\n", encoding="utf-8")
        assert cli_main(["verify", "--portable", str(rm_path)]) == 1


def test_verify_command_honors_runtime_options_roots_and_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work_root = tmp_path / "work"
    work_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(work_root)
    paths = AppPaths.resolve(portable=True)
    paths.ensure_dirs()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir(parents=True, exist_ok=True)

    artifact_in = paths.output_dir / "in_root.txt"
    artifact_in.write_text("safe payload\n", encoding="utf-8")
    artifact_out = outside_dir / "out_root.txt"
    artifact_out.write_text("outside payload\n", encoding="utf-8")

    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-ver", created_at_utc="2026-02-01T00:00:00Z")
        m_inside = build_runmanifest_from_db(db, "r-ver", outputs={"json": str(artifact_in)})
        m_out_ref = build_runmanifest_from_db(db, "r-ver", outputs={"json": str(artifact_out)})

    rm_in = paths.output_dir / "rm_inside.json"
    rm_out = outside_dir / "rm_outside.json"
    rm_out_ref = paths.output_dir / "rm_points_outside.json"
    write_runmanifest(None, m_inside, rm_in)
    write_runmanifest(None, m_inside, rm_out)
    write_runmanifest(None, m_out_ref, rm_out_ref)

    # 1. Honors --portable, --enforce-root-read, --log-level DEBUG, --log-file
    rc_ok = cli_main(
        [
            "verify",
            "--portable",
            "--enforce-root-read",
            "--log-level",
            "DEBUG",
            "--log-file",
            "custom_verify.log",
            str(rm_in),
        ]
    )
    assert rc_ok == 0
    assert any("custom_verify" in p.name for p in paths.log_dir.iterdir())

    # 2. Rejects out-of-root runmanifest when --enforce-root-read is enabled
    assert cli_main(["verify", "--portable", "--enforce-root-read", str(rm_out)]) == 1

    # 3. Rejects out-of-root listed output artifact when --enforce-root-read is enabled
    assert cli_main(["verify", "--portable", "--enforce-root-read", str(rm_out_ref)]) == 1

    # 4. Symlinked runmanifest rejected by default, honored with --allow-symlinks-read
    sym_rm = paths.output_dir / "sym_rm.json"
    sym_rm.symlink_to(rm_in)
    assert cli_main(["verify", "--portable", str(sym_rm)]) == 1
    assert cli_main(["verify", "--portable", "--allow-symlinks-read", str(sym_rm)]) == 0

    # 5. Direct programmatic call checks FilePathError/FilePermissionError cleanly
    pfh_test = _build_silent_ui_pfh(work_root)
    assert pfh_test.enforce_roots_on_read is False
    assert run_verify_command(SimpleNamespace(runmanifest=str(rm_in), portable=True, enforce_root_read=True)) == 0
    assert run_verify_command(SimpleNamespace(runmanifest=str(rm_out), portable=True, enforce_root_read=True)) == 1


def test_diff_engine_vector_only_fallback_without_scores_row() -> None:
    matcher = AssetContextMatcher(
        {
            "version": "v2",
            "rules": [{"id": "h1", "asset_id": "aid_vec", "aliases": ["10.8.8.8"], "internet_facing": False}],
        }
    )
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    rec_persist = _rec(
        ip_address="10.8.8.8",
        hostname="vec-host.corp.local",
        cves=["CVE-2024-8888"],
        scanner_sig="nessus:8888",
        title="Vector-only persisting finding",
        scanner_cvss_score=None,
        scanner_cvss_vector=vec,
    )
    rec_new = _rec(
        ip_address="10.8.8.8",
        hostname="vec-host.corp.local",
        cves=["CVE-2024-8889"],
        scanner_sig="nessus:8889",
        title="Vector-only new finding",
        scanner_cvss_score=None,
        scanner_cvss_vector=vec,
    )
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-base", created_at_utc="2026-01-01T00:00:00Z", profile="bod-26-04")
        ensure_run(db, "r-targ", created_at_utc="2026-02-01T00:00:00Z", profile="bod-26-04")
        ingest_normalized_batches(db, "r-base", [[rec_persist]], asset_matcher=matcher)
        ingest_normalized_batches(db, "r-targ", [[rec_persist, rec_new]], asset_matcher=matcher)

        b_fid = db.execute("SELECT finding_id FROM findings WHERE run_id = 'r-base'").fetchone()[0]
        t_fids = dict(db.execute("SELECT title, finding_id FROM findings WHERE run_id = 'r-targ'").fetchall())

        upsert_enrichment_snapshots(
            db,
            "r-base",
            [{"cve_id": "CVE-2024-8888", "cvss_score": None, "cvss_provenance": "Missing", "epss_score": 0.05, "in_kev": False}],
        )
        upsert_enrichment_snapshots(
            db,
            "r-targ",
            [
                {"cve_id": "CVE-2024-8888", "cvss_score": 9.8, "cvss_provenance": "NVD", "epss_score": 0.05, "in_kev": False},
                {"cve_id": "CVE-2024-8889", "cvss_score": None, "cvss_provenance": "Missing", "epss_score": 0.05, "in_kev": False},
            ],
        )
        upsert_triage_decisions(
            db,
            "r-base",
            [{"finding_id": b_fid, "asset_id": "aid_vec", "priority_tier": "P2", "sla_bucket": "60-day", "ssvc_action": "Attend", "decision_status": "active"}],
        )
        upsert_triage_decisions(
            db,
            "r-targ",
            [
                {"finding_id": t_fids["Vector-only persisting finding"], "asset_id": "aid_vec", "priority_tier": "P2", "sla_bucket": "60-day", "ssvc_action": "Attend", "decision_status": "active"},
                {"finding_id": t_fids["Vector-only new finding"], "asset_id": "aid_vec", "priority_tier": "P1", "sla_bucket": "14-day", "ssvc_action": "Act", "decision_status": "active"},
            ],
        )

        # Intentionally omit scores/score_trace rows: DiffEngine must match get_finding_detail via scanner_cvss_vector
        detail = get_finding_detail(db, "r-base", b_fid)
        assert detail is not None
        assert detail["cvss_score"] == pytest.approx(9.8)
        assert detail["cvss_provenance"] == "Scanner-Supplied"

        report = DiffEngine(db).compare("r-base", "r-targ")
        assert report.threat_intel_escalated == []
        assert len(report.newly_introduced_high_risk) == 1
        new_item = report.newly_introduced_high_risk[0]
        assert new_item.cvss_score == pytest.approx(9.8)
        assert new_item.cvss_provenance == "Scanner-Supplied"


def test_verify_command_is_read_only_without_custom_log_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "out.txt"
    artifact.write_text("verified content\n", encoding="utf-8")
    with VppDatabase(":memory:") as db:
        ensure_run(db, "r-ro-ver", created_at_utc="2026-02-01T00:00:00Z")
        manifest = build_runmanifest_from_db(db, "r-ro-ver", outputs={"json": str(artifact)})
    rm_path = tmp_path / "runmanifest.json"
    write_runmanifest(None, manifest, rm_path)

    ro_xdg = tmp_path / "ro_xdg"
    ro_xdg.mkdir(parents=True, exist_ok=True)
    ro_xdg.chmod(0o500)
    try:
        monkeypatch.setenv("XDG_DATA_HOME", str(ro_xdg))
        monkeypatch.delenv("VULNPARSE_PIN_PORTABLE", raising=False)
        rc = cli_main(["verify", str(rm_path)])
        assert rc == 0
        assert list(ro_xdg.iterdir()) == []
    finally:
        ro_xdg.chmod(0o700)

    # Custom --log-file still creates logs under paths.log_dir when explicitly requested
    custom_work = tmp_path / "custom_log_work"
    custom_work.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(custom_work)
    rc_log = cli_main(["verify", "--portable", "--log-file", "custom_verify.log", str(rm_path)])
    assert rc_log == 0
    assert any("custom_verify" in p.name for p in AppPaths.resolve(portable=True).log_dir.iterdir())


