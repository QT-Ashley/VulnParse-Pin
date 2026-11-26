# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import replace as dc_replace
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sqlite3
from typing import Any
import zipfile

import duckdb
import pytest

from vulnparse_pin.app.enrichment import populate_enrichment_snapshots
from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import (
    Asset,
    FeedCachePolicy,
    FeedSpec,
    Finding,
    RunContext,
    ScanMetaData,
    ScanResult,
    Services,
)
from vulnparse_pin.core.passes.Scoring.scoringPass import _resolve_best_cvss
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils import enricher as enricher_mod
from vulnparse_pin.utils import exploit_enrichment_service as exploit_mod
from vulnparse_pin.utils import ghsa_enrichment as ghsa_mod
from vulnparse_pin.utils import nvdcacher as nvd_mod
from vulnparse_pin.utils import osv_enrichment as osv_mod
from vulnparse_pin.utils.cvss_utils import compute_cvss_base_score
from vulnparse_pin.utils.enricher import (
    EPSSFeedCache,
    KEVFeedCache,
    _extract_advisory_cvss,
    _parse_bounded_prob,
    _parse_epss_csv_stream,
    enrich_scan_results,
    load_kev,
    resolve_cvss_with_provenance,
    update_enrichment_status,
)
from vulnparse_pin.utils.exploit_enrichment_service import (
    is_heuristic_exploit_mention,
    load_exploit_data,
)
from vulnparse_pin.utils.feed_cache import FeedCacheManager, FeedChecksumError
from vulnparse_pin.utils.ghsa_enrichment import GHSAEnrichmentSource
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.nvdcacher import NVDFeedCache
from vulnparse_pin.utils.osv_enrichment import OSVEnrichmentSource


def _make_ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "iter1_intel_sec.log"))
    cache_dir = tmp_path / "cache"
    nvd_dir = cache_dir / "nvd"
    cache_dir.mkdir(parents=True, exist_ok=True)
    nvd_dir.mkdir(parents=True, exist_ok=True)

    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=True,
        forbid_symlinks_read=True,
        forbid_symlinks_write=True,
    )
    paths = dc_replace(
        AppPaths.resolve(portable=True),
        cache_dir=cache_dir,
        nvd_feeds_dir=nvd_dir,
        log_dir=tmp_path,
        output_dir=tmp_path,
    )
    specs = {
        "epss": FeedSpec(key="epss", filename="epss_cache.csv", label="EPSS"),
        "kev": FeedSpec(key="kev", filename="kev_cache.json", label="CISA KEV"),
        "exploit_db": FeedSpec(key="exploit_db", filename="files_exploit.csv", label="Exploit-DB"),
    }
    policy = FeedCachePolicy(default_ttl_hours=24, ttl_hours={"epss": 6, "kev": 24, "exploit_db": 24})
    fc = FeedCacheManager(
        cache_dir=cache_dir,
        pfh=pfh,
        logger=logger,
        specs=specs,
        policy=policy,
        nvd_feeds_dir=nvd_dir,
    )
    return RunContext(
        paths=paths,
        pfh=pfh,
        logger=logger,
        services=Services(feed_cache=fc, global_config={"feed_cache": {"feeds": {"nvd": {"enabled": True}}}}),
    )


def _init_snapshot_duckdb(db_path: Path) -> duckdb.DuckDBPyConnection:
    conn = duckdb.connect(str(db_path))
    conn.execute("CREATE TABLE runs (run_id VARCHAR PRIMARY KEY, intel_metadata_json VARCHAR)")
    conn.execute("INSERT INTO runs VALUES ('run-1', NULL)")
    conn.execute(
        """
        CREATE TABLE findings (
            run_id VARCHAR,
            finding_id VARCHAR,
            primary_cve VARCHAR,
            scanner_cvss_score DOUBLE,
            scanner_cvss_vector VARCHAR,
            title VARCHAR,
            description VARCHAR,
            plugin_output VARCHAR,
            package_purl VARCHAR,
            PRIMARY KEY (run_id, finding_id)
        )
        """
    )
    conn.execute("CREATE TABLE finding_cves (run_id VARCHAR, finding_id VARCHAR, cve_id VARCHAR)")
    conn.execute(
        """
        CREATE TABLE enrichment_snapshots (
            run_id VARCHAR,
            cve_id VARCHAR,
            cvss_score DOUBLE,
            cvss_vector VARCHAR,
            cvss_version VARCHAR,
            cvss_provenance VARCHAR,
            epss_score DOUBLE,
            epss_percentile DOUBLE,
            epss_model_version VARCHAR,
            epss_date VARCHAR,
            in_kev BOOLEAN,
            kev_date_added VARCHAR,
            kev_due_date VARCHAR,
            kev_ransomware BOOLEAN,
            kev_required_action VARCHAR,
            verified_exploit BOOLEAN,
            heuristic_exploit_mention BOOLEAN,
            exploit_refs_json VARCHAR,
            ghsa_ids_json VARCHAR,
            osv_ids_json VARCHAR,
            enrichment_confidence INTEGER,
            sources_json VARCHAR,
            PRIMARY KEY (run_id, cve_id)
        )
        """
    )
    return conn


# ------------------------------------------------------------------
# Item 6: Never persist Scanner-Supplied CVSS into enrichment_snapshots
# ------------------------------------------------------------------

def test_populate_enrichment_snapshots_never_leaks_scanner_cvss(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    conn = _init_snapshot_duckdb(tmp_path / "snap_item6.vpp.db")
    try:
        conn.execute(
            "INSERT INTO findings VALUES "
            "('run-1', 'f-low', 'CVE-2024-9991', 4.0, 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N', 'F1', '', '', NULL), "
            "('run-1', 'f-high', 'CVE-2024-9991', 9.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'F2', '', '', NULL)"
        )
        conn.execute(
            "INSERT INTO finding_cves VALUES ('run-1', 'f-low', 'CVE-2024-9991'), ('run-1', 'f-high', 'CVE-2024-9991')"
        )

        populate_enrichment_snapshots(
            conn,
            "run-1",
            ctx,
            {"epss_data": {"CVE-2024-9991": 0.25}},
        )
        row = conn.execute(
            "SELECT cvss_score, cvss_vector, cvss_version, cvss_provenance, sources_json "
            "FROM enrichment_snapshots WHERE run_id = 'run-1' AND cve_id = 'CVE-2024-9991'"
        ).fetchone()
        assert row is not None
        snap_score, snap_vec, snap_ver, snap_prov, sources_raw = row
        assert snap_score is None
        assert snap_vec is None
        assert snap_ver is None
        assert snap_prov == "Missing"
        assert "nvd" not in json.loads(sources_raw)

        # Each finding independently resolves its own scanner CVSS in _resolve_best_cvss
        s1, v1, p1 = _resolve_best_cvss(
            snap_score, snap_ver, snap_prov, 4.0, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
        )
        s2, v2, p2 = _resolve_best_cvss(
            snap_score, snap_ver, snap_prov, 9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        assert (s1, v1, p1) == (4.0, "3.1", "Scanner-Supplied")
        assert (s2, v2, p2) == (9.0, "3.1", "Scanner-Supplied")
    finally:
        conn.close()


# ------------------------------------------------------------------
# Item 14: EPSS bounds, 0..100 percentile normalization, and 0.0 enriched
# ------------------------------------------------------------------

def test_epss_bounds_percentile_normalization_and_zero_score_enriched(tmp_path: Path) -> None:
    assert _parse_bounded_prob(0.0) == 0.0
    assert _parse_bounded_prob(1.0) == 1.0
    assert _parse_bounded_prob(float("nan")) is None
    assert _parse_bounded_prob(float("inf")) is None
    assert _parse_bounded_prob(-0.1) is None
    assert _parse_bounded_prob(1.5) is None
    assert _parse_bounded_prob(95.0, allow_percent=False) is None
    assert _parse_bounded_prob(95.0, allow_percent=True) == pytest.approx(0.95)
    assert _parse_bounded_prob(100.0, allow_percent=True) == 1.0
    assert _parse_bounded_prob(100.1, allow_percent=True) is None
    assert _parse_bounded_prob(True) is None

    csv_stream = io.StringIO(
        "#model_version:v2025.03.14,score_date:2026-11-24T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2026-0001,0.0,95.0\n"
        "CVE-2026-0002,1.5,0.5\n"
        "CVE-2026-0003,NaN,0.5\n"
    )
    lookup, all_rows = _parse_epss_csv_stream(csv_stream)
    assert lookup["CVE-2026-0001"] == 0.0
    assert lookup.get_percentile("CVE-2026-0001") == pytest.approx(0.95)
    assert "CVE-2026-0002" not in lookup
    assert "CVE-2026-0003" not in lookup
    assert len(all_rows) == 1

    ctx = _make_ctx(tmp_path)
    conn = _init_snapshot_duckdb(tmp_path / "snap_item14.vpp.db")
    try:
        conn.execute(
            "INSERT INTO findings VALUES "
            "('run-1', 'f1', 'CVE-2026-0001', NULL, NULL, 'F1', '', '', NULL), "
            "('run-1', 'f2', 'CVE-2026-0002', NULL, NULL, 'F2', '', '', NULL), "
            "('run-1', 'f3', 'CVE-2026-0003', NULL, NULL, 'F3', '', '', NULL)"
        )
        conn.execute(
            "INSERT INTO finding_cves VALUES "
            "('run-1', 'f1', 'CVE-2026-0001'), "
            "('run-1', 'f2', 'CVE-2026-0002'), "
            "('run-1', 'f3', 'CVE-2026-0003')"
        )
        populate_enrichment_snapshots(
            conn,
            "run-1",
            ctx,
            {
                "epss_data": {
                    "CVE-2026-0001": {"epss_score": 0.0, "epss_percentile": 95.0},
                    "CVE-2026-0002": {"epss_score": float("nan"), "epss_percentile": 0.5},
                    "CVE-2026-0003": {"epss_score": 1.25, "epss_percentile": 150.0},
                }
            },
        )
        rows = {
            r[0]: r[1:]
            for r in conn.execute(
                "SELECT cve_id, epss_score, epss_percentile, sources_json "
                "FROM enrichment_snapshots WHERE run_id = 'run-1'"
            ).fetchall()
        }
        assert rows["CVE-2026-0001"][0] == 0.0
        assert rows["CVE-2026-0001"][1] == pytest.approx(0.95)
        assert "epss" in json.loads(rows["CVE-2026-0001"][2])
        assert rows["CVE-2026-0002"][0] is None
        assert "epss" not in json.loads(rows["CVE-2026-0002"][2])
        assert rows["CVE-2026-0003"][0] is None
        assert rows["CVE-2026-0003"][1] is None
    finally:
        conn.close()

    # update_enrichment_status & enrich_scan_results treat epss_score == 0.0 as enriched
    f_direct = Finding(
        finding_id="F-ZERO",
        vuln_id="V-ZERO",
        title="Zero EPSS",
        description="desc",
        severity="Low",
        cves=["CVE-2026-0001"],
        epss_score=0.0,
    )
    update_enrichment_status(f_direct)
    assert f_direct.enriched is True

    finding = Finding(
        finding_id="F-SCAN-ZERO",
        vuln_id="V-SCAN-ZERO",
        title="Scan Zero EPSS",
        description="desc",
        severity="Low",
        cves=["CVE-2026-0001"],
        asset_id="A-1",
    )
    scan = ScanResult(
        scan_metadata=ScanMetaData(source="unit", scan_date=datetime.now(timezone.utc), asset_count=1, vulnerability_count=1),
        assets=[Asset(hostname="web", ip_address="10.0.0.1", asset_id="A-1", findings=[finding])],
    )
    enrich_scan_results(ctx, scan, kev_data={}, epss_data={"CVE-2026-0001": {"epss_score": 0.0, "epss_percentile": 95.0}})
    assert finding.epss_score == 0.0
    assert finding.epss_percentile == pytest.approx(0.95)
    assert finding.enriched is True
    assert "epss" in finding.enrichment_sources


# ------------------------------------------------------------------
# Item 10: Heuristic exploit negation regex
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "No working exploit exists.",
        "No functional exploit is known.",
        "No active exploit available.",
        "No published exploit found.",
        "No confirmed exploit exists.",
        "No practical exploit is known.",
        "No reliable exploit exists.",
        "Exploits are not known to exist.",
        "Exploit is not available.",
        "Unlikely to be exploitable.",
        "Unable to confirm whether this is exploitable.",
        "Unable to confirm if an exploit exists.",
    ],
)
def test_heuristic_exploit_negated_phrases_return_false(text: str) -> None:
    assert is_heuristic_exploit_mention(text) is False


@pytest.mark.parametrize(
    "text",
    [
        "Public exploit PoC observed on GitHub.",
        "Exploits are not only possible, they are actively used.",
        "Exploits are not publicly available, though a private exploit exists.",
        "Unable to confirm patch version; public exploit exists.",
        "Unable to confirm root cause but a working exploit exists.",
    ],
)
def test_heuristic_exploit_positive_mentions_remain_true(text: str) -> None:
    assert is_heuristic_exploit_mention(text) is True


# ------------------------------------------------------------------
# Item 12: CVSS v4.0 Decimal ROUND_HALF_UP, NVD Primary case/precedence, finite score validation
# ------------------------------------------------------------------

def test_cvss_v4_decimal_rounding_and_nvd_precedence(tmp_path: Path) -> None:
    assert compute_cvss_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H") == 8.6

    ctx = _make_ctx(tmp_path)
    nvd = NVDFeedCache(ctx)

    # Lowercase "primary" + NVD source must yield "NVD", and NVD v3.1 must beat CNA v4.0
    score, vec, ver, prov, _ = nvd._choose_cvss(
        {
            "cvssMetricV40": [
                {
                    "type": "Primary",
                    "source": "cna@vendor.test",
                    "cvssData": {
                        "version": "4.0",
                        "vectorString": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                        "baseScore": 4.6,
                    },
                }
            ],
            "cvssMetricV31": [
                {
                    "type": "primary",
                    "source": "nvd@nist.gov",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                    },
                }
            ],
        }
    )
    assert (score, ver, prov) == (9.8, "3.1", "NVD")
    assert vec == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    # Non-finite and out-of-range score-only CVSS must be rejected everywhere
    for bad in (float("nan"), float("inf"), float("-inf"), -5.0, 99.0, True):
        assert _extract_advisory_cvss([{"cvss_score": bad}]) == (None, None, None)
        res = resolve_cvss_with_provenance(
            ctx,
            nvd_record={"found": True, "cvss_score": bad, "cvss_provenance": "NVD"},
            scanner_score=bad,
            auth_cve="CVE-2026-1234",
        )
        assert res["cvss_provenance"] == "Missing"
        assert res["cvss_score"] is None


# ------------------------------------------------------------------
# Item 16: Reject HMAC downgrade & never auto-sign existing unsigned SQLite DBs
# ------------------------------------------------------------------

def test_hmac_downgrade_and_unsigned_sqlite_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. FeedCacheManager rejects sha256 downgrade when VP_FEED_CACHE_HMAC_KEY is set
    monkeypatch.setenv("VP_FEED_CACHE_HMAC_KEY", "feed-secret-key")
    ctx = _make_ctx(tmp_path)
    fc = ctx.services.feed_cache
    assert fc is not None
    data_path = fc.write_atomic(
        "kev",
        b'{"vulnerabilities": []}',
        source_url="https://example.test/kev.json",
        mode="Online",
        validated=False,
        checksum_src="Local",
    )
    data_path.write_bytes(b'{"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}')
    new_digest = fc.compute_checksum("kev")
    sha_path = Path(f"{data_path}.sha256")
    sha_path.write_text(f"{new_digest} {data_path.name}\n", encoding="utf-8")
    integrity_path = Path(f"{data_path}.integrity.json")
    integrity_path.write_text(
        json.dumps({"feed": "kev", "filename": data_path.name, "mode": "sha256", "digest": new_digest, "signature": new_digest}),
        encoding="utf-8",
    )
    with pytest.raises(FeedChecksumError):
        fc.ensure_feed_checksum("kev", allow_regen=False)
    assert not data_path.exists()

    # 2. All 5 SQLite caches reject sha256 downgrade and never auto-sign unsigned pre-existing DBs
    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "sqlite-secret-key")
    caches = [
        ("nvd", lambda c: NVDFeedCache(c), "nvd_records", "INSERT INTO nvd_records (cve_id, description) VALUES ('CVE-2099-1001', 'poison')"),
        ("epss", lambda c: EPSSFeedCache(c), "epss_records", "INSERT INTO epss_records (cve_id, epss_score, epss_percentile) VALUES ('CVE-2099-1001', 0.99, 0.99)"),
        ("kev", lambda c: KEVFeedCache(c), "kev_records", "INSERT INTO kev_records (cve_id) VALUES ('CVE-2099-1001')"),
        ("ghsa", lambda c: GHSAEnrichmentSource(c), "ghsa_cve_index", "INSERT INTO ghsa_cve_index (cve_id, advisory_id, advisory_json) VALUES ('CVE-2099-1001', 'GHSA-1111-2222-3333', '{}')"),
        ("osv", lambda c: OSVEnrichmentSource(c), "osv_advisories", "INSERT INTO osv_advisories (osv_id, advisory_json) VALUES ('OSV-POISON', '{}')"),
    ]
    for name, factory, table, poison_sql in caches:
        sub_ctx = _make_ctx(tmp_path / f"sqlite_{name}")
        inst = factory(sub_ctx)
        db_file = Path(inst._sqlite_path)
        sig_file = Path(inst._sqlite_sig_path)

        # Verify HMAC mode was written on clean init
        sig_payload = json.loads(sig_file.read_text(encoding="utf-8"))
        assert sig_payload["mode"] == "hmac-sha256"

        # Downgrade attack: tamper DB + write sha256 sidecar
        with sqlite3.connect(db_file) as raw_conn:
            raw_conn.execute(poison_sql)
        digest = inst._compute_digest() if hasattr(inst, "_compute_digest") else inst._sqlite_compute_digest()
        sig_file.write_text(json.dumps({"mode": "sha256", "digest": digest, "signature": digest}), encoding="utf-8")

        verify_fn = inst._verify_signature if hasattr(inst, "_verify_signature") else inst._sqlite_verify_signature
        assert verify_fn() is False

        # Re-init must quarantine tampered DB (never keep poisoned row)
        rebuilt = factory(sub_ctx)
        assert any(p.name.startswith(f"{db_file.name}.tampered.") for p in db_file.parent.iterdir())
        with sqlite3.connect(db_file) as raw_conn:
            cnt = raw_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert cnt == 0

        # Missing .sig.json attack: poison DB and delete .sig.json
        with sqlite3.connect(db_file) as raw_conn:
            raw_conn.execute(poison_sql)
        sig_file.unlink()
        verify_rebuilt = rebuilt._verify_signature if hasattr(rebuilt, "_verify_signature") else rebuilt._sqlite_verify_signature
        assert verify_rebuilt() is False
        assert not sig_file.exists()

        # Re-init must quarantine unsigned DB before trusting/connecting
        _ = factory(sub_ctx)
        with sqlite3.connect(db_file) as raw_conn:
            cnt_after = raw_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert cnt_after == 0


# ------------------------------------------------------------------
# Item 17: Streaming HTTP with allow_redirects=False and bounded reads
# ------------------------------------------------------------------

def test_streaming_http_enforces_redirects_and_byte_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _StreamResp:
        def __init__(self, *, url: str, status_code: int = 200, headers: dict[str, str] | None = None, chunks: list[bytes] | None = None):
            self.url = url
            self.status_code = status_code
            self.headers = headers or {}
            self._chunks = chunks or []
            self.iter_reads = 0

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

        def iter_content(self, chunk_size: int = 1024):
            for c in self._chunks:
                self.iter_reads += 1
                yield c

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    ctx = _make_ctx(tmp_path)

    # 1. KEV: must pass allow_redirects=False, stream=True and reject HTTP downgrade redirect before body fetch
    seen_kwargs: list[dict[str, Any]] = []

    def _kev_downgrade(url, **kwargs):
        seen_kwargs.append(kwargs)
        return _StreamResp(url=url, status_code=302, headers={"Location": "http://evil.test/kev.json"})

    monkeypatch.setattr("vulnparse_pin.utils.enricher.requests.get", _kev_downgrade)
    with pytest.raises(RuntimeError, match="non-HTTPS"):
        load_kev(ctx, "https://example.test/kev.json", force_refresh=True, allow_regen=True)
    assert seen_kwargs[0]["allow_redirects"] is False
    assert seen_kwargs[0]["stream"] is True

    # 2. KEV: chunked streaming aborts early without reading remaining chunks when limit exceeded
    monkeypatch.setattr(enricher_mod, "MAX_REMOTE_FEED_BYTES", 10)
    oversize_kev = _StreamResp(url="https://example.test/kev.json", chunks=[b"123456", b"789012", b"never_read"])
    monkeypatch.setattr("vulnparse_pin.utils.enricher.requests.get", lambda url, **kw: oversize_kev)
    with pytest.raises(RuntimeError, match="size limit"):
        load_kev(ctx, "https://example.test/kev.json", force_refresh=True, allow_regen=True)
    assert oversize_kev.iter_reads == 2

    # 3. Exploit-DB: HTTPS -> HTTPS redirect succeeds; oversized stream without Content-Length fails closed
    monkeypatch.setattr(exploit_mod, "MAX_EXPLOITDB_FEED_BYTES", 16)
    oversize_edb = _StreamResp(url="https://gitlab.com/exploitdb.csv", chunks=[b"0123456789", b"abcdefghij", b"never_read"])
    calls = {"n": 0}

    def _edb_redirect_then_oversize(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        calls["n"] += 1
        if calls["n"] == 1:
            return _StreamResp(url=url, status_code=302, headers={"Location": "https://cdn.example.test/files_exploits.csv"})
        return oversize_edb

    monkeypatch.setattr("vulnparse_pin.utils.exploit_enrichment_service.requests.get", _edb_redirect_then_oversize)
    with pytest.raises(RuntimeError, match="size limit"):
        load_exploit_data(ctx, source="online", force_refresh=True, allow_regen=True)
    assert calls["n"] == 2
    assert oversize_edb.iter_reads == 2


# ------------------------------------------------------------------
# Item 29: All sqlite3.connect handles are explicitly closed on scope exit
# ------------------------------------------------------------------

def test_sqlite_connections_always_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    open_conns: list[Any] = []
    real_connect = sqlite3.connect

    class _TrackedConn:
        def __init__(self, inner: sqlite3.Connection) -> None:
            self._inner = inner
            self.closed = False
            open_conns.append(self)

        def close(self) -> None:
            self.closed = True
            self._inner.close()

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb):
            return self._inner.__exit__(exc_type, exc, tb)

        def __getattr__(self, item: str) -> Any:
            return getattr(self._inner, item)

    def _tracked_connect(*args, **kwargs):
        return _TrackedConn(real_connect(*args, **kwargs))

    for mod in (nvd_mod, enricher_mod, ghsa_mod, osv_mod):
        monkeypatch.setattr(mod.sqlite3, "connect", _tracked_connect)

    ctx = _make_ctx(tmp_path)

    nvd = NVDFeedCache(ctx)
    nvd._sqlite_upsert([{"id": "CVE-2026-1111", "description": "demo", "cvss_score": 7.5}])
    nvd._sqlite_hydrate_targets({"CVE-2026-1111"})
    nvd._sqlite_get_one("CVE-2026-1111")

    epss = EPSSFeedCache(ctx)
    epss.rebuild_from_rows([("CVE-2026-1111", 0.5, 0.9)], model_version="v5", score_date="2026-11-24", source_sha256="abc")
    epss.query_cves({"CVE-2026-1111"})

    kev = KEVFeedCache(ctx)
    kev.rebuild_from_records([{"cve_id": "CVE-2026-1111"}], catalog_version="2026", date_released="2026-11-24", source_sha256="def")
    kev.query_cves({"CVE-2026-1111"})

    ghsa = GHSAEnrichmentSource(ctx)
    ghsa._sqlite_upsert_rows([("CVE-2026-1111", "GHSA-aaaa-bbbb-cccc", '{"id":"GHSA-aaaa-bbbb-cccc"}', "2026-11-24T00:00:00Z")])
    ghsa._sqlite_hydrate_targets({"CVE-2026-1111"})
    ghsa._sqlite_clear()

    osv = OSVEnrichmentSource(ctx)
    osv._sqlite_upsert_advisories([{"id": "PYSEC-2026-1", "aliases": ["CVE-2026-1111"]}])
    osv._sqlite_hydrate_targets(target_cves={"CVE-2026-1111"})
    osv._sqlite_clear()

    assert len(open_conns) > 0
    assert all(c.closed for c in open_conns)
