# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass, replace as dc_replace
from datetime import datetime, timezone
import gzip
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
from types import SimpleNamespace
import zipfile

import duckdb
import pytest

from vulnparse_pin.app.enrichment import populate_enrichment_snapshots
from vulnparse_pin.app.enrichment_handoff import EnrichmentHandoffBuilder
from vulnparse_pin.app.enrichment_source_loader import EnrichmentSourceLoader, EnrichmentSourcePlan
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
    WebhookRuntimeConfig,
)
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.enricher import (
    EPSSFeedCache,
    KEVFeedCache,
    enrich_scan_results,
    load_epss,
    load_kev,
    resolve_cvss_vector,
    resolve_cvss_with_provenance,
)
from vulnparse_pin.utils.exploit_enrichment_service import (
    apply_heuristic_exploit_tag,
    enrich_exploit_availability,
    is_heuristic_exploit_mention,
)
from vulnparse_pin.utils.feed_cache import FeedCacheManager, FeedChecksumError
from vulnparse_pin.utils.ghsa_enrichment import GHSAEnrichmentSource, parse_purl
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.utils.nvdcacher import NVDFeedCache, nvd_policy_from_config
from vulnparse_pin.utils.osv_enrichment import OSVEnrichmentSource, OSVSecurityError


def _make_real_ctx(
    tmp_path: Path,
    *,
    config: dict | None = None,
    services_kwargs: dict | None = None,
) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "intel_v2.log"))
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
    svc_kw = {
        "feed_cache": fc,
        "global_config": config or {"feed_cache": {"feeds": {"nvd": {"enabled": True}}}},
    }
    if services_kwargs:
        svc_kw.update(services_kwargs)
    return RunContext(paths=paths, pfh=pfh, logger=logger, services=Services(**svc_kw))


def _make_scan(cves: list[str], *, title: str = "Demo Finding", plugin_output: str = "", purl: str | None = None) -> ScanResult:
    finding = Finding(
        finding_id="F-1",
        vuln_id="V-1",
        title=title,
        description="demo",
        severity="High",
        cves=cves,
        plugin_output=plugin_output,
        asset_id="A-1",
    )
    if purl:
        finding.package_purl = purl  # type: ignore[attr-defined]
    asset = Asset(hostname="web-01", ip_address="10.0.0.10", asset_id="A-1", findings=[finding])
    meta = ScanMetaData(source="unit", scan_date=datetime.now(timezone.utc), asset_count=1, vulnerability_count=1)
    return ScanResult(scan_metadata=meta, assets=[asset])


# ------------------------------------------------------------------
# 1. feed_cache.py: non-interactive fail-closed + 0o600 + quarantine + Python 3.11 syntax
# ------------------------------------------------------------------

def test_feed_cache_fails_closed_without_input_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _make_real_ctx(tmp_path)
    fc = ctx.services.feed_cache
    assert fc is not None

    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("input() must not be called")))

    data_path = fc.write_atomic(
        "epss",
        b"cve,epss\nCVE-2024-0001,0.5\n",
        source_url="https://example.test/epss.csv.gz",
        mode="Online",
        validated=False,
        checksum_src="Local",
    )
    if os.name != "nt":
        assert stat.S_IMODE(data_path.stat().st_mode) == 0o600

    # Tamper cached file -> allow_regen=False must fail closed and quarantine
    data_path.write_bytes(b"cve,epss\nCVE-2024-0001,0.99\n")
    with pytest.raises(FeedChecksumError):
        fc.ensure_feed_checksum("epss", allow_regen=False)
    assert not data_path.exists()
    assert any(p.name.startswith("epss_cache.csv.tampered.") for p in data_path.parent.iterdir())

    # allow_regen=True regenerates cleanly without blocking on input()
    fc.write_atomic(
        "epss",
        b"cve,epss\nCVE-2024-0001,0.5\n",
        source_url="https://example.test/epss.csv.gz",
        mode="Online",
        validated=False,
        checksum_src="Local",
    )
    data_path, sha_path, _ = fc.resolve("epss")
    assert sha_path is not None
    sha_path.unlink()
    assert fc.ensure_feed_checksum("epss", allow_regen=True) is False
    assert sha_path.exists()


def test_feed_cache_rejects_world_writable_cache(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permissions test")
    ctx = _make_real_ctx(tmp_path)
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
    os.chmod(data_path, 0o666)
    with pytest.raises(PermissionError, match="world-writable"):
        fc.ensure_feed_checksum("kev", allow_regen=False)


# ------------------------------------------------------------------
# 2. nvdcacher.py: real PFH open_for_write fix + >1000 chunking + sentinel filter + get() + v4/NVD/CNA
# ------------------------------------------------------------------

def test_nvdcacher_real_pfh_open_for_write_and_1200_cve_chunking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "test-secret-key")
    ctx = _make_real_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    assert cache._sqlite_enabled is True
    assert cache._sqlite_sig_path is not None
    assert Path(cache._sqlite_sig_path).exists()

    records = [
        {
            "id": f"CVE-2025-{1000 + idx:04d}",
            "description": f"desc {idx}",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_version": "3.1",
            "cvss_provenance": "NVD",
            "source_identifier": "nvd@nist.gov",
            "published": "2025-01-01T00:00:00Z",
            "last_modified": "2025-01-02T00:00:00Z",
        }
        for idx in range(1200)
    ]
    cache._sqlite_upsert(records)

    warm = NVDFeedCache(ctx)
    targets = {r["id"] for r in records}
    targets.add("SENTINEL:No_CVE_Listed")
    unresolved = warm._sqlite_hydrate_targets(targets)
    assert unresolved == set()
    assert len(warm.lookup) == 1200

    # Sentinels only -> refresh must short-circuit without calling resolve_nvd_feed
    class _FailFC:
        def resolve_nvd_feed(self, **_kwargs):
            raise AssertionError("Should skip NVD feed resolve when only sentinels are present")

    warm.refresh(config={"feed_cache": {"feeds": {"nvd": {"enabled": True}}}}, feed_cache=_FailFC(), refresh_cache=False, offline=True, target_cves={"SENTINEL:No_CVE_Listed"})


def test_nvdcacher_get_missing_cve_and_dynamic_year(tmp_path: Path) -> None:
    ctx = _make_real_ctx(tmp_path)
    cache = NVDFeedCache(ctx)

    missing = cache.get("CVE-2026-999999")
    assert missing["found"] is False
    assert "last_modified" in missing
    assert "last_Modified" not in missing

    policy = nvd_policy_from_config({"feed_cache": {"feeds": {"nvd": {"enabled": True, "start_year": 2024}}}})
    assert policy["end_year"] == datetime.now(timezone.utc).year


def test_nvdcacher_cvss_v4_nvd_vs_cna_provenance_and_schema_migration(tmp_path: Path) -> None:
    # Simulate legacy SQLite DB missing new columns
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    legacy_db = cache_dir / "nvd_cache.sqlite3"
    with sqlite3.connect(legacy_db) as conn:
        conn.execute(
            """
            CREATE TABLE nvd_records (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                published TEXT,
                last_modified TEXT,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO nvd_records VALUES ('CVE-2024-0001', 'legacy', 5.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', '2024-01-01', '2024-01-02', '2026-01-01T00:00:00Z')"
        )

    ctx = _make_real_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    assert cache._sqlite_enabled is True
    with sqlite3.connect(legacy_db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(nvd_records)").fetchall()}
    assert {"cvss_version", "cvss_provenance", "source_identifier"}.issubset(cols)

    feed_path = tmp_path / "year.2026.json.gz"
    nvd_json = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1001",
                    "sourceIdentifier": "cna@vendor.test",
                    "descriptions": [{"lang": "en", "value": "v4 NVD wins over CNA within tier"}],
                    "published": "2026-01-01T00:00:00Z",
                    "lastModified": "2026-01-02T00:00:00Z",
                    "metrics": {
                        "cvssMetricV40": [
                            {
                                "type": "Secondary",
                                "source": "cna@vendor.test",
                                "cvssData": {
                                    "version": "4.0",
                                    "vectorString": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                                    "baseScore": 4.8,
                                },
                            },
                            {
                                "type": "Primary",
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "version": "4.0",
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                    "baseScore": 9.3,
                                },
                            },
                        ],
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                },
                            }
                        ],
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-1002",
                    "sourceIdentifier": "cna@vendor.test",
                    "descriptions": [{"lang": "en", "value": "CNA fallback when NVD absent"}],
                    "published": "2026-01-03T00:00:00Z",
                    "lastModified": "2026-01-04T00:00:00Z",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Secondary",
                                "source": "cna@vendor.test",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
                                    "baseScore": 6.4,
                                },
                            }
                        ]
                    },
                }
            },
        ]
    }
    with gzip.open(feed_path, "wt", encoding="utf-8") as fh:
        json.dump(nvd_json, fh)

    cache.target_cves = {"CVE-2026-1001", "CVE-2026-1002", "SENTINEL:No_CVE_Listed"}
    cache._parse_feed(str(feed_path))

    r1 = cache.get("CVE-2026-1001")
    assert r1["found"] is True
    assert r1["cvss_version"] == "4.0"
    assert r1["cvss_provenance"] == "NVD"
    assert r1["cvss_score"] == 9.3
    assert r1["source_identifier"] == "nvd@nist.gov"

    r2 = cache.get("CVE-2026-1002")
    assert r2["found"] is True
    assert r2["cvss_version"] == "3.1"
    assert r2["cvss_provenance"] == "CNA"
    assert r2["cvss_score"] == 6.4
    assert r2["source_identifier"] == "cna@vendor.test"


# ------------------------------------------------------------------
# 3. EPSS v5 + KEV Metadata + Unified CVSS Precedence
# ------------------------------------------------------------------

def test_epss_v5_parsing_sqlite_index_and_tamper_quarantine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "epss-hmac")
    ctx = _make_real_ctx(tmp_path)

    epss_csv = tmp_path / "epss_v5.csv"
    epss_csv.write_text(
        "#model_version:v2025.03.14,score_date:2026-11-23T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2026-0001,0.91234,0.99876\n"
        "CVE-2026-0002,0.04500,0.61200\n",
        encoding="utf-8",
    )

    epss = load_epss(ctx, path_url=str(epss_csv), force_refresh=False, allow_regen=True, target_cves={"CVE-2026-0001"})
    assert epss["CVE-2026-0001"] == pytest.approx(0.91234)
    assert "CVE-2026-0002" not in epss
    assert epss.get_percentile("CVE-2026-0001") == pytest.approx(0.99876)
    assert epss.model_version == "v2025.03.14"
    assert epss.score_date == "2026-11-23T00:00:00+0000"

    db_file = ctx.paths.cache_dir / "epss_cache.sqlite3"
    assert db_file.exists()
    if os.name != "nt":
        assert stat.S_IMODE(db_file.stat().st_mode) == 0o600

    # Warm SQLite query must not re-parse CSV
    monkeypatch.setattr("vulnparse_pin.utils.enricher._parse_epss_csv_stream", lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("Warm run should use epss_cache.sqlite3")))
    warm = load_epss(ctx, path_url=str(epss_csv), force_refresh=False, allow_regen=False, target_cves={"CVE-2026-0002"})
    assert warm["CVE-2026-0002"] == pytest.approx(0.045)
    assert warm.get_percentile("CVE-2026-0002") == pytest.approx(0.612)
    assert warm.model_version == "v2025.03.14"

    # Tamper SQLite -> verify detection & quarantine/reset on reload
    epss_cache = EPSSFeedCache(ctx)
    with sqlite3.connect(db_file) as conn:
        conn.execute("UPDATE epss_records SET epss_score = 0.0 WHERE cve_id = 'CVE-2026-0001'")
    assert epss_cache._verify_signature() is False
    reloaded = EPSSFeedCache(ctx)
    assert reloaded._verify_signature() is True
    assert any(p.name.startswith("epss_cache.sqlite3.tampered.") for p in ctx.paths.cache_dir.iterdir())
    assert reloaded.query_cves({"CVE-2026-0001"}).get("CVE-2026-0001") is None


def test_kev_full_metadata_and_sqlite_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "kev-hmac")
    ctx = _make_real_ctx(tmp_path)

    kev_file = tmp_path / "kev.json"
    kev_file.write_text(
        json.dumps(
            {
                "catalogVersion": "2026.11.20",
                "dateReleased": "2026-11-20T12:00:00Z",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-5001",
                        "dateAdded": "2026-11-01",
                        "dueDate": "2026-11-15",
                        "knownRansomwareCampaignUse": "Known",
                        "requiredAction": "Apply vendor update",
                        "vulnerabilityName": "Demo Critical RCE",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    kev = load_kev(ctx, str(kev_file), force_refresh=False, allow_regen=True)
    assert kev["CVE-2026-5001"] is True
    rec = kev.get_record("CVE-2026-5001")
    assert rec is not None
    assert rec["date_added"] == "2026-11-01"
    assert rec["due_date"] == "2026-11-15"
    assert rec["known_ransomware"] is True
    assert rec["required_action"] == "Apply vendor update"
    assert rec["vulnerability_name"] == "Demo Critical RCE"
    assert (ctx.paths.cache_dir / "kev_cache.sqlite3").exists()

    kev_db = KEVFeedCache(ctx)
    warm = kev_db.query_cves({"CVE-2026-5001"})
    assert warm["CVE-2026-5001"] is True
    assert warm.get_record("CVE-2026-5001")["known_ransomware"] is True


def test_unified_cvss_precedence_consistency(tmp_path: Path) -> None:
    ctx = _make_real_ctx(tmp_path)
    scanner_vec = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    osv_adv = [{"id": "OSV-1", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}]
    ghsa_adv = [{"id": "GHSA-aaaa-bbbb-cccc", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}]}]
    cna_rec = {"found": True, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": None, "cvss_provenance": "CNA", "cvss_version": "3.1"}
    nvd_rec = {"found": True, "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "cvss_score": None, "cvss_provenance": "NVD", "cvss_version": "4.0"}

    # Missing
    r_miss = resolve_cvss_with_provenance(ctx, auth_cve="CVE-2026-0099")
    assert r_miss["cvss_provenance"] == "Missing"
    assert r_miss["cvss_version"] is None

    # Scanner-Supplied
    r_scan = resolve_cvss_with_provenance(ctx, scanner_vector=scanner_vec, auth_cve="CVE-2026-0099")
    assert r_scan["cvss_provenance"] == "Scanner-Supplied"
    assert r_scan["cvss_version"] == "3.1"

    # OSV beats Scanner-Supplied (and computes score via cvss_utils)
    r_osv = resolve_cvss_with_provenance(ctx, scanner_vector=scanner_vec, auth_cve="CVE-2026-0099", osv_advisories=osv_adv)
    assert r_osv["cvss_provenance"] == "OSV"
    assert r_osv["cvss_score"] == 7.5

    # GHSA beats OSV
    r_ghsa = resolve_cvss_with_provenance(ctx, scanner_vector=scanner_vec, auth_cve="CVE-2026-0099", ghsa_advisories=ghsa_adv, osv_advisories=osv_adv)
    assert r_ghsa["cvss_provenance"] == "GHSA"
    assert r_ghsa["cvss_score"] == 9.1

    # CNA beats GHSA
    r_cna = resolve_cvss_with_provenance(ctx, scanner_vector=scanner_vec, auth_cve="CVE-2026-0099", nvd_record=cna_rec, ghsa_advisories=ghsa_adv, osv_advisories=osv_adv)
    assert r_cna["cvss_provenance"] == "CNA"
    assert r_cna["cvss_score"] == 9.8

    # NVD beats CNA & resolve_cvss_vector agrees identically
    class _StubNVD:
        def get(self, _cve):
            return nvd_rec

    r_nvd = resolve_cvss_with_provenance(ctx, scanner_vector=scanner_vec, auth_cve="CVE-2026-0099", nvd_cache=_StubNVD(), ghsa_advisories=ghsa_adv, osv_advisories=osv_adv)
    vec, score = resolve_cvss_vector(ctx, scanner_vec, "CVE-2026-0099", _StubNVD(), ghsa_advisories=ghsa_adv, osv_advisories=osv_adv)
    assert r_nvd["cvss_provenance"] == "NVD"
    assert r_nvd["cvss_version"] == "4.0"
    assert r_nvd["cvss_score"] == 9.3
    assert vec == r_nvd["resolved_vector"]
    assert score == 9.3


# ------------------------------------------------------------------
# 4. Exploit-DB vs Heuristic Separation & KEV Independence
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "This issue is not exploitable in default configurations.",
        "There is no known exploit in the wild.",
        "Vendor confirms condition is unexploitable.",
        "Cannot be leveraged without exploit chaining.",
        "Marked non-exploitable by security team.",
        "Currently there is no exploit available.",
    ],
)
def test_exploit_heuristic_negations_are_ignored(text: str) -> None:
    assert is_heuristic_exploit_mention(text) is False


def test_exploit_heuristic_kev_and_exploitdb_separation(tmp_path: Path) -> None:
    ctx = _make_real_ctx(tmp_path)

    # 1. Negated exploit text + KEV hit -> exploit_available MUST stay False, no 'exploitdb'
    scan1 = _make_scan(["CVE-2026-2001"], plugin_output="Confirmed not exploitable remotely.")
    f1 = scan1.assets[0].findings[0]
    assert apply_heuristic_exploit_tag(ctx, f1) is False
    enrich_scan_results(ctx, scan1, kev_data={"CVE-2026-2001": True}, epss_data={"CVE-2026-2001": 0.8})
    assert f1.cisa_kev is True
    assert f1.exploit_available is False
    assert getattr(f1, "verified_exploit", False) is False
    assert "exploitdb" not in f1.enrichment_sources
    assert f1.cve_analysis[0]["heuristic_exploit_mention"] is False
    assert f1.cve_analysis[0]["verified_exploit"] is False

    # 2. Positive regex hit -> heuristic_exploit_mention=True ONLY, NEVER verified_exploit or 'exploitdb'
    scan2 = _make_scan(["CVE-2026-2002"], plugin_output="Public exploit PoC observed in advisory text.")
    f2 = scan2.assets[0].findings[0]
    assert apply_heuristic_exploit_tag(ctx, f2) is True
    assert getattr(f2, "heuristic_exploit_mention", False) is True
    assert f2.exploit_available is False
    enrich_scan_results(ctx, scan2, kev_data={}, epss_data={})
    assert f2.exploit_available is False
    assert getattr(f2, "verified_exploit", False) is False
    assert "exploitdb" not in f2.enrichment_sources
    assert f2.cve_analysis[0]["heuristic_exploit_mention"] is True
    assert f2.cve_analysis[0]["verified_exploit"] is False

    # 3. Verified Exploit-DB match -> verified_exploit=True & 'exploitdb' in enrichment_sources
    scan3 = _make_scan(["CVE-2026-2003"])
    f3 = scan3.assets[0].findings[0]
    exploit_data = {"CVE-2026-2003": [{"exploit_id": "55555", "title": "Verified PoC", "source": "Exploit-DB"}]}
    enrich_exploit_availability(ctx, [f3], exploit_data, asset_id="A-1")
    enrich_scan_results(ctx, scan3, kev_data={}, epss_data={})
    assert f3.exploit_available is True
    assert getattr(f3, "verified_exploit", False) is True
    assert "exploitdb" in f3.enrichment_sources
    assert f3.cve_analysis[0]["verified_exploit"] is True


# ------------------------------------------------------------------
# 5. GHSA Package Index Warm Hit & OSV Offline ZIP/JSON + Security Checks
# ------------------------------------------------------------------

def test_ghsa_package_index_warm_purl_lookup(tmp_path: Path) -> None:
    eco, name = parse_purl("pkg:npm/%40scope/widget@1.2.3")
    assert (eco, name) == ("npm", "@scope/widget")

    adv_dir = tmp_path / "advisories" / "github-reviewed" / "2026" / "01" / "GHSA-pkg1-pkg2-pkg3"
    adv_dir.mkdir(parents=True, exist_ok=True)
    advisory = {
        "id": "GHSA-pkg1-pkg2-pkg3",
        "aliases": [],  # GHSA-only advisory (no CVE)
        "summary": "Prototype pollution in requests-demo",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "requests-demo"}}],
        "references": [{"type": "WEB", "url": "https://github.com/advisories/GHSA-pkg1-pkg2-pkg3"}],
    }
    (adv_dir / "GHSA-pkg1-pkg2-pkg3.json").write_text(json.dumps(advisory), encoding="utf-8")

    ctx = _make_real_ctx(tmp_path)
    cold = GHSAEnrichmentSource(ctx)
    assert cold.load_offline(db_path=str(tmp_path), target_purls={"pkg:pypi/requests-demo@2.0.0"}) is True
    assert "requests-demo" in cold.ghsa_by_package

    # Warm run: block JSON reads and resolve via ghsa_package_index
    warm = GHSAEnrichmentSource(ctx)
    warm._load_json_file = lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("Warm run must not re-read advisory JSONs"))  # type: ignore[method-assign]
    assert warm.load_offline(db_path=str(tmp_path), target_purls={"pkg:pypi/requests-demo@2.0.0"}) is True
    hits = warm.lookup_by_purl("pkg:pypi/requests-demo@2.0.0")
    assert len(hits) == 1
    assert hits[0]["id"] == "GHSA-pkg1-pkg2-pkg3"


def test_osv_offline_zip_json_and_security_protections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VP_SQLITE_HMAC_KEY", "osv-hmac")
    ctx = _make_real_ctx(tmp_path)

    zip_path = tmp_path / "pypi_osv.zip"
    osv_adv = {
        "id": "PYSEC-2026-0042",
        "aliases": ["CVE-2026-4200", "GHSA-xxxx-yyyy-zzzz"],
        "summary": "OSV demo vulnerability",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "urllib-demo"}}],
        "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/PYSEC-2026-0042"}],
    }
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("PYSEC-2026-0042.json", json.dumps(osv_adv))

    osv = OSVEnrichmentSource(ctx)
    assert osv.load_offline(db_path=str(zip_path), target_cves={"CVE-2026-4200"}) is True
    cve_hits = osv.lookup_by_cve("CVE-2026-4200")
    assert len(cve_hits) == 1
    assert cve_hits[0]["cvss_provenance"] == "OSV"
    assert cve_hits[0]["cvss_score"] == 7.5
    assert len(osv.lookup_by_ghsa("GHSA-xxxx-yyyy-zzzz")) == 1
    assert len(osv.lookup_by_purl("pkg:pypi/urllib-demo@1.0.0")) == 1

    # Path-traversal zip rejected fail-closed
    evil_zip = tmp_path / "evil_traversal.zip"
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("../../etc/passwd.json", json.dumps(osv_adv))
    with pytest.raises(OSVSecurityError, match="traversal"):
        OSVEnrichmentSource(ctx).load_offline(db_path=str(evil_zip))

    # Zip-bomb size cap rejected fail-closed
    bomb_zip = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.json", json.dumps({"id": "PYSEC-BIG", "summary": "A" * 8192}))
    small_limit_osv = OSVEnrichmentSource(ctx, max_zip_entry_bytes=512)
    with pytest.raises(OSVSecurityError, match="exceeds"):
        small_limit_osv.load_offline(db_path=str(bomb_zip))


# ------------------------------------------------------------------
# 6. Handoff Preservation, Source Loader Offline Fix & DuckDB Snapshotter
# ------------------------------------------------------------------

def test_enrichment_handoff_preserves_all_services_and_v2_fields(tmp_path: Path) -> None:
    wh_cfg = WebhookRuntimeConfig(enabled=True, key_id="v2-key")
    nmap_cfg = {"port_tiebreak_enabled": False, "scoring_port_bonus": 1.25}
    global_cfg = {"version": "v2"}

    # Subclass Services dynamically to simulate v2 fields added in Wave 2A
    @dataclass(frozen=True)
    class V2Services(Services):
        db: str = "duckdb-handle"
        run_id: str = "run-abc"

    ctx = _make_real_ctx(tmp_path)
    v2_svc = V2Services(
        feed_cache=ctx.services.feed_cache,
        nmap_ctx_config=nmap_cfg,
        webhook_config=wh_cfg,
        global_config=global_cfg,
        db="duckdb-handle",
        run_id="run-abc",
    )
    ctx = RunContext(paths=ctx.paths, pfh=ctx.pfh, logger=ctx.logger, services=v2_svc)
    scan = _make_scan(["CVE-2026-0001"])

    out = EnrichmentHandoffBuilder.build(ctx, scan)
    assert out.ctx.services.post_enrichment_index is not None
    assert out.ctx.services.nmap_ctx_config == nmap_cfg
    assert out.ctx.services.webhook_config == wh_cfg
    assert out.ctx.services.global_config == global_cfg
    assert out.ctx.services.db == "duckdb-handle"  # type: ignore[attr-defined]
    assert out.ctx.services.run_id == "run-abc"  # type: ignore[attr-defined]


def test_source_loader_uses_args_offline_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _make_real_ctx(tmp_path)
    scan = _make_scan(["CVE-2026-1111"])
    seen: dict[str, bool] = {}

    class _RecordingNVD:
        def refresh(self, *, offline: bool, **_kwargs):
            seen["offline"] = offline

    plan = EnrichmentSourcePlan(
        kev_enabled=False,
        epss_enabled=False,
        exploit_enabled=False,
        nvd_enabled=True,
        kev_source="/tmp/kev_cache.json",
        epss_source="/tmp/epss_cache.csv",
        exploit_source=None,
        refresh_cache=False,
        allow_regen=False,
        offline=False,
    )
    EnrichmentSourceLoader.load_sources(
        ctx=ctx,
        scan=scan,
        cfg_yaml={"feed_cache": {"feeds": {"nvd": {"enabled": True}}}},
        nvd_cache=_RecordingNVD(),
        feed_cache=ctx.services.feed_cache,
        plan=plan,
        nvdpol_start_y=2024,
        nvdpol_end_y=2026,
        args=SimpleNamespace(offline=True),
    )
    assert seen["offline"] is True


def test_populate_enrichment_snapshots_duckdb(tmp_path: Path) -> None:
    ctx = _make_real_ctx(tmp_path)
    conn = duckdb.connect(str(tmp_path / "test.vpp.db"))
    conn.execute(
        """
        CREATE TABLE runs (
            run_id VARCHAR PRIMARY KEY,
            intel_metadata_json VARCHAR
        )
        """
    )
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
    conn.execute(
        """
        CREATE TABLE finding_cves (
            run_id VARCHAR,
            finding_id VARCHAR,
            cve_id VARCHAR
        )
        """
    )
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
    conn.execute(
        "INSERT INTO findings VALUES ('run-1', 'f1', 'CVE-2026-9001', 5.0, NULL, 'Demo', 'Not exploitable locally', '', 'pkg:pypi/urllib-demo@1.0.0')"
    )
    conn.execute("INSERT INTO finding_cves VALUES ('run-1', 'f1', 'CVE-2026-9001')")

    epss_csv = tmp_path / "epss_snap.csv"
    epss_csv.write_text(
        "#model_version:v2025.04.01,score_date:2026-11-24T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2026-9001,0.75,0.98\n"
        "CVE-2026-9999,0.10,0.20\n",
        encoding="utf-8",
    )
    epss_data = load_epss(ctx, path_url=str(epss_csv), force_refresh=False, allow_regen=True)

    kev_file = tmp_path / "kev_snap.json"
    kev_file.write_text(
        json.dumps(
            {
                "catalogVersion": "2026.11.24",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-9001",
                        "dateAdded": "2026-11-10",
                        "dueDate": "2026-11-24",
                        "knownRansomwareCampaignUse": "Known",
                        "requiredAction": "Patch immediately",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    kev_data = load_kev(ctx, str(kev_file), force_refresh=False, allow_regen=True)

    osv_json = tmp_path / "osv_snap.json"
    osv_json.write_text(
        json.dumps(
            {
                "id": "PYSEC-2026-9001",
                "aliases": ["CVE-2026-9001"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            }
        ),
        encoding="utf-8",
    )
    osv_src = OSVEnrichmentSource(ctx)
    assert osv_src.load_offline(db_path=str(osv_json)) is True

    summary = populate_enrichment_snapshots(
        conn,
        "run-1",
        ctx,
        {
            "epss_data": epss_data,
            "kev_data": kev_data,
            "osv_source": osv_src,
            "exploit_data": {},
        },
        target_cves=None,
    )
    assert summary["snapshots_written"] == 1

    rows = conn.execute(
        "SELECT cve_id, cvss_score, cvss_version, cvss_provenance, epss_score, epss_percentile, epss_model_version, in_kev, kev_ransomware, verified_exploit, heuristic_exploit_mention, osv_ids_json FROM enrichment_snapshots WHERE run_id = 'run-1'"
    ).fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == "CVE-2026-9001"
    assert row[1] == 9.8
    assert row[2] == "3.1"
    assert row[3] == "OSV"
    assert row[4] == pytest.approx(0.75)
    assert row[5] == pytest.approx(0.98)
    assert row[6] == "v2025.04.01"
    assert row[7] is True
    assert row[8] is True
    assert row[9] is False
    assert row[10] is False
    assert json.loads(row[11]) == ["PYSEC-2026-9001"]

    intel_meta_raw = conn.execute("SELECT intel_metadata_json FROM runs WHERE run_id = 'run-1'").fetchone()[0]
    intel_meta = json.loads(intel_meta_raw)
    assert intel_meta["epss_model_version"] == "v2025.04.01"
    assert intel_meta["kev_catalog_version"] == "2026.11.24"
    assert intel_meta["populated_cves"] == 1
    conn.close()
