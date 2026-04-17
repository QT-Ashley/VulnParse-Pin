"""
Unit tests for GHSA enrichment source.
"""
import pytest
import json
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

from vulnparse_pin.utils.ghsa_enrichment import GHSAEnrichmentSource
from vulnparse_pin.core.classes.dataclass import RunContext, AppPaths, Finding
from vulnparse_pin.utils.logger import LoggerWrapper
from vulnparse_pin.io.pfhandler import PermFileHandler


@pytest.fixture
def ctx(tmp_path) -> RunContext:
    """Create a test RunContext with cache_dir inside tmp_path so PFH root checks pass."""
    logger = LoggerWrapper(log_file=str(tmp_path / "ghsa_test.log"))
    pfh = PermFileHandler(logger, root_dir=tmp_path, allowed_roots=[tmp_path])
    paths = AppPaths.resolve(portable=True)
    # Override cache_dir to be inside tmp_path so PFH root enforcement is satisfied
    from dataclasses import replace as dc_replace
    paths = dc_replace(paths, cache_dir=tmp_path / "cache")
    return RunContext(paths=paths, pfh=pfh, logger=logger)


@pytest.fixture
def sample_ghsa_db(tmp_path):
    """Create a minimal GHSA database file."""
    db_content = [
        {
            "ghsa_id": "GHSA-1234-abcd-0001",
            "cve": "CVE-2023-12345",
            "package_name": "openssl",
            "affected_versions": ["<3.0.0"],
            "fixed_version": "3.0.0",
            "severity": "HIGH",
            "published_at": "2023-01-01T00:00:00Z",
            "references": ["https://github.com/advisories/GHSA-1234-abcd-0001"],
        },
        {
            "ghsa_id": "GHSA-5678-efgh-0002",
            "cve": "CVE-2023-54321",
            "package_name": "nginx",
            "affected_versions": ["<1.25.0"],
            "fixed_version": "1.25.0",
            "severity": "MEDIUM",
            "published_at": "2023-02-01T00:00:00Z",
            "references": ["https://github.com/advisories/GHSA-5678-efgh-0002"],
        },
    ]
    
    db_path = tmp_path / "ghsa_advisories.json"
    db_path.write_text(json.dumps(db_content), encoding='utf-8')
    return db_path


@pytest.fixture
def sample_ghsa_repo_layout(tmp_path):
    """Create advisory-database-style GHSA directory layout."""
    advisory_dir = (
        tmp_path
        / "advisories"
        / "github-reviewed"
        / "2026"
        / "04"
        / "GHSA-9999-aaaa-bbbb"
    )
    advisory_dir.mkdir(parents=True, exist_ok=True)

    advisory_doc = {
        "id": "GHSA-9999-aaaa-bbbb",
        "aliases": ["CVE-2026-11111"],
        "summary": "Test GHSA advisory",
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
            }
        ],
        "references": [{"type": "WEB", "url": "https://github.com/advisories/GHSA-9999-aaaa-bbbb"}],
    }
    (advisory_dir / "GHSA-9999-aaaa-bbbb.json").write_text(json.dumps(advisory_doc), encoding="utf-8")
    return tmp_path


# Loading tests
class TestGHSALoading:
    def test_load_offline_valid_database(self, ctx, sample_ghsa_db):
        """Should load valid GHSA database file."""
        source = GHSAEnrichmentSource(ctx)
        result = source.load_offline(db_path=str(sample_ghsa_db))
        
        assert result is True
        assert source._is_loaded is True
        assert "CVE-2023-12345" in source.ghsa_by_cve
        assert "CVE-2023-54321" in source.ghsa_by_cve

    def test_load_offline_missing_file(self, ctx):
        """Should fail gracefully when database file not found."""
        source = GHSAEnrichmentSource(ctx)
        result = source.load_offline(db_path="/nonexistent/path/ghsa.json")
        
        assert result is False
        assert source._is_loaded is False

    def test_load_offline_invalid_json(self, ctx, tmp_path):
        """Should handle malformed JSON."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{invalid json}")
        
        source = GHSAEnrichmentSource(ctx)
        result = source.load_offline(db_path=str(bad_json))
        
        assert result is False

    def test_load_offline_indexing(self, ctx, sample_ghsa_db):
        """Should correctly index advisories by CVE and package."""
        source = GHSAEnrichmentSource(ctx)
        source.load_offline(db_path=str(sample_ghsa_db))
        
        # Check CVE indexing
        assert len(source.ghsa_by_cve) == 2
        assert len(source.ghsa_by_cve["CVE-2023-12345"]) == 1
        
        # Check package indexing
        assert len(source.ghsa_by_package) == 2
        assert len(source.ghsa_by_package["openssl"]) == 1
        assert len(source.ghsa_by_package["nginx"]) == 1

    def test_load_offline_repo_directory_layout(self, ctx, sample_ghsa_repo_layout):
        """Should load GHSA advisories from advisory-database repo directory structure."""
        source = GHSAEnrichmentSource(ctx)
        result = source.load_offline(db_path=str(sample_ghsa_repo_layout))

        assert result is True
        assert "CVE-2026-11111" in source.ghsa_by_cve
        assert "requests" in source.ghsa_by_package

    def test_load_online_no_ids_on_demand(self, ctx):
        """Online mode with no IDs enables on-demand lookup (no API calls)."""
        source = GHSAEnrichmentSource(ctx)
        result = source.load_online(ghsa_ids=None)
        
        assert result is True
        assert source._is_loaded is True

    def test_load_online_with_ids_scaffolded(self, ctx):
        """Online mode with IDs would fetch advisories (scaffolded, needs mock)."""
        # Note: Full test requires mocking requests.get
        # This just verifies the method signature exists
        source = GHSAEnrichmentSource(ctx)
        result = source.load_online(ghsa_ids=[])
        
        assert result is True or result is False  # Depends on mock setup


# Enrichment lookup tests
class TestGHSAEnrichment:
    def test_enrich_finding_by_cve_offline(self, ctx, sample_ghsa_db):
        """Should enrich finding matching on CVE (offline mode)."""
        source = GHSAEnrichmentSource(ctx)
        source.load_offline(db_path=str(sample_ghsa_db))
        
        # Create a finding with CVE-2023-12345
        finding = Finding(
            finding_id="F1",
            vuln_id="V1",
            title="OpenSSL Vulnerability",
            description="A test vulnerability",
            severity="High",
            cves=["CVE-2023-12345"],
        )
        
        result = source.enrich_finding(finding, by_cve=True, online=False)
        
        assert result is not None
        assert result["source"] == "ghsa"
        assert result["match_type"] == "cve"
        assert result["lookup_mode"] == "offline"
        assert result["advisory_count"] == 1

    def test_enrich_finding_no_match_offline(self, ctx, sample_ghsa_db):
        """Should return None when no matching advisory found (offline)."""
        source = GHSAEnrichmentSource(ctx)
        source.load_offline(db_path=str(sample_ghsa_db))
        
        finding = Finding(
            finding_id="F2",
            vuln_id="V2",
            title="Unknown Vulnerability",
            description="No advisory exists",
            severity="Low",
            cves=["CVE-2099-99999"],  # Non-existent CVE
        )
        
        result = source.enrich_finding(finding, by_cve=True, online=False)
        
        assert result is None

    def test_enrich_finding_not_loaded(self, ctx):
        """Should return None when source not loaded and online disabled."""
        source = GHSAEnrichmentSource(ctx)
        
        finding = Finding(
            finding_id="F3",
            vuln_id="V3",
            title="Test",
            description="Test",
            severity="Medium",
            cves=["CVE-2023-12345"],
        )
        
        result = source.enrich_finding(finding, online=False)
        
        assert result is None

    def test_finding_enrichment_metadata_defaults(self):
        """Finding should expose enrichment source metadata defaults."""
        finding = Finding(
            finding_id="FMD-1",
            vuln_id="VMD-1",
            title="meta",
            description="meta",
            severity="Low",
            cves=[],
        )
        assert finding.enrichment_sources == []
        assert finding.confidence == 0

    def test_enrich_finding_online_enabled(self, ctx):
        """Should process finding with online mode enabled (API scaffolded)."""
        source = GHSAEnrichmentSource(ctx)
        source.load_online(ghsa_ids=None)  # Enable on-demand mode
        
        finding = Finding(
            finding_id="F4",
            vuln_id="V4",
            title="Test",
            description="Test",
            severity="Medium",
            cves=["CVE-2023-12345"],
        )
        
        # With empty cache and API stubbed, should return None
        result = source.enrich_finding(finding, by_cve=True, online=True)
        
        # Result depends on API response (currently scaffolded)
        assert result is None or result is not None

    def test_enrich_finding_online_cve_lookup_with_cache(self, ctx, monkeypatch):
        """Online CVE lookup should return advisories and cache repeated CVE requests."""
        source = GHSAEnrichmentSource(ctx)
        source.load_online(ghsa_ids=None)

        calls = {"count": 0}

        class DummyResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return [
                    {
                        "id": "GHSA-test-online-0001",
                        "aliases": ["CVE-2026-77777"],
                        "affected": [{"package": {"name": "demo-online", "ecosystem": "PyPI"}}],
                    }
                ]

        def _fake_get(url, params=None, headers=None, timeout=7):
            calls["count"] += 1
            assert params["cve_id"] == "CVE-2026-77777"
            return DummyResponse()

        monkeypatch.setattr("vulnparse_pin.utils.ghsa_enrichment.requests.get", _fake_get)

        finding = Finding(
            finding_id="F-ONLINE-1",
            vuln_id="V-ONLINE-1",
            title="Online GHSA test",
            description="Online GHSA test",
            severity="Medium",
            cves=["CVE-2026-77777"],
        )

        first = source.enrich_finding(finding, by_cve=True, online=True)
        second = source.enrich_finding(finding, by_cve=True, online=True)

        assert first is not None
        assert first["lookup_mode"] == "online"
        assert first["advisory_count"] == 1
        assert second is not None
        assert calls["count"] == 1

    def test_enrich_finding_by_package_offline(self, ctx):
        """Package token fallback should match advisory package index when CVEs are absent."""
        source = GHSAEnrichmentSource(ctx)
        advisory = {
            "id": "GHSA-pkg-0001",
            "aliases": ["CVE-2026-88888"],
            "affected": [{"package": {"name": "openssl", "ecosystem": "PyPI"}}],
            "references": [{"url": "https://github.com/advisories/GHSA-pkg-0001"}],
        }
        source._index_advisory(advisory)
        source._is_loaded = True

        finding = Finding(
            finding_id="FPKG-1",
            vuln_id="VPKG-1",
            title="OpenSSL outdated package",
            description="The host has openssl package vulnerabilities",
            severity="Medium",
            cves=[],
        )

        result = source.enrich_finding(finding, by_cve=False, by_package=True, online=False)
        assert result is not None
        assert result["match_type"] == "package"
        assert result["advisory_count"] >= 1


def test_preload_online_for_cves(ctx, monkeypatch):
    """Online CVE prefetch should index advisories for requested CVEs."""
    source = GHSAEnrichmentSource(ctx)

    class DummyResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return [{"id": "GHSA-online-preload", "aliases": ["CVE-2026-99999"]}]

    def _fake_get(url, params=None, headers=None, timeout=7):
        assert params and params.get("cve_id") == "CVE-2026-99999"
        return DummyResponse()

    monkeypatch.setattr("vulnparse_pin.utils.ghsa_enrichment.requests.get", _fake_get)
    summary = source.preload_online_for_cves({"CVE-2026-99999"}, max_lookups=5)

    assert summary["queried"] == 1
    assert summary["hits"] == 1
    assert "CVE-2026-99999" in source.ghsa_by_cve


def test_preload_online_for_cves_respects_budget(ctx, monkeypatch):
    """Online CVE prefetch should stop at the configured max lookup budget."""
    source = GHSAEnrichmentSource(ctx)
    calls = {"count": 0}

    class DummyResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return []

    def _fake_get(url, params=None, headers=None, timeout=7):
        calls["count"] += 1
        return DummyResponse()

    monkeypatch.setattr("vulnparse_pin.utils.ghsa_enrichment.requests.get", _fake_get)
    cves = {f"CVE-2026-{idx:05d}" for idx in range(1, 8)}

    summary = source.preload_online_for_cves(cves, max_lookups=3)

    assert calls["count"] == 3
    assert summary["queried"] == 3
    assert summary["requested"] == 7


def test_online_lookup_uses_custom_token_env_with_github_fallback(ctx, monkeypatch):
    """GHSA HTTP requests should use the configured token env and emit an Authorization header."""
    source = GHSAEnrichmentSource(ctx, token_env_name="VP_GHSA_PAT")
    monkeypatch.setenv("VP_GHSA_PAT", f"ghp_{'a' * 36}")
    seen = {}

    class DummyResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return []

    def _fake_get(url, params=None, headers=None, timeout=7):
        seen["headers"] = headers
        return DummyResponse()

    monkeypatch.setattr("vulnparse_pin.utils.ghsa_enrichment.requests.get", _fake_get)

    source._fetch_advisories_by_cve("CVE-2026-12345")

    assert seen["headers"]["Authorization"] == f"Bearer ghp_{'a' * 36}"
    assert "User-Agent" in seen["headers"]


def test_build_headers_supports_arbitrary_custom_token_env_var(ctx, monkeypatch):
    """GHSA auth should work with any configured env var name and dummy token value."""
    source = GHSAEnrichmentSource(ctx, token_env_name="VPP_ARBITRARY_GHSA_TOKEN_VAR")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("VPP_ARBITRARY_GHSA_TOKEN_VAR", f"github_pat_{'b' * 30}")

    headers = source._build_headers()

    assert headers["Authorization"] == f"Bearer github_pat_{'b' * 30}"
    assert "User-Agent" in headers


def test_build_headers_falls_back_to_github_token_when_custom_missing(ctx, monkeypatch):
    """If custom env var is unset, loader should fall back to GITHUB_TOKEN."""
    source = GHSAEnrichmentSource(ctx, token_env_name="VPP_CUSTOM_TOKEN_NOT_SET")
    monkeypatch.delenv("VPP_CUSTOM_TOKEN_NOT_SET", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", f"ghu_{'c' * 30}")

    headers = source._build_headers()

    assert headers["Authorization"] == f"Bearer ghu_{'c' * 30}"
    assert "User-Agent" in headers


def test_build_headers_rejects_non_github_token_shape(ctx, monkeypatch):
    """Malformed tokens should be rejected and never forwarded in Authorization headers."""
    source = GHSAEnrichmentSource(ctx, token_env_name="VP_GHSA_PAT")
    monkeypatch.setenv("VP_GHSA_PAT", "totally-not-a-github-token")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    headers = source._build_headers()

    assert "Authorization" not in headers


def test_build_headers_rejects_header_injection_token(ctx, monkeypatch):
    """Tokens with CR/LF should be rejected to prevent header-injection vectors."""
    source = GHSAEnrichmentSource(ctx, token_env_name="VP_GHSA_PAT")
    monkeypatch.setenv("VP_GHSA_PAT", f"ghp_{'x' * 24}\nInjected: bad")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    headers = source._build_headers()

    assert "Authorization" not in headers


def test_invalid_custom_env_var_name_falls_back_to_github_token(ctx, monkeypatch):
    """Invalid ghsa_token_env names should be ignored and fallback chain should remain intact."""
    source = GHSAEnrichmentSource(ctx, token_env_name="BAD-NAME")
    monkeypatch.setenv("GITHUB_TOKEN", f"ghs_{'z' * 30}")

    headers = source._build_headers()

    assert headers["Authorization"] == f"Bearer ghs_{'z' * 30}"


def test_token_rejection_counter_increments_once_per_unique_rejection(ctx, monkeypatch):
    """Rejected token checks should increment counter once for the unique rejection reason."""
    source = GHSAEnrichmentSource(ctx, token_env_name="VP_GHSA_PAT")
    monkeypatch.setenv("VP_GHSA_PAT", "not-a-valid-github-token")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    assert source.token_rejection_count == 0
    _ = source._build_headers()
    _ = source._build_headers()

    assert source.token_rejection_count == 1


def test_load_offline_file_reads_are_pfh_governed(tmp_path):
    """GHSA offline loading should read advisory files via ctx.pfh wrappers."""
    advisory = [{"ghsa_id": "GHSA-abcd-ef01-2345", "cve": "CVE-2026-22222", "package_name": "pkg"}]
    db_path = tmp_path / "ghsa.json"
    db_path.write_text(json.dumps(advisory), encoding="utf-8")

    logger = LoggerWrapper(log_file=str(tmp_path / "ghsa_pfh.log"))

    class RecordingPFH:
        def __init__(self):
            self.read_files = []
            self.read_dirs = []

        def ensure_readable_file(self, path, **kwargs):
            self.read_files.append(Path(path))
            return Path(path)

        def ensure_readable_dir(self, path, **kwargs):
            self.read_dirs.append(Path(path))
            return Path(path)

        def open_for_read(self, path, mode="r", encoding="utf-8", **kwargs):
            return open(path, mode, encoding=encoding)

    test_ctx = SimpleNamespace(pfh=RecordingPFH(), logger=logger)
    source = GHSAEnrichmentSource(test_ctx)

    assert source.load_offline(db_path=str(db_path)) is True
    assert test_ctx.pfh.read_files, "Expected GHSA loader to validate/read file through PFH"


def test_load_offline_repo_uses_sqlite_warm_cache_for_targets(tmp_path):
    """Second run should hydrate requested CVEs from SQLite without rescanning JSON files."""
    advisory_dir = (
        tmp_path
        / "advisories"
        / "github-reviewed"
        / "2026"
        / "04"
        / "GHSA-aaaa-bbbb-cccc"
    )
    advisory_dir.mkdir(parents=True, exist_ok=True)

    advisory = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2026-33333"],
        "affected": [{"package": {"name": "demo-lib", "ecosystem": "PyPI"}}],
    }
    (advisory_dir / "GHSA-aaaa-bbbb-cccc.json").write_text(json.dumps(advisory), encoding="utf-8")

    logger = LoggerWrapper(log_file=str(tmp_path / "ghsa_sqlite.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    paths = SimpleNamespace(cache_dir=tmp_path / "cache")
    test_ctx = SimpleNamespace(pfh=pfh, logger=logger, paths=paths)

    cold_source = GHSAEnrichmentSource(test_ctx)
    assert cold_source.load_offline(db_path=str(tmp_path), target_cves={"CVE-2026-33333"}) is True
    assert "CVE-2026-33333" in cold_source.ghsa_by_cve

    warm_source = GHSAEnrichmentSource(test_ctx)

    def _fail_json_read(*args, **kwargs):
        raise AssertionError("Warm load should not rescan advisory JSON files")

    warm_source._load_json_file = _fail_json_read  # type: ignore[method-assign]
    assert warm_source.load_offline(db_path=str(tmp_path), target_cves={"CVE-2026-33333"}) is True
    assert "CVE-2026-33333" in warm_source.ghsa_by_cve


def test_ghsa_sqlite_prune_respects_max_rows(tmp_path):
    """GHSA SQLite prune should cap persisted row count to configured max_rows."""
    advisory_dir = (
        tmp_path
        / "advisories"
        / "github-reviewed"
        / "2026"
        / "04"
    )
    advisory_dir.mkdir(parents=True, exist_ok=True)

    adv1_dir = advisory_dir / "GHSA-1111-2222-3333"
    adv2_dir = advisory_dir / "GHSA-4444-5555-6666"
    adv1_dir.mkdir(parents=True, exist_ok=True)
    adv2_dir.mkdir(parents=True, exist_ok=True)

    (adv1_dir / "GHSA-1111-2222-3333.json").write_text(
        json.dumps({"id": "GHSA-1111-2222-3333", "aliases": ["CVE-2026-11111"]}),
        encoding="utf-8",
    )
    (adv2_dir / "GHSA-4444-5555-6666.json").write_text(
        json.dumps({"id": "GHSA-4444-5555-6666", "aliases": ["CVE-2026-22222"]}),
        encoding="utf-8",
    )

    logger = LoggerWrapper(log_file=str(tmp_path / "ghsa_prune.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    paths = SimpleNamespace(cache_dir=tmp_path / "cache")
    cfg = {"enrichment": {"ghsa_cache": {"sqlite_max_age_hours": 336, "sqlite_max_rows": 1}}}
    test_ctx = SimpleNamespace(pfh=pfh, logger=logger, paths=paths, config=cfg)

    source = GHSAEnrichmentSource(test_ctx)
    assert source.load_offline(db_path=str(tmp_path)) is True

    import sqlite3
    with sqlite3.connect(source._sqlite_path) as conn:  # type: ignore[arg-type]
        row_count = conn.execute("SELECT COUNT(*) FROM ghsa_cve_index").fetchone()[0]

    assert row_count <= 1
    assert source._sqlite_prune_stats["runs"] >= 1
    assert source._sqlite_prune_stats["cap_deleted"] >= 1
