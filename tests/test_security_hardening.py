from __future__ import annotations

import gzip
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vulnparse_pin.app.io_resolution import resolve_io_paths_and_modes
from vulnparse_pin.core.classes.dataclass import FeedCachePolicy, FeedSpec, RunContext, Services
from vulnparse_pin.utils.enricher import load_kev
from vulnparse_pin.utils.exploit_enrichment_service import load_exploit_data
from vulnparse_pin.utils.feed_cache import FeedCacheManager


class _PFH:
    def ensure_writable_file(self, path, label=None, create_parents=True, overwrite=False):
        p = Path(path)
        if create_parents:
            p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.touch()
        return p

    def ensure_readable_file(self, path, label=None):
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(str(path))
        return p

    def open_for_read(self, path, mode="r", **kwargs):
        return open(path, mode, encoding=kwargs.get("encoding", None))

    def open_for_write(self, path, mode="w", **kwargs):
        return open(path, mode, encoding=kwargs.get("encoding", None))

    def format_for_log(self, path):
        return str(path)


class _Paths:
    def __init__(self, cache_dir: Path, output_dir: Path):
        self.cache_dir = cache_dir
        self.nvd_feeds_dir = cache_dir / "nvd"
        self.output_dir = output_dir


class _RawStream:
    def __init__(self, payload: bytes):
        self._buffer = io.BytesIO(payload)
        self.decode_content = False

    def read(self, size=-1):
        return self._buffer.read(size)


class _FakeResp:
    def __init__(self, *, body: bytes, url: str, status_ok: bool = True, content_length: int | None = None):
        self.content = body
        self.url = url
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        self.raw = _RawStream(body)
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            raise RuntimeError("HTTP error")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _make_ctx(tmp_path: Path) -> RunContext:
    pfh = _PFH()
    logger = Mock()
    logger.print_info = Mock()
    logger.print_success = Mock()
    logger.print_warning = Mock()
    logger.exception = Mock()
    logger.success = Mock()
    logger.debug = Mock()

    specs = {
        "exploit_db": FeedSpec(key="exploit_db", filename="files_exploit.csv", label="Exploit-DB"),
        "kev": FeedSpec(key="kev", filename="kev_cache.json", label="CISA KEV"),
        "epss": FeedSpec(key="epss", filename="epss_cache.csv", label="EPSS"),
    }
    policy = FeedCachePolicy(default_ttl_hours=24, ttl_hours={"exploit_db": 24, "kev": 24, "epss": 24})
    paths = _Paths(tmp_path / "cache", tmp_path / "out")
    feed_cache = FeedCacheManager(
        cache_dir=paths.cache_dir,
        pfh=pfh,
        logger=logger,
        specs=specs,
        policy=policy,
        nvd_feeds_dir=paths.nvd_feeds_dir,
    )

    return RunContext(
        paths=paths,
        pfh=pfh,
        logger=logger,
        services=Services(feed_cache=feed_cache),
    )


def test_feed_cache_gunzip_enforces_max_decompressed_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _make_ctx(tmp_path)
    fc = ctx.services.feed_cache

    compressed = gzip.compress(b"A" * 128)

    def _fake_get(*args, **kwargs):
        return _FakeResp(body=compressed, url="https://example.com/epss.csv.gz")

    monkeypatch.setattr("vulnparse_pin.utils.feed_cache.requests.get", _fake_get)

    with pytest.raises(RuntimeError, match="Decompressed feed exceeds safety limit"):
        fc.write_atomic_stream_gunzip(
            "epss",
            source_url="https://example.com/epss.csv.gz",
            mode="Online",
            validated=False,
            checksum_src="Local",
            max_decompressed_bytes=32,
        )


def test_load_kev_rejects_https_downgrade_redirect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _make_ctx(tmp_path)
    kev_json = b'{"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}'

    def _fake_get(*args, **kwargs):
        return _FakeResp(body=kev_json, url="http://evil.test/kev.json", content_length=len(kev_json))

    monkeypatch.setattr("vulnparse_pin.utils.enricher.requests.get", _fake_get)

    with pytest.raises(RuntimeError, match="non-HTTPS"):
        load_kev(ctx, "https://example.com/kev.json", force_refresh=True, allow_regen=True)


def test_load_kev_rejects_oversized_response_by_content_length(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _make_ctx(tmp_path)
    kev_json = b'{"vulnerabilities": []}'

    def _fake_get(*args, **kwargs):
        return _FakeResp(body=kev_json, url="https://example.com/kev.json", content_length=300 * 1024 * 1024)

    monkeypatch.setattr("vulnparse_pin.utils.enricher.requests.get", _fake_get)

    with pytest.raises(RuntimeError, match="size limit"):
        load_kev(ctx, "https://example.com/kev.json", force_refresh=True, allow_regen=True)


def test_load_exploit_data_rejects_oversized_response_by_content_length(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _make_ctx(tmp_path)
    csv_body = b"id,description,date_published,type,platform,date_updated,verified,codes\n"

    def _fake_get(*args, **kwargs):
        return _FakeResp(body=csv_body, url="https://gitlab.com/exploit-database/exploitdb", content_length=300 * 1024 * 1024)

    monkeypatch.setattr("vulnparse_pin.utils.exploit_enrichment_service.requests.get", _fake_get)

    with pytest.raises(RuntimeError, match="size limit"):
        load_exploit_data(ctx, source="online", force_refresh=True, allow_regen=True)


def test_io_resolution_rejects_http_online_overrides(tmp_path: Path) -> None:
    scan = tmp_path / "scan.json"
    scan.write_text("{}", encoding="utf-8")

    ctx = _make_ctx(tmp_path)
    runtime = SimpleNamespace(paths=ctx.paths, pfh=ctx.pfh, ctx=ctx, logger=ctx.logger)

    args = SimpleNamespace(
        file=scan,
        output=None,
        output_csv=None,
        output_md=None,
        output_md_technical=None,
        output_runmanifest=None,
        no_csv_sanitize=False,
        no_exploit=True,
        exploit_source="online",
        exploit_db=None,
        no_kev=False,
        kev_source="online",
        kev_feed="http://example.com/kev.json",
        no_epss=False,
        epss_source="online",
        epss_feed="http://example.com/epss.csv.gz",
    )

    with pytest.raises(ValueError, match="--kev-source online requires an HTTPS URL override"):
        resolve_io_paths_and_modes(args, runtime, kev_feed="https://default/kev.json", epss_feed="https://default/epss.csv.gz")
