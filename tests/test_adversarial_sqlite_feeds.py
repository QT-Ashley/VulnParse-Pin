import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock

from vulnparse_pin.utils.nvdcacher import NVDFeedCache, nvd_policy_from_config


class _PFH:
    def ensure_writable_file(self, path, label=None, create_parents=True, overwrite=False):
        p = Path(path)
        if create_parents:
            p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and not overwrite:
            return p
        if not p.exists():
            p.touch()
        return p

    def open_for_read(self, path, mode="r", **kwargs):
        return open(path, mode, encoding=kwargs.get("encoding", None))

    def ensure_readable_file(self, path, label=None):
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(str(path))
        return p

    def open_for_write(self, path, mode="w", **kwargs):
        return open(path, mode, encoding=kwargs.get("encoding", None))

    def format_for_log(self, p):
        return str(p)


class _Paths:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir


def _make_ctx(tmp_path: Path, config=None):
    ctx = Mock()
    ctx.pfh = _PFH()
    ctx.paths = _Paths(tmp_path)
    ctx.config = config or {"feed_cache": {"feeds": {"nvd": {"enabled": True}}}}
    ctx.logger = Mock()
    return ctx


def test_sqlite_signature_detects_manual_tamper(tmp_path):
    ctx = _make_ctx(tmp_path)
    cache = NVDFeedCache(ctx)

    cache._sqlite_upsert([
        {"id": "CVE-2024-1111", "description": "ok", "cvss_score": 5.0, "cvss_vector": "CVSS:3.1/..."}
    ])
    assert cache._sqlite_verify_signature() is True

    with sqlite3.connect(cache._sqlite_path) as conn:
        conn.execute(
            "UPDATE nvd_records SET description = ? WHERE cve_id = ?",
            ("tampered", "CVE-2024-1111"),
        )

    assert cache._sqlite_verify_signature() is False


def test_sqlite_blocks_invalid_cve_and_injection(tmp_path):
    ctx = _make_ctx(tmp_path)
    cache = NVDFeedCache(ctx)

    assert cache._is_valid_cve_id("CVE-2024-1234") is True
    assert cache._is_valid_cve_id("'; DROP TABLE nvd_records; --") is False
    assert cache._sqlite_get_one("'; DROP TABLE nvd_records; --") is None


def test_sqlite_quarantines_and_recovers(tmp_path):
    ctx = _make_ctx(tmp_path)
    cache = NVDFeedCache(ctx)

    cache._sqlite_upsert([
        {"id": "CVE-2024-2222", "description": "ok"}
    ])

    with sqlite3.connect(cache._sqlite_path) as conn:
        conn.execute("DROP TABLE nvd_records")

    cache._sqlite_quarantine_and_reset()
    assert Path(cache._sqlite_path).exists()
    assert cache._sqlite_verify_signature() is True


def test_sqlite_prune_enforces_row_cap(tmp_path):
    cfg = {
        "feed_cache": {
            "feeds": {
                "nvd": {
                    "enabled": True,
                    "sqlite_max_rows": 2,
                    "sqlite_max_age_hours": 168,
                }
            }
        }
    }
    ctx = _make_ctx(tmp_path, cfg)
    cache = NVDFeedCache(ctx)

    cache._sqlite_upsert([
        {"id": "CVE-2024-0001", "description": "a"},
        {"id": "CVE-2024-0002", "description": "b"},
        {"id": "CVE-2024-0003", "description": "c"},
    ])

    with sqlite3.connect(cache._sqlite_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM nvd_records").fetchone()[0]
    assert count <= 2


def test_nvd_policy_handles_malicious_values_with_defaults():
    policy = nvd_policy_from_config(
        {
            "feed_cache": {
                "feeds": {
                    "nvd": {
                        "enabled": "true",
                        "ttl_yearly": "not-int",
                        "ttl_modified": "bad",
                        "start_year": "../../etc/passwd",
                        "end_year": "$(whoami)",
                    }
                },
                "defaults": {"ttl_hours": 24},
            }
        }
    )

    assert isinstance(policy["enabled"], bool)
    assert isinstance(policy["ttl_yearly"], int)
    assert isinstance(policy["ttl_modified"], int)
    assert isinstance(policy["start_year"], int)
    assert isinstance(policy["end_year"], int)
