# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

import json
import gzip
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from vulnparse_pin.utils.nvdcacher import NVDFeedCache, nvd_policy_from_config
from vulnparse_pin.utils.logger import LoggerWrapper


def make_logger(tmp_path):
    return LoggerWrapper(log_file=str(tmp_path / "nvd_test.log"))


def make_mock_ctx(tmp_path):
    """Create a minimal mock context with PFH."""
    logger = make_logger(tmp_path)
    
    class MockPFH:
        def open_for_read(self, path, mode="r", label=None, **kwargs):
            # ignore label/log flags for simplicity
            return open(path, mode)
    
    ctx = Mock()
    ctx.logger = logger
    ctx.pfh = MockPFH()
    return ctx


def test_nvd_cache_accepts_target_cves_parameter(tmp_path):
    """Verify NVDFeedCache.refresh() accepts target_cves parameter without error."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    
    # Verify the attribute can be set
    cache.target_cves = {"CVE-2023-1234"}
    assert cache.target_cves == {"CVE-2023-1234"}
    
    # Verify refresh() signature accepts the parameter (won't fail on signature mismatch)
    import inspect
    sig = inspect.signature(cache.refresh)
    assert "target_cves" in sig.parameters


def test_nvd_cache_target_cves_stored(tmp_path):
    """Verify target_cves is stored in cache instance."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    
    target = {"CVE-2023-1234", "CVE-2023-5678"}
    cache.target_cves = target
    
    assert cache.target_cves == target


def test_parse_feed_with_target_cves_filters(tmp_path):
    """Verify _parse_feed skips CVEs not in target_cves."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    
    # Create a sample NVD JSON file
    nvd_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1111",
                    "descriptions": [{"value": "Description 1"}],
                    "published": "2023-01-01",
                    "lastModified": "2023-01-02",
                    "metrics": {"cvssMetricV31": [
                        {"type": "Primary", "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/..."}}
                    ]},
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-2222",
                    "descriptions": [{"value": "Description 2"}],
                    "published": "2023-02-01",
                    "lastModified": "2023-02-02",
                    "metrics": {},
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-3333",
                    "descriptions": [{"value": "Description 3"}],
                    "published": "2023-03-01",
                    "lastModified": "2023-03-02",
                    "metrics": {},
                }
            },
        ]
    }
    
    # Write as gzipped JSON
    temp_file = tmp_path / "test_nvd.json.gz"
    with gzip.open(temp_file, "wt", encoding="utf-8") as f:
        json.dump(nvd_data, f)
    
    # Set target to only include first and last CVE
    cache.target_cves = {"CVE-2023-1111", "CVE-2023-3333"}
    
    # Parse
    cache._parse_feed(str(temp_file))
    
    # Verify only target CVEs were indexed
    assert "CVE-2023-1111" in cache.lookup
    assert "CVE-2023-3333" in cache.lookup
    assert "CVE-2023-2222" not in cache.lookup  # Should be skipped
    assert len(cache.lookup) == 2


def test_parse_feed_without_target_cves_indexes_all(tmp_path):
    """Verify _parse_feed indexes all CVEs when target_cves is None."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    
    # Create a sample NVD JSON file
    nvd_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1111",
                    "descriptions": [{"value": "Description 1"}],
                    "published": "2023-01-01",
                    "lastModified": "2023-01-02",
                    "metrics": {},
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-2222",
                    "descriptions": [{"value": "Description 2"}],
                    "published": "2023-02-01",
                    "lastModified": "2023-02-02",
                    "metrics": {},
                }
            },
        ]
    }
    
    # Write as gzipped JSON
    temp_file = tmp_path / "test_nvd.json.gz"
    with gzip.open(temp_file, "wt", encoding="utf-8") as f:
        json.dump(nvd_data, f)
    
    # target_cves is None (default)
    cache.target_cves = None
    
    # Parse
    cache._parse_feed(str(temp_file))
    
    # Verify all CVEs were indexed
    assert "CVE-2023-1111" in cache.lookup
    assert "CVE-2023-2222" in cache.lookup
    assert len(cache.lookup) == 2


def test_parse_feed_uses_ijson_streaming(tmp_path):
    """Verify _parse_feed uses ijson.items for streaming when available."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    
    nvd_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1111",
                    "descriptions": [],
                    "metrics": {},
                }
            }
        ]
    }
    
    temp_file = tmp_path / "test_nvd.json.gz"
    with gzip.open(temp_file, "wt", encoding="utf-8") as f:
        json.dump(nvd_data, f)
    
    # Patch ijson to verify it gets called
    with patch("vulnparse_pin.utils.nvdcacher.ijson") as mock_ijson:
        mock_ijson.items = Mock(return_value=[nvd_data["vulnerabilities"][0]])
        cache._parse_feed(str(temp_file))
        
        # ijson.items should have been called
        mock_ijson.items.assert_called_once()


def test_parse_feed_early_exit_uses_remaining(tmp_path):
    """Ensure parsing stops early once all target CVEs in a year file are found."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)

    cache.target_cves = {"CVE-2023-1111"}

    # create a counting generator to observe consumption
    class CountingGen:
        def __init__(self):
            self.count = 0
        def __iter__(self):
            return self
        def __next__(self):
            self.count += 1
            if self.count > 10000:
                raise StopIteration
            # return the target CVE on the 5th item, otherwise a filler ID
            return {"cve": {"id": "CVE-2023-1111" if self.count == 5 else "CVE-2023-9999"}}

    gen = CountingGen()

    # create a dummy gz file so PFH.open_for_read doesn't fail
    temp_file = tmp_path / "year.2023.json.gz"
    with gzip.open(temp_file, "wt", encoding="utf-8") as f:
        f.write("{}")

    with patch("vulnparse_pin.utils.nvdcacher.ijson") as mock_ijson:
        mock_ijson.items = Mock(return_value=gen)
        cache._parse_feed(str(temp_file))
        assert "CVE-2023-1111" in cache.lookup
        # early exit should prevent iterating all 10k elements
        assert gen.count < 10000


def test_parse_feed_skips_year_with_no_targets(tmp_path):
    """If no scan CVEs correspond to a specific year, the feed should be skipped entirely."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)
    cache.target_cves = {"CVE-2023-1111"}

    # create a dummy gz file so PFH.open_for_read succeeds
    temp_file = tmp_path / "year.2022.json.gz"
    with gzip.open(temp_file, "wt", encoding="utf-8") as f:
        f.write("{}")

    with patch("vulnparse_pin.utils.nvdcacher.ijson") as mock_ijson:
        # generator that would raise if iterated at all
        def bad_gen():
            raise RuntimeError("Iteration should not occur when there are no targets for this year")
            yield None
        mock_ijson.items = Mock(return_value=bad_gen())

        # feed path indicates year 2022, which is not in target set
        cache._parse_feed(str(temp_file))
        assert cache.lookup == {}  # nothing was indexed


def test_refresh_combines_multiple_feeds(tmp_path, monkeypatch):
    """refresh() should walk all resolved feed paths and merge their entries."""
    ctx = make_mock_ctx(tmp_path)
    cache = NVDFeedCache(ctx)

    # prepare two gz feeds containing distinct CVEs
    feed1 = tmp_path / "f1.json.gz"
    feed2 = tmp_path / "f2.json.gz"
    data1 = {"vulnerabilities": [{"cve": {"id": "CVE-2019-0001", "descriptions": [], "metrics": {}}}]}
    data2 = {"vulnerabilities": [{"cve": {"id": "CVE-2020-0002", "descriptions": [], "metrics": {}}}]}
    with gzip.open(feed1, "wt", encoding="utf-8") as f:
        json.dump(data1, f)
    with gzip.open(feed2, "wt", encoding="utf-8") as f:
        json.dump(data2, f)

    # Make feed plan return two entries
    monkeypatch.setattr(
        "vulnparse_pin.utils.nvdcacher.nvd_feed_plan",
        lambda config: [{"key": "a", "fname": "f1", "ttl_hours": 1},
                        {"key": "b", "fname": "f2", "ttl_hours": 1}],
    )

    class DummyCache:
        def resolve_nvd_feed(self, key, ttl_hours, refresh_cache, offline):
            return str(feed1) if key == "a" else str(feed2)

    # Run refresh with targets covering both CVEs
    cache.target_cves = {"CVE-2019-0001", "CVE-2020-0002"}
    cache.refresh(config={}, feed_cache=DummyCache(), refresh_cache=False, offline=True, years=None, include_modified=False)

    # Both CVEs should be indexed
    assert "CVE-2019-0001" in cache.lookup
    assert "CVE-2020-0002" in cache.lookup


def test_nvd_policy_prefers_centralized_nvd_ttl_keys():
    cfg = {
        "feed_cache": {
            "defaults": {"ttl_hours": 24},
            "ttl_hours": {"nvd_yearly": 10, "nvd_modified": 1},
            "nvd": {
                "enabled": True,
                "ttl_yearly": 30,
                "ttl_modified": 4,
                "start_year": 2021,
                "end_year": 2025,
            },
        }
    }

    policy = nvd_policy_from_config(cfg)
    assert policy["ttl_yearly"] == 30
    assert policy["ttl_modified"] == 4

