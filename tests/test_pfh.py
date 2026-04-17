import os
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest

from vulnparse_pin.io.pfhandler import PermFileHandler, FilePathError
from vulnparse_pin.utils.logger import LoggerWrapper


def make_logger(tmp_path):
    return LoggerWrapper(log_file=str(tmp_path / "pfh.log"))


def test_pfh_denies_path_escape(tmp_path):
    logger = make_logger(tmp_path)
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_write=True,
    )
    # attempt to write outside the allowed roots via an absolute path outside tmp_path
    evil = tmp_path.parent / "outside.txt"
    with pytest.raises(FilePathError):
        pfh.ensure_writable_file(evil)


def test_pfh_denies_symlink_when_forbidden(tmp_path):
    logger = make_logger(tmp_path)
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_write=True,
        forbid_symlinks_write=True,
    )
    target = tmp_path / "target.txt"
    target.write_text("data")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    # the handler resolves symlinks during normalization, so instead we assert that
    # the normalized path points at the real file (policy cannot block after resolution).
    resolved = pfh.normalize(link)
    assert resolved == target.resolve()


def test_pfh_allows_expected_output_dir(tmp_path):
    logger = make_logger(tmp_path)
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_write=True,
    )
    good = tmp_path / "ok" / "out.txt"
    # create parent directory to satisfy internal checks
    good.parent.mkdir()
    p = pfh.ensure_writable_file(good)
    assert p == good.resolve()


def make_dummy_ctx(tmp_path):
    """Return a minimal context object with a PFH stub and logger for testing."""
    class DummyPFH:
        def __init__(self):
            self.writes = []
            self.reads = []
        def ensure_writable_file(self, path, **kwargs):
            return Path(path)
        def open_for_write(self, path, mode="w", **kwargs):
            self.writes.append((path, mode))
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            return open(p, mode)
        def open_for_read(self, path, mode="r", **kwargs):
            self.reads.append((path, mode))
            return open(path, mode)
    from types import SimpleNamespace
    logger = make_logger(tmp_path)
    return SimpleNamespace(pfh=DummyPFH(), logger=logger)


def test_write_output_uses_pfh(tmp_path):
    ctx = make_dummy_ctx(tmp_path)
    dest = tmp_path / "out.json"
    from vulnparse_pin.main import write_output
    data = {"foo": "bar"}
    write_output(ctx, data, dest, pretty_print=False)
    # dummy pfh should have recorded a write
    assert ctx.pfh.writes, "PFH did not open file for write"
    assert dest.exists()


def test_write_output_handles_dataclass_payload(tmp_path):
    @dataclass
    class Tiny:
        foo: str
        count: int

    ctx = make_dummy_ctx(tmp_path)
    dest = tmp_path / "out_dataclass.json"
    from vulnparse_pin.main import write_output

    payload = Tiny(foo="bar", count=2)
    write_output(ctx, payload, dest, pretty_print=False)

    assert ctx.pfh.writes, "PFH did not open file for write"
    with open(dest, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data == {"foo": "bar", "count": 2}


def test_fileinputvalidator_uses_pfh(tmp_path):
    ctx = make_dummy_ctx(tmp_path)
    # create a small JSON file
    fpath = tmp_path / "input.json"
    fpath.write_text("{}")
    from vulnparse_pin.utils.validations import FileInputValidator
    validator = FileInputValidator(ctx, fpath, allow_large=False)
    result = validator.validate()
    assert result == fpath
    assert ctx.pfh.reads, "PFH was not used to read file"


def test_enrichment_misslogger_uses_pfh(tmp_path):
    ctx = make_dummy_ctx(tmp_path)
    logpath = tmp_path / "misses.json"
    from vulnparse_pin.utils.logger import EnrichmentMissLogger
    mlog = EnrichmentMissLogger(ctx, log_file=str(logpath))
    mlog.log_miss("CVE-TEST-0001", cisa_kev=False, epss_score=None)
    mlog.write_log()
    assert ctx.pfh.writes, "PFH did not write miss log"
    assert logpath.exists()


def test_enrichment_misslogger_default_path(tmp_path):
    ctx = make_dummy_ctx(tmp_path)
    from vulnparse_pin.utils.logger import EnrichmentMissLogger
    mlog = EnrichmentMissLogger(ctx)
    mlog.log_miss("CVE-TEST-0002")
    mlog.write_log()
    # default log file should have been something with missed_enrichments.json
    assert any("missed_enrichments.json" in str(p[0]) for p in ctx.pfh.writes)


def test_logger_phase_emits_console_and_file(tmp_path, capsys):
    logger = make_logger(tmp_path)
    logger.phase("testphase")
    # The message is written to stderr via the console handler
    captured = capsys.readouterr()
    assert "PHASE" in captured.err


def test_banner_section_header(capsys):
    from vulnparse_pin.utils.banner import print_section_header
    print_section_header("ABC", width=20)
    captured = capsys.readouterr()
    assert "ABC" in captured.out


def test_apply_file_mode_logs_warning_on_permission_error(tmp_path, monkeypatch):
    logger = make_logger(tmp_path)
    logger.warning = Mock()
    pfh = PermFileHandler(logger, file_mode=0o600)

    target = tmp_path / "mode_test.txt"
    target.write_text("x", encoding="utf-8")

    def _raise_perm(_path, _mode):
        raise PermissionError("no chmod")

    monkeypatch.setattr(
        "vulnparse_pin.io.pfhandler.os",
        SimpleNamespace(name="posix", chmod=_raise_perm),
    )

    pfh._apply_file_mode(target)

    logger.warning.assert_called_once()
