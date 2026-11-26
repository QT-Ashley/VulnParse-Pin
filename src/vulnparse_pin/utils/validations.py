# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import sys
from typing import Any, BinaryIO, Optional

import ijson
from ijson.common import IncompleteJSONError

from vulnparse_pin.parsers._xml_security import (
    MAX_XML_PROLOG_BYTES,
    _detect_xml_encoding,
    _strip_bom_and_ws_for_prolog,
    inspect_xml_prolog,
)


SUPPORTED_INPUT_EXTENSIONS = (
    ".xml",
    ".nessus",
    ".csv",
    ".json",
    ".sarif",
    ".jsonl",
    ".ndjson",
)
_HEAD_CHECK_BYTES = 65_536
_LARGE_JSON_PREFIX_BYTES = 262_144
_SMALL_JSON_FULL_STREAM_BYTES = 2 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 8 * 1024 * 1024


def max_depth(obj, depth=0):
    """
    Checks depth of json structures. Legacy helper retained for compatibility.
    """
    if isinstance(obj, dict):
        return max([max_depth(v, depth + 1) for v in obj.values()] + [depth])
    elif isinstance(obj, list):
        return max([max_depth(i, depth + 1) for i in obj] + [depth])
    return depth


def is_valid_cve_api_response(data):
    """Check and see if the api response has valid cve data in it."""
    return isinstance(data, dict) and "cve" in data


def _strip_utf8_bom(data: bytes) -> bytes:
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:]
    return data


def _trim_incomplete_utf8_tail(data: bytes) -> bytes:
    """Drop trailing truncated UTF-8 multi-byte sequence when slicing a prefix buffer."""
    if not data:
        return data
    # Find last byte that is ASCII (<0x80) or start of multi-byte; check up to 3 trailing bytes
    n = len(data)
    i = n - 1
    while i >= max(0, n - 4) and (data[i] & 0xC0) == 0x80:
        i -= 1
    if i >= max(0, n - 4) and data[i] >= 0xC0:
        b = data[i]
        expected_len = 2 if (b & 0xE0) == 0xC0 else 3 if (b & 0xF0) == 0xE0 else 4 if (b & 0xF8) == 0xF0 else 1
        if n - i < expected_len:
            return data[:i]
    return data


class _BomStrippingStream:
    """Binary stream wrapper that strips a leading UTF-8 BOM and leading whitespace."""

    def __init__(self, raw: BinaryIO) -> None:
        self._raw = raw
        self._started = False
        self._buf = b""

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        if not self._started:
            self._started = True
            head = bytearray()
            while len(head) < 64:
                chunk = self._raw.read(max(64, size if size and size > 0 else 65536))
                if not chunk:
                    break
                head.extend(chunk)
                if len(head) >= 3 and not head.startswith(b"\xef\xbb\xbf"):
                    if bytes(head).lstrip():
                        break
                elif len(head) > 3 and bytes(head[3:]).lstrip():
                    break
            data = bytes(head)
            if data.startswith(b"\xef\xbb\xbf"):
                data = data[3:]
            self._buf = data.lstrip()

        if self._buf:
            if size is None or size < 0 or size >= len(self._buf):
                out = self._buf
                self._buf = b""
                return out
            out = self._buf[:size]
            self._buf = self._buf[size:]
            return out

        return self._raw.read(size)


class FileInputValidator:
    def __init__(
        self,
        ctx,
        file_path,
        max_size_mb: int = 500,
        max_nesting: Optional[int] = None,
        allow_large: bool = False,
    ):
        """Validate a supported scanner input file via bounded streaming checks."""
        self.ctx = ctx
        self.pfh = getattr(ctx, "pfh", None)
        self.file_path = file_path
        self.allow_large = bool(allow_large)
        self.max_size_bytes = int(max_size_mb) * 1024 * 1024
        self.max_large_size_bytes = 50 * 1024 * 1024 * 1024
        self.max_nesting = max_nesting
        self.report_json = None

    def _open_rb(self) -> BinaryIO:
        if self.pfh is not None and hasattr(self.pfh, "open_for_read"):
            return self.pfh.open_for_read(self.file_path, mode="rb", label="File Validator")
        return open(self.file_path, "rb")

    def _read_head(self, limit: int = _HEAD_CHECK_BYTES) -> bytes:
        with self._open_rb() as f:
            return f.read(limit)

    def _record_allow_large_hint(self) -> None:
        if self.pfh is None:
            return
        try:
            allow_map = getattr(self.pfh, "_allow_large_paths", None)
            if allow_map is None:
                allow_map = {}
                setattr(self.pfh, "_allow_large_paths", allow_map)
            allow_map[str(Path(self.file_path).resolve())] = self.allow_large
        except Exception:
            pass

    def is_valid_extension_structure(self) -> bool:
        fstr = str(self.file_path).lower()
        ext = Path(fstr).suffix
        if ext not in SUPPORTED_INPUT_EXTENSIONS:
            return False
        try:
            head = self._read_head(_HEAD_CHECK_BYTES)
        except Exception:
            return False

        if not head:
            return False

        clean = _strip_utf8_bom(head).lstrip()

        if ext in (".xml", ".nessus"):
            enc, _ = _detect_xml_encoding(head)
            if enc is not None:
                try:
                    norm = _strip_bom_and_ws_for_prolog(head, is_eof=False)
                except ValueError:
                    return False
                return norm.startswith(b"<") if norm else True
            if not clean:
                return False
            return clean.startswith(b"<")
        if not clean:
            return False
        if ext in (".json", ".sarif"):
            return clean.startswith((b"{", b"["))
        if ext in (".jsonl", ".ndjson"):
            for line in clean.splitlines():
                s = line.strip()
                if s:
                    return s.startswith(b"{")
            return False
        if ext == ".csv":
            if b"\x00" in clean:
                return False
            first_line = clean.splitlines()[0].strip() if clean.splitlines() else b""
            if not first_line or first_line.startswith((b"<", b"{", b"[")):
                return False
            return any(d in first_line for d in (b",", b";", b"\t", b"|"))
        return False

    def _validate_jsonl_stream(self, max_lines: int = 16) -> None:
        checked = 0
        with self._open_rb() as fh:
            for idx in range(64):
                raw_line = fh.readline(_MAX_JSONL_LINE_BYTES + 1)
                if not raw_line:
                    break
                if len(raw_line) > _MAX_JSONL_LINE_BYTES:
                    raise ValueError("JSONL line exceeds maximum safe line length.")
                if idx == 0:
                    raw_line = _strip_utf8_bom(raw_line)
                line = raw_line.strip()
                if not line:
                    continue
                obj = json.loads(line.decode("utf-8"))
                if not isinstance(obj, dict):
                    raise ValueError("JSONL line must decode to a JSON object.")
                checked += 1
                if checked >= max_lines:
                    break
        if checked == 0:
            raise ValueError("JSONL file contains no JSON objects.")

    def _validate_json_stream(self, size_bytes: int) -> None:
        head = self._read_head(_HEAD_CHECK_BYTES)
        clean_head = _strip_utf8_bom(head).lstrip()
        if not clean_head:
            raise ValueError("Empty JSON file.")

        # Support Nuclei JSONL accidentally given a .json suffix
        lines = [ln.strip() for ln in clean_head.splitlines() if ln.strip()]
        if len(lines) >= 2 and lines[0].startswith(b"{") and lines[1].startswith(b"{"):
            try:
                first_obj = json.loads(lines[0].decode("utf-8"))
                if isinstance(first_obj, dict):
                    self._validate_jsonl_stream()
                    return
            except Exception:
                pass

        if size_bytes <= _SMALL_JSON_FULL_STREAM_BYTES:
            with self._open_rb() as fh:
                events = ijson.basic_parse(_BomStrippingStream(fh))
                first = next(events, None)
                if first is None:
                    raise ValueError("Empty JSON document.")
                if first[0] != "start_map":
                    raise ValueError("Top-level JSON structure is not an object.")
                for _ in events:
                    pass
            return

        # Bounded streaming prefix check for large JSON/SARIF (> 2 MB) without loading into RAM
        with self._open_rb() as fh:
            prefix = fh.read(_LARGE_JSON_PREFIX_BYTES)
        clean_prefix = _trim_incomplete_utf8_tail(_strip_utf8_bom(prefix).lstrip())
        if not clean_prefix:
            raise ValueError("Empty JSON file.")

        try:
            events = ijson.basic_parse(io.BytesIO(clean_prefix))
            first = next(events, None)
            if first is None:
                raise ValueError("Empty JSON document.")
            if first[0] != "start_map":
                raise ValueError("Top-level JSON structure is not an object.")
            count = 1
            for _ in events:
                count += 1
                if count >= 2000:
                    break
        except IncompleteJSONError as exc:
            if "premature eof" not in str(exc).lower():
                raise ValueError(f"Invalid JSON format: {exc}") from exc

        # Tail sanity check for truncated large JSON object
        try:
            with self._open_rb() as fh:
                if fh.seekable():
                    fh.seek(max(0, size_bytes - 4096))
                    tail = fh.read(4096).rstrip()
                    if tail and not tail.endswith(b"}"):
                        raise ValueError("Large JSON file appears truncated (missing closing '}').")
        except ValueError:
            raise
        except Exception:
            pass

    def _validate_csv_stream(self) -> None:
        with self._open_rb() as fh:
            head_buf = bytearray()
            while len(head_buf) < _HEAD_CHECK_BYTES:
                chunk = fh.read(_HEAD_CHECK_BYTES - len(head_buf))
                if not chunk:
                    break
                head_buf.extend(chunk)
            head = bytes(head_buf)
            if b"\x00" in head:
                raise ValueError("CSV input contains invalid binary NUL bytes.")
            text = _strip_utf8_bom(head).decode("utf-8", errors="replace")
            if not text.strip():
                raise ValueError("CSV input is empty.")
            try:
                dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            row = next(csv.reader(io.StringIO(text), dialect), None)
            if not row or len([c for c in row if str(c).strip()]) < 2:
                raise ValueError("CSV input missing valid multi-column header.")

            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                if b"\x00" in chunk:
                    raise ValueError("CSV input contains invalid binary NUL bytes.")

    def _validate_xml_stream(self) -> None:
        buf = bytearray()
        enc_checked = False
        with self._open_rb() as fh:
            while True:
                chunk = fh.read(_HEAD_CHECK_BYTES)
                if not chunk:
                    inspect_xml_prolog(bytes(buf), is_eof=True)
                    return
                buf.extend(chunk)
                if not enc_checked and len(buf) >= 2:
                    enc, _ = _detect_xml_encoding(bytes(buf))
                    if enc in ("utf-16-le", "utf-16-be"):
                        raise ValueError(
                            "Unsupported BOM-less UTF-16 XML encoding; provide a UTF-16 BOM or UTF-8."
                        )
                    if len(buf) >= 4 or enc is not None:
                        enc_checked = True
                root_reached, _ = inspect_xml_prolog(bytes(buf), is_eof=False)
                if root_reached:
                    return
                if len(buf) > MAX_XML_PROLOG_BYTES:
                    raise ValueError("XML prolog exceeds maximum safe size before root element.")

    def validate(self):
        if not os.path.exists(self.file_path):
            self.ctx.logger.print_error(f"File does not exist: {self.file_path}")
            sys.exit(1)

        if not os.access(self.file_path, os.R_OK):
            self.ctx.logger.print_error(f"File is not readable: {self.file_path}")
            sys.exit(1)

        if not self.is_valid_extension_structure():
            self.ctx.logger.print_error("File extention or initial structure invalid.")
            sys.exit(1)

        size_bytes = os.path.getsize(self.file_path)
        limit = self.max_large_size_bytes if self.allow_large else self.max_size_bytes

        if size_bytes > limit:
            self.ctx.logger.print_error(
                f"File exceeds size limit. Size: {size_bytes/1024/1024:.2f} MB exceeds limit"
                f"({limit/1024/1024:.0f} MB). Use --allow-large for enterprise-size reports."
            )
            sys.exit(1)

        if self.allow_large and size_bytes > self.max_size_bytes:
            self.ctx.logger.print_warning(
                f"⚠️ Large file mode enabled. File size = {size_bytes/1024/1024:.2f} MB. "
                f"Parsing may be slow or memory intensive."
            )

        self._record_allow_large_hint()

        ext = Path(str(self.file_path).lower()).suffix
        try:
            if ext in (".jsonl", ".ndjson"):
                self._validate_jsonl_stream()
                self.ctx.logger.print_success(f"File validated: {self.file_path}")
            elif ext in (".json", ".sarif"):
                self._validate_json_stream(size_bytes)
                self.ctx.logger.print_success(f"File loaded: {self.file_path}")
            elif ext == ".csv":
                self._validate_csv_stream()
                self.ctx.logger.print_success(f"File validated: {self.file_path}")
            else:
                self._validate_xml_stream()
                self.ctx.logger.print_success(f"File validated: {self.file_path}")
        except (IncompleteJSONError, json.JSONDecodeError) as e:
            self.ctx.logger.print_error(f"Invalid JSON format: {e}")
            sys.exit(1)
        except ValueError as e:
            msg = str(e)
            if "not an object" in msg:
                self.ctx.logger.print_error("Top-level JSON structure is not an object.")
            else:
                self.ctx.logger.print_error(f"Invalid input structure: {e}")
            sys.exit(1)
        except Exception as e:
            self.ctx.logger.print_error(f"Error reading file: {e}")
            sys.exit(1)

        return self.file_path
