# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import codecs
import io
import json
from pathlib import Path
import re
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, TYPE_CHECKING

import ijson
from ijson.common import IncompleteJSONError

from vulnparse_pin.core.classes.dataclass import ScanResult
from vulnparse_pin.parsers.base_parser import (
    BaseParser,
    NormalizedFindingRecord,
    PURL_RE,
    extract_cves_from_text,
    extract_cwes_from_text,
    extract_ghsas_from_text,
    normalize_severity,
    safe_excerpt,
)
from vulnparse_pin.utils.cvss_utils import compute_cvss_base_score

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


_SCA_CONTAINER_TOOLS = (
    "trivy",
    "grype",
    "snyk-container",
    "snyk container",
    "clair",
    "anchore",
    "syft",
    "dockle",
)


_SARIF_WS_CHARS = frozenset((" ", "\t", "\r", "\n"))
_SARIF_WS_RE = re.compile(r"[ \t\r\n]+")
_SKIP_OUTSIDE_RE = re.compile(r'["{}\[\]]')
_SKIP_STRING_RE = re.compile(r'["\\]')
_INCOMPLETE_NUM_TAILS = (".", "e", "E", "e+", "e-", "E+", "E-")
_MAX_PENDING_RESULTS = 4096


class _FastSarifStreamReader:
    """
    Chunked UTF-8 + C JSONDecoder.raw_decode streaming reader for SARIF 2.1.0 documents.

    Iterates top-level keys and `runs` objects without materializing huge `results`
    arrays in memory, validating strict JSON framing and handling arbitrary chunk
    boundaries and key order.
    """

    def __init__(self, raw_fh: BinaryIO, chunk_bytes: int = 4 * 1024 * 1024) -> None:
        self._raw = raw_fh
        self._chunk_bytes = chunk_bytes
        self._utf8_dec = codecs.getincrementaldecoder("utf-8")("strict")
        self._buf = ""
        self._pos = 0
        self._eof = False
        self._started = False
        self._decoder = json.JSONDecoder()

    def _fill(self) -> bool:
        if self._eof:
            return False
        if self._pos > 0:
            self._buf = self._buf[self._pos :]
            self._pos = 0
        while True:
            raw = self._raw.read(self._chunk_bytes)
            if not raw:
                try:
                    tail = self._utf8_dec.decode(b"", final=True)
                except UnicodeDecodeError as exc:
                    raise ValueError(f"Failed to parse SARIF JSON: invalid UTF-8 ({exc})") from exc
                if not self._started:
                    self._started = True
                    if tail.startswith("\ufeff"):
                        tail = tail[1:]
                if tail:
                    self._buf += tail
                self._eof = True
                return bool(tail)
            try:
                text = self._utf8_dec.decode(raw, final=False)
            except UnicodeDecodeError as exc:
                raise ValueError(f"Failed to parse SARIF JSON: invalid UTF-8 ({exc})") from exc
            if not self._started:
                if not text:
                    continue
                self._started = True
                if text.startswith("\ufeff"):
                    text = text[1:]
            if text:
                self._buf += text
                return True

    def _skip_ws(self) -> None:
        buf = self._buf
        pos = self._pos
        n = len(buf)
        while True:
            if pos < n and buf[pos] in _SARIF_WS_CHARS:
                m = _SARIF_WS_RE.match(buf, pos)
                if m is not None:
                    pos = m.end()
            if pos < n:
                self._pos = pos
                return
            self._pos = pos
            if not self._fill():
                return
            buf = self._buf
            pos = self._pos
            n = len(buf)

    def _peek(self) -> str:
        self._skip_ws()
        if self._pos >= len(self._buf):
            raise ValueError("Failed to parse SARIF JSON: unexpected end of file")
        return self._buf[self._pos]

    def _expect(self, ch: str) -> None:
        got = self._peek()
        if got != ch:
            raise ValueError(f"Failed to parse SARIF JSON: expected '{ch}', got '{got}'")
        self._pos += 1

    def _decode_value(self, *, max_value_chars: int = 128 * 1024 * 1024) -> Any:
        self._skip_ws()
        if self._pos >= len(self._buf):
            raise ValueError("Failed to parse SARIF JSON: unexpected end of file")
        decoder = self._decoder
        while True:
            buf = self._buf
            pos = self._pos
            try:
                val, end = decoder.raw_decode(buf, pos)
                if not self._eof:
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        if end == len(buf) or buf[end:] in _INCOMPLETE_NUM_TAILS:
                            if self._fill():
                                continue
                    elif end == len(buf) and buf[pos] not in ('"', "{", "["):
                        if self._fill():
                            continue
                self._pos = end
                return val
            except json.JSONDecodeError as exc:
                if self._eof:
                    raise ValueError(f"Failed to parse SARIF JSON: {exc}") from exc
                could_be_truncated = (
                    exc.pos >= len(buf) - 6
                    or "Unterminated string" in exc.msg
                )
                if not could_be_truncated or (len(buf) - pos) > max_value_chars:
                    raise ValueError(f"Failed to parse SARIF JSON: {exc}") from exc
                if not self._fill():
                    raise ValueError(f"Failed to parse SARIF JSON: {exc}") from exc

    def _decode_key(self) -> str:
        ch = self._peek()
        if ch != '"':
            raise ValueError(f"Failed to parse SARIF JSON: expected string key, got '{ch}'")
        key = self._decode_value(max_value_chars=1024 * 1024)
        if not isinstance(key, str):
            raise ValueError("Failed to parse SARIF JSON: expected string key")
        return key

    def ensure_eof(self) -> None:
        self._skip_ws()
        if self._pos < len(self._buf):
            raise ValueError("Failed to parse SARIF JSON: unexpected trailing data")

    def _skip_json_value(self) -> None:
        """Skip an arbitrary JSON value in O(1) memory without allocating Python objects."""
        ch = self._peek()
        if ch not in ("{", "["):
            self._decode_value()
            return
        self._pos += 1
        depth = 1
        in_string = False
        while depth > 0:
            buf = self._buf
            pos = self._pos
            if in_string:
                m = _SKIP_STRING_RE.search(buf, pos)
                if m is None:
                    self._pos = len(buf)
                    if not self._fill():
                        raise ValueError("Failed to parse SARIF JSON: unterminated string")
                    continue
                hit = m.group(0)
                pos = m.end()
                if hit == "\\":
                    if pos >= len(buf):
                        self._pos = pos
                        if not self._fill():
                            raise ValueError("Failed to parse SARIF JSON: unterminated string escape")
                        buf = self._buf
                        pos = self._pos
                    self._pos = pos + 1
                else:
                    in_string = False
                    self._pos = pos
            else:
                m = _SKIP_OUTSIDE_RE.search(buf, pos)
                if m is None:
                    self._pos = len(buf)
                    if not self._fill():
                        raise ValueError("Failed to parse SARIF JSON: unexpected end of file")
                    continue
                hit = m.group(0)
                self._pos = m.end()
                if hit == '"':
                    in_string = True
                elif hit in ("{", "["):
                    depth += 1
                else:
                    depth -= 1


def _trim_incomplete_utf8_tail(data: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    i = n - 1
    while i >= max(0, n - 4) and (data[i] & 0xC0) == 0x80:
        i -= 1
    if i >= max(0, n - 4) and data[i] >= 0xC0:
        b = data[i]
        expected_len = (
            2 if (b & 0xE0) == 0xC0 else 3 if (b & 0xF0) == 0xE0 else 4 if (b & 0xF8) == 0xF0 else 1
        )
        if n - i < expected_len:
            return data[:i]
    return data


def _coerce_str_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [s.strip() for s in val.split(",") if s.strip()]
    if isinstance(val, list):
        out: List[str] = []
        for item in val:
            if item is not None:
                s = str(item).strip()
                if s:
                    out.append(s)
        return out
    return [str(val).strip()] if str(val).strip() else []


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "-", (name or "sarif").strip().lower()).strip("-")
    return slug or "sarif"


def _looks_like_container_ref(uri: Optional[str]) -> bool:
    if not uri:
        return False
    u = uri.strip()
    if u.startswith(("docker://", "oci://", "container://")):
        return True
    if " (" in u and ")" in u and ":" in u.split(" (", 1)[0]:
        return True
    # image:tag or registry/image:tag without URL scheme or Windows drive letter
    if ":" in u and not u.startswith(("http://", "https://", "file://", "pkg:")):
        if len(u) >= 2 and u[1] == ":" and u[0].isalpha() and ("\\" in u or u[2:3] == "/"):
            return False
        image_part, tag_part = u.rsplit(":", 1)
        if image_part and tag_part and " " not in u and "\\" not in u and "/" not in tag_part:
            return True
    return False


class SarifParser(BaseParser):
    """Streaming SARIF 2.1.0 parser backed by ijson."""

    NAME = "sarif-2.1.0"

    def __init__(
        self,
        ctx: "RunContext",
        filepath: str | Path | None = None,
        *,
        allow_large: Optional[bool] = None,
    ):
        super().__init__(ctx=ctx, filepath=filepath, allow_large=allow_large)

    @classmethod
    def detect_file(
        cls,
        filepath: str | Path,
        *,
        ctx: Optional["RunContext"] = None,
        allow_large: Optional[bool] = None,
        head_bytes: Optional[bytes] = None,
    ) -> tuple[float, list[tuple[str, str]]]:
        """Bounded (<= 64 KB) detection for SARIF 2.1.0 documents."""
        evidence: list[tuple[str, str]] = []
        path = Path(filepath)
        suffix = path.suffix.lower()
        if suffix not in {".sarif", ".json"}:
            return 0.0, [("extension", f"rejected:{suffix}")]

        try:
            max_bytes = cls._max_bytes_for(path, ctx=ctx, allow_large=allow_large)
            if path.stat().st_size > max_bytes:
                return 0.0, [("size", "exceeds_limit")]
            raw_head = cls._read_head_bytes(path, ctx=ctx, head_bytes=head_bytes)
        except Exception:
            return 0.0, [("parse", "failed")]

        if raw_head.startswith(b"\xef\xbb\xbf"):
            raw_head = raw_head[3:]
        clean = _trim_incomplete_utf8_tail(raw_head.lstrip())
        if not clean.startswith(b"{"):
            return 0.0, [("structure", "not_json_object")]

        saw_version_210 = False
        saw_sarif_schema = False
        saw_runs = False
        saw_driver = False
        saw_results = False

        try:
            for prefix, event, value in ijson.parse(io.BytesIO(clean)):
                if prefix == "version" and event == "string" and str(value).strip() == "2.1.0":
                    saw_version_210 = True
                elif prefix == "$schema" and event == "string" and "sarif" in str(value).lower():
                    saw_sarif_schema = True
                elif prefix == "runs" and event == "start_array":
                    saw_runs = True
                elif prefix == "runs.item.tool.driver" and event == "start_map":
                    saw_driver = True
                elif prefix == "runs.item.results" and event == "start_array":
                    saw_results = True
                if saw_version_210 and saw_sarif_schema and saw_runs and saw_driver:
                    break
        except IncompleteJSONError as exc:
            if "premature eof" not in str(exc).lower():
                return 0.0, [("parse", "invalid_json")]
        except Exception:
            return 0.0, [("parse", "failed")]

        if not (
            (saw_version_210 and saw_runs)
            or saw_sarif_schema
            or (saw_runs and saw_driver)
            or (suffix == ".sarif" and (saw_runs or saw_version_210))
        ):
            return 0.0, [("schema", "not_sarif")]

        score = 0.0
        if saw_version_210:
            score += 0.35
            evidence.append(("version", "2.1.0"))
        if saw_sarif_schema:
            score += 0.25
            evidence.append(("schema", "sarif"))
        if saw_runs:
            score += 0.20
            evidence.append(("structure", "runs"))
        if saw_driver:
            score += 0.15
            evidence.append(("structure", "tool.driver"))
        if saw_results:
            score += 0.05
            evidence.append(("structure", "results"))
        if suffix == ".sarif":
            score += 0.30
            evidence.append(("extension", ".sarif"))

        return min(score, 1.0), evidence

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        path = self._validate_filepath_and_size()
        return self._stream_batches(path, batch_size)

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        saw_runs = False
        first_tool_name: Optional[str] = None
        first_scan_date: Optional[str] = None

        with self._open_read(path, self.ctx, mode="rb", label="SARIF JSON") as fh:
            is_seekable = bool(getattr(fh, "seekable", lambda: False)())
            reader = _FastSarifStreamReader(fh)
            reader._expect("{")
            if reader._peek() == "}":
                reader._pos += 1
            else:
                while True:
                    top_key = reader._decode_key()
                    reader._expect(":")
                    if top_key != "runs":
                        reader._decode_value()
                    elif reader._peek() != "[":
                        reader._decode_value()
                    else:
                        saw_runs = True
                        reader._pos += 1  # consume '['
                        if reader._peek() == "]":
                            reader._pos += 1
                        else:
                            run_idx = 0
                            while True:
                                if reader._peek() != "{":
                                    # Consume non-object entry safely if ever present
                                    reader._decode_value()
                                else:
                                    reader._pos += 1  # consume '{'
                                    run_tool: Optional[Dict[str, Any]] = None
                                    run_ctx_cached: Optional[Dict[str, Any]] = None
                                    run_props: Dict[str, Any] = {}
                                    run_vcp: List[Dict[str, Any]] = []
                                    run_artifacts: List[Dict[str, Any]] = []
                                    pending_results: List[Dict[str, Any]] = []
                                    deferred_large_run = False
                                    streamed_inline = False
                                    result_idx = 0

                                    if reader._peek() == "}":
                                        reader._pos += 1
                                    else:
                                        while True:
                                            rkey = reader._decode_key()
                                            reader._expect(":")
                                            if rkey == "tool":
                                                built = reader._decode_value()
                                                run_tool = built if isinstance(built, dict) else {}
                                                run_ctx_cached = None
                                                if first_tool_name is None:
                                                    drv = run_tool.get("driver") if isinstance(run_tool.get("driver"), dict) else {}
                                                    if drv.get("name"):
                                                        first_tool_name = str(drv["name"]).strip()
                                            elif rkey == "properties":
                                                built = reader._decode_value()
                                                if isinstance(built, dict):
                                                    run_props = built
                                                    run_ctx_cached = None
                                            elif rkey == "versionControlProvenance":
                                                built = reader._decode_value()
                                                if isinstance(built, list):
                                                    run_vcp = [x for x in built if isinstance(x, dict)]
                                                    run_ctx_cached = None
                                            elif rkey == "invocations":
                                                built = reader._decode_value()
                                                if isinstance(built, list) and first_scan_date is None:
                                                    invs = [x for x in built if isinstance(x, dict)]
                                                    if invs:
                                                        first_scan_date = (
                                                            invs[0].get("endTimeUtc")
                                                            or invs[0].get("startTimeUtc")
                                                        )
                                            elif rkey == "artifacts":
                                                built = reader._decode_value()
                                                if isinstance(built, list):
                                                    run_artifacts = [x for x in built if isinstance(x, dict)]
                                                    run_ctx_cached = None
                                            elif rkey == "results":
                                                if reader._peek() != "[":
                                                    val = reader._decode_value()
                                                    if val is not None:
                                                        raise ValueError("SARIF run 'results' field must be an array or null.")
                                                else:
                                                    reader._pos += 1  # consume '['
                                                    if reader._peek() == "]":
                                                        reader._pos += 1
                                                    else:
                                                        while True:
                                                            built_res = reader._decode_value()
                                                            if isinstance(built_res, dict):
                                                                if streamed_inline:
                                                                    if run_ctx_cached is None:
                                                                        run_ctx_cached = self._prepare_run_ctx(
                                                                            run_tool or {}, run_props, run_vcp, run_artifacts
                                                                        )
                                                                    result_idx += 1
                                                                    batch.append(self._build_record(built_res, run_ctx_cached, result_idx))
                                                                    if len(batch) >= batch_size:
                                                                        yield batch
                                                                        batch = []
                                                                elif len(pending_results) < _MAX_PENDING_RESULTS:
                                                                    pending_results.append(built_res)
                                                                elif is_seekable:
                                                                    # Reclaim pending RAM and finish reading trailing run metadata,
                                                                    # then rewind to stream this run's results in O(1) memory.
                                                                    pending_results.clear()
                                                                    deferred_large_run = True
                                                                    res_nxt = reader._peek()
                                                                    while res_nxt == ",":
                                                                        reader._pos += 1
                                                                        reader._skip_json_value()
                                                                        res_nxt = reader._peek()
                                                                    if res_nxt != "]":
                                                                        raise ValueError(
                                                                            f"Failed to parse SARIF JSON: expected ',' or ']', got '{res_nxt}'"
                                                                        )
                                                                    reader._pos += 1
                                                                    break
                                                                elif run_tool is not None:
                                                                    streamed_inline = True
                                                                    run_ctx_cached = self._prepare_run_ctx(
                                                                        run_tool, run_props, run_vcp, run_artifacts
                                                                    )
                                                                    for prev_res in pending_results:
                                                                        result_idx += 1
                                                                        batch.append(self._build_record(prev_res, run_ctx_cached, result_idx))
                                                                        if len(batch) >= batch_size:
                                                                            yield batch
                                                                            batch = []
                                                                    pending_results.clear()
                                                                    result_idx += 1
                                                                    batch.append(self._build_record(built_res, run_ctx_cached, result_idx))
                                                                    if len(batch) >= batch_size:
                                                                        yield batch
                                                                        batch = []
                                                                else:
                                                                    raise ValueError(
                                                                        "SARIF 'results' array exceeds streaming buffer before 'tool' metadata on non-seekable stream."
                                                                    )
                                                            res_nxt = reader._peek()
                                                            if res_nxt == ",":
                                                                reader._pos += 1
                                                                continue
                                                            if res_nxt == "]":
                                                                reader._pos += 1
                                                                break
                                                            raise ValueError(f"Failed to parse SARIF JSON: expected ',' or ']', got '{res_nxt}'")
                                            else:
                                                reader._decode_value()

                                            run_nxt = reader._peek()
                                            if run_nxt == ",":
                                                reader._pos += 1
                                                continue
                                            if run_nxt == "}":
                                                reader._pos += 1
                                                break
                                            raise ValueError(f"Failed to parse SARIF JSON: expected ',' or '}}', got '{run_nxt}'")

                                    if run_ctx_cached is None:
                                        run_ctx_cached = self._prepare_run_ctx(
                                            run_tool or {}, run_props, run_vcp, run_artifacts
                                        )

                                    if deferred_large_run:
                                        reader = self._seek_to_run_and_prepare(fh, run_idx)
                                        while True:
                                            rkey = reader._decode_key()
                                            reader._expect(":")
                                            if rkey == "results" and reader._peek() == "[":
                                                reader._pos += 1
                                                if reader._peek() == "]":
                                                    reader._pos += 1
                                                else:
                                                    while True:
                                                        built_res = reader._decode_value()
                                                        if isinstance(built_res, dict):
                                                            result_idx += 1
                                                            batch.append(self._build_record(built_res, run_ctx_cached, result_idx))
                                                            if len(batch) >= batch_size:
                                                                yield batch
                                                                batch = []
                                                        res_nxt = reader._peek()
                                                        if res_nxt == ",":
                                                            reader._pos += 1
                                                            continue
                                                        if res_nxt == "]":
                                                            reader._pos += 1
                                                            break
                                                        raise ValueError(f"Failed to parse SARIF JSON: expected ',' or ']', got '{res_nxt}'")
                                            else:
                                                reader._skip_json_value()
                                            run_nxt = reader._peek()
                                            if run_nxt == ",":
                                                reader._pos += 1
                                                continue
                                            if run_nxt == "}":
                                                reader._pos += 1
                                                break
                                            raise ValueError(f"Failed to parse SARIF JSON: expected ',' or '}}', got '{run_nxt}'")
                                    elif pending_results:
                                        for raw_res in pending_results:
                                            result_idx += 1
                                            batch.append(self._build_record(raw_res, run_ctx_cached, result_idx))
                                            if len(batch) >= batch_size:
                                                yield batch
                                                batch = []
                                        pending_results.clear()

                                run_idx += 1
                                runs_nxt = reader._peek()
                                if runs_nxt == ",":
                                    reader._pos += 1
                                    continue
                                if runs_nxt == "]":
                                    reader._pos += 1
                                    break
                                raise ValueError(f"Failed to parse SARIF JSON: expected ',' or ']', got '{runs_nxt}'")

                    top_nxt = reader._peek()
                    if top_nxt == ",":
                        reader._pos += 1
                        continue
                    if top_nxt == "}":
                        reader._pos += 1
                        break
                    raise ValueError(f"Failed to parse SARIF JSON: expected ',' or '}}', got '{top_nxt}'")

            reader.ensure_eof()

        if not saw_runs:
            raise ValueError("SARIF input missing top-level 'runs' array.")

        if self._collecting_for_parse:
            self._last_scan_meta = {
                "scan_name": first_tool_name or path.stem,
                "scan_date": first_scan_date,
                "empty_assets": [],
            }

        if batch:
            yield batch

    @staticmethod
    def _seek_to_run_and_prepare(fh: BinaryIO, target_run_idx: int) -> _FastSarifStreamReader:
        """Seek a SARIF file back to the start of runs[target_run_idx] (after '{')."""
        fh.seek(0)
        reader = _FastSarifStreamReader(fh)
        reader._expect("{")
        while True:
            top_key = reader._decode_key()
            reader._expect(":")
            if top_key == "runs" and reader._peek() == "[":
                reader._pos += 1
                idx = 0
                while idx < target_run_idx:
                    reader._skip_json_value()
                    if reader._peek() != ",":
                        raise ValueError("Failed to seek to target SARIF run.")
                    reader._pos += 1
                    idx += 1
                reader._expect("{")
                return reader
            reader._skip_json_value()
            if reader._peek() != ",":
                raise ValueError("Failed to locate 'runs' while seeking SARIF file.")
            reader._pos += 1

    def parse(self) -> ScanResult:
        """Parse SARIF 2.1.0 into ScanResult in a single streaming pass."""
        return self._build_scan_result_from_batches(source_label="SARIF")

    @classmethod
    def _prepare_run_ctx(
        cls,
        run_tool: Dict[str, Any],
        run_props: Dict[str, Any],
        run_vcp: List[Dict[str, Any]],
        run_artifacts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        driver = run_tool.get("driver") if isinstance(run_tool.get("driver"), dict) else {}
        tool_name = str(driver.get("name") or "sarif").strip()
        tool_version = str(
            driver.get("semanticVersion") or driver.get("version") or ""
        ).strip() or None
        detection_mode = cls._classify_detection_mode(tool_name)

        rules_by_id: Dict[str, Dict[str, Any]] = {}
        rules_by_index: Dict[int, Dict[str, Any]] = {}
        driver_rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
        for idx, rule in enumerate(driver_rules):
            if not isinstance(rule, dict):
                continue
            rules_by_index[idx] = rule
            rid = rule.get("id")
            if rid:
                rules_by_id[str(rid)] = rule

        extensions = run_tool.get("extensions") if isinstance(run_tool.get("extensions"), list) else []
        for ext in extensions:
            if not isinstance(ext, dict):
                continue
            for rule in ext.get("rules") or []:
                if isinstance(rule, dict) and rule.get("id"):
                    rules_by_id.setdefault(str(rule["id"]), rule)

        run_image_or_repo = cls._extract_image_or_repo(run_props, run_vcp, run_artifacts)
        run_target_uri = cls._extract_target_uri(run_props, run_vcp)

        return {
            "tool_name": tool_name,
            "tool_slug": _slugify(tool_name),
            "tool_version": tool_version,
            "detection_mode": detection_mode,
            "rules_by_id": rules_by_id,
            "rules_by_index": rules_by_index,
            "run_props": run_props,
            "run_artifacts": run_artifacts,
            "run_image_or_repo": run_image_or_repo,
            "run_target_uri": run_target_uri,
        }

    @staticmethod
    def _safe_index_int(value: Any) -> Optional[int]:
        """Parse integer indices/line numbers while rejecting booleans and floats."""
        if value is None or isinstance(value, (bool, float)) or value == "":
            return None
        if isinstance(value, int):
            return value
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _classify_detection_mode(tool_name: str) -> str:
        tl = (tool_name or "").strip().lower()
        if any(marker in tl for marker in _SCA_CONTAINER_TOOLS):
            return "sca_container"
        return "static_sast"

    @staticmethod
    def _extract_image_or_repo(
        props: Dict[str, Any],
        vcp: List[Dict[str, Any]],
        artifacts: List[Dict[str, Any]],
    ) -> Optional[str]:
        for key in (
            "imageName",
            "containerImage",
            "image",
            "artifactName",
            "target",
            "repository",
            "repo",
            "repoName",
        ):
            val = props.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        for entry in vcp:
            repo_uri = entry.get("repositoryUri")
            if isinstance(repo_uri, str) and repo_uri.strip():
                return repo_uri.strip()
        for art in artifacts:
            art_props = art.get("properties") if isinstance(art.get("properties"), dict) else {}
            for key in ("imageName", "containerImage", "image", "repository"):
                val = art_props.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
            loc_uri = (art.get("location") or {}).get("uri") if isinstance(art.get("location"), dict) else None
            if _looks_like_container_ref(loc_uri):
                return str(loc_uri).strip()
        return None

    @staticmethod
    def _extract_target_uri(props: Dict[str, Any], vcp: List[Dict[str, Any]]) -> Optional[str]:
        for key in ("targetUri", "target_uri", "targetUrl", "url"):
            val = props.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        for entry in vcp:
            repo_uri = entry.get("repositoryUri")
            if isinstance(repo_uri, str) and repo_uri.strip().startswith(("http://", "https://")):
                return repo_uri.strip()
        return None

    def _build_record(
        self,
        res: Dict[str, Any],
        run_ctx: Dict[str, Any],
        idx: int,
    ) -> NormalizedFindingRecord:
        res_props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
        rule_ref = res.get("rule") if isinstance(res.get("rule"), dict) else {}

        raw_rule_id = res.get("ruleId") or rule_ref.get("id")
        rule_index = res.get("ruleIndex")
        if rule_index is None:
            rule_index = rule_ref.get("index")
        rule_idx_int = self._safe_index_int(rule_index)

        rule: Dict[str, Any] = {}
        if raw_rule_id and str(raw_rule_id) in run_ctx["rules_by_id"]:
            rule = run_ctx["rules_by_id"][str(raw_rule_id)]
        elif rule_idx_int is not None and rule_idx_int in run_ctx["rules_by_index"]:
            rule = run_ctx["rules_by_index"][rule_idx_int]

        rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
        rule_id = str(raw_rule_id or rule.get("id") or f"rule_{idx}").strip()

        msg_obj = res.get("message") if isinstance(res.get("message"), dict) else {}
        message_text = str(msg_obj.get("text") or msg_obj.get("markdown") or "").strip()

        short_desc = (
            (rule.get("shortDescription") or {}).get("text")
            if isinstance(rule.get("shortDescription"), dict)
            else None
        )
        full_desc = (
            (rule.get("fullDescription") or {}).get("text")
            if isinstance(rule.get("fullDescription"), dict)
            else None
        )
        title = str(short_desc or rule.get("name") or rule_id).strip()

        desc_parts: List[str] = []
        if message_text:
            desc_parts.append(message_text)
        if full_desc and str(full_desc).strip() and str(full_desc).strip() != message_text:
            desc_parts.append(str(full_desc).strip())
        description = "\n".join(desc_parts) if desc_parts else title

        help_obj = rule.get("help") if isinstance(rule.get("help"), dict) else {}
        solution = str(
            res_props.get("remediation")
            or rule_props.get("remediation")
            or help_obj.get("text")
            or ""
        ).strip()

        # Location extraction
        locations = res.get("locations") if isinstance(res.get("locations"), list) else []
        first_loc = locations[0] if locations and isinstance(locations[0], dict) else {}
        phys_loc = first_loc.get("physicalLocation") if isinstance(first_loc.get("physicalLocation"), dict) else {}
        art_loc = phys_loc.get("artifactLocation") if isinstance(phys_loc.get("artifactLocation"), dict) else {}
        location_uri = str(art_loc.get("uri") or "").strip() or None
        if not location_uri and art_loc.get("index") is not None:
            art_idx = self._safe_index_int(art_loc.get("index"))
            if art_idx is not None and 0 <= art_idx < len(run_ctx["run_artifacts"]):
                alt_uri = (
                    (run_ctx["run_artifacts"][art_idx].get("location") or {}).get("uri")
                    if isinstance(run_ctx["run_artifacts"][art_idx].get("location"), dict)
                    else None
                )
                if alt_uri:
                    location_uri = str(alt_uri).strip() or None

        region = phys_loc.get("region") if isinstance(phys_loc.get("region"), dict) else {}
        line_number = self._safe_index_int(region.get("startLine"))
        if line_number is not None and line_number < 1:
            line_number = None

        snippet_obj = region.get("snippet") if isinstance(region.get("snippet"), dict) else {}
        snippet_text = str(snippet_obj.get("text") or "").strip()

        logical_locs = (
            first_loc.get("logicalLocations")
            if isinstance(first_loc.get("logicalLocations"), list)
            else []
        )
        logical_name = None
        if logical_locs and isinstance(logical_locs[0], dict):
            logical_name = (
                logical_locs[0].get("fullyQualifiedName")
                or logical_locs[0].get("name")
            )

        # Container image or repo attribution
        image_or_repo = None
        for key in ("imageName", "containerImage", "image", "artifactName", "repository", "repo"):
            val = res_props.get(key)
            if isinstance(val, str) and val.strip():
                image_or_repo = val.strip()
                break
        if not image_or_repo:
            image_or_repo = run_ctx["run_image_or_repo"]
        if not image_or_repo and run_ctx["detection_mode"] == "sca_container":
            if _looks_like_container_ref(location_uri):
                image_or_repo = location_uri
            elif isinstance(logical_name, str) and logical_name.strip():
                image_or_repo = logical_name.strip()

        target_uri = (
            str(res_props.get("targetUri") or res_props.get("url") or "").strip()
            or run_ctx["run_target_uri"]
        )

        # PURL extraction
        package_purl = None
        for key in ("purl", "packagePurl", "pkgPurl", "package_purl", "PkgID"):
            val = res_props.get(key)
            if isinstance(val, str) and val.strip().startswith("pkg:"):
                package_purl = val.strip()
                break
        if not package_purl:
            for candidate in (
                str(logical_name or ""),
                message_text,
                str(res_props.get("pkgName") or ""),
            ):
                m = PURL_RE.search(candidate)
                if m:
                    package_purl = m.group(0)
                    break

        # Tags, CWEs, CVEs, GHSAs
        tags: List[str] = []
        for t in _coerce_str_list(rule_props.get("tags")) + _coerce_str_list(res_props.get("tags")):
            if t not in tags:
                tags.append(t)

        id_sources = [
            rule_id,
            str(rule.get("name") or ""),
            title,
            message_text,
            str(full_desc or ""),
            " ".join(tags),
            str(rule.get("helpUri") or ""),
            str(res_props.get("cve") or ""),
            str(res_props.get("cves") or ""),
            str(res_props.get("cwe") or ""),
            str(res_props.get("cwes") or ""),
            str(rule_props.get("cwe") or ""),
        ]
        cves = extract_cves_from_text(*id_sources)
        cwes = extract_cwes_from_text(*id_sources)
        ghsa_ids = extract_ghsas_from_text(*id_sources)

        # CVSS / security-severity extraction
        scanner_cvss_score, scanner_cvss_vector = self._extract_cvss(res_props, rule_props)

        # Severity normalization
        prop_sev = (
            res_props.get("severity")
            or rule_props.get("problem.severity")
            or rule_props.get("severity")
        )
        default_level = (
            (rule.get("defaultConfiguration") or {}).get("level")
            if isinstance(rule.get("defaultConfiguration"), dict)
            else None
        )
        sarif_level = res.get("level") or default_level

        if scanner_cvss_score is not None:
            severity = normalize_severity(None, scanner_cvss_score)
        elif prop_sev:
            severity = normalize_severity(str(prop_sev))
        elif any(str(t).lower() == "critical" for t in tags):
            severity = "Critical"
        else:
            severity = normalize_severity(str(sarif_level or "warning"))

        references: List[str] = []
        help_uri = rule.get("helpUri")
        if isinstance(help_uri, str) and help_uri.strip():
            references.append(help_uri.strip())
        for ref in _coerce_str_list(res_props.get("references")) + _coerce_str_list(rule_props.get("references")):
            if ref not in references:
                references.append(ref)

        partial_fps = (
            res.get("partialFingerprints")
            if isinstance(res.get("partialFingerprints"), dict)
            else {}
        )

        plugin_output = message_text or snippet_text or ""
        if snippet_text and snippet_text not in plugin_output:
            plugin_output = f"{plugin_output}\n{snippet_text}".strip()

        missing_fields: List[str] = []
        if not location_uri:
            missing_fields.append("location_uri")
        if not cves and not cwes and not ghsa_ids:
            missing_fields.append("cves_or_cwes")
        if not message_text:
            missing_fields.append("plugin_output")

        if not missing_fields:
            fidelity_tier = "high"
            ingestion_confidence = 0.90 if run_ctx["detection_mode"] == "sca_container" else 0.85
        elif len(missing_fields) == 1:
            fidelity_tier = "medium"
            ingestion_confidence = 0.72
        else:
            fidelity_tier = "low"
            ingestion_confidence = 0.50

        asset_meta: Dict[str, Any] = {
            "credentialed": False,
            "open_ports": [],
            "tool": run_ctx["tool_name"],
        }
        if run_ctx["tool_version"]:
            asset_meta["tool_version"] = run_ctx["tool_version"]
        if partial_fps:
            asset_meta["partial_fingerprints"] = partial_fps

        return {
            "ip_address": None,
            "hostname": None,
            "target_uri": target_uri,
            "image_or_repo": image_or_repo,
            "os": None,
            "asset_metadata": asset_meta,
            "source_format": "sarif-2.1.0",
            "scanner_sig": f"{run_ctx['tool_slug']}:{rule_id}",
            "title": title,
            "description": description,
            "solution": solution,
            "plugin_output": plugin_output,
            "severity": severity,
            "cves": cves,
            "cwes": cwes,
            "ghsa_ids": ghsa_ids,
            "affected_port": None,
            "protocol": None,
            "service_name": None,
            "location_uri": location_uri,
            "line_number": line_number,
            "package_purl": package_purl,
            "scanner_cvss_score": scanner_cvss_score,
            "scanner_cvss_vector": scanner_cvss_vector,
            "detection_mode": run_ctx["detection_mode"],
            "fidelity_tier": fidelity_tier,
            "ingestion_confidence": ingestion_confidence,
            "missing_fields": missing_fields,
            "degraded_input": fidelity_tier != "high",
            "references": references,
            "tags": tags,
            "exploit_evidence": None,
            "raw_evidence_excerpt": safe_excerpt(plugin_output or description),
        }

    def _extract_cvss(
        self,
        res_props: Dict[str, Any],
        rule_props: Dict[str, Any],
    ) -> tuple[Optional[float], Optional[str]]:
        score: Optional[float] = None
        vector: Optional[str] = None

        for props in (res_props, rule_props):
            if score is None:
                for key in ("security-severity", "cvss_score", "cvssScore", "cvss3_score", "cvssV3Score"):
                    val = props.get(key)
                    parsed = self._safe_float(val)
                    if parsed is not None and 0.0 <= parsed <= 10.0:
                        score = parsed
                        break
            if vector is None:
                for key in ("cvss_vector", "cvssVector", "cvss3_vector", "cvssV3Vector", "cvss_v3"):
                    val = props.get(key)
                    if isinstance(val, str) and "CVSS:" in val.upper():
                        vector = val.strip()
                        break

            # Trivy SARIF embeds properties.cvss = {"nvd": {"V3Score": ..., "V3Vector": ...}}
            cvss_obj = props.get("cvss")
            if isinstance(cvss_obj, dict):
                for source_entry in cvss_obj.values():
                    if isinstance(source_entry, dict):
                        if score is None:
                            s = self._safe_float(source_entry.get("V3Score") or source_entry.get("V2Score"))
                            if s is not None and 0.0 <= s <= 10.0:
                                score = s
                        if vector is None:
                            v = source_entry.get("V3Vector") or source_entry.get("V2Vector")
                            if isinstance(v, str) and v.strip():
                                vector = v.strip()
            elif cvss_obj is not None and score is None:
                parsed = self._safe_float(cvss_obj)
                if parsed is not None and 0.0 <= parsed <= 10.0:
                    score = parsed

        if vector and score is None:
            computed = compute_cvss_base_score(vector)
            if computed is not None:
                score = float(computed)

        return score, vector
