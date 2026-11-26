# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

"""Hardened streaming XML prolog validation and bounded lxml helpers."""

from __future__ import annotations

import io
import re
from typing import BinaryIO, Iterator, Optional, Sequence, Tuple, Union
from lxml import etree


MAX_XML_PROLOG_BYTES = 1024 * 1024  # 1 MiB cap before root element
HEAD_SNIFF_BYTES = 65_536

_ENTITY_DECL_RE = re.compile(rb"<!\s*ENTITY\b", re.IGNORECASE)
_DOCTYPE_START_RE = re.compile(rb"<!\s*DOCTYPE\b", re.IGNORECASE)
_EXTERNAL_DTD_KW_RE = re.compile(rb"\b(?:SYSTEM|PUBLIC)\b", re.IGNORECASE)
_ROOT_START_RE = re.compile(rb"^[A-Za-z_:]")


def _detect_xml_encoding(data: bytes) -> Tuple[Optional[str], int]:
    """
    Detect XML byte encoding from BOM or BOM-less UTF-16 start patterns.

    Returns (encoding_name, bom_byte_length).
    """
    if data.startswith(b"\xef\xbb\xbf"):
        return "utf-8", 3
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return "utf-32", 4
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16", 2

    n = len(data)
    # BOM-less UTF-16LE: optional UTF-16LE whitespace pairs followed by '<\x00'
    pos = 0
    while pos + 1 < n and data[pos : pos + 2] in (b" \x00", b"\t\x00", b"\n\x00", b"\r\x00"):
        pos += 2
    if (pos + 1 < n and data[pos : pos + 2] == b"<\x00") or (pos >= 4 and pos == n):
        return "utf-16-le", 0

    # BOM-less UTF-16BE: optional UTF-16BE whitespace pairs followed by '\x00<'
    pos = 0
    while pos + 1 < n and data[pos : pos + 2] in (b"\x00 ", b"\x00\t", b"\x00\n", b"\x00\r"):
        pos += 2
    if (pos + 1 < n and data[pos : pos + 2] == b"\x00<") or (pos >= 4 and pos == n):
        return "utf-16-be", 0

    return None, 0


def _strip_bom_and_ws_for_prolog(data: bytes, *, is_eof: bool = True) -> bytes:
    """Normalize UTF-8 BOM, UTF-16 (with or without BOM), or UTF-32 to UTF-8 bytes for prolog inspection."""
    enc, bom_len = _detect_xml_encoding(data)
    if enc is None:
        return data.lstrip()
    if enc == "utf-8":
        return data[bom_len:].lstrip()

    if enc in ("utf-16", "utf-16-le", "utf-16-be"):
        payload = data
        if len(payload) % 2 == 1:
            if not is_eof:
                payload = payload[:-1]
            else:
                raise ValueError("Malformed UTF-16 XML prolog (odd byte length).")
        if len(payload) <= bom_len:
            return b""
        try:
            text = payload.decode(enc, errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Malformed UTF-16 XML prolog: {exc}") from exc
        return text.encode("utf-8").lstrip()

    if enc == "utf-32":
        payload = data
        rem = len(payload) % 4
        if rem != 0:
            if not is_eof:
                payload = payload[: len(payload) - rem]
            else:
                raise ValueError("Malformed UTF-32 XML prolog.")
        if len(payload) <= bom_len:
            return b""
        try:
            text = payload.decode("utf-32", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Malformed UTF-32 XML prolog: {exc}") from exc
        return text.encode("utf-8").lstrip()

    return data.lstrip()


def _strip_outside_quotes(buf: bytes) -> bytes:
    """Return bytes outside single/double quotes so keyword scans do not hit quoted names."""
    out = bytearray()
    quote: int | None = None
    for b in buf:
        if quote is not None:
            if b == quote:
                quote = None
        else:
            if b in (34, 39):  # " or '
                quote = b
            else:
                out.append(b)
    return bytes(out)


def _find_doctype_end(buf: bytes, start: int) -> int | None:
    """Find closing '>' of a <!DOCTYPE ...> block respecting quotes and [...] subset."""
    n = len(buf)
    i = start + 2  # skip <!
    quote: int | None = None
    bracket_depth = 0
    while i < n:
        b = buf[i]
        if quote is not None:
            if b == quote:
                quote = None
        else:
            if b in (34, 39):
                quote = b
            elif b == 91:  # '['
                bracket_depth += 1
            elif b == 93:  # ']'
                if bracket_depth > 0:
                    bracket_depth -= 1
            elif b == 62 and bracket_depth == 0:  # '>'
                return i + 1
        i += 1
    return None


def _validate_doctype_block(block: bytes) -> None:
    """Allow harmless <!DOCTYPE root> while rejecting entities and external DTDs."""
    if _ENTITY_DECL_RE.search(block):
        raise ValueError("Forbidden XML <!ENTITY declaration in DOCTYPE.")

    # Inspect internal DTD subset if present
    lbracket = block.find(b"[")
    if lbracket != -1:
        rbracket = block.rfind(b"]")
        subset = block[lbracket + 1 : rbracket] if rbracket > lbracket else block[lbracket + 1 :]
        if subset.strip():
            if b"<!" in subset or b"%" in subset:
                raise ValueError("Forbidden internal DTD subset or parameter entity in DOCTYPE.")

    outside = _strip_outside_quotes(block)
    if _EXTERNAL_DTD_KW_RE.search(outside):
        raise ValueError("Forbidden external DTD reference (SYSTEM/PUBLIC) in DOCTYPE.")
    if b"%" in outside:
        raise ValueError("Forbidden parameter entity reference in DOCTYPE.")


def inspect_xml_prolog(raw_bytes: bytes, *, is_eof: bool = True) -> Tuple[bool, int]:
    """
    Validate XML prolog constructs up to the root element start tag.

    Returns (root_reached, consumed_or_checked_pos).
    Raises ValueError immediately on forbidden ENTITY/external-DTD constructs.
    """
    if (
        not is_eof
        and len(raw_bytes) < 4
        and raw_bytes
        in (
            b"",
            b"\x00",
            b"\x00\x00",
            b"\x00\x00\x00",
            b"\xff",
            b"\xfe",
            b"\xff\xfe",
            b"\xfe\xff",
            b"\xef",
            b"\xef\xbb",
            b"<",
            b" ",
            b"\t",
            b"\n",
            b"\r",
        )
    ):
        return False, 0

    buf = _strip_bom_and_ws_for_prolog(raw_bytes, is_eof=is_eof)
    if b"\x00" in buf:
        raise ValueError("Forbidden NUL byte in XML prolog.")
    n = len(buf)
    i = 0

    while i < n:
        while i < n and buf[i] in (32, 9, 10, 13):
            i += 1
        if i >= n:
            return False, i

        if buf[i] != 60:  # '<'
            # Unexpected text before root; let lxml report syntax error unless ENTITY present
            if _ENTITY_DECL_RE.search(buf[i:]):
                raise ValueError("Forbidden XML <!ENTITY declaration detected.")
            return True, i

        # Check construct starting at '<'
        if i + 1 >= n:
            return False, i

        if buf.startswith(b"<?", i):
            end = buf.find(b"?>", i + 2)
            if end == -1:
                if is_eof:
                    return True, i
                return False, i
            i = end + 2
            continue

        if buf.startswith(b"<!--", i):
            end = buf.find(b"-->", i + 4)
            if end == -1:
                if is_eof:
                    return True, i
                return False, i
            i = end + 3
            continue

        if _ENTITY_DECL_RE.match(buf[i : i + 16]):
            raise ValueError("Forbidden XML <!ENTITY declaration detected.")

        if _DOCTYPE_START_RE.match(buf[i : i + 16]):
            end = _find_doctype_end(buf, i)
            if end is None:
                # Even on incomplete DOCTYPE buffer, fail immediately if ENTITY/SYSTEM/PUBLIC already visible
                partial = buf[i:]
                if _ENTITY_DECL_RE.search(partial):
                    raise ValueError("Forbidden XML <!ENTITY declaration in DOCTYPE.")
                if _EXTERNAL_DTD_KW_RE.search(_strip_outside_quotes(partial)):
                    raise ValueError("Forbidden external DTD reference (SYSTEM/PUBLIC) in DOCTYPE.")
                if is_eof:
                    raise ValueError("Malformed or unterminated XML DOCTYPE declaration.")
                return False, i
            _validate_doctype_block(buf[i:end])
            i = end
            continue

        if buf.startswith(b"<!", i):
            # Any other prolog declaration (e.g. ATTLIST/ELEMENT outside DOCTYPE)
            if _ENTITY_DECL_RE.search(buf[i : i + 32]):
                raise ValueError("Forbidden XML <!ENTITY declaration detected.")
            end = buf.find(b">", i + 2)
            if end == -1:
                return (True, i) if is_eof else (False, i)
            i = end + 1
            continue

        # Root element start tag reached
        if _ROOT_START_RE.match(buf[i + 1 : i + 2]):
            return True, i

        return True, i

    return False, i


def validate_xml_prolog(head_bytes: bytes) -> None:
    """Validate bounded XML prolog bytes; raises ValueError on XXE/DTD attacks."""
    inspect_xml_prolog(head_bytes, is_eof=False)


class _PrologGuardedStream:
    """
    Binary stream wrapper that strips UTF-8 BOM + leading whitespace before
    <?xml, validates the entire XML prolog up to the root element (capped at
    MAX_XML_PROLOG_BYTES), and then streams chunks directly to lxml.etree.iterparse.
    """

    def __init__(self, raw_stream: BinaryIO) -> None:
        self._raw = raw_stream
        self._prolog_buf = bytearray()
        self._prolog_done = False
        self._remainder = b""

    def read(self, size: int = -1) -> bytes:
        if not self._prolog_done:
            while not self._prolog_done:
                chunk = self._raw.read(65536)
                if not chunk:
                    inspect_xml_prolog(bytes(self._prolog_buf), is_eof=True)
                    self._remainder = self._normalize_initial_bytes(bytes(self._prolog_buf))
                    self._prolog_buf.clear()
                    self._prolog_done = True
                    break

                self._prolog_buf.extend(chunk)
                root_reached, _ = inspect_xml_prolog(bytes(self._prolog_buf), is_eof=False)
                if root_reached:
                    self._remainder = self._normalize_initial_bytes(bytes(self._prolog_buf))
                    self._prolog_buf.clear()
                    self._prolog_done = True
                    break

                if len(self._prolog_buf) > MAX_XML_PROLOG_BYTES:
                    raise ValueError(
                        "XML prolog exceeds maximum safe size before root element."
                    )

        if self._remainder:
            if size is None or size < 0 or size >= len(self._remainder):
                out = self._remainder
                self._remainder = b""
                return out
            out = self._remainder[:size]
            self._remainder = self._remainder[size:]
            return out

        return self._raw.read(size)

    @staticmethod
    def _normalize_initial_bytes(data: bytes) -> bytes:
        enc, bom_len = _detect_xml_encoding(data)
        if enc == "utf-8":
            return data[bom_len:].lstrip()
        if enc in ("utf-16", "utf-16-le", "utf-16-be", "utf-32"):
            return data
        return data.lstrip()


def assert_no_entity_nodes(elem: etree._Element) -> None:
    """Fail closed if any lxml Entity reference node appears in an element subtree."""
    if isinstance(elem, etree._Entity) or elem.tag is etree.Entity:
        raise ValueError("Forbidden XML entity reference encountered.")
    if next(elem.iter(etree.Entity), None) is not None:
        raise ValueError("Forbidden XML entity reference encountered.")


def prune_element(elem: etree._Element) -> None:
    """Clear element contents and delete preceding siblings for O(1) streaming memory."""
    elem.clear()
    parent = elem.getparent()
    if parent is not None:
        while elem.getprevious() is not None:
            del parent[0]


def safe_iterparse(
    raw_stream: BinaryIO,
    *,
    events: Tuple[str, ...] = ("end",),
    tag: Optional[Union[str, Sequence[str]]] = None,
) -> Iterator[Tuple[str, etree._Element]]:
    """
    Stream XML events using hardened lxml.etree.iterparse with prolog validation
    and entity-node fail-closed enforcement across the entire document.
    """
    guarded = _PrologGuardedStream(raw_stream)
    events_tuple = tuple(events)
    events_set = set(events_tuple)
    tag_filter_set: Optional[set[Any]] = None
    iter_events = events_tuple
    iter_tag = tag
    if tag is not None and tag != "*":
        tag_filter_set = {tag} if isinstance(tag, str) else set(tag)
        # Iterate all elements internally so entity references outside tag= never evade rejection.
        iter_tag = None
        if "end" not in events_set:
            iter_events = tuple(dict.fromkeys((*events_tuple, "end")))

    ctx = etree.iterparse(
        guarded,
        events=iter_events,
        tag=iter_tag,
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
    for event, elem in ctx:
        if isinstance(elem, etree._Entity) or elem.tag is etree.Entity:
            raise ValueError("Forbidden XML entity reference encountered.")
        if event == "end":
            if tag_filter_set is None or elem.tag in tag_filter_set:
                assert_no_entity_nodes(elem)
            else:
                for child in elem:
                    if isinstance(child, etree._Entity) or child.tag is etree.Entity:
                        raise ValueError("Forbidden XML entity reference encountered.")
        if event in events_set and (tag_filter_set is None or elem.tag in tag_filter_set):
            yield event, elem


def sniff_xml_head_events(head_bytes: bytes) -> Tuple[str | None, list[Tuple[str, str, dict[str, str], str | None]]]:
    """
    Parse at most HEAD_SNIFF_BYTES using a hardened non-blocking XMLPullParser.

    Returns (root_tag, [(event, tag, attrib_dict, text), ...]).
    Raises ValueError or etree.XMLSyntaxError on XXE/invalid XML.
    """
    sample = head_bytes[:HEAD_SNIFF_BYTES]
    validate_xml_prolog(sample)

    enc, bom_len = _detect_xml_encoding(sample)
    if enc == "utf-8":
        sample = sample[bom_len:].lstrip()
    elif enc is None:
        sample = sample.lstrip()

    norm_head = _strip_bom_and_ws_for_prolog(sample, is_eof=False)
    if norm_head and not norm_head.startswith(b"<"):
        raise ValueError("Input does not start with XML markup.")
    if enc is None and not sample.startswith(b"<"):
        raise ValueError("Input does not start with XML markup.")

    pull = etree.XMLPullParser(
        events=("start", "end"),
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
    pull.feed(sample)

    root_tag: str | None = None
    collected: list[Tuple[str, str, dict[str, str], str | None]] = []
    for event, elem in pull.read_events():
        if isinstance(elem, etree._Entity) or elem.tag is etree.Entity:
            raise ValueError("Forbidden XML entity reference encountered.")
        if event == "end":
            assert_no_entity_nodes(elem)
        tag = elem.tag if isinstance(elem.tag, str) else ""
        if event == "start" and root_tag is None and tag:
            root_tag = tag
        collected.append((event, tag, dict(elem.attrib), elem.text if event == "end" else None))

    return root_tag, collected
