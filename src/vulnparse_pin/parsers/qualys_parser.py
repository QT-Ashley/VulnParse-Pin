# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, TYPE_CHECKING
from lxml import etree

from vulnparse_pin.core.id import make_asset_id
from vulnparse_pin.parsers._xml_security import (
    prune_element,
    safe_iterparse,
    sniff_xml_head_events,
)
from vulnparse_pin.parsers.base_parser import (
    BaseParser,
    NormalizedFindingRecord,
    extract_cves_from_text,
    extract_cwes_from_text,
    extract_ghsas_from_text,
    normalize_severity,
    safe_excerpt,
)
from vulnparse_pin.core.classes.dataclass import ScanResult

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


_QUALYS_ROOT_TAGS = frozenset(
    {"SCAN", "SCAN_REPORT", "ASSET_DATA_REPORT", "HOST_LIST_VM_DETECTION_OUTPUT"}
)
_ASSET_TAGS = frozenset({"ASSET", "HOST"})
_VULN_TAGS = frozenset({"VULN", "VULNERABILITY", "VULN_INFO", "DETECTION"})
_QID_TAGS = frozenset({"QID", "QID_ID", "VULN_ID"})
_TITLE_TAGS = frozenset({"TITLE", "NAME", "VULN_TITLE"})
_PRIMARY_DESC_TAGS = frozenset({"DESCRIPTION", "DIAGNOSIS", "DETAILS"})
_SECONDARY_DESC_TAGS = frozenset({"THREAT", "IMPACT"})
_PORT_TAGS = frozenset({"PORT", "SERVICE_PORT", "AFFECTED_PORT"})
_PROTO_TAGS = frozenset({"PROTOCOL", "PROTO"})

_CVSS_V4_BASE_TAGS = ("CVSS4_BASE", "CVSS_V4_BASE", "CVSS40_BASE")
_CVSS_V31_BASE_TAGS = ("CVSS3_1_BASE", "CVSS31_BASE", "CVSS_V3_1_BASE", "CVSS3.1_BASE")
_CVSS_V3_BASE_TAGS = ("CVSS3_BASE", "CVSS_V3_BASE")
_CVSS_V2_BASE_TAGS = ("CVSS_BASE", "CVSS2_BASE", "CVSS_V2_BASE", "CVSS_SCORE")
_CVSS_BASE_TAG_GROUPS = (
    _CVSS_V4_BASE_TAGS,
    _CVSS_V31_BASE_TAGS,
    _CVSS_V3_BASE_TAGS,
    _CVSS_V2_BASE_TAGS,
)
_CVSS_BASE_TAGS = frozenset(
    (*_CVSS_V4_BASE_TAGS, *_CVSS_V31_BASE_TAGS, *_CVSS_V3_BASE_TAGS, *_CVSS_V2_BASE_TAGS)
)

_CVSS_V4_VEC_TAGS = ("CVSS4_VECTOR", "CVSS_V4_VECTOR", "CVSS40_VECTOR")
_CVSS_V31_VEC_TAGS = ("CVSS3_1_VECTOR", "CVSS31_VECTOR", "CVSS_V3_1_VECTOR", "CVSS3.1_VECTOR")
_CVSS_V3_VEC_TAGS = ("CVSS3_VECTOR", "CVSS_V3_VECTOR")
_CVSS_V2_VEC_TAGS = ("CVSS_VECTOR", "CVSS2_VECTOR", "CVSS_V2_VECTOR")
_CVSS_VEC_TAG_GROUPS = (
    _CVSS_V4_VEC_TAGS,
    _CVSS_V31_VEC_TAGS,
    _CVSS_V3_VEC_TAGS,
    _CVSS_V2_VEC_TAGS,
)
_CVSS_VEC_TAGS = frozenset(
    (*_CVSS_V4_VEC_TAGS, *_CVSS_V31_VEC_TAGS, *_CVSS_V3_VEC_TAGS, *_CVSS_V2_VEC_TAGS)
)

_CVE_TAGS = frozenset({"CVE_ID", "CVE", "CVES"})
_CWE_TAGS = frozenset({"CWE_ID", "CWE", "CWES"})
_SOL_TAGS = frozenset({"SOLUTION", "FIX", "REMEDIATION"})
_RES_TAGS = frozenset({"RESULTS", "RESULT", "EVIDENCE", "DIAGNOSIS"})
_SEV_TAGS = ("SEVERITY", "RISK", "THREAT")
_SEVERITY_TOKENS = frozenset(
    {"1", "2", "3", "4", "5", "critical", "high", "medium", "low", "info", "informational"}
)
_IP_TAGS = frozenset({"IP", "IP_ADDRESS", "HOST_IP"})
_FQDN_TAGS = frozenset({"FQDN", "HOSTNAME", "DNS", "DNS_NAME", "NETBIOS"})
_HOST_TAG_PRIORITY = {"FQDN": 4, "DNS": 3, "DNS_NAME": 3, "HOSTNAME": 2, "NETBIOS": 1}
_OS_TAGS = frozenset({"OS", "OPERATING_SYSTEM"})
_SCAN_DATE_TAGS = frozenset(
    {"SCAN_DATETIME", "SCAN_DATE", "DATETIME", "GENERATION_DATETIME", "CREATED"}
)
_SCAN_NAME_TAGS = frozenset({"TITLE", "SCAN_TITLE", "NAME"})


def _normalize_cvss_vector(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.startswith("SENTINEL:"):
        return None
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        s = s[1:-1].strip()
    if "#" in s:
        prefix, rest = s.split("#", 1)
        if prefix.upper().startswith("CVSS"):
            s = rest.strip()
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        s = s[1:-1].strip()
    return s or None


def _norm_qid(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = str(raw).strip()
    if s.lower().startswith("qid_"):
        s = s[4:].strip()
    return s or None


def _local_name(tag: str) -> str:
    if not tag:
        return ""
    return str(tag).split("}")[-1].strip().upper()


def _iter_by_local(root, names: Iterable[str]):
    wanted = {str(n).strip().upper() for n in names}
    for elem in root.iter():
        if _local_name(elem.tag) in wanted:
            yield elem


def _first_text_by_local(root, names: Iterable[str]) -> Optional[str]:
    for elem in _iter_by_local(root, names):
        text = (elem.text or "").strip()
        if text:
            return text
    return None


def _is_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


class QualysXMLParser(BaseParser):
    """Streaming lxml Qualys XML report parser for vulnerability findings."""

    NAME = "qualys-xml"

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
        """Bounded (<= 64 KB) detection for Qualys XML exports."""
        evidence: list[tuple[str, str]] = []
        path = Path(filepath)
        if path.suffix.lower() != ".xml":
            return 0.0, [("extension", f"rejected:{path.suffix}")]

        try:
            max_bytes = cls._max_bytes_for(path, ctx=ctx, allow_large=allow_large)
            if path.stat().st_size > max_bytes:
                return 0.0, [("size", "exceeds_limit")]
            head = cls._read_head_bytes(path, ctx=ctx, head_bytes=head_bytes)
            root_tag, events = sniff_xml_head_events(head)
        except Exception:
            return 0.0, [("parse", "failed")]

        score = 0.0
        root_name = _local_name(root_tag or "")
        if root_name in _QUALYS_ROOT_TAGS:
            score += 0.30
            evidence.append(("root_tag", root_name))
        else:
            return 0.0, [("root_tag", f"rejected:{root_name or root_tag}")]

        asset_count = 0
        vuln_count = 0
        first_qid: Optional[str] = None
        saw_cvss = False
        saw_asset_id = False
        saw_enterprise_list = False
        in_first_vuln = False

        for ev, tag, attrib, text in events:
            lname = _local_name(tag)
            if ev == "start":
                if lname in _ASSET_TAGS:
                    asset_count += 1
                elif lname in _VULN_TAGS:
                    vuln_count += 1
                    if vuln_count == 1:
                        in_first_vuln = True
                elif lname in {
                    "HOST_LIST",
                    "VULN_INFO_LIST",
                    "DETECTION_LIST",
                    "GLOSSARY",
                    "VULN_DETAILS_LIST",
                }:
                    saw_enterprise_list = True
            elif ev == "end":
                txt = (text or "").strip()
                if in_first_vuln and lname in _QID_TAGS and first_qid is None:
                    cand_qid = _norm_qid(txt or attrib.get("id"))
                    if cand_qid:
                        first_qid = cand_qid
                if lname in _VULN_TAGS and in_first_vuln:
                    in_first_vuln = False
                if txt and lname in (_CVSS_BASE_TAGS | _CVSS_VEC_TAGS):
                    saw_cvss = True
                if txt and lname in (_IP_TAGS | _FQDN_TAGS):
                    saw_asset_id = True

        if asset_count > 0:
            score += 0.25
            evidence.append(("structure", f"asset_count={asset_count}"))
        elif saw_enterprise_list and root_name in {
            "ASSET_DATA_REPORT",
            "HOST_LIST_VM_DETECTION_OUTPUT",
        }:
            score += 0.25
            evidence.append(("structure", "enterprise_list"))

        if vuln_count > 0:
            score += 0.25
            evidence.append(("structure", f"vuln_count={vuln_count}"))

        if first_qid and re.match(r"^\d+$", first_qid):
            score += 0.10
            evidence.append(("qid", f"numeric:{first_qid[:10]}"))

        if saw_cvss:
            score += 0.05
            evidence.append(("meta", "cvss_present"))

        if saw_asset_id:
            score += 0.05
            evidence.append(("asset_id", "ip_or_fqdn"))

        return min(score, 1.0), evidence

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        path = self._validate_filepath_and_size()
        return self._stream_batches(path, batch_size)

    def _preload_asset_data_glossary(self, path: Path) -> Dict[str, Dict[str, Any]]:
        glossary: Dict[str, Dict[str, Any]] = {}
        in_glossary = False
        in_details = False
        try:
            with self._open_read(path, self.ctx, mode="rb", label="Qualys XML") as fh:
                for event, elem in safe_iterparse(fh, events=("start", "end")):
                    lname = _local_name(elem.tag if isinstance(elem.tag, str) else "")
                    if event == "start":
                        if lname == "GLOSSARY":
                            in_glossary = True
                        elif in_glossary and lname == "VULN_DETAILS":
                            in_details = True
                        continue

                    if in_glossary and lname == "VULN_DETAILS":
                        in_details = False
                        self._register_glossary_entry(elem, glossary)
                        prune_element(elem)
                    elif lname == "GLOSSARY":
                        in_glossary = False
                        prune_element(elem)
                    elif not in_details and lname in {"HEADER", "HOST", "VULN_INFO", "VULN", "DETECTION"}:
                        prune_element(elem)
        except (OSError, etree.XMLSyntaxError) as exc:
            raise ValueError(f"Failed to parse XML: {exc}") from exc
        return glossary

    def _register_glossary_entry(
        self, details_elem: etree._Element, glossary: Dict[str, Dict[str, Any]]
    ) -> None:
        raw_vuln = self._extract_raw_vuln(details_elem, from_glossary=True)
        keys: set[str] = set()
        if raw_vuln.get("qid"):
            keys.add(str(raw_vuln["qid"]))
        attr_qid = _norm_qid(details_elem.get("id"))
        if attr_qid:
            keys.add(attr_qid)
        for qnode in _iter_by_local(details_elem, _QID_TAGS):
            for cand in (_norm_qid(qnode.text), _norm_qid(qnode.get("id"))):
                if cand:
                    keys.add(cand)
        for key in keys:
            glossary[key] = raw_vuln

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        dropped = 0
        scan_date: Optional[str] = None
        scan_name: Optional[str] = None
        root_checked = False
        root_tag_name = ""
        empty_assets: List[Dict[str, Any]] = []

        in_glossary = False
        glossary_seen = False
        glossary_preloaded = False
        glossary_by_qid: Dict[str, Dict[str, Any]] = {}

        in_asset = False
        asset_depth = 0
        in_vuln = False
        vuln_depth = 0
        asset_ip: Optional[str] = None
        asset_fqdn: Optional[str] = None
        asset_fqdn_rank = 0
        asset_os: Optional[str] = None
        asset_cred = False
        asset_vuln_count = 0
        pending_vulns: List[Dict[str, Any]] = []

        try:
            with self._open_read(path, self.ctx, mode="rb", label="Qualys XML") as fh:
                for event, elem in safe_iterparse(fh, events=("start", "end")):
                    lname = _local_name(elem.tag if isinstance(elem.tag, str) else "")

                    if event == "start":
                        if not root_checked:
                            root_checked = True
                            root_tag_name = lname
                            if lname not in _QUALYS_ROOT_TAGS:
                                raise ValueError(
                                    f"Qualys XML missing expected root tag. got={lname or elem.tag}"
                                )
                            if not scan_name and elem.attrib.get("id"):
                                scan_name = elem.attrib.get("id")
                        if lname == "GLOSSARY" and not in_asset:
                            in_glossary = True
                        elif lname == "HOST_LIST" and not in_asset:
                            if (
                                root_tag_name == "ASSET_DATA_REPORT"
                                and not glossary_seen
                                and not glossary_preloaded
                            ):
                                glossary_by_qid = self._preload_asset_data_glossary(path)
                                glossary_preloaded = True
                        elif lname in _ASSET_TAGS and not in_glossary:
                            asset_depth += 1
                            if asset_depth == 1:
                                in_asset = True
                                asset_ip = None
                                asset_fqdn = None
                                asset_fqdn_rank = 0
                                asset_os = None
                                asset_cred = False
                                asset_vuln_count = 0
                                pending_vulns = []
                        elif lname in _VULN_TAGS and in_asset:
                            vuln_depth += 1
                            in_vuln = True
                        continue

                    # event == "end"
                    if in_glossary:
                        if lname == "VULN_DETAILS":
                            if not glossary_preloaded:
                                self._register_glossary_entry(elem, glossary_by_qid)
                            prune_element(elem)
                        elif lname == "GLOSSARY":
                            in_glossary = False
                            glossary_seen = True
                            prune_element(elem)
                        continue

                    if not in_asset:
                        txt = (elem.text or "").strip()
                        if txt and lname in _SCAN_DATE_TAGS and not scan_date:
                            scan_date = txt
                        elif (
                            txt
                            and lname == "KEY"
                            and (elem.get("value") or "").strip().upper() == "REPORT_TITLE"
                            and not scan_name
                        ):
                            scan_name = txt
                        elif txt and lname in _SCAN_NAME_TAGS and not scan_name:
                            scan_name = txt
                        if lname == "HEADER":
                            prune_element(elem)
                        continue

                    if not in_vuln:
                        txt = (elem.text or "").strip()
                        if txt and lname in _IP_TAGS and not asset_ip:
                            asset_ip = txt
                        elif txt and lname in _FQDN_TAGS:
                            rank = _HOST_TAG_PRIORITY.get(lname, 1)
                            if not asset_fqdn or rank > asset_fqdn_rank:
                                asset_fqdn = txt
                                asset_fqdn_rank = rank
                        elif txt and lname in _OS_TAGS and not asset_os:
                            asset_os = txt
                        elif txt and lname in {"AUTHENTICATION", "AUTH_STATUS", "CREDENTIALED"}:
                            if txt.lower() in {"yes", "true", "passed", "authenticated", "1"}:
                                asset_cred = True
                        elif txt and lname == "HOST" and asset_depth > 1:
                            if _is_ip(txt) and not asset_ip:
                                asset_ip = txt
                            elif not asset_fqdn:
                                asset_fqdn = txt
                                asset_fqdn_rank = 1

                        if (asset_ip or asset_fqdn) and pending_vulns:
                            host_ctx = self._make_host_ctx(asset_ip, asset_fqdn, asset_os, asset_cred)
                            for raw_vuln in pending_vulns:
                                rec = self._finalize_record(raw_vuln, host_ctx)
                                batch.append(rec)
                                asset_vuln_count += 1
                                if len(batch) >= batch_size:
                                    yield batch
                                    batch = []
                            pending_vulns.clear()

                        if lname in _ASSET_TAGS:
                            asset_depth = max(0, asset_depth - 1)
                            if asset_depth == 0:
                                if not (asset_ip or asset_fqdn):
                                    self.ctx.logger.warning(
                                        "Dropping Qualys ASSET with no IP or FQDN entry — malformed or incomplete XML."
                                    )
                                    dropped += 1
                                    pending_vulns.clear()
                                else:
                                    host_ctx = self._make_host_ctx(asset_ip, asset_fqdn, asset_os, asset_cred)
                                    if self._collecting_for_parse and asset_vuln_count == 0:
                                        canon_id = make_asset_id(
                                            ip=host_ctx["ip_address"] or host_ctx["fallback_host"],
                                            hostname=host_ctx["hostname"] or host_ctx["fallback_host"],
                                        )
                                        empty_assets.append(
                                            {
                                                "lookup_key": canon_id,
                                                "asset_id": canon_id,
                                                "hostname": host_ctx["hostname"] or host_ctx["fallback_host"],
                                                "ip_address": host_ctx["ip_address"] or host_ctx["fallback_host"],
                                                "os": host_ctx["os"],
                                            }
                                        )
                                in_asset = False
                                prune_element(elem)
                    else:
                        if lname in _VULN_TAGS:
                            vuln_depth = max(0, vuln_depth - 1)
                            if vuln_depth == 0:
                                raw_vuln = self._extract_raw_vuln(
                                    elem, glossary_by_qid=glossary_by_qid
                                )
                                in_vuln = False
                                prune_element(elem)
                                if asset_ip or asset_fqdn:
                                    host_ctx = self._make_host_ctx(asset_ip, asset_fqdn, asset_os, asset_cred)
                                    rec = self._finalize_record(raw_vuln, host_ctx)
                                    batch.append(rec)
                                    asset_vuln_count += 1
                                    if len(batch) >= batch_size:
                                        yield batch
                                        batch = []
                                else:
                                    pending_vulns.append(raw_vuln)
        except (OSError, etree.XMLSyntaxError) as exc:
            raise ValueError(f"Failed to parse XML: {exc}") from exc

        if not root_checked:
            raise ValueError("Failed to parse XML: empty document.")

        if dropped > 0:
            self.ctx.logger.warning(f"Dropped {dropped} malformed ASSET entries during parsing.")

        if self._collecting_for_parse:
            self._last_scan_meta = {
                "scan_name": scan_name or path.stem,
                "scan_date": scan_date,
                "empty_assets": empty_assets,
            }

        if batch:
            yield batch

    def parse(self) -> ScanResult:
        """Parse Qualys XML into ScanResult object in a single streaming pass."""
        return self._build_scan_result_from_batches(
            source_label="Qualys",
            detection_plugin_prefix="Qualys",
        )

    @staticmethod
    def _make_host_ctx(
        asset_ip: Optional[str],
        asset_fqdn: Optional[str],
        asset_os: Optional[str],
        credentialed: bool,
    ) -> Dict[str, Any]:
        ip_val = asset_ip or (asset_fqdn if asset_fqdn and _is_ip(asset_fqdn) else None)
        host_val = asset_fqdn or asset_ip
        fallback = ip_val or host_val or "unknown"
        return {
            "ip_address": ip_val,
            "hostname": host_val,
            "fallback_host": fallback,
            "os": asset_os,
            "credentialed": credentialed,
        }

    def _extract_raw_vuln(
        self,
        vuln: etree._Element,
        *,
        glossary_by_qid: Optional[Dict[str, Dict[str, Any]]] = None,
        from_glossary: bool = False,
    ) -> Dict[str, Any]:
        qid: Optional[str] = None
        for qnode in _iter_by_local(vuln, _QID_TAGS):
            qid = _norm_qid(qnode.text) or _norm_qid(qnode.get("id"))
            if qid:
                break
        if not qid and from_glossary:
            qid = _norm_qid(vuln.get("id"))

        raw_title = self._safe_text(_first_text_by_local(vuln, _TITLE_TAGS))
        description = self._safe_text(_first_text_by_local(vuln, _PRIMARY_DESC_TAGS)) or ""
        if not description:
            sec_parts: List[str] = []
            for sec_el in _iter_by_local(vuln, _SECONDARY_DESC_TAGS):
                sec_txt = self._safe_text(sec_el.text)
                if not sec_txt:
                    continue
                if _local_name(sec_el.tag) == "THREAT" and sec_txt.lower() in _SEVERITY_TOKENS:
                    continue
                if sec_txt not in sec_parts:
                    sec_parts.append(sec_txt)
            description = " ".join(sec_parts)

        port: Optional[int] = None
        protocol: Optional[str] = None
        port_text = _first_text_by_local(vuln, _PORT_TAGS)
        if port_text:
            parts = [p.strip().lower() for p in str(port_text).split("/") if p.strip()]
            if len(parts) == 2 and parts[0].isdigit():
                port = self._safe_int(parts[0])
                protocol = parts[1]
            elif len(parts) == 2 and parts[1].isdigit():
                protocol = parts[0]
                port = self._safe_int(parts[1])
            else:
                port = self._safe_int(parts[0] if parts else port_text)

        if not protocol:
            proto_node = _first_text_by_local(vuln, _PROTO_TAGS)
            if proto_node:
                protocol = proto_node.strip().lower()

        protocol = (protocol or "tcp").lower()
        if protocol not in {"tcp", "udp", "icmp"}:
            protocol = "tcp"
        if port is not None and not (0 <= int(port) <= 65535):
            port = None

        cvss_score: Optional[float] = None
        for tag_group in _CVSS_BASE_TAG_GROUPS:
            for candidate_el in _iter_by_local(vuln, tag_group):
                candidate_txt = (candidate_el.text or "").strip()
                if not candidate_txt:
                    continue
                parsed = self._safe_float(candidate_txt)
                if parsed is not None and 0.0 <= parsed <= 10.0:
                    cvss_score = parsed
                    break
            if cvss_score is not None:
                break

        cvss_vector: Optional[str] = None
        for tag_group in _CVSS_VEC_TAG_GROUPS:
            for candidate_el in _iter_by_local(vuln, tag_group):
                norm_vec = _normalize_cvss_vector(self._safe_text(candidate_el.text))
                if norm_vec:
                    cvss_vector = norm_vec
                    break
            if cvss_vector is not None:
                break

        cve_text = " ".join(
            " ".join(t.strip() for t in e.itertext() if t and t.strip())
            for e in _iter_by_local(vuln, _CVE_TAGS)
        )
        cves = extract_cves_from_text(cve_text)

        cwe_text = " ".join(
            " ".join(t.strip() for t in e.itertext() if t and t.strip())
            for e in _iter_by_local(vuln, _CWE_TAGS)
        )
        cwes = extract_cwes_from_text(cwe_text, description)

        solution = self._safe_text(_first_text_by_local(vuln, _SOL_TAGS)) or ""
        plugin_output = self._safe_text(_first_text_by_local(vuln, _RES_TAGS)) or ""

        raw_sev: Optional[str] = None
        for sev_tag in _SEV_TAGS:
            cand = _first_text_by_local(vuln, (sev_tag,))
            if cand and (sev_tag != "THREAT" or cand.strip().lower() in _SEVERITY_TOKENS):
                raw_sev = cand
                break

        refs: List[str] = []
        for ref_el in _iter_by_local(vuln, {"VENDOR_REFERENCE", "URL", "REFERENCE"}):
            for t in ref_el.itertext():
                txt = (t or "").strip()
                if txt and txt not in refs:
                    refs.append(txt)

        if glossary_by_qid and qid and qid in glossary_by_qid and not from_glossary:
            g = glossary_by_qid[qid]
            if not raw_title and g.get("raw_title"):
                raw_title = g["raw_title"]
            if not description and g.get("description"):
                description = g["description"]
            if not solution and g.get("solution"):
                solution = g["solution"]
            if g.get("cves"):
                cves = sorted(set(cves) | set(g["cves"]))
            if g.get("cwes"):
                seen_cwes = list(cwes)
                for cw in g["cwes"]:
                    if cw not in seen_cwes:
                        seen_cwes.append(cw)
                cwes = seen_cwes
            if g.get("references"):
                for r in g["references"]:
                    if r not in refs:
                        refs.append(r)
            if cvss_score is None and g.get("scanner_cvss_score") is not None:
                cvss_score = g["scanner_cvss_score"]
            if cvss_vector is None and g.get("scanner_cvss_vector") is not None:
                cvss_vector = g["scanner_cvss_vector"]
            if raw_sev is None and g.get("raw_sev") is not None:
                raw_sev = g["raw_sev"]

        title = raw_title or (f"Qualys QID {qid}" if (qid and not from_glossary) else "SENTINEL:No_Title")
        severity = self._map_qualys_severity(raw_sev, cvss_score)
        ghsa_ids = extract_ghsas_from_text(description, " ".join(refs))

        return {
            "qid": qid,
            "raw_title": raw_title,
            "raw_sev": raw_sev,
            "title": title,
            "description": description,
            "solution": solution,
            "plugin_output": plugin_output,
            "affected_port": port,
            "protocol": protocol,
            "severity": severity,
            "cves": cves,
            "cwes": cwes,
            "ghsa_ids": ghsa_ids,
            "scanner_cvss_score": cvss_score,
            "scanner_cvss_vector": cvss_vector,
            "references": refs,
        }

    def _finalize_record(self, raw_vuln: Dict[str, Any], host_ctx: Dict[str, Any]) -> NormalizedFindingRecord:
        cves = raw_vuln["cves"]
        cvss_vector = raw_vuln["scanner_cvss_vector"]
        plugin_output = raw_vuln["plugin_output"]
        port = raw_vuln["affected_port"]

        missing_fields: List[str] = []
        if not cves:
            missing_fields.append("cves")
        if not cvss_vector:
            missing_fields.append("cvss_vector")
        if not plugin_output:
            missing_fields.append("plugin_output")
        if port is None:
            missing_fields.append("affected_port")

        if not missing_fields:
            fidelity_tier = "high"
            ingestion_confidence = 0.95
        elif len(missing_fields) <= 2:
            fidelity_tier = "medium"
            ingestion_confidence = 0.70
        else:
            fidelity_tier = "low"
            ingestion_confidence = 0.45

        qid = raw_vuln["qid"]
        scanner_sig = f"qualys:{qid}" if qid else "qualys:unknown"

        return {
            "ip_address": host_ctx["ip_address"],
            "hostname": host_ctx["hostname"] or host_ctx["fallback_host"],
            "target_uri": None,
            "image_or_repo": None,
            "os": host_ctx["os"],
            "asset_metadata": {
                "credentialed": host_ctx["credentialed"],
                "open_ports": [port] if port is not None else [],
            },
            "source_format": "qualys-xml",
            "scanner_sig": scanner_sig,
            "title": raw_vuln["title"],
            "description": raw_vuln["description"],
            "solution": raw_vuln["solution"],
            "plugin_output": plugin_output,
            "severity": raw_vuln["severity"],
            "cves": list(cves),
            "cwes": list(raw_vuln["cwes"]),
            "ghsa_ids": list(raw_vuln["ghsa_ids"]),
            "affected_port": port,
            "protocol": raw_vuln["protocol"],
            "service_name": None,
            "location_uri": None,
            "line_number": None,
            "package_purl": None,
            "scanner_cvss_score": raw_vuln["scanner_cvss_score"],
            "scanner_cvss_vector": cvss_vector,
            "detection_mode": "credentialed_host" if host_ctx["credentialed"] else "uncredentialed_banner",
            "fidelity_tier": fidelity_tier,
            "ingestion_confidence": ingestion_confidence,
            "missing_fields": missing_fields,
            "degraded_input": fidelity_tier != "high",
            "references": list(raw_vuln["references"]),
            "tags": [],
            "exploit_evidence": None,
            "raw_evidence_excerpt": safe_excerpt(plugin_output or raw_vuln["description"]),
        }

    @staticmethod
    def _map_qualys_severity(raw: Optional[str], cvss_score: Optional[float] = None) -> str:
        val = str(raw or "").strip().lower()
        mapping = {
            "5": "Critical",
            "4": "High",
            "3": "Medium",
            "2": "Low",
            "1": "Informational",
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
            "informational": "Informational",
        }
        if val in mapping:
            return mapping[val]
        return normalize_severity(raw, cvss_score)
