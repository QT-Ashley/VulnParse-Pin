# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple, TYPE_CHECKING
from lxml import etree

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


_CREDENTIALED_QOD_TYPES = frozenset(
    {"package", "registry", "executable_version", "authenticated", "ssh_func"}
)
_GVM_ROOT_TAGS = frozenset(
    {"report", "get_reports_response", "omp", "get_results_response"}
)


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


def _is_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


class OpenVASXMLParser(BaseParser):
    NAME = "openvas-xml"

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
        """
        Bounded (<= 64 KB) detection for OpenVAS/GVM XML exports.
        Hard negative gate: any NessusClientData_v2 presence -> 0.0.
        """
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

        if root_tag == "NessusClientData_v2" or any(
            ev == "start" and tag == "NessusClientData_v2" for ev, tag, _, _ in events
        ):
            return 0.0, [("rejected", "NessusClientData_v2_found")]

        score = 0.0
        if root_tag in _GVM_ROOT_TAGS:
            score += 0.20
            evidence.append(("root_tag", root_tag))

        # Track element path depth for results//result, nvt, creation_time, host
        stack: list[str] = []
        saw_result = False
        saw_nvt = False
        first_oid: Optional[str] = None
        saw_creation_time = False
        host_count = 0

        for ev, tag, attrib, text in events:
            if ev == "start":
                stack.append(tag)
                if tag == "result" and "results" in stack[:-1]:
                    saw_result = True
                elif tag == "nvt":
                    saw_nvt = True
                    if first_oid is None:
                        first_oid = attrib.get("oid", "")
                elif tag == "host":
                    host_count += 1
            elif ev == "end":
                if tag == "creation_time" and (text or "").strip():
                    saw_creation_time = True
                if stack:
                    stack.pop()

        if saw_result:
            score += 0.30
            evidence.append(("structure", "results//result"))

        if saw_nvt:
            score += 0.25
            evidence.append(("structure", "nvt"))
            if first_oid and re.match(r"^\d+(\.\d+)+$", first_oid):
                score += 0.10
                evidence.append(("nvt_oid", first_oid[:40]))

        if saw_creation_time:
            score += 0.05
            evidence.append(("meta", "creation_time"))

        if host_count > 0:
            score += 0.05
            evidence.append(("structure", f"host_count={host_count}"))

        return min(score, 1.0), evidence

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        path = self._validate_filepath_and_size()
        return self._stream_batches(path, batch_size)

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        dropped = 0
        scan_date: Optional[str] = None
        scan_name: Optional[str] = None
        inside_result = False

        try:
            with self._open_read(path, self.ctx, mode="rb", label="OpenVAS XML") as fh:
                for event, elem in safe_iterparse(fh, events=("start", "end")):
                    tag = elem.tag if isinstance(elem.tag, str) else ""

                    if event == "start":
                        if tag == "report":
                            rid = elem.get("id")
                            if rid and (scan_name is None or scan_name == "SENTINEL:Not_Found"):
                                scan_name = rid
                        elif tag == "result":
                            inside_result = True
                        continue

                    # event == "end"
                    if tag == "creation_time" and not inside_result and not scan_date:
                        ct = (elem.text or "").strip()
                        if ct:
                            scan_date = ct
                    elif tag in {"ports", "tls_certificates", "host"} and not inside_result:
                        prune_element(elem)
                    elif tag == "result":
                        inside_result = False
                        rec = self._extract_result_record(elem)
                        prune_element(elem)
                        if rec is None:
                            dropped += 1
                            continue
                        batch.append(rec)
                        if len(batch) >= batch_size:
                            yield batch
                            batch = []
        except (OSError, etree.XMLSyntaxError) as exc:
            raise ValueError(f"Failed to parse XML: {exc}") from exc

        if dropped:
            self.ctx.logger.debug("Dropped '%s' malformed OpenVAS result(s) with no host.", dropped)

        if self._collecting_for_parse:
            self._last_scan_meta = {
                "scan_name": scan_name or "SENTINEL:Not_Found",
                "scan_date": scan_date or "SENTINEL:Date_Unavailable",
                "empty_assets": [],
            }

        if batch:
            yield batch

    def _extract_result_record(self, result: etree._Element) -> Optional[NormalizedFindingRecord]:
        host_elem = result.find("host")
        inner_hostname = (
            (host_elem.findtext("hostname") or "").strip()
            if host_elem is not None
            else ""
        )
        raw_host = ((host_elem.text or "").strip() if host_elem is not None else "") or inner_hostname
        if not raw_host:
            self.ctx.logger.warning(
                "Dropping Openvas result with no host entry — malformed or incomplete XML <result> block."
            )
            return None
        if _is_ip(raw_host):
            ip_address: Optional[str] = raw_host
            hostname: Optional[str] = inner_hostname or raw_host
        else:
            ip_address = None
            hostname = raw_host

        port_raw = result.findtext("port")
        port = self._safe_int(self._parse_port(port_raw))
        if port is not None and not (0 <= port <= 65535):
            port = None
        protocol = self._safe_text(self._parse_protocol(port_raw))
        if protocol == "SENTINEL:Protocol_Unknown":
            protocol = None
        elif protocol:
            protocol = protocol.lower()

        description = self._safe_text(result.findtext("description")) or ""
        raw_threat = self._safe_text(result.findtext("threat"))
        raw_sev_score = self._safe_float(result.findtext("severity"))

        nvt_field = result.find("nvt")
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        cves: List[str] = []
        cwes: List[str] = []
        references: List[str] = []
        tags_list: List[str] = []
        oid = "SENTINEL:No_OID"

        if nvt_field is not None:
            oid = (nvt_field.attrib.get("oid") or "").strip() or "SENTINEL:No_OID"
            tags_str = nvt_field.findtext("tags") or ""
            title = (
                self._safe_text(nvt_field.findtext("name"))
                or self._safe_text(result.findtext("name"))
                or "SENTINEL:No_Title"
            )
            cvss_score, cvss_vector = self._extract_cvss(nvt_field, result)
            solution = self._safe_text(nvt_field.findtext("solution")) or self._safe_text(result.findtext("solution")) or ""
            plugin_output = self._extract_from_tags(tags_str, "summary=") or ""
            cves = self._extract_cves(nvt_field, result)
            cwes = self._extract_cwes(nvt_field, result, tags_str, description)
            references = self._extract_references(nvt_field, tags_str)
            family = self._safe_text(nvt_field.findtext("family"))
            if family:
                tags_list.append(family)
        else:
            tags_str = ""
            title = self._safe_text(result.findtext("name")) or "SENTINEL:No_Title_Found"
            cvss_score = raw_sev_score if raw_sev_score is not None else 0.0
            solution = self._safe_text(result.findtext("solution")) or ""
            plugin_output = ""
            cves = []
            cwes = extract_cwes_from_text(description)

        detection = result.find("detection")
        det_evidence: List[str] = []
        if detection is not None:
            for detail in detection.findall(".//detail"):
                dname = detail.findtext("name") or "Unknown"
                dval = detail.findtext("value") or "N/A"
                det_evidence.append(f"{dname}: {dval}")

        if not plugin_output and det_evidence:
            plugin_output = "; ".join(det_evidence)

        qod_type = self._safe_text(result.findtext(".//qod/type")) or ""
        if qod_type.lower() in _CREDENTIALED_QOD_TYPES:
            detection_mode = "credentialed_host"
            credentialed = True
        else:
            detection_mode = "uncredentialed_banner"
            credentialed = False

        if cvss_score is None and raw_sev_score is not None and 0.0 <= raw_sev_score <= 10.0:
            cvss_score = raw_sev_score

        severity = normalize_severity(raw_threat, cvss_score)
        ghsa_ids = extract_ghsas_from_text(description, " ".join(references))

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
            ingestion_confidence = 0.75
        else:
            fidelity_tier = "low"
            ingestion_confidence = 0.50

        scanner_sig = f"openvas:{oid}" if oid != "SENTINEL:No_OID" else "No_SigID"

        return {
            "ip_address": ip_address,
            "hostname": hostname,
            "target_uri": None,
            "image_or_repo": None,
            "os": None,
            "asset_metadata": {
                "credentialed": credentialed,
                "open_ports": [port] if port is not None else [],
                "qod_type": qod_type or None,
            },
            "source_format": "openvas-xml",
            "scanner_sig": scanner_sig,
            "title": title,
            "description": description,
            "solution": solution,
            "plugin_output": plugin_output,
            "severity": severity,
            "cves": cves,
            "cwes": cwes,
            "ghsa_ids": ghsa_ids,
            "affected_port": port,
            "protocol": protocol,
            "service_name": None,
            "location_uri": None,
            "line_number": None,
            "package_purl": None,
            "scanner_cvss_score": cvss_score,
            "scanner_cvss_vector": cvss_vector,
            "detection_mode": detection_mode,
            "fidelity_tier": fidelity_tier,
            "ingestion_confidence": ingestion_confidence,
            "missing_fields": missing_fields,
            "degraded_input": fidelity_tier != "high",
            "references": references,
            "tags": tags_list,
            "exploit_evidence": None,
            "raw_evidence_excerpt": safe_excerpt(plugin_output or description),
        }

    def parse(self) -> ScanResult:
        """Parse OpenVAS XML into ScanResult object in a single streaming pass."""
        return self._build_scan_result_from_batches(source_label="OpenVAS")

    def _extract_cves(self, nvt_elem, result_elem) -> List[str]:
        cves: List[str] = []
        if nvt_elem is not None:
            for ref in nvt_elem.findall(".//refs/ref[@type='cve']"):
                raw = (ref.get("id") or (ref.text or "")).strip()
                if raw:
                    cves.extend(extract_cves_from_text(raw))

        tags_text = []
        if nvt_elem is not None:
            tags_text.append(self._safe_text(nvt_elem.findtext("tags")))
            tags_text.append(self._safe_text(nvt_elem.findtext("description")))
        tags_text.append(self._safe_text(result_elem.findtext("tags")))
        tags_text.append(self._safe_text(result_elem.findtext("description")))

        for match in extract_cves_from_text(*(t for t in tags_text if t)):
            cves.append(match)

        seen: set[str] = set()
        out: List[str] = []
        for cv in cves:
            if cv and cv not in seen:
                seen.add(cv)
                out.append(cv)
        return out

    def _extract_cwes(self, nvt_elem, result_elem, tags_str: str, description: str) -> List[str]:
        texts = [tags_str, description]
        if nvt_elem is not None:
            for ref in nvt_elem.findall(".//refs/ref[@type='cwe']"):
                raw = (ref.get("id") or (ref.text or "")).strip()
                if raw:
                    texts.append(raw)
        if result_elem is not None:
            texts.append(self._safe_text(result_elem.findtext("tags")) or "")
        return extract_cwes_from_text(*texts)

    def _extract_references(self, nvt_elem, tags_str: str) -> List[str]:
        refs: List[str] = []
        if nvt_elem is not None:
            for ref in nvt_elem.findall(".//refs/ref"):
                rtype = (ref.get("type") or "").strip().lower()
                if rtype in {"url", "xref"}:
                    val = (ref.get("id") or (ref.text or "")).strip()
                    if val and val not in refs:
                        refs.append(val)
            xref_text = (nvt_elem.findtext("xref") or "").strip()
            if xref_text and xref_text.upper() != "NOXREF":
                for part in xref_text.split(","):
                    cleaned = part.strip()
                    if cleaned and cleaned not in refs:
                        refs.append(cleaned)
        see_also = self._extract_from_tags(tags_str, "see_also=")
        if see_also:
            for part in see_also.split(","):
                cleaned = part.strip()
                if cleaned and cleaned not in refs:
                    refs.append(cleaned)
        return refs

    def _extract_cvss(self, nvt_elem, result_elem) -> Tuple[Optional[float], Optional[str]]:
        v4_scores: List[Optional[str]] = [
            nvt_elem.findtext("cvss4_base") if nvt_elem is not None else None,
            result_elem.findtext("cvss4_base"),
        ]
        v3_scores: List[Optional[str]] = [
            nvt_elem.findtext("cvss3_base") if nvt_elem is not None else None,
            result_elem.findtext("cvss3_base"),
        ]
        v2_scores: List[Optional[str]] = [
            nvt_elem.findtext("cvss_base") if nvt_elem is not None else None,
            result_elem.findtext("cvss_base"),
            nvt_elem.findtext("cvss_base_score") if nvt_elem is not None else None,
            result_elem.findtext("cvss_base_score"),
        ]

        v4_vectors: List[Optional[str]] = [
            nvt_elem.findtext("cvss4_vector") if nvt_elem is not None else None,
            result_elem.findtext("cvss4_vector"),
        ]
        v3_vectors: List[Optional[str]] = [
            nvt_elem.findtext("cvss3_vector") if nvt_elem is not None else None,
            result_elem.findtext("cvss3_vector"),
        ]
        v2_vectors: List[Optional[str]] = [
            nvt_elem.findtext("cvss_base_vector") if nvt_elem is not None else None,
            nvt_elem.findtext("cvss_vector") if nvt_elem is not None else None,
            result_elem.findtext("cvss_vector"),
        ]

        if nvt_elem is not None:
            for sev_node in nvt_elem.findall(".//severities/severity"):
                stype = (sev_node.get("type") or "").strip().lower()
                val = (sev_node.findtext("value") or "").strip()
                sc = sev_node.findtext("score") or sev_node.get("score")
                if "v4" in stype or "4.0" in stype or val.upper().startswith("CVSS:4."):
                    if sc:
                        v4_scores.append(sc)
                    if val:
                        v4_vectors.append(val)
                elif "v3" in stype or "3." in stype or val.upper().startswith("CVSS:3."):
                    if sc:
                        v3_scores.append(sc)
                    if val:
                        v3_vectors.append(val)
                else:
                    if sc:
                        v2_scores.append(sc)
                    if val:
                        v2_vectors.append(val)

        tag_texts = []
        if nvt_elem is not None:
            tag_texts.append(self._safe_text(nvt_elem.findtext("tags")))
        tag_texts.append(self._safe_text(result_elem.findtext("tags")))

        for tags in tag_texts:
            if not tags:
                continue
            v4_vec = self._extract_from_tags(tags, "cvss4_vector=")
            if v4_vec:
                v4_vectors.append(v4_vec)
            v3_vec = self._extract_from_tags(tags, "cvss3_vector=")
            if v3_vec:
                v3_vectors.append(v3_vec)
            base_vec = self._extract_from_tags(tags, "cvss_base_vector=")
            if base_vec:
                norm_bv = _normalize_cvss_vector(base_vec) or ""
                if norm_bv.upper().startswith("CVSS:4."):
                    v4_vectors.append(norm_bv)
                elif norm_bv.upper().startswith("CVSS:3."):
                    v3_vectors.append(norm_bv)
                else:
                    v2_vectors.append(base_vec)

        score: Optional[float] = None
        for raw_s in (*v4_scores, *v3_scores, *v2_scores):
            if not raw_s:
                continue
            val = self._safe_float(raw_s)
            if val is not None and 0.0 <= val <= 10.0:
                score = val
                break

        vector: Optional[str] = None
        for raw_v in (*v4_vectors, *v3_vectors, *v2_vectors):
            norm = _normalize_cvss_vector(self._safe_text(raw_v) if raw_v else None)
            if norm:
                vector = norm
                break

        return score, vector

    @staticmethod
    def _extract_nvd_oid(result_elem) -> Optional[str]:
        nvt = result_elem.find("nvt")
        if nvt is not None:
            return nvt.get("oid")
        return None

    @staticmethod
    def _parse_port(port_field: Optional[str]) -> Optional[int]:
        if not port_field:
            return None
        try:
            return int(port_field.split("/")[0])
        except ValueError:
            return None

    @staticmethod
    def _parse_protocol(port_field: Optional[str]) -> Optional[str]:
        if not port_field or "/" not in port_field:
            return None
        return port_field.split("/")[1]

    @staticmethod
    def _extract_from_tags(tags_text: str, key: str) -> Optional[str]:
        if not tags_text or key not in tags_text:
            return None
        for item in tags_text.split("|"):
            if item.strip().startswith(key):
                return item.split("=", 1)[1].strip()
        return None
