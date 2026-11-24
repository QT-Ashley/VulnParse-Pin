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


_ASSET_TAGS = frozenset({"ASSET", "HOST"})
_VULN_TAGS = frozenset({"VULN", "VULNERABILITY"})
_QID_TAGS = frozenset({"QID", "QID_ID", "VULN_ID"})
_TITLE_TAGS = frozenset({"TITLE", "NAME", "VULN_TITLE"})
_DESC_TAGS = frozenset({"DESCRIPTION", "DIAGNOSIS", "DETAILS"})
_PORT_TAGS = frozenset({"PORT", "SERVICE_PORT", "AFFECTED_PORT"})
_CVSS_BASE_TAGS = frozenset({"CVSS_BASE", "CVSS3_BASE", "CVSS_SCORE"})
_CVSS_VEC_TAGS = frozenset({"CVSS_VECTOR", "CVSS3_VECTOR"})
_CVE_TAGS = frozenset({"CVE_ID", "CVE", "CVES"})
_CWE_TAGS = frozenset({"CWE_ID", "CWE", "CWES"})
_SOL_TAGS = frozenset({"SOLUTION", "FIX", "REMEDIATION"})
_RES_TAGS = frozenset({"RESULT", "EVIDENCE", "DIAGNOSIS"})
_SEV_TAGS = frozenset({"SEVERITY", "THREAT", "RISK"})
_IP_TAGS = frozenset({"IP", "IP_ADDRESS", "HOST_IP"})
_FQDN_TAGS = frozenset({"FQDN", "HOSTNAME", "DNS"})
_OS_TAGS = frozenset({"OS", "OPERATING_SYSTEM"})
_SCAN_DATE_TAGS = frozenset({"SCAN_DATETIME", "SCAN_DATE", "DATETIME", "CREATED"})
_SCAN_NAME_TAGS = frozenset({"TITLE", "SCAN_TITLE", "NAME"})


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
        if root_name in {"SCAN", "SCAN_REPORT"}:
            score += 0.30
            evidence.append(("root_tag", root_name))
        else:
            return 0.0, [("root_tag", f"rejected:{root_name or root_tag}")]

        asset_count = 0
        vuln_count = 0
        first_qid: Optional[str] = None
        saw_cvss = False
        saw_asset_id = False
        in_first_vuln = False

        for ev, tag, _, text in events:
            lname = _local_name(tag)
            if ev == "start":
                if lname in _ASSET_TAGS:
                    asset_count += 1
                elif lname in _VULN_TAGS:
                    vuln_count += 1
                    if vuln_count == 1:
                        in_first_vuln = True
            elif ev == "end":
                txt = (text or "").strip()
                if in_first_vuln and lname in _QID_TAGS and first_qid is None and txt:
                    first_qid = txt
                if lname in _VULN_TAGS and in_first_vuln:
                    in_first_vuln = False
                if txt and lname in (_CVSS_BASE_TAGS | _CVSS_VEC_TAGS):
                    saw_cvss = True
                if txt and lname in (_IP_TAGS | _FQDN_TAGS):
                    saw_asset_id = True

        if asset_count > 0:
            score += 0.25
            evidence.append(("structure", f"asset_count={asset_count}"))

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

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        dropped = 0
        scan_date: Optional[str] = None
        scan_name: Optional[str] = None
        root_checked = False
        empty_assets: List[Dict[str, Any]] = []

        in_asset = False
        asset_depth = 0
        in_vuln = False
        vuln_depth = 0
        asset_ip: Optional[str] = None
        asset_fqdn: Optional[str] = None
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
                            if lname not in {"SCAN", "SCAN_REPORT"}:
                                raise ValueError(
                                    f"Qualys XML missing expected root tag. got={lname or elem.tag}"
                                )
                            if not scan_name and elem.attrib.get("id"):
                                scan_name = elem.attrib.get("id")
                        if lname in _ASSET_TAGS:
                            asset_depth += 1
                            if asset_depth == 1:
                                in_asset = True
                                asset_ip = None
                                asset_fqdn = None
                                asset_os = None
                                asset_cred = False
                                asset_vuln_count = 0
                                pending_vulns = []
                        elif lname in _VULN_TAGS and in_asset:
                            vuln_depth += 1
                            in_vuln = True
                        continue

                    # event == "end"
                    if not in_asset:
                        txt = (elem.text or "").strip()
                        if txt and lname in _SCAN_DATE_TAGS and not scan_date:
                            scan_date = txt
                        elif txt and lname in _SCAN_NAME_TAGS and not scan_name:
                            scan_name = txt
                        continue

                    if not in_vuln:
                        txt = (elem.text or "").strip()
                        if txt and lname in _IP_TAGS and not asset_ip:
                            asset_ip = txt
                        elif txt and lname in _FQDN_TAGS and not asset_fqdn:
                            asset_fqdn = txt
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
                                raw_vuln = self._extract_raw_vuln(elem)
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

    def _extract_raw_vuln(self, vuln: etree._Element) -> Dict[str, Any]:
        qid = self._safe_text(_first_text_by_local(vuln, _QID_TAGS))
        title = self._safe_text(_first_text_by_local(vuln, _TITLE_TAGS)) or "SENTINEL:No_Title"
        description = self._safe_text(_first_text_by_local(vuln, _DESC_TAGS)) or ""

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

        protocol = (protocol or "tcp").lower()
        if protocol not in {"tcp", "udp", "icmp"}:
            protocol = "tcp"
        if port is not None and not (0 <= int(port) <= 65535):
            port = None

        cvss_score: Optional[float] = None
        cvss_base = _first_text_by_local(vuln, _CVSS_BASE_TAGS)
        if cvss_base:
            cvss_score = self._safe_float(cvss_base)
            if cvss_score is not None and not (0.0 <= cvss_score <= 10.0):
                cvss_score = None

        cvss_vector_node = _first_text_by_local(vuln, _CVSS_VEC_TAGS)
        cvss_vector = self._safe_text(cvss_vector_node) if cvss_vector_node else None

        cve_text = " ".join(
            (e.text or "").strip() for e in _iter_by_local(vuln, _CVE_TAGS) if (e.text or "").strip()
        )
        cves = extract_cves_from_text(cve_text)

        cwe_text = " ".join(
            (e.text or "").strip() for e in _iter_by_local(vuln, _CWE_TAGS) if (e.text or "").strip()
        )
        cwes = extract_cwes_from_text(cwe_text, description)

        solution = self._safe_text(_first_text_by_local(vuln, _SOL_TAGS)) or ""
        plugin_output = self._safe_text(_first_text_by_local(vuln, _RES_TAGS)) or ""

        raw_sev = _first_text_by_local(vuln, _SEV_TAGS)
        severity = self._map_qualys_severity(raw_sev, cvss_score)

        refs: List[str] = []
        for ref_el in _iter_by_local(vuln, {"VENDOR_REFERENCE", "URL", "REFERENCE"}):
            txt = (ref_el.text or "").strip()
            if txt and txt not in refs:
                refs.append(txt)

        ghsa_ids = extract_ghsas_from_text(description, " ".join(refs))

        return {
            "qid": qid,
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
