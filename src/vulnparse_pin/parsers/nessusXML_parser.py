# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple, TYPE_CHECKING
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


_CREDENTIALED_19506_RE = re.compile(r"Credentialed checks\s*:\s*yes\b", re.IGNORECASE)
_MAX_HOST_ITEM_BUFFER = 50_000

_EXPLOIT_TAGS = frozenset(
    {
        "exploit_available",
        "exploit_framework_metasploit",
        "exploit_framework_canvas",
        "exploit_framework_core",
        "exploit_framework_d2_elliot",
        "exploited_by_malware",
        "exploited_by_nessus",
    }
)
_TRUTHY_TOKENS = frozenset({"true", "yes", "1"})
_FALSY_TOKENS = frozenset({"false", "no", "0"})


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


class NessusXMLParser(BaseParser):
    NAME = "nessus-xml"

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
        Bounded (<= 64 KB) detection for Nessus XML exports.

        Signals:
          root tag NessusClientData_v2 : +0.50
          nested NessusClientData_v2   : +0.35
          ReportHost present           : +0.20
          ReportItem present           : +0.20
          HostProperties present       : +0.05
          first pluginID is numeric    : +0.05
          extension is .nessus         : +0.10
        """
        evidence: list[tuple[str, str]] = []
        path = Path(filepath)
        suffix = path.suffix.lower()
        if suffix not in (".nessus", ".xml"):
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
        has_nested_nessus = any(
            ev == "start" and tag == "NessusClientData_v2"
            for ev, tag, _, _ in events[1:]
        )

        if root_tag == "NessusClientData_v2":
            score += 0.50
            evidence.append(("root_tag", "NessusClientData_v2"))
        elif has_nested_nessus:
            score += 0.35
            evidence.append(("nested_tag", "NessusClientData_v2"))
        else:
            return 0.0, [("root_tag", "absent")]

        has_report_host = False
        has_host_props = False
        first_plugin_id: Optional[str] = None
        for ev, tag, attrib, _ in events:
            if ev != "start":
                continue
            if tag == "ReportHost":
                has_report_host = True
            elif tag == "HostProperties":
                has_host_props = True
            elif tag == "ReportItem" and first_plugin_id is None:
                first_plugin_id = attrib.get("pluginID", "")

        if has_report_host:
            score += 0.20
            evidence.append(("structure", "ReportHost"))

        if first_plugin_id is not None:
            score += 0.20
            evidence.append(("structure", "ReportItem"))

        if has_host_props:
            score += 0.05
            evidence.append(("structure", "HostProperties"))

        if first_plugin_id and first_plugin_id.isdigit():
            score += 0.05
            evidence.append(("plugin_id", f"numeric:{first_plugin_id[:8]}"))

        if suffix == ".nessus":
            score += 0.10
            evidence.append(("extension", ".nessus"))

        return min(score, 1.0), evidence

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        path = self._validate_filepath_and_size()
        return self._stream_batches(path, batch_size)

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        seen_report = False
        scan_name: Optional[str] = None
        scan_date: Optional[str] = None
        empty_assets: List[Dict[str, Any]] = []

        host_name_attr: Optional[str] = None
        host_props: Dict[str, str] = {}
        host_cred_from_19506 = False
        pending_items: List[Dict[str, Any]] = []
        host_item_count = 0
        host_overflow_streamed = False

        try:
            with self._open_read(path, self.ctx, mode="rb", label="Nessus XML") as fh:
                for event, elem in safe_iterparse(
                    fh,
                    events=("start", "end"),
                    tag=("Report", "ReportHost", "HostProperties", "ReportItem", "Policy"),
                ):
                    tag = elem.tag if isinstance(elem.tag, str) else ""

                    if event == "start":
                        if tag == "Report":
                            seen_report = True
                            if scan_name is None:
                                scan_name = elem.get("name") or "SENTINEL:ScanName_Unavailable"
                        elif tag == "ReportHost":
                            host_name_attr = elem.get("name") or "SENTINEL:HostName_Unavailable"
                            host_props = {}
                            host_cred_from_19506 = False
                            pending_items = []
                            host_item_count = 0
                            host_overflow_streamed = False
                        continue

                    # event == "end"
                    if tag == "Policy":
                        prune_element(elem)
                    elif tag == "HostProperties":
                        host_props.update(self._host_properties_map(elem))
                        if not scan_date:
                            scan_date = host_props.get("HOST_END") or host_props.get("HOST_START")
                        prune_element(elem)
                    elif tag == "ReportItem":
                        raw_item = self._extract_raw_item(elem)
                        prune_element(elem)
                        if raw_item["plugin_id"] == "19506" and _CREDENTIALED_19506_RE.search(
                            raw_item["plugin_output"]
                        ):
                            host_cred_from_19506 = True

                        if host_overflow_streamed:
                            host_ctx = self._build_host_ctx(
                                host_name_attr or "",
                                host_props,
                                cred_override=host_cred_from_19506,
                            )
                            rec = self._finalize_record(raw_item, host_ctx)
                            batch.append(rec)
                            host_item_count += 1
                            if len(batch) >= batch_size:
                                yield batch
                                batch = []
                        else:
                            pending_items.append(raw_item)
                            if len(pending_items) >= _MAX_HOST_ITEM_BUFFER:
                                host_ctx = self._build_host_ctx(
                                    host_name_attr or "",
                                    host_props,
                                    cred_override=host_cred_from_19506,
                                )
                                for buffered_item in pending_items:
                                    rec = self._finalize_record(buffered_item, host_ctx)
                                    batch.append(rec)
                                    host_item_count += 1
                                    if len(batch) >= batch_size:
                                        yield batch
                                        batch = []
                                pending_items.clear()
                                host_overflow_streamed = True
                    elif tag == "ReportHost":
                        host_ctx = self._build_host_ctx(
                            host_name_attr or "",
                            host_props,
                            cred_override=host_cred_from_19506,
                        )
                        if pending_items:
                            for raw_item in pending_items:
                                rec = self._finalize_record(raw_item, host_ctx)
                                batch.append(rec)
                                host_item_count += 1
                                if len(batch) >= batch_size:
                                    yield batch
                                    batch = []
                            pending_items.clear()
                        if self._collecting_for_parse and host_item_count == 0:
                            canon_id = make_asset_id(
                                host_ctx["ip_address"] or host_ctx["fallback_host"],
                                host_ctx["hostname"] or host_ctx["fallback_host"],
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
                        prune_element(elem)
        except (OSError, etree.XMLSyntaxError) as exc:
            raise ValueError(f"Failed to parse XML: {exc}") from exc

        if not seen_report:
            raise ValueError("Nessus XML missing <Report> node.")

        if self._collecting_for_parse:
            self._last_scan_meta = {
                "scan_name": scan_name or "SENTINEL:ScanName_Unavailable",
                "scan_date": scan_date,
                "empty_assets": empty_assets,
            }

        if batch:
            yield batch

    def parse(self) -> ScanResult:
        """Parse Nessus XML (.nessus/.xml) into ScanResult in a single streaming pass."""
        return self._build_scan_result_from_batches(source_label="Nessus")

    # ------------------------- Helpers ------------------------

    @classmethod
    def _build_host_ctx(
        cls,
        host_name_attr: str,
        host_props: Dict[str, str],
        *,
        cred_override: bool = False,
    ) -> Dict[str, Any]:
        raw_ip = (host_props.get("host-ip") or "").strip()
        raw_fqdn = (
            host_props.get("host-fqdn")
            or host_props.get("hostname")
            or host_props.get("netbios-name")
            or ""
        ).strip()

        if raw_ip:
            ip_address: Optional[str] = raw_ip
        elif _is_ip(host_name_attr):
            ip_address = host_name_attr.strip()
        else:
            ip_address = None

        if raw_fqdn:
            hostname: Optional[str] = raw_fqdn
        elif host_name_attr and not host_name_attr.startswith("SENTINEL:") and not _is_ip(host_name_attr):
            hostname = host_name_attr.strip()
        elif host_name_attr and not host_name_attr.startswith("SENTINEL:"):
            hostname = host_name_attr.strip()
        else:
            hostname = None

        fallback_host = ip_address or hostname or host_name_attr or "SENTINEL:HostName_Unavailable"

        cred_raw = (
            host_props.get("Credentialed_checks")
            or host_props.get("Credentialed_Scan")
            or host_props.get("credentialed_checks")
            or host_props.get("credentialed_scan")
            or ""
        ).strip().lower()
        credentialed = cred_override or (cred_raw in _TRUTHY_TOKENS)

        open_ports: list[int] = []
        for k, v in host_props.items():
            if k.startswith("enumerated-ports-") and str(v).strip().lower() == "open":
                parts = k.split("-")
                for tok in parts:
                    if tok.isdigit():
                        p_num = int(tok)
                        if 0 <= p_num <= 65535 and p_num not in open_ports:
                            open_ports.append(p_num)

        return {
            "ip_address": ip_address,
            "hostname": hostname,
            "fallback_host": fallback_host,
            "os": cls._extract_os(host_props),
            "credentialed": credentialed,
            "open_ports": sorted(open_ports),
        }

    def _extract_raw_item(self, item: etree._Element) -> Dict[str, Any]:
        plugin_id = item.get("pluginID") or "SENTINEL:No_PluginID"

        plugin_name_text: Optional[str] = None
        desc_text: Optional[str] = None
        syn_text: Optional[str] = None
        sol_text: Optional[str] = None
        out_text: Optional[str] = None
        rf_text: Optional[str] = None
        exploit_vals: List[str] = []
        v4_score_text: Optional[str] = None
        v4_alt_score_text: Optional[str] = None
        v3_score_text: Optional[str] = None
        v3_alt_score_text: Optional[str] = None
        v2_score_text: Optional[str] = None
        v4_vec_text: Optional[str] = None
        v4_alt_vec_text: Optional[str] = None
        v3_vec_text: Optional[str] = None
        v3_alt_vec_text: Optional[str] = None
        v2_vec_text: Optional[str] = None
        cve_texts: List[str] = []
        cwe_texts: List[str] = []
        see_also_texts: List[str] = []

        for child in item:
            ctag = child.tag
            if not isinstance(ctag, str):
                continue
            ctext = child.text
            if ctag == "description":
                if desc_text is None:
                    desc_text = ctext or ""
            elif ctag == "solution":
                if sol_text is None:
                    sol_text = ctext or ""
            elif ctag == "plugin_output":
                if out_text is None:
                    out_text = ctext or ""
            elif ctag == "risk_factor":
                if rf_text is None:
                    rf_text = ctext or ""
            elif ctag == "cve":
                if ctext:
                    s = ctext.strip()
                    if s:
                        cve_texts.append(s)
            elif ctag == "cwe":
                if ctext:
                    s = ctext.strip()
                    if s:
                        cwe_texts.append(s)
            elif ctag == "cvss4_base_score":
                if v4_score_text is None:
                    v4_score_text = ctext or ""
            elif ctag == "cvssV4_base_score":
                if v4_alt_score_text is None:
                    v4_alt_score_text = ctext or ""
            elif ctag == "cvss4_vector":
                if v4_vec_text is None:
                    v4_vec_text = ctext or ""
            elif ctag == "cvssV4_vector":
                if v4_alt_vec_text is None:
                    v4_alt_vec_text = ctext or ""
            elif ctag == "cvss_base_score":
                if v2_score_text is None:
                    v2_score_text = ctext or ""
            elif ctag == "cvss3_vector":
                if v3_vec_text is None:
                    v3_vec_text = ctext or ""
            elif ctag == "cvss3_base_score":
                if v3_score_text is None:
                    v3_score_text = ctext or ""
            elif ctag == "cvssV3_base_score":
                if v3_alt_score_text is None:
                    v3_alt_score_text = ctext or ""
            elif ctag == "cvssV3_vector":
                if v3_alt_vec_text is None:
                    v3_alt_vec_text = ctext or ""
            elif ctag == "cvss_vector":
                if v2_vec_text is None:
                    v2_vec_text = ctext or ""
            elif ctag == "synopsis":
                if syn_text is None:
                    syn_text = ctext or ""
            elif ctag == "plugin_name":
                if plugin_name_text is None:
                    plugin_name_text = ctext or ""
            elif ctag == "see_also":
                if ctext:
                    see_also_texts.append(ctext)
            elif ctag in _EXPLOIT_TAGS:
                if ctext:
                    val = ctext.strip().lower()
                    if val:
                        exploit_vals.append(val)

        title = (plugin_name_text or item.get("pluginName") or "SENTINEL:No_Title").strip()
        description = (desc_text or syn_text or "").strip()
        solution = (sol_text or "").strip()
        plugin_output = (out_text or "").strip()

        port = self._parse_port(item.get("port"))
        protocol = (item.get("protocol") or "").strip().lower() or None
        service_name = (item.get("svc_name") or "").strip() or None
        if service_name == "general":
            service_name = None

        severity_code = item.get("severity") or "0"
        risk_factor = (rf_text or "").strip()
        severity = self._map_severity(severity_code, risk_factor)

        cves = extract_cves_from_text(" ".join(cve_texts)) if cve_texts else []
        cwes = extract_cwes_from_text(" ".join(cwe_texts), description, plugin_output)

        score = self._pick_valid_cvss_score(
            v4_score_text,
            v4_alt_score_text,
            v3_score_text,
            v3_alt_score_text,
            v2_score_text,
        )
        cvss_vector = self._pick_normalized_cvss_vector(
            v4_vec_text,
            v4_alt_vec_text,
            v3_vec_text,
            v3_alt_vec_text,
            v2_vec_text,
        )

        references: List[str] = []
        if see_also_texts:
            seen_refs: set[str] = set()
            for rtext in see_also_texts:
                for line in rtext.splitlines():
                    cleaned = line.strip()
                    if cleaned and cleaned not in seen_refs:
                        seen_refs.add(cleaned)
                        references.append(cleaned)

        ghsa_ids = extract_ghsas_from_text(description, " ".join(references))
        exploit_evidence: Optional[bool]
        if any(v in _TRUTHY_TOKENS for v in exploit_vals):
            exploit_evidence = True
        elif any(v in _FALSY_TOKENS for v in exploit_vals):
            exploit_evidence = False
        else:
            exploit_evidence = None

        plugin_family = (item.get("pluginFamily") or "").strip()
        tags = [plugin_family] if plugin_family else []

        return {
            "plugin_id": plugin_id,
            "title": title,
            "description": description,
            "solution": solution,
            "plugin_output": plugin_output,
            "affected_port": port,
            "protocol": protocol,
            "service_name": service_name,
            "severity": severity,
            "cves": cves,
            "cwes": cwes,
            "ghsa_ids": ghsa_ids,
            "scanner_cvss_score": score,
            "scanner_cvss_vector": cvss_vector,
            "references": references,
            "tags": tags,
            "exploit_evidence": exploit_evidence,
        }

    def _finalize_record(self, raw_item: Dict[str, Any], host_ctx: Dict[str, Any]) -> NormalizedFindingRecord:
        cves = raw_item["cves"]
        cvss_vector = raw_item["scanner_cvss_vector"]
        plugin_output = raw_item["plugin_output"]
        port = raw_item["affected_port"]

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
            ingestion_confidence = 0.55

        if host_ctx["credentialed"]:
            detection_mode = "credentialed_host"
            ingestion_confidence = min(1.0, round(ingestion_confidence + 0.03, 4))
        else:
            detection_mode = "uncredentialed_banner"

        return {
            "ip_address": host_ctx["ip_address"],
            "hostname": host_ctx["hostname"] or host_ctx["fallback_host"],
            "target_uri": None,
            "image_or_repo": None,
            "os": host_ctx["os"],
            "asset_metadata": {
                "credentialed": host_ctx["credentialed"],
                "open_ports": list(host_ctx["open_ports"]),
            },
            "source_format": "nessus-xml",
            "scanner_sig": f"nessus:{raw_item['plugin_id']}",
            "title": raw_item["title"],
            "description": raw_item["description"],
            "solution": raw_item["solution"],
            "plugin_output": plugin_output,
            "severity": raw_item["severity"],
            "cves": list(cves),
            "cwes": list(raw_item["cwes"]),
            "ghsa_ids": list(raw_item["ghsa_ids"]),
            "affected_port": port,
            "protocol": raw_item["protocol"],
            "service_name": raw_item["service_name"],
            "location_uri": None,
            "line_number": None,
            "package_purl": None,
            "scanner_cvss_score": raw_item["scanner_cvss_score"],
            "scanner_cvss_vector": cvss_vector,
            "detection_mode": detection_mode,
            "fidelity_tier": fidelity_tier,
            "ingestion_confidence": ingestion_confidence,
            "missing_fields": missing_fields,
            "degraded_input": fidelity_tier != "high",
            "references": list(raw_item["references"]),
            "tags": list(raw_item["tags"]),
            "exploit_evidence": raw_item["exploit_evidence"],
            "raw_evidence_excerpt": safe_excerpt(plugin_output or raw_item["description"]),
        }

    @staticmethod
    def _host_properties_map(host_props_elem) -> Dict[str, str]:
        props: Dict[str, str] = {}
        if host_props_elem is None:
            return props
        for tag in host_props_elem.findall("tag"):
            name = tag.get("name")
            if not name:
                continue
            props[name] = (tag.text or "").strip()
        return props

    @staticmethod
    def _extract_os(props: Dict[str, str]) -> Optional[str]:
        for key in ("cpe-0", "operating-system", "os"):
            val = props.get(key)
            if not val:
                continue
            if "->" in val:
                val = val.split("->", 1)[1]
            val = val.strip()
            if val:
                return val
        return None

    @staticmethod
    def _parse_port(port_str: Optional[str]) -> Optional[int]:
        if not port_str:
            return None
        try:
            p = int(port_str)
            return p if 0 <= p <= 65535 else None
        except ValueError:
            return None

    @staticmethod
    def _map_severity(severity_code: str, risk_factor: str) -> str:
        rf = (risk_factor or "").strip()
        if rf:
            return normalize_severity(rf)
        mapping = {
            "0": "Informational",
            "1": "Low",
            "2": "Medium",
            "3": "High",
            "4": "Critical",
        }
        return mapping.get(str(severity_code).strip(), "Informational")

    @staticmethod
    def _extract_cves(item) -> List[str]:
        texts = [c.text.strip() for c in item.findall("cve") if c is not None and c.text]
        if not texts:
            return []
        return extract_cves_from_text(" ".join(texts))

    @staticmethod
    def _extract_cwes(item, description: str, plugin_output: str) -> List[str]:
        cwe_texts = [c.text.strip() for c in item.findall("cwe") if c is not None and c.text]
        return extract_cwes_from_text(" ".join(cwe_texts), description, plugin_output)

    def _pick_valid_cvss_score(self, *candidates: Optional[str]) -> Optional[float]:
        for raw in candidates:
            if not raw:
                continue
            val = self._safe_float(raw.strip())
            if val is not None and 0.0 <= val <= 10.0:
                return val
        return None

    @staticmethod
    def _pick_normalized_cvss_vector(*candidates: Optional[str]) -> Optional[str]:
        for raw in candidates:
            norm = _normalize_cvss_vector(raw)
            if norm:
                return norm
        return None

    def _extract_cvss(self, item) -> Tuple[Optional[float], Optional[str]]:
        score = self._pick_valid_cvss_score(
            item.findtext("cvss4_base_score"),
            item.findtext("cvssV4_base_score"),
            item.findtext("cvss3_base_score"),
            item.findtext("cvssV3_base_score"),
            item.findtext("cvss_base_score"),
        )
        vector = self._pick_normalized_cvss_vector(
            item.findtext("cvss4_vector"),
            item.findtext("cvssV4_vector"),
            item.findtext("cvss3_vector"),
            item.findtext("cvssV3_vector"),
            item.findtext("cvss_vector"),
        )
        return score, vector
