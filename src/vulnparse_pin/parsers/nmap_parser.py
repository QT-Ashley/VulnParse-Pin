# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, TYPE_CHECKING
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


class NmapXMLParser(BaseParser):
    """Streaming lxml parser for Nmap XML port/service/NSE outputs."""

    NAME = "nmap-xml"

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
        Bounded (<= 64 KB) detection for Nmap XML exports.

        Signals:
          - Root tag "nmaprun"                 : +0.40
          - host elements within <nmaprun>     : +0.20
          - port elements                      : +0.20
          - version / osclass probing          : +0.10
          - start/end timestamp attributes     : +0.10
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

        if root_tag != "nmaprun":
            return 0.0, [("root_tag", f"rejected:{root_tag or 'absent'}")]

        score = 0.40
        evidence.append(("root_tag", "nmaprun"))

        saw_host = False
        saw_port = False
        saw_version = False
        saw_ts = False

        for ev, tag, attrib, _ in events:
            if ev != "start":
                continue
            if tag == "nmaprun":
                if attrib.get("start") or attrib.get("startstr"):
                    saw_ts = True
                if attrib.get("version"):
                    saw_version = True
            elif tag == "host":
                saw_host = True
                if attrib.get("starttime") or attrib.get("endtime"):
                    saw_ts = True
            elif tag == "port":
                saw_port = True
            elif tag in {"service", "osclass"} and attrib.get("version"):
                saw_version = True

        if saw_host:
            score += 0.20
            evidence.append(("structure", "host"))
        if saw_port:
            score += 0.20
            evidence.append(("structure", "port"))
        if saw_version:
            score += 0.10
            evidence.append(("detection", "version_probing"))
        if saw_ts:
            score += 0.10
            evidence.append(("meta", "timestamps"))

        return min(score, 1.0), evidence

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        path = self._validate_filepath_and_size()
        return self._stream_batches(path, batch_size)

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        root_seen = False
        scan_date: Optional[str] = None
        scan_name: Optional[str] = None
        empty_assets: List[Dict[str, Any]] = []

        try:
            with self._open_read(path, self.ctx, mode="rb", label="Nmap XML") as fh:
                for event, elem in safe_iterparse(fh, events=("start", "end")):
                    tag = elem.tag if isinstance(elem.tag, str) else ""

                    if event == "start":
                        if tag == "nmaprun":
                            root_seen = True
                            scan_name = elem.get("args") or path.stem
                            raw_start = elem.get("start")
                            if raw_start and raw_start.isdigit():
                                scan_date = (
                                    datetime.fromtimestamp(int(raw_start), tz=timezone.utc)
                                    .isoformat()
                                    .replace("+00:00", "Z")
                                )
                        continue

                    # event == "end"
                    if tag in {"hosthint", "scaninfo", "verbose", "debugging"}:
                        prune_element(elem)
                    elif tag == "finished" and not scan_date:
                        raw_t = elem.get("time")
                        if raw_t and raw_t.isdigit():
                            scan_date = (
                                datetime.fromtimestamp(int(raw_t), tz=timezone.utc)
                                .isoformat()
                                .replace("+00:00", "Z")
                            )
                    elif tag == "host":
                        records, asset_summary = self._extract_host_records(elem)
                        prune_element(elem)
                        if asset_summary is not None and not records and self._collecting_for_parse:
                            empty_assets.append(asset_summary)
                        for rec in records:
                            batch.append(rec)
                            if len(batch) >= batch_size:
                                yield batch
                                batch = []
        except (OSError, etree.XMLSyntaxError) as exc:
            raise ValueError(f"Failed to parse XML: {exc}") from exc

        if not root_seen:
            raise ValueError("Nmap XML missing <nmaprun> root node.")

        if self._collecting_for_parse:
            self._last_scan_meta = {
                "scan_name": scan_name or path.stem,
                "scan_date": scan_date,
                "empty_assets": empty_assets,
            }

        if batch:
            yield batch

    def parse(self) -> ScanResult:
        """Parse Nmap XML into ScanResult object in a single streaming pass."""
        return self._build_scan_result_from_batches(source_label="Nmap")

    def _extract_host_records(
        self, host_elem: etree._Element
    ) -> tuple[List[NormalizedFindingRecord], Optional[Dict[str, Any]]]:
        status_elem = host_elem.find("status")
        state = (status_elem.get("state") or "").strip().lower() if status_elem is not None else "up"

        ipv4: Optional[str] = None
        ipv6: Optional[str] = None
        mac: Optional[str] = None
        for addr in host_elem.findall("address"):
            atype = (addr.get("addrtype") or "").strip().lower()
            aval = (addr.get("addr") or "").strip()
            if not aval:
                continue
            if atype == "ipv4" and not ipv4:
                ipv4 = aval
            elif atype == "ipv6" and not ipv6:
                ipv6 = aval
            elif atype == "mac" and not mac:
                mac = aval

        ip_address = ipv4 or ipv6
        hostname: Optional[str] = None
        for hn in host_elem.findall("./hostnames/hostname"):
            hval = (hn.get("name") or "").strip()
            if hval:
                hostname = hval
                break

        if not ip_address and not hostname:
            return [], None

        os_name: Optional[str] = None
        best_acc = -1
        for osmatch in host_elem.findall("./os/osmatch"):
            name = (osmatch.get("name") or "").strip()
            acc = self._safe_int(osmatch.get("accuracy")) or 0
            if name and acc > best_acc:
                best_acc = acc
                os_name = name
        if not os_name:
            osclass = host_elem.find("./os/osclass")
            if osclass is not None:
                fam = (osclass.get("osfamily") or "").strip()
                gen = (osclass.get("osgen") or "").strip()
                os_name = f"{fam} {gen}".strip() or None

        open_ports_meta: List[Dict[str, Any]] = []
        open_port_ints: List[int] = []
        port_nodes = host_elem.findall("./ports/port")

        for port_el in port_nodes:
            st_el = port_el.find("state")
            p_state = (st_el.get("state") or "").strip().lower() if st_el is not None else ""
            if p_state not in {"open", "open|filtered"}:
                continue
            p_num = self._safe_int(port_el.get("portid"))
            if p_num is None or not (0 <= p_num <= 65535):
                continue
            proto = (port_el.get("protocol") or "tcp").strip().lower()
            svc_el = port_el.find("service")
            svc_name = (svc_el.get("name") or "").strip() if svc_el is not None else ""
            product = (svc_el.get("product") or "").strip() if svc_el is not None else ""
            version = (svc_el.get("version") or "").strip() if svc_el is not None else ""
            ostype = (svc_el.get("ostype") or "").strip() if svc_el is not None else ""
            if not os_name and ostype:
                os_name = ostype
            if p_num not in open_port_ints:
                open_port_ints.append(p_num)
            open_ports_meta.append(
                {
                    "port": p_num,
                    "protocol": proto,
                    "service": svc_name or None,
                    "product": product or None,
                    "version": version or None,
                }
            )

        asset_meta: Dict[str, Any] = {
            "credentialed": False,
            "open_ports": sorted(open_port_ints),
            "services": open_ports_meta,
        }
        if mac:
            asset_meta["mac"] = mac

        records: List[NormalizedFindingRecord] = []

        for port_el in port_nodes:
            st_el = port_el.find("state")
            p_state = (st_el.get("state") or "").strip().lower() if st_el is not None else ""
            if p_state not in {"open", "open|filtered"}:
                continue
            p_num = self._safe_int(port_el.get("portid"))
            if p_num is None or not (0 <= p_num <= 65535):
                continue
            proto = (port_el.get("protocol") or "tcp").strip().lower()
            svc_el = port_el.find("service")
            svc_name = (svc_el.get("name") or "").strip() if svc_el is not None else ""
            product = (svc_el.get("product") or "").strip() if svc_el is not None else ""
            version = (svc_el.get("version") or "").strip() if svc_el is not None else ""
            extrainfo = (svc_el.get("extrainfo") or "").strip() if svc_el is not None else ""
            cpes = [
                (c.text or "").strip()
                for c in (svc_el.findall("cpe") if svc_el is not None else [])
                if (c.text or "").strip()
            ]

            scripts = port_el.findall("script")
            script_parts: List[str] = []
            script_ids: List[str] = []
            cvss_score: Optional[float] = None
            cvss_score_rank = 0
            cvss_vector: Optional[str] = None
            cvss_vec_rank = 0
            refs: List[str] = []
            for sc in scripts:
                sid = (sc.get("id") or "").strip()
                sout = (sc.get("output") or "").strip()
                if sid:
                    script_ids.append(sid)
                if sout:
                    script_parts.append(f"[{sid}] {sout}" if sid else sout)
                for elem in sc.iter():
                    k = (elem.get("key") or "").strip().lower()
                    val = (elem.text or "").strip()
                    if k in {"cvss4", "cvss_v4", "cvss3", "cvss_v3", "cvss"}:
                        rank = 3 if "4" in k else (2 if "3" in k else 1)
                        parsed_cvss = self._safe_float(val)
                        if parsed_cvss is not None and 0.0 <= parsed_cvss <= 10.0 and rank > cvss_score_rank:
                            cvss_score = parsed_cvss
                            cvss_score_rank = rank
                    elif k in {"cvss4_vector", "cvss_v4_vector", "cvss3_vector", "cvss_v3_vector", "cvss_vector"}:
                        rank = 3 if "4" in k else (2 if "3" in k else 1)
                        norm_vec = _normalize_cvss_vector(val)
                        if norm_vec and rank > cvss_vec_rank:
                            cvss_vector = norm_vec
                            cvss_vec_rank = rank
                    elif k == "references" or (val.startswith(("http://", "https://")) and val not in refs):
                        if val.startswith(("http://", "https://")) and val not in refs:
                            refs.append(val)

            script_blob = "\n".join(script_parts)
            cves = extract_cves_from_text(script_blob, " ".join(script_ids))
            cwes = extract_cwes_from_text(script_blob)
            ghsa_ids = extract_ghsas_from_text(script_blob)

            svc_label = svc_name or "unknown"
            banner_bits = [b for b in (product, version, extrainfo) if b]
            banner = " ".join(banner_bits)

            if cves or "state: vulnerable" in script_blob.lower():
                if cvss_score is not None:
                    severity = normalize_severity(None, cvss_score)
                else:
                    severity = "High"
            else:
                severity = "Informational"

            title = f"Open {proto.upper()} Port {p_num} ({svc_label})"
            if script_ids and cves:
                title = f"{title} - {', '.join(script_ids[:3])}"

            desc_parts = [f"Port {p_num}/{proto} is {p_state} running service '{svc_label}'."]
            if banner:
                desc_parts.append(f"Detected banner: {banner}.")
            if cpes:
                desc_parts.append(f"CPEs: {', '.join(cpes)}.")
            description = " ".join(desc_parts)

            plugin_output = script_blob or (f"Banner: {banner}" if banner else f"{p_num}/{proto} {p_state} {svc_label}")

            missing_fields: List[str] = []
            if not cves:
                missing_fields.append("cves")
            if cvss_score is None and not cvss_vector:
                missing_fields.append("cvss_vector")
            if not banner and not script_blob:
                missing_fields.append("plugin_output")

            if banner or script_blob:
                fidelity_tier = "high" if cves or (product and version) else "medium"
                ingestion_confidence = 0.85 if fidelity_tier == "high" else 0.75
            else:
                fidelity_tier = "low"
                ingestion_confidence = 0.60

            scanner_sig = f"nmap:{proto}/{p_num}:{svc_label}"
            records.append(
                {
                    "ip_address": ip_address,
                    "hostname": hostname or ip_address,
                    "target_uri": None,
                    "image_or_repo": None,
                    "os": os_name,
                    "asset_metadata": asset_meta,
                    "source_format": "nmap-xml",
                    "scanner_sig": scanner_sig,
                    "title": title,
                    "description": description,
                    "solution": "Review service exposure, restrict unnecessary open ports, and apply vendor patches.",
                    "plugin_output": plugin_output,
                    "severity": severity,
                    "cves": cves,
                    "cwes": cwes,
                    "ghsa_ids": ghsa_ids,
                    "affected_port": p_num,
                    "protocol": proto,
                    "service_name": svc_name or None,
                    "location_uri": None,
                    "line_number": None,
                    "package_purl": None,
                    "scanner_cvss_score": cvss_score,
                    "scanner_cvss_vector": cvss_vector,
                    "detection_mode": "network_probe",
                    "fidelity_tier": fidelity_tier,
                    "ingestion_confidence": ingestion_confidence,
                    "missing_fields": missing_fields,
                    "degraded_input": fidelity_tier == "low",
                    "references": refs,
                    "tags": cpes,
                    "exploit_evidence": None,
                    "raw_evidence_excerpt": safe_excerpt(plugin_output),
                }
            )

        # Also emit findings for host-level NSE scripts (e.g. smb-vuln-ms17-010)
        for hscript in host_elem.findall("./hostscript/script"):
            sid = (hscript.get("id") or "").strip() or "hostscript"
            sout = (hscript.get("output") or "").strip()
            cves = extract_cves_from_text(sid, sout)
            if not cves and "vulnerable" not in sout.lower():
                continue
            h_cvss_score: Optional[float] = None
            h_cvss_score_rank = 0
            h_cvss_vector: Optional[str] = None
            h_cvss_vec_rank = 0
            h_refs: List[str] = []
            for elem in hscript.iter():
                k = (elem.get("key") or "").strip().lower()
                val = (elem.text or "").strip()
                if k in {"cvss4", "cvss_v4", "cvss3", "cvss_v3", "cvss"}:
                    rank = 3 if "4" in k else (2 if "3" in k else 1)
                    parsed_cvss = self._safe_float(val)
                    if parsed_cvss is not None and 0.0 <= parsed_cvss <= 10.0 and rank > h_cvss_score_rank:
                        h_cvss_score = parsed_cvss
                        h_cvss_score_rank = rank
                elif k in {"cvss4_vector", "cvss_v4_vector", "cvss3_vector", "cvss_v3_vector", "cvss_vector"}:
                    rank = 3 if "4" in k else (2 if "3" in k else 1)
                    norm_vec = _normalize_cvss_vector(val)
                    if norm_vec and rank > h_cvss_vec_rank:
                        h_cvss_vector = norm_vec
                        h_cvss_vec_rank = rank
                elif k == "references" or (val.startswith(("http://", "https://")) and val not in h_refs):
                    if val.startswith(("http://", "https://")) and val not in h_refs:
                        h_refs.append(val)
            cwes = extract_cwes_from_text(sout)
            ghsa_ids = extract_ghsas_from_text(sout)
            h_missing = [] if h_cvss_vector else ["cvss_vector"]
            h_missing.append("affected_port")
            h_sev = (
                normalize_severity(None, h_cvss_score)
                if h_cvss_score is not None
                else ("High" if cves or "vulnerable" in sout.lower() else "Informational")
            )
            records.append(
                {
                    "ip_address": ip_address,
                    "hostname": hostname or ip_address,
                    "target_uri": None,
                    "image_or_repo": None,
                    "os": os_name,
                    "asset_metadata": asset_meta,
                    "source_format": "nmap-xml",
                    "scanner_sig": f"nmap:hostscript:{sid}",
                    "title": f"Nmap NSE {sid}",
                    "description": sout or f"Host script {sid} reported findings.",
                    "solution": "Review NSE finding details and apply appropriate vendor mitigations.",
                    "plugin_output": sout,
                    "severity": h_sev,
                    "cves": cves,
                    "cwes": cwes,
                    "ghsa_ids": ghsa_ids,
                    "affected_port": None,
                    "protocol": None,
                    "service_name": None,
                    "location_uri": None,
                    "line_number": None,
                    "package_purl": None,
                    "scanner_cvss_score": h_cvss_score,
                    "scanner_cvss_vector": h_cvss_vector,
                    "detection_mode": "network_probe",
                    "fidelity_tier": "medium",
                    "ingestion_confidence": 0.80,
                    "missing_fields": h_missing,
                    "degraded_input": False,
                    "references": h_refs,
                    "tags": [sid],
                    "exploit_evidence": None,
                    "raw_evidence_excerpt": safe_excerpt(sout),
                }
            )

        if state == "down" and not records:
            return [], None

        canon_id = make_asset_id(ip_address or hostname, hostname or ip_address)
        asset_summary = {
            "lookup_key": canon_id,
            "asset_id": canon_id,
            "hostname": hostname or ip_address or "unknown",
            "ip_address": ip_address or hostname or "",
            "os": os_name,
        }
        return records, asset_summary
