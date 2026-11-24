# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.dataclass import ScanResult
from vulnparse_pin.parsers.base_parser import (
    BaseParser,
    NormalizedFindingRecord,
    extract_cves_from_text,
    extract_cwes_from_text,
    extract_ghsas_from_text,
    normalize_severity,
    safe_excerpt,
)
from vulnparse_pin.utils.cvss_utils import compute_cvss_base_score

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


def _is_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _coerce_list(val: Any) -> List[str]:
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


class NucleiJSONLParser(BaseParser):
    """Streaming line-by-line parser for Nuclei JSONL / NDJSON outputs."""

    NAME = "nuclei-jsonl"

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
        """Bounded (<= 64 KB) detection inspecting up to 16 non-empty JSON lines."""
        evidence: list[tuple[str, str]] = []
        path = Path(filepath)
        suffix = path.suffix.lower()
        if suffix not in {".jsonl", ".ndjson", ".json"}:
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
        text = raw_head.decode("utf-8", errors="ignore").lstrip()
        if not text.startswith("{"):
            return 0.0, [("structure", "not_json_lines")]

        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        # If the 64 KB cut truncated the very last line (and we already have >= 1 full line), ignore trailing partial
        if len(raw_head) >= 65_536 and not raw_head.endswith((b"\n", b"\r")) and len(lines) > 1:
            lines = lines[:-1]

        inspected = 0
        matched_lines = 0
        saw_target = False
        saw_info_details = False

        for ln in lines[:16]:
            try:
                obj = json.loads(ln)
            except Exception:
                # Could be multi-line pretty JSON (not JSONL)
                if inspected == 0:
                    return 0.0, [("structure", "not_jsonl")]
                continue

            if not isinstance(obj, dict):
                return 0.0, [("structure", "non_object_line")]

            inspected += 1
            info = obj.get("info")
            if "template-id" in obj and isinstance(info, dict):
                matched_lines += 1
                if any(k in obj for k in ("matched-at", "host", "ip")):
                    saw_target = True
                if "severity" in info or "name" in info:
                    saw_info_details = True

        if inspected == 0 or matched_lines == 0:
            return 0.0, [("schema", "not_nuclei_jsonl")]

        score = 0.50
        evidence.append(("nuclei_lines", f"{matched_lines}/{inspected}"))
        if matched_lines == inspected:
            score += 0.20
            evidence.append(("consistency", "all_lines_matched"))
        if saw_target:
            score += 0.15
            evidence.append(("target", "host_or_matched_at"))
        if saw_info_details:
            score += 0.10
            evidence.append(("info", "name_or_severity"))
        if suffix in {".jsonl", ".ndjson"}:
            score += 0.05
            evidence.append(("extension", suffix))

        return min(score, 1.0), evidence

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        path = self._validate_filepath_and_size()
        return self._stream_batches(path, batch_size)

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        malformed_rows = 0
        first_timestamp: Optional[str] = None

        with self._open_read(path, self.ctx, mode="rb", label="Nuclei JSONL") as fh:
            for idx, raw_line in enumerate(fh, start=1):
                if idx == 1 and raw_line.startswith(b"\xef\xbb\xbf"):
                    raw_line = raw_line[3:]
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line.decode("utf-8"))
                except Exception:
                    malformed_rows += 1
                    continue

                if not isinstance(obj, dict):
                    malformed_rows += 1
                    continue

                if first_timestamp is None and obj.get("timestamp"):
                    first_timestamp = str(obj["timestamp"]).strip() or None

                rec = self._extract_record(obj, idx)
                batch.append(rec)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []

        if malformed_rows > 0:
            self.ctx.logger.print_warning(
                f"Nuclei JSONL parser skipped {malformed_rows} malformed JSON lines.",
                label="Normalization",
            )
            services = getattr(self.ctx, "services", None)
            ledger = getattr(services, "ledger", None)
            if ledger is not None:
                ledger.append_event(
                    component="Ingestion",
                    event_type="decision",
                    subject_ref=f"parser:{self.NAME}",
                    reason_code=DecisionReasonCodes.INGESTION_MALFORMED_ROWS_SKIPPED,
                    reason_text="Nuclei JSONL ingestion skipped malformed JSON lines.",
                    factor_refs=["jsonl_row_shape", "malformed_rows"],
                    confidence="high",
                    evidence={
                        "parser": self.NAME,
                        "malformed_rows": malformed_rows,
                    },
                )

        if self._collecting_for_parse:
            self._last_scan_meta = {
                "scan_name": path.stem,
                "scan_date": first_timestamp,
                "empty_assets": [],
            }

        if batch:
            yield batch

    def parse(self) -> ScanResult:
        """Parse Nuclei JSONL into ScanResult in a single streaming pass."""
        return self._build_scan_result_from_batches(source_label="Nuclei")

    def _extract_record(self, obj: Dict[str, Any], line_idx: int) -> NormalizedFindingRecord:
        template_id = str(obj.get("template-id") or obj.get("template") or f"line_{line_idx}").strip()
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}

        title = str(info.get("name") or template_id).strip()
        description = str(info.get("description") or "").strip()
        solution = str(info.get("remediation") or "").strip()

        tags = _coerce_list(info.get("tags"))
        references = _coerce_list(info.get("reference"))

        classification = (
            info.get("classification") if isinstance(info.get("classification"), dict) else {}
        )
        raw_cves = _coerce_list(classification.get("cve-id"))
        raw_cwes = _coerce_list(classification.get("cwe-id"))
        cves = extract_cves_from_text(" ".join(raw_cves), template_id)
        cwes = extract_cwes_from_text(" ".join(raw_cwes), description)
        ghsa_ids = extract_ghsas_from_text(template_id, description, " ".join(references))

        cvss_score = self._safe_float(classification.get("cvss-score"))
        if cvss_score is not None and not (0.0 <= cvss_score <= 10.0):
            cvss_score = None
        cvss_vector = str(classification.get("cvss-metrics") or "").strip() or None
        if cvss_vector and cvss_score is None:
            computed = compute_cvss_base_score(cvss_vector)
            if computed is not None:
                cvss_score = float(computed)

        severity = normalize_severity(info.get("severity"), cvss_score)

        # Target & network parsing
        host_raw = str(obj.get("host") or "").strip() or None
        ip_raw = str(obj.get("ip") or "").strip() or None
        matched_at = str(obj.get("matched-at") or "").strip() or None

        parsed_url = None
        uri_candidate = matched_at or host_raw
        if uri_candidate and "://" in uri_candidate:
            try:
                parsed_url = urlparse(uri_candidate)
            except Exception:
                parsed_url = None

        target_uri = matched_at or (host_raw if host_raw and "://" in host_raw else None)

        hostname: Optional[str] = None
        if parsed_url and parsed_url.hostname:
            if not _is_ip(parsed_url.hostname):
                hostname = parsed_url.hostname
            elif not ip_raw:
                ip_raw = parsed_url.hostname

        host_only: Optional[str] = None
        host_port: Optional[int] = None
        if host_raw and "://" not in host_raw:
            if _is_ip(host_raw):
                host_only = host_raw
            elif host_raw.startswith("[") and "]" in host_raw:
                inner, rest = host_raw[1:].split("]", 1)
                inner = inner.strip()
                host_only = inner or None
                if rest.startswith(":") and rest[1:].isdigit():
                    host_port = int(rest[1:])
            elif host_raw.count(":") == 1:
                h_part, p_part = host_raw.split(":", 1)
                host_only = h_part.strip() or None
                if p_part.strip().isdigit():
                    host_port = int(p_part.strip())
            else:
                host_only = host_raw

        if not hostname and host_only:
            if _is_ip(host_only):
                if not ip_raw:
                    ip_raw = host_only
            else:
                hostname = host_only

        raw_port = obj.get("port")
        affected_port = None if isinstance(raw_port, bool) else self._safe_int(raw_port)
        if affected_port is None and parsed_url:
            try:
                if parsed_url.port:
                    affected_port = parsed_url.port
            except ValueError:
                affected_port = None
        if affected_port is None and host_port is not None:
            affected_port = host_port
        if affected_port is not None and not (0 <= affected_port <= 65535):
            affected_port = None

        proto_raw = str(obj.get("type") or "").strip().lower()
        if proto_raw in {"tcp", "udp", "icmp"}:
            protocol: Optional[str] = proto_raw
        elif proto_raw in {"http", "https", "ssl", "dns", "websocket", "network"}:
            protocol = "udp" if proto_raw == "dns" else "tcp"
        else:
            protocol = "tcp" if affected_port is not None else None

        service_name = (
            str(obj.get("scheme") or "").strip().lower()
            or (parsed_url.scheme.lower() if parsed_url and parsed_url.scheme else "")
            or (proto_raw if proto_raw else "")
            or None
        )

        matcher_name = str(obj.get("matcher-name") or "").strip()
        extracted = obj.get("extracted-results")
        extracted_items = _coerce_list(extracted) if not isinstance(extracted, list) else [
            str(x).strip() for x in extracted if x is not None and str(x).strip()
        ]
        curl_cmd = str(obj.get("curl-command") or "").strip()

        ev_parts: List[str] = []
        if matched_at:
            ev_parts.append(f"matched-at: {matched_at}")
        if matcher_name:
            ev_parts.append(f"matcher: {matcher_name}")
        if extracted_items:
            ev_parts.append(f"extracted: {', '.join(extracted_items[:10])}")
        if curl_cmd:
            ev_parts.append(f"curl: {safe_excerpt(curl_cmd, limit=240)}")
        plugin_output = "\n".join(ev_parts)
        raw_excerpt = safe_excerpt(" | ".join(ev_parts) or description, limit=500)

        return {
            "ip_address": ip_raw,
            "hostname": hostname or ip_raw or (parsed_url.hostname if parsed_url else None),
            "target_uri": target_uri,
            "image_or_repo": None,
            "os": None,
            "asset_metadata": {
                "credentialed": False,
                "open_ports": [affected_port] if affected_port is not None else [],
                "matcher_name": matcher_name or None,
            },
            "source_format": "nuclei-jsonl",
            "scanner_sig": f"nuclei:{template_id}",
            "title": title,
            "description": description,
            "solution": solution,
            "plugin_output": plugin_output,
            "severity": severity,
            "cves": cves,
            "cwes": cwes,
            "ghsa_ids": ghsa_ids,
            "affected_port": affected_port,
            "protocol": protocol,
            "service_name": service_name,
            "location_uri": matched_at,
            "line_number": None,
            "package_purl": None,
            "scanner_cvss_score": cvss_score,
            "scanner_cvss_vector": cvss_vector,
            "detection_mode": "active_dast",
            "fidelity_tier": "high",
            "ingestion_confidence": 0.95,
            "missing_fields": [],
            "degraded_input": False,
            "references": references,
            "tags": tags,
            "exploit_evidence": None,
            "raw_evidence_excerpt": raw_excerpt,
        }
