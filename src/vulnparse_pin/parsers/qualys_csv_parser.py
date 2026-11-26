# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

import csv
import io
import ipaddress
from pathlib import Path
import re
import sys
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, TYPE_CHECKING

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.dataclass import ScanResult
from vulnparse_pin.parsers.base_parser import (
    BaseParser,
    NormalizedFindingRecord,
    extract_cves_from_text,
    extract_cwes_from_text,
    extract_ghsas_from_text,
    safe_excerpt,
)

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


_QID_ALIASES = ("qid", "vuln id", "vulnerability id", "id")
_TITLE_ALIASES = ("title", "name", "vulnerability", "vulnerability title")
_SEVERITY_ALIASES = ("severity", "risk", "threat")
_CVSS_V4_ALIASES = ("cvss4 base", "cvss v4.0 base", "cvss4_base", "cvss v4 base")
_CVSS_V31_ALIASES = (
    "cvss3.1 base",
    "cvss31 base",
    "cvss 3.1 base",
    "cvss v3.1 base",
    "cvss3_1_base",
    "cvss3.1",
    "cvss31",
)
_CVSS_V3_ALIASES = ("cvss3.0 base", "cvss3 base", "cvss v3.0 base", "cvss3_base", "cvss3")
_CVSS_V2_ALIASES = ("cvss base", "cvss_base", "cvss v2.0 base", "cvss2 base", "cvss score", "cvss")
_CVSS_ALIASES = (*_CVSS_V4_ALIASES, *_CVSS_V31_ALIASES, *_CVSS_V3_ALIASES, *_CVSS_V2_ALIASES)

_CVSS_V4_VEC_ALIASES = ("cvss4 vector", "cvss v4.0 vector", "cvss4_vector", "cvss v4 vector")
_CVSS_V31_VEC_ALIASES = (
    "cvss3.1 vector",
    "cvss31 vector",
    "cvss 3.1 vector",
    "cvss v3.1 vector",
    "cvss3_1_vector",
)
_CVSS_V3_VEC_ALIASES = ("cvss3.0 vector", "cvss3 vector", "cvss v3.0 vector", "cvss3_vector")
_CVSS_V2_VEC_ALIASES = ("cvss vector", "cvss_vector", "cvss v2.0 vector", "cvss2 vector")
_CVSS_VEC_ALIASES = (
    *_CVSS_V4_VEC_ALIASES,
    *_CVSS_V31_VEC_ALIASES,
    *_CVSS_V3_VEC_ALIASES,
    *_CVSS_V2_VEC_ALIASES,
)

_IP_ALIASES = ("ip", "ip address", "host ip", "asset ip")
_HOST_ALIASES = ("hostname", "fqdn", "dns", "dns name", "netbios", "netbios name", "host")
_CVE_ALIASES = ("cve", "cves", "cve id", "cve_id")
_CWE_ALIASES = ("cwe", "cwes", "cwe id", "cwe_id")
_PORT_ALIASES = ("port", "service port", "affected_port")
_PROTO_ALIASES = ("protocol", "proto", "transport")
_DESC_ALIASES = ("description", "details", "diagnosis")
_SOL_ALIASES = ("solution", "fix", "remediation")
_OUT_ALIASES = ("results", "result", "evidence", "plugin output")
_REF_ALIASES = ("references", "vendor reference", "see also")
_CRED_ALIASES = ("authenticated", "authentication", "credentialed")
_HEADER_SCAN_MAX_ROWS = 25
_MAX_CSV_FIELD_BYTES = min(32 * 1024 * 1024, sys.maxsize)


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


class QualysCSVParser(BaseParser):
    NAME = "qualys-csv"

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
        evidence: list[tuple[str, str]] = []
        path = Path(filepath)
        if path.suffix.lower() != ".csv":
            return 0.0, [("extension", f"rejected:{path.suffix.lower()}")]

        try:
            max_bytes = cls._max_bytes_for(path, ctx=ctx, allow_large=allow_large)
            if path.stat().st_size > max_bytes:
                return 0.0, [("size", "exceeds_limit")]
            raw_head = cls._read_head_bytes(path, ctx=ctx, head_bytes=head_bytes)
            if raw_head.startswith(b"\xef\xbb\xbf"):
                raw_head = raw_head[3:]
            sample = raw_head.decode("utf-8", errors="ignore")
            if not sample.strip():
                return 0.0, [("header", "missing")]
            dialect = cls._sniff_csv_dialect(sample)
            header_row = cls._find_header_row(csv.reader(io.StringIO(sample), dialect))
        except (OSError, csv.Error):
            return 0.0, [("parse", "failed")]

        if not header_row:
            return 0.0, [("header", "missing")]

        header_norm = {
            cls._normalize_key(str(h).lstrip("\ufeff")) for h in header_row if str(h).strip()
        }
        if len(header_norm) < 3:
            return 0.0, [("header", "too_few_columns")]

        qid_norm = {cls._normalize_key(a) for a in _QID_ALIASES}
        title_norm = {cls._normalize_key(a) for a in _TITLE_ALIASES}
        sev_cvss_norm = {cls._normalize_key(a) for a in (*_SEVERITY_ALIASES, *_CVSS_ALIASES)}
        asset_norm = {cls._normalize_key(a) for a in (*_IP_ALIASES, *_HOST_ALIASES)}
        cve_norm = {cls._normalize_key(a) for a in _CVE_ALIASES}

        score = 0.0
        if header_norm & qid_norm:
            score += 0.35
            evidence.append(("header", "qid"))
        if header_norm & title_norm:
            score += 0.20
            evidence.append(("header", "title"))
        if header_norm & sev_cvss_norm:
            score += 0.20
            evidence.append(("header", "severity_or_cvss"))
        if header_norm & asset_norm:
            score += 0.15
            evidence.append(("header", "asset_identifier"))
        if header_norm & cve_norm:
            score += 0.10
            evidence.append(("header", "cve"))

        if not (header_norm & qid_norm):
            score = max(0.0, score - 0.25)
            evidence.append(("header", "missing_qid"))

        return min(score, 1.0), evidence

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        path = self._validate_filepath_and_size()
        return self._stream_batches(path, batch_size)

    def _stream_batches(self, path: Path, batch_size: int) -> Iterator[List[Dict[str, Any]]]:
        batch: List[Dict[str, Any]] = []
        dropped_rows = 0
        malformed_rows = 0

        csv.field_size_limit(_MAX_CSV_FIELD_BYTES)
        with self._open_read(path, self.ctx, mode="r", encoding="utf-8-sig", label="Qualys CSV") as handle:
            sample = handle.read(16384)
            if not sample.strip():
                raise ValueError("Qualys CSV parsing failed: empty file.")
            sample_clean = sample.lstrip("\ufeff")
            dialect = self._sniff_csv_dialect(sample_clean)
            handle.seek(0)
            reader = csv.reader(handle, dialect=dialect)

            try:
                header_row = self._find_header_row(reader)
            except csv.Error as exc:
                raise ValueError(f"Qualys CSV parsing failed: {exc}") from exc
            if not header_row:
                raise ValueError("Qualys CSV parsing failed: missing header row.")

            header_row[0] = header_row[0].lstrip("\ufeff")
            header_len = len(header_row)
            norm_to_idx = self._build_header_index_map(header_row)

            if not self._resolve_indices(norm_to_idx, _TITLE_ALIASES):
                raise ValueError("Qualys CSV parsing failed: no recognized vulnerability title column.")
            if not self._resolve_indices(norm_to_idx, (*_SEVERITY_ALIASES, *_CVSS_ALIASES)):
                raise ValueError("Qualys CSV parsing failed: no recognized severity or CVSS score column.")

            ip_idx = self._resolve_indices(norm_to_idx, _IP_ALIASES)
            host_idx = self._resolve_indices(norm_to_idx, _HOST_ALIASES)
            qid_idx = self._resolve_indices(norm_to_idx, _QID_ALIASES)
            title_idx = self._resolve_indices(norm_to_idx, _TITLE_ALIASES)
            sev_idx = self._resolve_indices(norm_to_idx, _SEVERITY_ALIASES)
            cvss_idx = self._resolve_indices(norm_to_idx, _CVSS_ALIASES)
            vec_idx = self._resolve_indices(norm_to_idx, _CVSS_VEC_ALIASES)
            cve_idx = self._resolve_indices(norm_to_idx, _CVE_ALIASES)
            cwe_idx = self._resolve_indices(norm_to_idx, _CWE_ALIASES)
            port_idx = self._resolve_indices(norm_to_idx, _PORT_ALIASES)
            proto_idx = self._resolve_indices(norm_to_idx, _PROTO_ALIASES)
            desc_idx = self._resolve_indices(norm_to_idx, _DESC_ALIASES)
            sol_idx = self._resolve_indices(norm_to_idx, _SOL_ALIASES)
            out_idx = self._resolve_indices(norm_to_idx, _OUT_ALIASES)
            ref_idx = self._resolve_indices(norm_to_idx, _REF_ALIASES)
            cred_idx = self._resolve_indices(norm_to_idx, _CRED_ALIASES)

            try:
                for idx, row in enumerate(reader, start=1):
                    if not row or (len(row) == 1 and not row[0].strip()):
                        continue
                    if len(row) > header_len:
                        malformed_rows += 1
                        dropped_rows += 1
                        continue

                    raw_ip = self._pick_indexed(row, ip_idx)
                    raw_host = self._pick_indexed(row, host_idx)
                    if not raw_ip and raw_host and _is_ip(raw_host):
                        raw_ip = raw_host
                    asset_identifier = raw_ip or raw_host

                    qid = self._pick_indexed(row, qid_idx)
                    title = self._pick_indexed(row, title_idx)
                    severity_raw = self._pick_indexed(row, sev_idx)
                    cvss_score, has_out_of_range_cvss = self._pick_cvss_score(row, cvss_idx)
                    if has_out_of_range_cvss and cvss_score is None:
                        dropped_rows += 1
                        continue
                    severity = self._map_severity(severity_raw, cvss_score)

                    if not asset_identifier or not title or (severity == "Unknown" and cvss_score is None):
                        dropped_rows += 1
                        continue

                    if severity == "Unknown":
                        severity = "Informational"

                    cve_text = self._pick_indexed(row, cve_idx) or ""
                    cves = extract_cves_from_text(cve_text)

                    port = self._safe_int(self._pick_indexed(row, port_idx))
                    if port is not None and not (0 <= port <= 65535):
                        port = None
                    proto = (self._pick_indexed(row, proto_idx) or "tcp").strip().lower()
                    if proto not in {"tcp", "udp", "icmp"}:
                        proto = "tcp"

                    cvss_vector = self._pick_cvss_vector(row, vec_idx)
                    description = self._pick_indexed(row, desc_idx) or ""
                    solution = self._pick_indexed(row, sol_idx) or ""
                    plugin_output = self._pick_indexed(row, out_idx) or ""

                    cwe_text = self._pick_indexed(row, cwe_idx) or ""
                    cwes = extract_cwes_from_text(cwe_text, description, plugin_output)

                    ref_text = self._pick_indexed(row, ref_idx) or ""
                    references = [r.strip() for r in re.split(r"[\n,;]+", ref_text) if r.strip()]
                    ghsa_ids = extract_ghsas_from_text(description, ref_text)

                    cred_val = (self._pick_indexed(row, cred_idx) or "").strip().lower()
                    credentialed = cred_val in {"yes", "true", "passed", "authenticated", "1"}
                    detection_mode = "credentialed_host" if credentialed else "uncredentialed_banner"

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

                    scanner_sig = f"qualys-csv:{qid or idx}"

                    rec: NormalizedFindingRecord = {
                        "ip_address": raw_ip,
                        "hostname": raw_host or raw_ip,
                        "target_uri": None,
                        "image_or_repo": None,
                        "os": None,
                        "asset_metadata": {
                            "credentialed": credentialed,
                            "open_ports": [port] if port is not None else [],
                        },
                        "source_format": "qualys-csv",
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
                        "protocol": proto,
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
                        "tags": [],
                        "exploit_evidence": None,
                        "raw_evidence_excerpt": safe_excerpt(plugin_output or description),
                    }
                    batch.append(rec)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
            except csv.Error as exc:
                raise ValueError(f"Qualys CSV parsing failed: {exc}") from exc

        self._emit_row_warnings_and_ledger(dropped_rows, malformed_rows)

        if batch:
            yield batch

    def parse(self) -> ScanResult:
        return self._build_scan_result_from_batches(
            source_label="Qualys CSV",
            detection_plugin_prefix="Qualys",
        )

    def _emit_row_warnings_and_ledger(self, dropped_rows: int, malformed_rows: int) -> None:
        if dropped_rows > 0:
            self.ctx.logger.print_warning(
                f"Qualys CSV parser dropped {dropped_rows} rows missing minimum signal contract.",
                label="Normalization",
            )
        if malformed_rows > 0:
            self.ctx.logger.print_warning(
                f"Qualys CSV parser skipped {malformed_rows} malformed rows with unexpected extra columns.",
                label="Normalization",
            )

        services = getattr(self.ctx, "services", None)
        ledger = getattr(services, "ledger", None)
        if ledger is not None and dropped_rows > 0:
            ledger.append_event(
                component="Ingestion",
                event_type="decision",
                subject_ref=f"parser:{self.NAME}",
                reason_code=DecisionReasonCodes.INGESTION_ROWS_DROPPED,
                reason_text="CSV ingestion dropped rows that failed minimum signal contract checks.",
                factor_refs=["minimum_signal_contract", "dropped_rows"],
                confidence="high",
                evidence={
                    "parser": self.NAME,
                    "dropped_rows": dropped_rows,
                    "malformed_rows": malformed_rows,
                },
            )
        if ledger is not None and malformed_rows > 0:
            ledger.append_event(
                component="Ingestion",
                event_type="decision",
                subject_ref=f"parser:{self.NAME}",
                reason_code=DecisionReasonCodes.INGESTION_MALFORMED_ROWS_SKIPPED,
                reason_text="CSV ingestion skipped malformed rows with extra columns.",
                factor_refs=["csv_row_shape", "malformed_rows"],
                confidence="high",
                evidence={
                    "parser": self.NAME,
                    "malformed_rows": malformed_rows,
                },
            )

    @staticmethod
    def _normalize_key(key: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(key or "").strip().lower())

    @classmethod
    def _build_header_index_map(cls, fieldnames: Sequence[str]) -> Dict[str, int]:
        mapping: Dict[str, int] = {}
        for idx, col in enumerate(fieldnames):
            nk = cls._normalize_key(col)
            if nk and nk not in mapping:
                mapping[nk] = idx
        return mapping

    @classmethod
    def _resolve_indices(cls, norm_to_idx: Dict[str, int], aliases: Sequence[str]) -> Tuple[int, ...]:
        out: List[int] = []
        for alias in aliases:
            idx = norm_to_idx.get(cls._normalize_key(alias))
            if idx is not None and idx not in out:
                out.append(idx)
        return tuple(out)

    @classmethod
    def _sniff_csv_dialect(cls, sample: str):
        snippet = sample[:16384]
        for candidate in (snippet[:4096], snippet):
            try:
                return csv.Sniffer().sniff(candidate, delimiters=",;\t|")
            except csv.Error:
                pass
        lines = [ln for ln in snippet.splitlines() if ln.strip()]
        for start in range(1, min(_HEADER_SCAN_MAX_ROWS, len(lines))):
            tail = "\n".join(lines[start:])
            try:
                return csv.Sniffer().sniff(tail, delimiters=",;\t|")
            except csv.Error:
                continue
        best_delim = ","
        best_count = 0
        for delim in (",", ";", "\t", "|"):
            cnt = max((ln.count(delim) for ln in lines[:_HEADER_SCAN_MAX_ROWS]), default=0)
            if cnt > best_count:
                best_count = cnt
                best_delim = delim
        if best_delim == ",":
            return csv.excel
        class _FallbackDialect(csv.excel):
            delimiter = best_delim
        return _FallbackDialect

    @classmethod
    def _is_qualys_header_row(cls, row: Sequence[str]) -> bool:
        non_empty = [str(c).lstrip("\ufeff").strip() for c in row if str(c).strip()]
        if len(non_empty) < 3:
            return False
        norm_set = {cls._normalize_key(c) for c in non_empty}
        qid_norm = {cls._normalize_key(a) for a in _QID_ALIASES}
        host_norm = {cls._normalize_key(a) for a in (*_IP_ALIASES, *_HOST_ALIASES)}
        detail_norm = {
            cls._normalize_key(a)
            for a in (*_TITLE_ALIASES, *_SEVERITY_ALIASES, "type", "vuln status", "vulnstatus")
        }
        return bool((norm_set & qid_norm) and (norm_set & host_norm) and (norm_set & detail_norm))

    @classmethod
    def _find_header_row(cls, reader) -> Optional[List[str]]:
        non_empty_seen = 0
        for row in reader:
            if not row or all(not str(c).strip() for c in row):
                continue
            non_empty_seen += 1
            if cls._is_qualys_header_row(row):
                row_copy = list(row)
                if row_copy:
                    row_copy[0] = row_copy[0].lstrip("\ufeff")
                return row_copy
            if non_empty_seen >= _HEADER_SCAN_MAX_ROWS:
                break
        return None

    @staticmethod
    def _pick_indexed(row: List[str], indices: Tuple[int, ...]) -> Optional[str]:
        row_len = len(row)
        for idx in indices:
            if idx < row_len:
                val = row[idx].strip()
                if val:
                    return val
        return None

    def _pick_cvss_score(
        self, row: List[str], indices: Tuple[int, ...]
    ) -> Tuple[Optional[float], bool]:
        row_len = len(row)
        saw_out_of_range = False
        for idx in indices:
            if idx < row_len:
                raw = row[idx].strip()
                if not raw:
                    continue
                val = self._safe_float(raw)
                if val is not None:
                    if 0.0 <= val <= 10.0:
                        return val, False
                    saw_out_of_range = True
        return None, saw_out_of_range

    @staticmethod
    def _pick_cvss_vector(row: List[str], indices: Tuple[int, ...]) -> Optional[str]:
        row_len = len(row)
        for idx in indices:
            if idx < row_len:
                norm = _normalize_cvss_vector(row[idx])
                if norm:
                    return norm
        return None

    @staticmethod
    def _map_severity(raw: Optional[str], cvss_score: Optional[float]) -> str:
        if raw is not None and str(raw).strip() != "":
            val = str(raw).strip().lower()
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
            mapped = mapping.get(val)
            if mapped:
                return mapped

        if cvss_score is None:
            return "Unknown"
        if cvss_score >= 9.0:
            return "Critical"
        if cvss_score >= 7.0:
            return "High"
        if cvss_score >= 4.0:
            return "Medium"
        if cvss_score > 0:
            return "Low"
        return "Informational"
