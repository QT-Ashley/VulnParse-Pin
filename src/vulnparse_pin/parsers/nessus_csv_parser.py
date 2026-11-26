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
    normalize_severity,
    safe_excerpt,
)

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


_PLUGIN_ID_ALIASES = (
    "plugin id",
    "pluginid",
    "plugin_id",
    "plugin",
    "plugin oid",
)
_TITLE_ALIASES = (
    "plugin name",
    "plugin_name",
    "name",
    "title",
    "vulnerability",
    "vulnerability name",
)
_SEVERITY_ALIASES = (
    "risk",
    "severity",
    "severity level",
    "threat",
)
_CVSS_V4_SCORE_ALIASES = (
    "cvss v4.0 base score",
    "cvss4.0 base score",
    "cvss4 base score",
    "cvss v4 base score",
    "cvss_v4_base_score",
    "cvss4_base_score",
)
_CVSS_V3_SCORE_ALIASES = (
    "cvss v3.1 base score",
    "cvss v3.0 base score",
    "cvssv3 base score",
    "cvss3 base score",
    "cvss v3 base score",
    "cvss_v3_base_score",
    "cvss3_base_score",
)
_CVSS_V2_SCORE_ALIASES = (
    "cvss v2.0 base score",
    "cvss v2 base score",
    "cvss base score",
    "cvss_base_score",
    "cvss score",
    "cvss",
)
_CVSS_SCORE_ALIASES = (
    *_CVSS_V4_SCORE_ALIASES,
    *_CVSS_V3_SCORE_ALIASES,
    *_CVSS_V2_SCORE_ALIASES,
)
_CVSS_V4_VECTOR_ALIASES = (
    "cvss v4.0 vector",
    "cvss4.0 vector",
    "cvss4 vector",
    "cvss v4 vector",
    "cvss_v4_vector",
    "cvss4_vector",
)
_CVSS_V3_VECTOR_ALIASES = (
    "cvss v3.1 vector",
    "cvss v3.0 vector",
    "cvssv3 vector",
    "cvss3 vector",
    "cvss v3 vector",
    "cvss_v3_vector",
    "cvss3_vector",
)
_CVSS_V2_VECTOR_ALIASES = (
    "cvss v2.0 vector",
    "cvss v2 vector",
    "cvss vector",
    "cvss_vector",
)
_CVSS_VECTOR_ALIASES = (
    *_CVSS_V4_VECTOR_ALIASES,
    *_CVSS_V3_VECTOR_ALIASES,
    *_CVSS_V2_VECTOR_ALIASES,
)
_IP_ALIASES = ("ip", "ip address", "host ip")
_HOST_ALIASES = (
    "hostname",
    "host name",
    "dns name",
    "dns",
    "fqdn",
    "netbios name",
    "netbios",
    "host",
)
_ASSET_ALIASES = (
    "host",
    "hostname",
    "host name",
    "ip",
    "ip address",
    "host ip",
    "dns name",
    "dns",
    "fqdn",
    "netbios name",
    "netbios",
)
_CVE_ALIASES = ("cve", "cves", "cve_id", "cve id")
_CWE_ALIASES = ("cwe", "cwes", "cwe_id", "cwe id")
_PROTO_ALIASES = ("protocol", "proto", "transport")
_PORT_ALIASES = ("port", "affected_port", "plugin port", "service port")
_DESC_ALIASES = ("description", "synopsis")
_SOL_ALIASES = ("solution", "remediation", "fix")
_OUT_ALIASES = ("plugin output", "plugin_output", "plugin text", "evidence")
_REF_ALIASES = ("see also", "see_also", "references", "xref")
_CRED_ALIASES = ("credentialed", "credentialed scan", "credentialed checks", "authenticated")
_MAX_CSV_FIELD_BYTES = min(32 * 1024 * 1024, sys.maxsize)
_CREDENTIALED_RE = re.compile(r"Credentialed checks\s*:\s*yes\b", re.IGNORECASE)


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


class NessusCSVParser(BaseParser):
    """Streaming parser for flattened Nessus CSV exports with one-time header indexing."""

    NAME = "nessus-csv"

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
            try:
                dialect = csv.Sniffer().sniff(sample[:4096], delimiters=",;\t|")
            except csv.Error:
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                except csv.Error:
                    dialect = csv.excel
            first_row = next(csv.reader(io.StringIO(sample), dialect), None)
        except OSError:
            return 0.0, [("parse", "failed")]

        if not first_row:
            return 0.0, [("header", "missing")]

        header = [h.lstrip("\ufeff").strip().lower() for h in first_row if str(h).strip()]
        if not header:
            return 0.0, [("header", "empty")]
        if len(header) < 3:
            return 0.0, [("header", "too_few_columns")]

        header_norm = {cls._normalize_key(h) for h in header}
        plugin_norm = {cls._normalize_key(a) for a in _PLUGIN_ID_ALIASES}
        title_norm = {cls._normalize_key(a) for a in _TITLE_ALIASES}
        sev_score_norm = {cls._normalize_key(a) for a in (*_SEVERITY_ALIASES, *_CVSS_SCORE_ALIASES)}
        asset_norm = {cls._normalize_key(a) for a in _ASSET_ALIASES}
        cve_norm = {cls._normalize_key(a) for a in _CVE_ALIASES}

        score = 0.0
        if header_norm & plugin_norm:
            score += 0.35
            evidence.append(("header", "plugin_id"))
        if header_norm & title_norm:
            score += 0.20
            evidence.append(("header", "title"))
        if header_norm & sev_score_norm:
            score += 0.20
            evidence.append(("header", "severity_or_score"))
        if header_norm & asset_norm:
            score += 0.15
            evidence.append(("header", "asset_identifier"))
        if header_norm & cve_norm:
            score += 0.10
            evidence.append(("header", "cve"))

        if not (header_norm & (plugin_norm | title_norm)):
            score = max(0.0, score - 0.25)
            evidence.append(("header", "missing_vuln_identity"))

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
        with self._open_read(path, self.ctx, mode="r", encoding="utf-8-sig", label="Nessus CSV") as handle:
            sample = handle.read(16384)
            if not sample.strip():
                raise ValueError("Nessus CSV parsing failed: empty file.")
            sample_clean = sample.lstrip("\ufeff")
            try:
                dialect = csv.Sniffer().sniff(sample_clean[:4096], delimiters=",;\t|")
            except csv.Error:
                try:
                    dialect = csv.Sniffer().sniff(sample_clean, delimiters=",;\t|")
                except csv.Error:
                    dialect = csv.excel
            handle.seek(0)
            reader = csv.reader(handle, dialect=dialect)

            try:
                header_row = next(reader, None)
            except csv.Error as exc:
                raise ValueError(f"Nessus CSV parsing failed: {exc}") from exc
            if not header_row:
                raise ValueError("Nessus CSV parsing failed: missing header row.")

            header_row[0] = header_row[0].lstrip("\ufeff")
            header_len = len(header_row)
            norm_to_idx = self._build_header_index_map(header_row)

            if not self._resolve_indices(norm_to_idx, _TITLE_ALIASES):
                raise ValueError("Nessus CSV parsing failed: no recognized vulnerability title column.")
            if not self._resolve_indices(norm_to_idx, (*_SEVERITY_ALIASES, *_CVSS_SCORE_ALIASES)):
                raise ValueError("Nessus CSV parsing failed: no recognized severity or CVSS score column.")

            ip_idx = self._resolve_indices(norm_to_idx, _IP_ALIASES)
            host_idx = self._resolve_indices(norm_to_idx, _HOST_ALIASES)
            title_idx = self._resolve_indices(norm_to_idx, _TITLE_ALIASES)
            sev_idx = self._resolve_indices(norm_to_idx, _SEVERITY_ALIASES)
            cvss_idx = self._resolve_indices(norm_to_idx, _CVSS_SCORE_ALIASES)
            vec_idx = self._resolve_indices(norm_to_idx, _CVSS_VECTOR_ALIASES)
            cve_idx = self._resolve_indices(norm_to_idx, _CVE_ALIASES)
            cwe_idx = self._resolve_indices(norm_to_idx, _CWE_ALIASES)
            pid_idx = self._resolve_indices(norm_to_idx, _PLUGIN_ID_ALIASES)
            desc_idx = self._resolve_indices(norm_to_idx, _DESC_ALIASES)
            sol_idx = self._resolve_indices(norm_to_idx, _SOL_ALIASES)
            out_idx = self._resolve_indices(norm_to_idx, _OUT_ALIASES)
            proto_idx = self._resolve_indices(norm_to_idx, _PROTO_ALIASES)
            port_idx = self._resolve_indices(norm_to_idx, _PORT_ALIASES)
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

                    title = self._pick_indexed(row, title_idx)
                    severity_raw = self._pick_indexed(row, sev_idx)
                    cvss_score, has_out_of_range_cvss = self._pick_cvss_score(row, cvss_idx)

                    if has_out_of_range_cvss and cvss_score is None:
                        dropped_rows += 1
                        continue

                    if not severity_raw and cvss_score is not None:
                        severity = self._severity_from_cvss(cvss_score)
                    elif severity_raw:
                        severity = normalize_severity(severity_raw, cvss_score)
                    else:
                        severity = ""

                    if not asset_identifier or not title or (not severity and cvss_score is None):
                        dropped_rows += 1
                        continue

                    cve_text = self._pick_indexed(row, cve_idx) or ""
                    cves = extract_cves_from_text(cve_text)

                    plugin_id = self._pick_indexed(row, pid_idx) or f"csv_row_{idx}"
                    description = self._pick_indexed(row, desc_idx) or ""
                    solution = self._pick_indexed(row, sol_idx) or ""
                    plugin_output = self._pick_indexed(row, out_idx) or ""
                    cvss_vector = self._pick_cvss_vector(row, vec_idx)
                    protocol = (self._pick_indexed(row, proto_idx) or "tcp").strip().lower()
                    affected_port = self._safe_int(self._pick_indexed(row, port_idx))
                    if affected_port is not None and not (0 <= affected_port <= 65535):
                        affected_port = None

                    cwe_text = self._pick_indexed(row, cwe_idx) or ""
                    cwes = extract_cwes_from_text(cwe_text, description, plugin_output)

                    ref_text = self._pick_indexed(row, ref_idx) or ""
                    references = [r.strip() for r in re.split(r"[\n,;]+", ref_text) if r.strip()]
                    ghsa_ids = extract_ghsas_from_text(description, ref_text)

                    cred_val = (self._pick_indexed(row, cred_idx) or "").strip().lower()
                    credentialed = cred_val in {"yes", "true", "1"} or bool(
                        _CREDENTIALED_RE.search(plugin_output)
                    )
                    detection_mode = "credentialed_host" if credentialed else "uncredentialed_banner"

                    missing_fields = self._missing_fields(
                        cves=cves,
                        cvss_vector=cvss_vector,
                        plugin_output=plugin_output,
                        affected_port=affected_port,
                        protocol=protocol,
                    )
                    fidelity_tier = self._fidelity_tier(
                        cves=cves,
                        cvss_vector=cvss_vector,
                        plugin_output=plugin_output,
                        affected_port=affected_port,
                    )
                    degraded_input = fidelity_tier != "high"
                    ingestion_confidence, _ = self._ingestion_confidence(
                        fidelity_tier=fidelity_tier,
                        cves=cves,
                        cvss_vector=cvss_vector,
                        plugin_output=plugin_output,
                    )

                    rec: NormalizedFindingRecord = {
                        "ip_address": raw_ip,
                        "hostname": raw_host or raw_ip,
                        "target_uri": None,
                        "image_or_repo": None,
                        "os": None,
                        "asset_metadata": {
                            "credentialed": credentialed,
                            "open_ports": [affected_port] if affected_port is not None else [],
                        },
                        "source_format": "nessus-csv",
                        "scanner_sig": f"nessus-csv:{plugin_id}",
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
                        "degraded_input": degraded_input,
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
                raise ValueError(f"Nessus CSV parsing failed: {exc}") from exc

        self._emit_row_warnings_and_ledger(dropped_rows, malformed_rows)

        if batch:
            yield batch

    def parse(self) -> ScanResult:
        res = self._build_scan_result_from_batches(source_label="Nessus CSV")
        for asset in res.assets:
            for finding in asset.findings:
                finding.detection_plugin = "Nessus CSV"
        return res

    def _emit_row_warnings_and_ledger(self, dropped_rows: int, malformed_rows: int) -> None:
        if dropped_rows > 0:
            self.ctx.logger.print_warning(
                f"Nessus CSV parser dropped {dropped_rows} rows missing minimum signal contract.",
                label="Normalization",
            )
        if malformed_rows > 0:
            self.ctx.logger.print_warning(
                f"Nessus CSV parser skipped {malformed_rows} malformed rows with unexpected extra columns.",
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
    def _severity_from_cvss(cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "Critical"
        if cvss_score >= 7.0:
            return "High"
        if cvss_score >= 4.0:
            return "Medium"
        if cvss_score > 0:
            return "Low"
        return "Informational"

    @staticmethod
    def _fidelity_tier(
        *,
        cves: List[str],
        cvss_vector: Optional[str],
        plugin_output: str,
        affected_port: Optional[int],
    ) -> str:
        has_cve = len(cves) > 0
        has_vector = bool(cvss_vector)
        has_output = bool(plugin_output)
        has_port = affected_port is not None

        if has_cve and has_vector and has_output:
            return "high"
        if has_cve or has_vector or has_output or has_port:
            return "medium"
        return "low"

    @staticmethod
    def _missing_fields(
        *,
        cves: List[str],
        cvss_vector: Optional[str],
        plugin_output: str,
        affected_port: Optional[int],
        protocol: str,
    ) -> List[str]:
        missing: List[str] = []
        if not cves:
            missing.append("cves")
        if not cvss_vector:
            missing.append("cvss_vector")
        if not plugin_output:
            missing.append("plugin_output")
        if affected_port is None:
            missing.append("affected_port")
        if not protocol:
            missing.append("protocol")
        return missing

    @staticmethod
    def _ingestion_confidence(
        *,
        fidelity_tier: str,
        cves: List[str],
        cvss_vector: Optional[str],
        plugin_output: str,
    ) -> tuple[float, List[str]]:
        base = {"high": 0.95, "medium": 0.70, "low": 0.45}.get(fidelity_tier, 0.45)
        conf = base
        reasons = [f"base:{fidelity_tier}={base:.2f}"]

        if cves:
            conf += 0.05
            reasons.append("+cve")
        else:
            conf -= 0.10
            reasons.append("-missing_cve")

        if cvss_vector:
            conf += 0.05
            reasons.append("+cvss_vector")

        if plugin_output:
            conf += 0.05
            reasons.append("+evidence")
        else:
            conf -= 0.05
            reasons.append("-missing_evidence")

        conf = max(0.0, min(1.0, conf))
        return round(conf, 4), reasons
