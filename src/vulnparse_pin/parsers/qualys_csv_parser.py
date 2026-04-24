# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 Quashawn Ashley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Dict, Iterable, List, Optional, TYPE_CHECKING

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.dataclass import Asset, Finding, ScanMetaData, ScanResult
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id
from vulnparse_pin.parsers.base_parser import BaseParser

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MAX_CSV_BYTES = 500 * 1024 * 1024

_QID_ALIASES = ("qid", "vuln id", "vulnerability id", "id")
_TITLE_ALIASES = ("title", "name", "vulnerability", "vulnerability title")
_SEVERITY_ALIASES = ("severity", "risk", "threat")
_CVSS_ALIASES = ("cvss", "cvss score", "cvss base", "cvss3 base", "cvss_base")
_IP_ALIASES = ("ip", "ip address", "host ip", "asset ip")
_HOST_ALIASES = ("hostname", "fqdn", "host", "dns")
_CVE_ALIASES = ("cve", "cves", "cve id", "cve_id")
_PORT_ALIASES = ("port", "service port", "affected_port")
_PROTO_ALIASES = ("protocol", "proto", "transport")


class QualysCSVParser(BaseParser):
    NAME = "qualys-csv"

    def __init__(self, ctx: "RunContext", filepath: str | None = None):
        super().__init__(ctx=ctx, filepath=filepath)

    @classmethod
    def detect_file(cls, filepath) -> tuple[float, list[tuple[str, str]]]:
        evidence: list[tuple[str, str]] = []
        path = Path(filepath)
        if path.suffix.lower() != ".csv":
            return 0.0, [("extension", f"rejected:{path.suffix.lower()}")]

        try:
            if path.stat().st_size > _MAX_CSV_BYTES:
                return 0.0, [("size", "exceeds_500MB")]
            with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
                sample = handle.read(4096)
                if not sample.strip():
                    return 0.0, [("header", "missing")]
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                except csv.Error:
                    dialect = csv.excel
                handle.seek(0)
                header_row = next(csv.reader(handle, dialect), None)
        except OSError:
            return 0.0, [("parse", "failed")]

        if not header_row:
            return 0.0, [("header", "missing")]

        header = [str(h).strip().lower() for h in header_row if str(h).strip()]
        if len(header) < 3:
            return 0.0, [("header", "too_few_columns")]

        score = 0.0
        if any(h in _QID_ALIASES for h in header):
            score += 0.35
            evidence.append(("header", "qid"))
        if any(h in _TITLE_ALIASES for h in header):
            score += 0.20
            evidence.append(("header", "title"))
        if any(h in _SEVERITY_ALIASES or h in _CVSS_ALIASES for h in header):
            score += 0.20
            evidence.append(("header", "severity_or_cvss"))
        if any(h in _IP_ALIASES or h in _HOST_ALIASES for h in header):
            score += 0.15
            evidence.append(("header", "asset_identifier"))
        if any(h in _CVE_ALIASES for h in header):
            score += 0.10
            evidence.append(("header", "cve"))

        if not any(h in _QID_ALIASES for h in header):
            score = max(0.0, score - 0.25)
            evidence.append(("header", "missing_qid"))

        return min(score, 1.0), evidence

    def parse(self) -> ScanResult:
        if not self.filepath:
            raise ValueError("QualysCSVParser requires filepath.")

        path = Path(self.filepath)
        try:
            if path.stat().st_size > _MAX_CSV_BYTES:
                raise ValueError(f"Refusing to parse files larger than 500MB: {path}")
        except OSError as exc:
            raise ValueError(f"Failed to stat file {path}: {exc}") from exc

        assets: Dict[str, Asset] = {}
        dropped_rows = 0
        malformed_rows = 0

        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(4096)
            if not sample.strip():
                raise ValueError("Qualys CSV parsing failed: empty file.")
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            handle.seek(0)
            reader = csv.DictReader(handle, dialect=dialect, restkey="__extra_columns__")

            if reader.fieldnames is None:
                raise ValueError("Qualys CSV parsing failed: missing header row.")

            headers = {self._normalize_key(h) for h in reader.fieldnames if h}
            if not any(self._normalize_key(a) in headers for a in _TITLE_ALIASES):
                raise ValueError("Qualys CSV parsing failed: no recognized vulnerability title column.")
            if not any(self._normalize_key(a) in headers for a in (*_SEVERITY_ALIASES, *_CVSS_ALIASES)):
                raise ValueError("Qualys CSV parsing failed: no recognized severity or CVSS score column.")

            for idx, row in enumerate(reader, start=1):
                if not isinstance(row, dict):
                    dropped_rows += 1
                    continue
                if row.get("__extra_columns__"):
                    malformed_rows += 1
                    dropped_rows += 1
                    continue

                ip = self._pick(row, _IP_ALIASES)
                host = self._pick(row, _HOST_ALIASES)
                asset_identifier = ip or host

                qid = self._pick(row, _QID_ALIASES)
                title = self._pick(row, _TITLE_ALIASES)
                severity_raw = self._pick(row, _SEVERITY_ALIASES)
                cvss_score = self._safe_float(self._pick(row, _CVSS_ALIASES))
                severity = self._map_severity(severity_raw, cvss_score)

                if not asset_identifier or not title or (severity == "Unknown" and cvss_score is None):
                    dropped_rows += 1
                    continue

                if cvss_score is not None and not (0.0 <= cvss_score <= 10.0):
                    dropped_rows += 1
                    continue

                asset_id = make_asset_id(ip=ip or asset_identifier, hostname=host or asset_identifier)
                asset_obj = assets.get(asset_id)
                if asset_obj is None:
                    asset_obj = Asset(
                        hostname=host or asset_identifier,
                        ip_address=ip or asset_identifier,
                        asset_id=asset_id,
                        findings=[],
                    )
                    assets[asset_id] = asset_obj

                cve_text = self._pick(row, _CVE_ALIASES) or ""
                cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(cve_text)})

                port = self._safe_int(self._pick(row, _PORT_ALIASES))
                if port is not None and not (0 <= port <= 65535):
                    port = None
                proto = (self._pick(row, _PROTO_ALIASES) or "tcp").strip().lower()
                if proto not in {"tcp", "udp", "icmp"}:
                    proto = "tcp"

                cvss_vector = self._pick(row, ("cvss vector", "cvss_vector", "cvss3 vector"))
                description = self._pick(row, ("description", "details", "diagnosis")) or "SENTINEL:No_Description"
                solution = self._pick(row, ("solution", "fix", "remediation")) or "SENTINEL:No_Solution"
                plugin_output = self._pick(row, ("result", "evidence", "plugin output")) or "SENTINEL:No_Plugin_Output"

                missing_fields: List[str] = []
                if not cves:
                    missing_fields.append("cves")
                if not cvss_vector:
                    missing_fields.append("cvss_vector")
                if plugin_output == "SENTINEL:No_Plugin_Output":
                    missing_fields.append("plugin_output")
                if port is None:
                    missing_fields.append("affected_port")

                if not missing_fields:
                    fidelity_tier = "full"
                    ingestion_confidence = 0.95
                    confidence_reasons = ["base:full=0.95"]
                elif len(missing_fields) <= 2:
                    fidelity_tier = "partial"
                    ingestion_confidence = 0.70
                    confidence_reasons = ["base:partial=0.70"]
                else:
                    fidelity_tier = "minimal"
                    ingestion_confidence = 0.45
                    confidence_reasons = ["base:minimal=0.45"]

                finding_id = make_finding_id(
                    make_finding_base_canon(
                        asset_id=asset_id,
                        scanner_sig=f"qualys-csv:{qid or idx}",
                        proto=proto,
                        port=str(port if port is not None else 0),
                        kind=title,
                    )
                )

                finding = Finding(
                    finding_id=finding_id,
                    vuln_id=qid or f"csv_row_{idx}",
                    title=title,
                    description=description,
                    severity=severity,
                    cves=list(cves),
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    affected_port=port,
                    protocol=proto,
                    detection_plugin=f"Qualys:{qid}" if qid else "Qualys:unknown",
                    plugin_output=plugin_output,
                    plugin_evidence=[plugin_output] if plugin_output != "SENTINEL:No_Plugin_Output" else ["SENTINEL:No_Evidence"],
                    solution=solution,
                    asset_id=asset_id,
                    source_format="qualys-csv",
                    fidelity_tier=fidelity_tier,
                    missing_fields=missing_fields,
                    degraded_input=(fidelity_tier != "full"),
                    ingestion_confidence=ingestion_confidence,
                    confidence_reasons=confidence_reasons,
                )
                asset_obj.findings.append(finding)

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

        parsed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        scan_metadata = ScanMetaData(
            source="Qualys CSV",
            scan_date=parsed_at,
            parsed_at=parsed_at,
            source_file=str(path),
            scan_name=path.stem,
            asset_count=len(assets),
            vulnerability_count=sum(len(a.findings) for a in assets.values()),
        )
        return ScanResult(scan_metadata=scan_metadata, assets=list(assets.values()))

    @staticmethod
    def _normalize_key(key: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(key or "").strip().lower())

    def _pick(self, row: dict[str, str], aliases: Iterable[str]) -> Optional[str]:
        normalized = {self._normalize_key(k): (v.strip() if isinstance(v, str) else "") for k, v in row.items()}
        for alias in aliases:
            value = normalized.get(self._normalize_key(alias))
            if value:
                return value
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
