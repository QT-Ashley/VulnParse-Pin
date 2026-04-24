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
from typing import Dict, List, Optional, TYPE_CHECKING

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.dataclass import Asset, Finding, ScanMetaData, ScanResult
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id
from vulnparse_pin.parsers.base_parser import BaseParser

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MAX_CSV_BYTES = 500 * 1024 * 1024

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
_CVSS_SCORE_ALIASES = (
    "cvss",
    "cvss base score",
    "cvss_base_score",
    "cvss score",
    "cvssv3 base score",
)
_ASSET_ALIASES = (
    "host",
    "hostname",
    "host name",
    "ip",
    "ip address",
    "host ip",
    "dns name",
    "fqdn",
)
_CVE_ALIASES = ("cve", "cves", "cve_id", "cve id")
_PROTO_ALIASES = ("protocol", "proto", "transport")
_PORT_ALIASES = ("port", "affected_port", "plugin port", "service port")


class NessusCSVParser(BaseParser):
    """Parser for flattened Nessus CSV exports with confidence-aware degradation metadata."""

    NAME = "nessus-csv"

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
                reader = csv.reader(handle, dialect)
                first_row = next(reader, None)
        except OSError:
            return 0.0, [("parse", "failed")]

        if not first_row:
            return 0.0, [("header", "missing")]

        header = [h.strip().lower() for h in first_row if str(h).strip()]
        if not header:
            return 0.0, [("header", "empty")]
        if len(header) < 3:
            return 0.0, [("header", "too_few_columns")]

        score = 0.0

        if any(h in _PLUGIN_ID_ALIASES for h in header):
            score += 0.35
            evidence.append(("header", "plugin_id"))

        if any(h in _TITLE_ALIASES for h in header):
            score += 0.20
            evidence.append(("header", "title"))

        if any(h in _SEVERITY_ALIASES or h in _CVSS_SCORE_ALIASES for h in header):
            score += 0.20
            evidence.append(("header", "severity_or_score"))

        if any(h in _ASSET_ALIASES for h in header):
            score += 0.15
            evidence.append(("header", "asset_identifier"))

        if any(h in _CVE_ALIASES for h in header):
            score += 0.10
            evidence.append(("header", "cve"))

        # Defensive negative signal: common inventory-only exports with no vuln semantics.
        if not any(h in _PLUGIN_ID_ALIASES or h in _TITLE_ALIASES for h in header):
            score = max(0.0, score - 0.25)
            evidence.append(("header", "missing_vuln_identity"))

        return min(score, 1.0), evidence

    def parse(self) -> ScanResult:
        if not self.filepath:
            raise ValueError("NessusCSVParser requires filepath.")

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
                raise ValueError("Nessus CSV parsing failed: empty file.")
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            handle.seek(0)
            reader = csv.DictReader(handle, dialect=dialect, restkey="__extra_columns__")

            if reader.fieldnames is None:
                raise ValueError("Nessus CSV parsing failed: missing header row.")

            normalized_headers = {self._normalize_key(h) for h in reader.fieldnames if h}
            if not any(self._normalize_key(a) in normalized_headers for a in _TITLE_ALIASES):
                raise ValueError("Nessus CSV parsing failed: no recognized vulnerability title column.")
            if not any(
                self._normalize_key(a) in normalized_headers
                for a in (*_SEVERITY_ALIASES, *_CVSS_SCORE_ALIASES)
            ):
                raise ValueError("Nessus CSV parsing failed: no recognized severity or CVSS score column.")

            for idx, row in enumerate(reader, start=1):
                if not isinstance(row, dict):
                    dropped_rows += 1
                    continue
                if row.get("__extra_columns__"):
                    malformed_rows += 1
                    dropped_rows += 1
                    continue

                ip = self._pick(row, *(_ASSET_ALIASES[:6]))
                host = self._pick(row, *("hostname", "host name", "dns name", "fqdn"))
                asset_identifier = ip or host

                title = self._pick(row, *_TITLE_ALIASES)
                severity = self._pick(row, *_SEVERITY_ALIASES)
                cvss_score = self._safe_float(self._pick(row, *_CVSS_SCORE_ALIASES))

                if not severity and cvss_score is not None:
                    severity = self._severity_from_cvss(cvss_score)

                if not asset_identifier or not title or (not severity and cvss_score is None):
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

                cve_text = self._pick(row, *_CVE_ALIASES) or ""
                cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(cve_text)})

                plugin_id = self._pick(row, *_PLUGIN_ID_ALIASES) or f"csv_row_{idx}"
                description = self._pick(row, "description", "synopsis") or "SENTINEL:No_Description"
                solution = self._pick(row, "solution") or "SENTINEL:No_Solution"
                plugin_output = self._pick(row, "plugin output", "plugin_output", "evidence") or ""
                cvss_vector = self._pick(row, "cvss vector", "cvss_vector")
                protocol = (self._pick(row, *_PROTO_ALIASES) or "tcp").strip().lower()
                affected_port = self._safe_int(self._pick(row, *_PORT_ALIASES))
                if affected_port is not None and not (0 <= affected_port <= 65535):
                    affected_port = None

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
                degraded_input = fidelity_tier != "full"
                ingestion_confidence, confidence_reasons = self._ingestion_confidence(
                    fidelity_tier=fidelity_tier,
                    cves=cves,
                    cvss_vector=cvss_vector,
                    plugin_output=plugin_output,
                )

                finding_id = make_finding_id(
                    make_finding_base_canon(
                        asset_id=asset_id,
                        scanner_sig=f"nessus-csv:{plugin_id}",
                        proto=protocol,
                        port=str(affected_port if affected_port is not None else 0),
                        kind=title,
                    )
                )

                finding = Finding(
                    finding_id=finding_id,
                    vuln_id=plugin_id,
                    title=title,
                    description=description,
                    severity=severity,
                    cves=cves,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    affected_port=affected_port,
                    protocol=protocol,
                    plugin_output=plugin_output if plugin_output else "SENTINEL:No_Plugin_Output",
                    plugin_evidence=[plugin_output] if plugin_output else ["SENTINEL:No_Evidence"],
                    solution=solution,
                    detection_plugin="Nessus CSV",
                    asset_id=asset_id,
                    source_format="nessus-csv",
                    fidelity_tier=fidelity_tier,
                    missing_fields=missing_fields,
                    degraded_input=degraded_input,
                    ingestion_confidence=ingestion_confidence,
                    confidence_reasons=confidence_reasons,
                )
                asset_obj.findings.append(finding)

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

        parsed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        scan_metadata = ScanMetaData(
            source="Nessus CSV",
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

    def _pick(self, row: dict[str, str], *aliases: str) -> Optional[str]:
        normalized = {self._normalize_key(k): (v.strip() if isinstance(v, str) else "") for k, v in row.items()}
        for alias in aliases:
            value = normalized.get(self._normalize_key(alias))
            if value:
                return value
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
    def _fidelity_tier(*, cves: List[str], cvss_vector: Optional[str], plugin_output: str, affected_port: Optional[int]) -> str:
        has_cve = len(cves) > 0
        has_vector = bool(cvss_vector)
        has_output = bool(plugin_output)
        has_port = affected_port is not None

        if has_cve and has_vector and has_output:
            return "full"
        if has_cve or has_vector or has_output or has_port:
            return "partial"
        return "minimal"

    @staticmethod
    def _missing_fields(*, cves: List[str], cvss_vector: Optional[str], plugin_output: str, affected_port: Optional[int], protocol: str) -> List[str]:
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
    def _ingestion_confidence(*, fidelity_tier: str, cves: List[str], cvss_vector: Optional[str], plugin_output: str) -> tuple[float, List[str]]:
        base = {"full": 0.95, "partial": 0.70, "minimal": 0.45}.get(fidelity_tier, 0.45)
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
