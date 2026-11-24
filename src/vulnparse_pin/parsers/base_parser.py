# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple, TypedDict, TYPE_CHECKING

from vulnparse_pin.core.classes.dataclass import Asset, Finding, ScanMetaData, ScanResult
from vulnparse_pin.core.id import make_asset_id, make_finding_base_canon, make_finding_id

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext


DEFAULT_MAX_FILE_BYTES = 500 * 1024 * 1024  # 500 MiB default parser cap
LARGE_MAX_FILE_BYTES = 50 * 1024 * 1024 * 1024  # 50 GiB cap with --allow-large
HEAD_SNIFF_BYTES = 65_536

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE[-_:\s]*0*(\d{1,6})\b", re.IGNORECASE)
GHSA_RE = re.compile(
    r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b",
    re.IGNORECASE,
)
PURL_RE = re.compile(r"\bpkg:[a-z0-9._-]+/[^\s,;\"'<>]+", re.IGNORECASE)

VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")


class NormalizedFindingRecord(TypedDict):
    """Canonical Wave 2 streaming finding record yielded by BaseParser.iter_batches."""

    ip_address: Optional[str]
    hostname: Optional[str]
    target_uri: Optional[str]
    image_or_repo: Optional[str]
    os: Optional[str]
    asset_metadata: Dict[str, Any]
    source_format: str
    scanner_sig: str
    title: str
    description: str
    solution: str
    plugin_output: str
    severity: str
    cves: List[str]
    cwes: List[str]
    ghsa_ids: List[str]
    affected_port: Optional[int]
    protocol: Optional[str]
    service_name: Optional[str]
    location_uri: Optional[str]
    line_number: Optional[int]
    package_purl: Optional[str]
    scanner_cvss_score: Optional[float]
    scanner_cvss_vector: Optional[str]
    detection_mode: str
    fidelity_tier: str
    ingestion_confidence: float
    missing_fields: List[str]
    degraded_input: bool
    references: List[str]
    tags: List[str]
    exploit_evidence: Optional[bool]
    raw_evidence_excerpt: str


def normalize_severity(raw: Optional[str], cvss_score: Optional[float] = None) -> str:
    """Normalize scanner severity strings or CVSS score into canonical severity tier."""
    val = str(raw or "").strip().lower()
    mapping = {
        "critical": "Critical",
        "crit": "Critical",
        "5": "Critical",
        "4": "Critical",
        "high": "High",
        "error": "High",
        "medium": "Medium",
        "med": "Medium",
        "moderate": "Medium",
        "warning": "Medium",
        "warn": "Medium",
        "low": "Low",
        "note": "Low",
        "info": "Informational",
        "informational": "Informational",
        "none": "Informational",
        "log": "Informational",
        "0": "Informational",
    }
    if val in mapping:
        return mapping[val]
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "Critical"
        if cvss_score >= 7.0:
            return "High"
        if cvss_score >= 4.0:
            return "Medium"
        if cvss_score > 0.0:
            return "Low"
    return "Informational"


def fidelity_to_scanresult(tier: Optional[str]) -> str:
    """Map v2 NormalizedFindingRecord fidelity_tier ('high'|'medium'|'low') to ScanResult schema enum."""
    t = str(tier or "").strip().lower()
    if t in {"high", "full"}:
        return "full"
    if t in {"medium", "partial"}:
        return "partial"
    return "minimal"


def fidelity_from_scanresult(tier: Optional[str]) -> str:
    """Map legacy ScanResult fidelity_tier ('full'|'partial'|'minimal') to v2 enum."""
    t = str(tier or "").strip().lower()
    if t in {"full", "high"}:
        return "high"
    if t in {"partial", "medium"}:
        return "medium"
    return "low"


def extract_cves_from_text(*texts: Optional[str]) -> List[str]:
    """Extract sorted unique CVE identifiers from one or more strings."""
    found: set[str] = set()
    for txt in texts:
        if not txt:
            continue
        s = txt if isinstance(txt, str) else str(txt)
        if "cve-" in s.lower():
            for match in CVE_RE.finditer(s):
                found.add(match.group(0).upper())
    return sorted(found)


def extract_cwes_from_text(*texts: Optional[str]) -> List[str]:
    """Extract normalized unique CWE-NNN identifiers from one or more strings."""
    found: list[str] = []
    seen: set[str] = set()
    for txt in texts:
        if not txt:
            continue
        s = txt if isinstance(txt, str) else str(txt)
        if "cwe" in s.lower():
            for match in CWE_RE.finditer(s):
                cwe = f"CWE-{int(match.group(1))}"
                if cwe not in seen:
                    seen.add(cwe)
                    found.append(cwe)
    return found


def extract_ghsas_from_text(*texts: Optional[str]) -> List[str]:
    """Extract normalized unique GHSA-xxxx-xxxx-xxxx identifiers from strings."""
    found: list[str] = []
    seen: set[str] = set()
    for txt in texts:
        if not txt:
            continue
        s = txt if isinstance(txt, str) else str(txt)
        if "ghsa-" in s.lower():
            for match in GHSA_RE.finditer(s):
                raw = match.group(0)
                norm = "GHSA-" + raw[5:].lower()
                if norm not in seen:
                    seen.add(norm)
                    found.append(norm)
    return found


def safe_excerpt(text: Optional[str], limit: int = 500) -> str:
    """Return bounded single-line/compact evidence excerpt without unbounded RAM retention."""
    if not text:
        return ""
    cleaned = str(text).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit] + "..."


class BaseParser(ABC):
    ctx: "RunContext"
    NAME: str = "unknown"

    def __init__(
        self,
        ctx: "RunContext",
        filepath: str | Path | None = None,
        *,
        allow_large: Optional[bool] = None,
    ):
        self.ctx = ctx
        self.filepath = filepath
        self._explicit_allow_large = allow_large
        self.allow_large = self._resolve_allow_large(filepath, ctx=ctx, allow_large=allow_large)
        self._collecting_for_parse = False
        self._last_scan_meta: Dict[str, Any] = {}

    @classmethod
    def _resolve_allow_large(
        cls,
        filepath: str | Path | None,
        ctx: Optional["RunContext"] = None,
        allow_large: Optional[bool] = None,
    ) -> bool:
        if allow_large is not None:
            return bool(allow_large)
        if ctx is not None:
            ctx_flag = getattr(ctx, "allow_large", None)
            if ctx_flag is not None:
                return bool(ctx_flag)
            pfh = getattr(ctx, "pfh", None)
            if pfh is not None:
                if filepath is not None:
                    allow_map = getattr(pfh, "_allow_large_paths", None)
                    if isinstance(allow_map, dict):
                        try:
                            key = str(Path(filepath).resolve())
                            if key in allow_map:
                                return bool(allow_map[key])
                        except Exception:
                            pass
                pfh_flag = getattr(pfh, "_allow_large_mode", None)
                if pfh_flag is not None:
                    return bool(pfh_flag)
        return False

    @classmethod
    def _max_bytes_for(
        cls,
        filepath: str | Path | None,
        ctx: Optional["RunContext"] = None,
        allow_large: Optional[bool] = None,
    ) -> int:
        if cls._resolve_allow_large(filepath, ctx=ctx, allow_large=allow_large):
            return LARGE_MAX_FILE_BYTES
        return DEFAULT_MAX_FILE_BYTES

    @staticmethod
    def _open_read(
        filepath: str | Path,
        ctx: Optional["RunContext"] = None,
        *,
        mode: str = "rb",
        encoding: Optional[str] = "utf-8",
        label: str = "Input File",
    ):
        pfh = getattr(ctx, "pfh", None) if ctx is not None else None
        if pfh is not None and hasattr(pfh, "open_for_read"):
            if "b" in mode:
                return pfh.open_for_read(filepath, mode=mode, label=label, log=False)
            return pfh.open_for_read(filepath, mode=mode, encoding=encoding, label=label, log=False)
        p = Path(filepath)
        if "b" in mode:
            return p.open(mode)
        return p.open(mode, encoding=encoding)

    @classmethod
    def _read_head_bytes(
        cls,
        filepath: str | Path,
        ctx: Optional["RunContext"] = None,
        *,
        limit: int = HEAD_SNIFF_BYTES,
        head_bytes: Optional[bytes] = None,
    ) -> bytes:
        if head_bytes is not None:
            return head_bytes[:limit]
        with cls._open_read(filepath, ctx=ctx, mode="rb", label="Input File") as fh:
            return fh.read(limit)

    def _validate_filepath_and_size(self, *, allow_large: Optional[bool] = None) -> Path:
        if not self.filepath:
            raise ValueError(f"{self.__class__.__name__} requires an accessible filepath.")
        path = Path(self.filepath)
        effective_allow = self._resolve_allow_large(
            path,
            ctx=self.ctx,
            allow_large=allow_large if allow_large is not None else self._explicit_allow_large,
        )
        max_bytes = LARGE_MAX_FILE_BYTES if effective_allow else DEFAULT_MAX_FILE_BYTES
        try:
            pfh = getattr(self.ctx, "pfh", None) if self.ctx is not None else None
            if pfh is not None and hasattr(pfh, "ensure_readable_file"):
                path = Path(pfh.ensure_readable_file(path, label="Input File", log=False))
            size = os.path.getsize(path)
        except Exception as exc:
            raise ValueError(f"Failed to stat file {self.filepath}: {exc}") from exc

        if size > max_bytes:
            limit_mb = max_bytes / (1024 * 1024)
            raise ValueError(
                f"Refusing to parse files larger than {limit_mb:.0f}MB without --allow-large: {self.filepath}"
            )
        return path

    @classmethod
    def detect(cls, data: dict) -> bool:
        """Return True if this parser can handle the given data"""
        return False

    @classmethod
    def detect_file(
        cls,
        filepath: str | Path,
        *,
        ctx: Optional["RunContext"] = None,
        allow_large: Optional[bool] = None,
        head_bytes: Optional[bytes] = None,
    ) -> Any:
        """Detect based on bounded file-level sniffing (<= 64 KB)."""
        return 0.0, []

    def iter_batches(self, batch_size: int = 10_000) -> Iterator[List[Dict[str, Any]]]:
        """
        Yield batches of NormalizedFindingRecord dicts.

        Streaming subclasses override this method natively; the fallback wraps parse().
        """
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        scan_result = self.parse()
        batch: List[Dict[str, Any]] = []
        source_fmt = getattr(self, "NAME", "unknown")
        for asset in scan_result.assets:
            for finding in asset.findings:
                cves = [
                    c for c in (finding.cves or [])
                    if c and not str(c).startswith("SENTINEL:")
                ]
                rec: NormalizedFindingRecord = {
                    "ip_address": asset.ip_address or None,
                    "hostname": asset.hostname or None,
                    "target_uri": None,
                    "image_or_repo": None,
                    "os": asset.os,
                    "asset_metadata": {"credentialed": False, "open_ports": []},
                    "source_format": str(finding.source_format or source_fmt),
                    "scanner_sig": f"{source_fmt}:{finding.vuln_id}",
                    "title": finding.title or "",
                    "description": finding.description or "",
                    "solution": finding.solution or "",
                    "plugin_output": finding.plugin_output or "",
                    "severity": normalize_severity(finding.severity, finding.cvss_score),
                    "cves": cves,
                    "cwes": extract_cwes_from_text(finding.description, finding.plugin_output),
                    "ghsa_ids": extract_ghsas_from_text(finding.description, " ".join(finding.references or [])),
                    "affected_port": finding.affected_port,
                    "protocol": finding.protocol,
                    "service_name": None,
                    "location_uri": None,
                    "line_number": None,
                    "package_purl": None,
                    "scanner_cvss_score": finding.cvss_score,
                    "scanner_cvss_vector": (
                        finding.cvss_vector
                        if finding.cvss_vector and not str(finding.cvss_vector).startswith("SENTINEL:")
                        else None
                    ),
                    "detection_mode": "uncredentialed_banner",
                    "fidelity_tier": fidelity_from_scanresult(finding.fidelity_tier),
                    "ingestion_confidence": float(finding.ingestion_confidence if finding.ingestion_confidence is not None else 0.70),
                    "missing_fields": list(finding.missing_fields or []),
                    "degraded_input": bool(finding.degraded_input),
                    "references": list(finding.references or []),
                    "tags": [],
                    "exploit_evidence": None,
                    "raw_evidence_excerpt": safe_excerpt(finding.plugin_output),
                }
                batch.append(rec)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
        if batch:
            yield batch

    @abstractmethod
    def parse(self) -> ScanResult:
        """Parse the data and return normalized VulnParse-Pin format."""
        pass

    def _build_scan_result_from_batches(
        self,
        *,
        source_label: str,
        default_scan_name: Optional[str] = None,
        vuln_id_from_sig: bool = True,
        detection_plugin_prefix: Optional[str] = None,
    ) -> ScanResult:
        """Materialize a ScanResult in one pass by consuming iter_batches()."""
        self._collecting_for_parse = True
        self._last_scan_meta = {}
        try:
            assets: Dict[str, Asset] = {}
            for batch in self.iter_batches(batch_size=10_000):
                for rec in batch:
                    ip = rec.get("ip_address")
                    host = rec.get("hostname")
                    target_uri = rec.get("target_uri")
                    image_or_repo = rec.get("image_or_repo")
                    location_uri = rec.get("location_uri")

                    asset_hostname = host or image_or_repo or target_uri or ip or location_uri or "unknown-asset"
                    asset_ip = ip or ""
                    asset_key = rec.get("_asset_key") if "_asset_key" in rec else None
                    canon_id = make_asset_id(asset_ip or asset_hostname, asset_hostname)
                    lookup_key = asset_key or canon_id

                    asset_obj = assets.get(lookup_key)
                    if asset_obj is None:
                        asset_obj = Asset(
                            hostname=str(asset_hostname),
                            ip_address=str(asset_ip or asset_hostname),
                            criticality=None,
                            os=rec.get("os"),
                            findings=[],
                            shodan_data=None,
                            asset_id=canon_id,
                        )
                        assets[lookup_key] = asset_obj
                    elif rec.get("os") and not asset_obj.os:
                        asset_obj.os = rec.get("os")

                    scanner_sig = str(rec.get("scanner_sig") or f"{self.NAME}:unknown")
                    if vuln_id_from_sig and ":" in scanner_sig:
                        vuln_id = scanner_sig.split(":", 1)[1] or scanner_sig
                    else:
                        vuln_id = scanner_sig

                    port = rec.get("affected_port")
                    proto = rec.get("protocol")
                    title = str(rec.get("title") or "Untitled Finding")
                    finding_id = make_finding_id(
                        make_finding_base_canon(
                            asset_id=asset_obj.asset_id or canon_id,
                            scanner_sig=scanner_sig,
                            proto=str(proto or "unknown"),
                            port=str(port if port is not None else 0),
                            kind=title,
                        )
                    )

                    plugin_output = rec.get("plugin_output") or "SENTINEL:No_Plugin_Output"
                    _, summarized_evidence = self._summarize_plugin_output(
                        None if plugin_output == "SENTINEL:No_Plugin_Output" else plugin_output
                    )
                    if plugin_output == "SENTINEL:No_Plugin_Output":
                        plugin_evidence = ["SENTINEL:No_Evidence"]
                    else:
                        plugin_evidence = summarized_evidence or [safe_excerpt(plugin_output)]

                    scan_fidelity = fidelity_to_scanresult(rec.get("fidelity_tier"))
                    conf_reasons = list(
                        rec.get("_confidence_reasons")
                        or [f"base:{scan_fidelity}={float(rec.get('ingestion_confidence', 0.7)):.2f}"]
                    )
                    det_plugin = (
                        f"{detection_plugin_prefix}:{vuln_id}"
                        if detection_plugin_prefix
                        else title
                    )

                    finding = Finding(
                        finding_id=finding_id,
                        vuln_id=vuln_id,
                        title=title,
                        description=rec.get("description") or "SENTINEL:No_Description",
                        severity=rec.get("severity") or "Informational",
                        cves=list(rec.get("cves") or []),
                        cvss_score=rec.get("scanner_cvss_score"),
                        cvss_vector=rec.get("scanner_cvss_vector"),
                        epss_score=None,
                        affected_port=port,
                        protocol=proto,
                        detection_plugin=det_plugin,
                        plugin_output=plugin_output,
                        plugin_evidence=plugin_evidence,
                        solution=rec.get("solution") or "SENTINEL:No_Solution",
                        references=list(rec.get("references") or []),
                        asset_id=asset_obj.asset_id,
                        source_format=rec.get("source_format"),
                        fidelity_tier=scan_fidelity,
                        missing_fields=list(rec.get("missing_fields") or []),
                        degraded_input=bool(rec.get("degraded_input", False)),
                        ingestion_confidence=rec.get("ingestion_confidence"),
                        confidence_reasons=conf_reasons,
                    )
                    asset_obj.findings.append(finding)

            # Include observed assets that had zero findings (e.g., clean hosts)
            for entry in self._last_scan_meta.get("empty_assets", []):
                lookup_key = entry["lookup_key"]
                if lookup_key not in assets:
                    assets[lookup_key] = Asset(
                        hostname=entry["hostname"],
                        ip_address=entry["ip_address"],
                        criticality=None,
                        os=entry.get("os"),
                        findings=[],
                        shodan_data=None,
                        asset_id=entry["asset_id"],
                    )

            parsed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            raw_scan_date = self._last_scan_meta.get("scan_date")
            if not raw_scan_date or str(raw_scan_date).startswith("SENTINEL:"):
                raw_scan_date = parsed_at

            scan_name = (
                self._last_scan_meta.get("scan_name")
                or default_scan_name
                or (Path(self.filepath).stem if self.filepath else None)
            )

            metadata = ScanMetaData(
                source=source_label,
                scan_date=raw_scan_date,
                asset_count=len(assets),
                vulnerability_count=sum(len(a.findings) for a in assets.values()),
                parsed_at=parsed_at,
                source_file=str(self.filepath) if self.filepath else None,
                scan_name=scan_name,
            )
            return ScanResult(scan_metadata=metadata, assets=list(assets.values()))
        finally:
            self._collecting_for_parse = False

    @staticmethod
    def _safe_float(value: Any) -> Optional[float]:
        try:
            if value is None or value == "":
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_text(elem_text: Optional[str]) -> Optional[str]:
        """Normalize text from xml by stripping leading/trailing whitespace and collapsing newlines."""
        if not elem_text:
            return None
        return " ".join(elem_text.split())

    _KEY_PATTERNS = [
        re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
        re.compile(r"\bversion\s*[:=]?\s*[v]?\d+(\.\d+){0,4}\b", re.IGNORECASE),
        re.compile(r"\b(cvss[:=]?\s*\d+(\.\d+)?)\b", re.IGNORECASE),
        re.compile(r"\b(epss|epS S)\b", re.IGNORECASE),
        re.compile(r"\b(?:port|tcp|udp)\s*[:=]?\s*\d{1,5}\b", re.IGNORECASE),
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
        re.compile(r"\b(error|failed|denied|not found|timeout|exception)\b", re.IGNORECASE),
        re.compile(r"\b(Registry|HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\b", re.IGNORECASE),
        re.compile(r"\b(Microsoft-IIS|nginx|apache|OpenSSH|OpenSSL|IIS|Tomcat)\b", re.IGNORECASE),
        re.compile(r"\b(Named pipe|\\PIPE\\|\\\\[A-Z0-9-_]+)"),
        re.compile(r"\b(Scan Start Date|Scan Start|Scan duration|Scanner IP)\b", re.IGNORECASE),
    ]

    _SPLIT_DELIMS_RE = re.compile(
        r"(?:\r\n|\n)|"
        r"\.\s+|"
        r"\?\s+|"
        r"!\s+|"
        r"\s;+\s|"
        r"\s\|\s|"
        r"\s-\s|"
        r"\s:\s(?!\d)",
        re.VERBOSE,
    )

    @classmethod
    def _smart_chunk_lines(cls, raw: str, max_chunk_len: int = 350) -> List[str]:
        """Turn raw plugin_output into a list of chunks to evaluate."""
        if not raw:
            return []
        lines = BaseParser._SPLIT_DELIMS_RE.split(raw)
        chunks, buf = [], ""
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if len(buf) + len(line) < max_chunk_len:
                buf += (" " if buf else "") + line
            else:
                chunks.append(buf.strip())
                buf = line
        if buf:
            chunks.append(buf.strip())
        return chunks

    @staticmethod
    def _summarize_plugin_output(output: Optional[str], max_lines: int = 3) -> Tuple[str, List[str]]:
        """Summarize plugin_output field from scanners."""
        if not output:
            return ("SENTINEL:No_Plugin_Output", ["SENTINEL:No_Plugin_Output_Src"])

        chunks = BaseParser._smart_chunk_lines(output)
        if not chunks:
            cleaned = output.strip()
            return cleaned, [cleaned]

        summary = chunks[0]
        evidence = chunks[:max_lines] if chunks else [summary]
        if len(chunks) > max_lines:
            evidence.append(f"...truncated (~{len(chunks) - max_lines} more lines)")
        if len(evidence) == 1 and evidence[0] == summary:
            evidence = ["SENTINEL:Deduped_From_Output"]
        return summary, evidence
