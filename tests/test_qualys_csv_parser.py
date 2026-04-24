from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.parsers.qualys_csv_parser import QualysCSVParser


class _PFH:
    def ensure_readable_file(self, path, **_kwargs):
        return Path(path)


class _Logger:
    def print_warning(self, *_args, **_kwargs):
        return None


class _Ctx:
    def __init__(self):
        self.pfh = _PFH()
        self.logger = _Logger()
        self.services = SimpleNamespace(ledger=LedgerService())


def test_qualys_csv_detect_file_confidence(tmp_path: Path) -> None:
    csv_file = tmp_path / "qualys.csv"
    csv_file.write_text(
        "IP,QID,Title,Severity,CVE\n"
        "10.10.1.20,90101,OpenSSL Weakness,4,CVE-2024-1111\n",
        encoding="utf-8",
    )

    conf, evidence = QualysCSVParser.detect_file(csv_file)
    assert conf >= 0.70
    assert any(k == "header" for k, _ in evidence)


def test_qualys_csv_parse_adds_ingestion_metadata(tmp_path: Path) -> None:
    csv_file = tmp_path / "qualys.csv"
    csv_file.write_text(
        "IP,QID,Title,Severity,CVE,CVSS Vector,Result,Port,Protocol,Description,Solution\n"
        "10.10.1.21,90102,SMB Exposure,5,CVE-2023-2222,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,Confirmed vulnerable service,445,tcp,desc,sol\n",
        encoding="utf-8",
    )

    parser = QualysCSVParser(_Ctx(), filepath=str(csv_file))
    scan = parser.parse()

    assert len(scan.assets) == 1
    assert scan.scan_metadata.vulnerability_count == 1
    finding = scan.assets[0].findings[0]

    assert finding.source_format == "qualys-csv"
    assert finding.severity == "Critical"
    assert finding.affected_port == 445
    assert finding.protocol == "tcp"
    assert finding.fidelity_tier in {"full", "partial", "minimal"}
    assert finding.ingestion_confidence is not None


def test_qualys_csv_parse_supports_semicolon_variant(tmp_path: Path) -> None:
    csv_file = tmp_path / "qualys_semicolon.csv"
    csv_file.write_text(
        "IP;QID;Vulnerability Title;Risk;CVE\n"
        "10.10.1.22;90103;DNS Weak Config;3;CVE-2022-3333\n",
        encoding="utf-8",
    )

    parser = QualysCSVParser(_Ctx(), filepath=str(csv_file))
    scan = parser.parse()

    assert len(scan.assets) == 1
    assert scan.scan_metadata.vulnerability_count == 1


def test_qualys_csv_parse_skips_malformed_extra_columns(tmp_path: Path) -> None:
    csv_file = tmp_path / "qualys_bad.csv"
    csv_file.write_text(
        "IP,QID,Title,Severity\n"
        "10.10.1.23,90104,Valid,4\n"
        "10.10.1.24,90105,Bad,3,unexpected_extra\n",
        encoding="utf-8",
    )

    parser = QualysCSVParser(_Ctx(), filepath=str(csv_file))
    scan = parser.parse()

    assert len(scan.assets) == 1
    assert scan.scan_metadata.vulnerability_count == 1


def test_qualys_csv_parse_emits_ingestion_ledger_events_for_row_drops(tmp_path: Path) -> None:
    csv_file = tmp_path / "qualys_ledger.csv"
    csv_file.write_text(
        "IP,QID,Title,Severity\n"
        "10.10.1.30,90106,Valid,4\n"
        "10.10.1.31,90107,Bad,3,extra\n"
        ",90108,Missing Asset,2\n",
        encoding="utf-8",
    )

    ctx = _Ctx()
    parser = QualysCSVParser(ctx, filepath=str(csv_file))
    parser.parse()

    entries = ctx.services.ledger.snapshot().entries
    codes = [entry.why.reason_code for entry in entries]
    assert DecisionReasonCodes.INGESTION_ROWS_DROPPED in codes
    assert DecisionReasonCodes.INGESTION_MALFORMED_ROWS_SKIPPED in codes
