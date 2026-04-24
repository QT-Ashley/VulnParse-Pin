from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vulnparse_pin.core.classes.decision_reasons import DecisionReasonCodes
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.parsers.nessus_csv_parser import NessusCSVParser


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


def test_nessus_csv_detect_file_confidence(tmp_path: Path) -> None:
    csv_file = tmp_path / "nessus.csv"
    csv_file.write_text(
        "Host,Plugin ID,Plugin Name,Risk,CVE,Port,Protocol\n"
        "10.0.0.10,10001,SMB Signing Not Required,High,CVE-2020-1234,445,tcp\n",
        encoding="utf-8",
    )

    conf, evidence = NessusCSVParser.detect_file(csv_file)
    assert conf >= 0.70
    assert any(k == "header" for k, _ in evidence)


def test_nessus_csv_parse_adds_ingestion_metadata(tmp_path: Path) -> None:
    csv_file = tmp_path / "nessus.csv"
    csv_file.write_text(
        "Host,Plugin ID,Plugin Name,Risk,CVE,CVSS Vector,Plugin Output,Port,Protocol,Description,Solution\n"
        "10.0.0.20,10002,Weak Cipher Suites,Medium,CVE-2021-0001,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N,Detected weak ciphers,443,tcp,desc,sol\n",
        encoding="utf-8",
    )

    parser = NessusCSVParser(_Ctx(), filepath=str(csv_file))
    scan = parser.parse()

    assert len(scan.assets) == 1
    assert len(scan.assets[0].findings) == 1
    finding = scan.assets[0].findings[0]

    assert finding.source_format == "nessus-csv"
    assert finding.fidelity_tier == "full"
    assert finding.degraded_input is False
    assert finding.ingestion_confidence is not None
    assert 0.0 <= finding.ingestion_confidence <= 1.0
    assert isinstance(finding.confidence_reasons, list)


def test_nessus_csv_parse_drops_rows_missing_minimum_contract(tmp_path: Path) -> None:
    csv_file = tmp_path / "nessus.csv"
    csv_file.write_text(
        "Host,Plugin ID,Plugin Name,Risk,CVE\n"
        ",10003,Incomplete Row,,\n"
        "10.0.0.21,10004,Has Risk,Low,\n",
        encoding="utf-8",
    )

    parser = NessusCSVParser(_Ctx(), filepath=str(csv_file))
    scan = parser.parse()

    assert len(scan.assets) == 1
    assert scan.scan_metadata.vulnerability_count == 1


def test_nessus_csv_detect_supports_semicolon_schema_variant(tmp_path: Path) -> None:
    csv_file = tmp_path / "nessus_semicolon.csv"
    csv_file.write_text(
        "Host;Plugin ID;Vulnerability Name;Severity;CVE\n"
        "10.0.0.30;10005;TLS Weak Config;Medium;CVE-2022-1111\n",
        encoding="utf-8",
    )

    conf, _ = NessusCSVParser.detect_file(csv_file)
    assert conf >= 0.70


def test_nessus_csv_parse_skips_malformed_extra_column_rows(tmp_path: Path) -> None:
    csv_file = tmp_path / "nessus_malformed.csv"
    csv_file.write_text(
        "Host,Plugin ID,Plugin Name,Risk,CVE\n"
        "10.0.0.40,10006,Valid Row,High,CVE-2023-1111\n"
        "10.0.0.41,10007,Bad Row,Medium,CVE-2023-1112,unexpected_extra\n",
        encoding="utf-8",
    )

    parser = NessusCSVParser(_Ctx(), filepath=str(csv_file))
    scan = parser.parse()

    assert scan.scan_metadata.vulnerability_count == 1
    assert len(scan.assets) == 1


def test_nessus_csv_parse_emits_ingestion_ledger_events_for_row_drops(tmp_path: Path) -> None:
    csv_file = tmp_path / "nessus_ledger.csv"
    csv_file.write_text(
        "Host,Plugin ID,Plugin Name,Risk,CVE\n"
        "10.0.0.50,10008,Valid Row,High,CVE-2023-1113\n"
        "10.0.0.51,10009,Malformed Row,Medium,CVE-2023-1114,extra\n"
        ",10010,Missing Asset,Low,CVE-2023-1115\n",
        encoding="utf-8",
    )

    ctx = _Ctx()
    parser = NessusCSVParser(ctx, filepath=str(csv_file))
    parser.parse()

    entries = ctx.services.ledger.snapshot().entries
    codes = [entry.why.reason_code for entry in entries]
    assert DecisionReasonCodes.INGESTION_ROWS_DROPPED in codes
    assert DecisionReasonCodes.INGESTION_MALFORMED_ROWS_SKIPPED in codes
