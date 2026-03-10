from datetime import datetime
from pathlib import Path

import pytest

from vulnparse_pin.app.normalization import normalize_input
from vulnparse_pin.core.classes.dataclass import Asset, Finding, ScanMetaData, ScanResult
from vulnparse_pin.utils.schema_validate import validate_scan_result_schema


class _Logger:
    def print_info(self, *_args, **_kwargs):
        return None

    def phase(self, *_args, **_kwargs):
        return None

    def print_success(self, *_args, **_kwargs):
        return None

    def print_error(self, *_args, **_kwargs):
        return None


class _Ctx:
    def __init__(self):
        self.logger = _Logger()


class _ValidationStub:
    def validate(self):
        return Path("dummy.xml")


class _Parser:
    def __init__(self, *_args, **_kwargs):
        pass

    def parse(self):
        finding = Finding(
            finding_id="F-1",
            vuln_id="V-1",
            title="Test",
            description="desc",
            severity="Low",
            cves=["CVE-2025-0001"],
            asset_id="A-1",
        )
        asset = Asset(hostname="host-1", ip_address="10.0.0.1", findings=[finding])
        meta = ScanMetaData(
            source="Nessus",
            scan_date=datetime.now(),
            asset_count=1,
            vulnerability_count=1,
            scan_name="unit",
        )
        return ScanResult(scan_metadata=meta, assets=[asset])


class _DetectorResult:
    parser_cls = _Parser


class _Detector:
    def select(self, *_args, **_kwargs):
        return _DetectorResult()


def test_validate_scanresult_schema_accepts_valid_dataclass():
    finding = Finding(
        finding_id="F-1",
        vuln_id="V-1",
        title="Valid",
        description="desc",
        severity="Medium",
        cves=["CVE-2026-1234"],
        asset_id="A-1",
    )
    asset = Asset(hostname="asset-1", ip_address="192.168.1.10", findings=[finding])
    meta = ScanMetaData(
        source="Nessus",
        scan_date=datetime.now(),
        asset_count=1,
        vulnerability_count=1,
    )
    scan = ScanResult(scan_metadata=meta, assets=[asset])

    validate_scan_result_schema(scan)


def test_validate_scanresult_schema_rejects_missing_metadata_source():
    invalid_payload = {
        "scan_metadata": {
            "scan_date": "2026-03-08T00:00:00Z",
            "asset_count": 0,
            "vulnerability_count": 0,
        },
        "assets": [],
        "derived": {"passes": {}},
    }

    with pytest.raises(ValueError):
        validate_scan_result_schema(invalid_payload)


def test_normalization_exits_when_schema_validation_fails(monkeypatch):
    import vulnparse_pin.app.normalization as norm

    monkeypatch.setattr(norm, "FileInputValidator", lambda *_args, **_kwargs: _ValidationStub())
    monkeypatch.setattr(norm, "validate_scan_result_schema", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad schema")))

    with pytest.raises(SystemExit) as exc:
        normalize_input(_Ctx(), _Detector(), Path("dummy.xml"), allow_large=False)

    assert exc.value.code == 1
