from __future__ import annotations

from datetime import datetime
from pathlib import Path

from vulnparse_pin.app.enrichment_handoff import EnrichmentHandoffBuilder
from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import Asset, Finding, RunContext, ScanMetaData, ScanResult, Services
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.utils.logger import LoggerWrapper


def _make_ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "handoff.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    paths = AppPaths.resolve(portable=True)
    return RunContext(paths=paths, pfh=pfh, logger=logger, services=Services())


def _make_scan() -> ScanResult:
    meta = ScanMetaData(
        source="unit-test",
        scan_date=datetime.now(),
        asset_count=1,
        vulnerability_count=1,
    )
    finding = Finding(
        finding_id="F-1",
        vuln_id="V-1",
        title="Demo Finding",
        description="demo",
        severity="High",
        cves=["CVE-2026-0001"],
        asset_id="A-1",
    )
    asset = Asset(hostname="asset1", ip_address="10.0.0.1", asset_id="A-1", findings=[finding])
    return ScanResult(scan_metadata=meta, assets=[asset])


def test_handoff_builder_sets_post_enrichment_index(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    scan = _make_scan()

    out = EnrichmentHandoffBuilder.build(ctx, scan)

    assert out.ctx.services is not None
    assert out.ctx.services.post_enrichment_index is not None
    assert out.scan_result is scan
    idx = out.ctx.services.post_enrichment_index
    assert idx.get_finding("F-1") is not None
    assert idx.get_asset_observation("A-1") is not None
