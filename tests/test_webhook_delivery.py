from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vulnparse_pin.core.classes.dataclass import Asset, Finding, RunContext, ScanMetaData, ScanResult, Services, WebhookEndpointConfig, WebhookRuntimeConfig
from vulnparse_pin.core.classes.execution_manifest import LedgerService
from vulnparse_pin.core.classes.pass_classes import DerivedContext, DerivedPassResult, PassMeta
from vulnparse_pin.utils.runmanifest import verify_runmanifest_file
from vulnparse_pin.app.output import run_output_and_summary
from vulnparse_pin.utils.webhook_delivery import emit_configured_webhooks


class _PFH:
    def ensure_writable_file(self, path, **kwargs):
        p = Path(path)
        if kwargs.get("create_parents", True):
            p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.touch()
        return p

    def open_for_write(self, path, mode="w", **kwargs):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return open(p, mode, encoding=kwargs.get("encoding", None))


def _make_ctx(tmp_path: Path, webhook_cfg: WebhookRuntimeConfig) -> RunContext:
    logger = Mock()
    logger.print_success = Mock()
    logger.print_warning = Mock()
    logger.print_info = Mock()
    logger.debug = Mock()
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "config.yaml").write_text("summary: {}\n", encoding="utf-8")
    (config_dir / "scoring.json").write_text("{}\n", encoding="utf-8")
    (config_dir / "tn_triage.json").write_text("{}\n", encoding="utf-8")
    return RunContext(
        paths=SimpleNamespace(output_dir=tmp_path / "out", config_dir=config_dir),
        pfh=_PFH(),
        logger=logger,
        services=Services(ledger=LedgerService(), webhook_config=webhook_cfg),
    )


def _make_scan() -> ScanResult:
    finding = Finding(
        finding_id="finding-1",
        vuln_id="plugin-1",
        title="Critical Internet-Facing Service",
        description="test",
        severity="Critical",
        cves=["CVE-2026-0001"],
        exploit_available=True,
        cisa_kev=True,
        asset_id="asset-1",
    )
    asset = Asset(hostname="host1", ip_address="10.0.0.10", asset_id="asset-1", findings=[finding])
    derived = DerivedContext()
    derived = derived.put(
        DerivedPassResult(
            meta=PassMeta(name="TopN", version="1.0", created_at_utc="2026-04-22T00:00:00Z"),
            data={
                "assets": [
                    {
                        "asset_id": "asset-1",
                        "rank": 1,
                        "score": 9.9,
                        "score_basis": "operational",
                        "inference": {"externally_facing_inferred": True},
                    }
                ],
                "global_top_findings": [
                    {
                        "finding_id": "finding-1",
                        "asset_id": "asset-1",
                        "score": 9.9,
                        "risk_band": "Critical",
                        "port": 443,
                        "proto": "tcp",
                    }
                ],
            },
        )
    )
    derived = derived.put(
        DerivedPassResult(
            meta=PassMeta(name="Summary", version="1.0", created_at_utc="2026-04-22T00:00:01Z"),
            data={"overview": {"scored_findings": 1}},
        )
    )
    derived = derived.put(
        DerivedPassResult(
            meta=PassMeta(name="ACI", version="1.0", created_at_utc="2026-04-22T00:00:02Z"),
            data={
                "metrics": {"inferred_findings": 1, "coverage_ratio": 1.0},
                "finding_semantics": {
                    "finding-1": {"confidence": 0.95, "chain_candidates": ["chain-1"]}
                },
            },
        )
    )
    return ScanResult(
        scan_metadata=ScanMetaData(
            source="nessus",
            scan_date=__import__("datetime").datetime(2026, 4, 22),
            asset_count=1,
            vulnerability_count=1,
            source_file="scan.nessus",
        ),
        assets=[asset],
        derived=derived,
    )


def test_emit_configured_webhooks_delivers_signed_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    webhook_cfg = WebhookRuntimeConfig(
        enabled=True,
        endpoints=(WebhookEndpointConfig(url="https://hooks.example.org/vpp", oal_filter="P1"),),
    )
    ctx = _make_ctx(tmp_path, webhook_cfg)
    scan = _make_scan()
    monkeypatch.setenv("VP_WEBHOOK_HMAC_KEY", "super-secret")

    captured: dict[str, object] = {}

    class _Resp:
        status_code = 202
        url = "https://hooks.example.org/vpp"

        def raise_for_status(self) -> None:
            return None

    def _fake_post(url, data=None, headers=None, timeout=None, allow_redirects=None):
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        captured["timeout"] = timeout
        captured["allow_redirects"] = allow_redirects
        return _Resp()

    monkeypatch.setattr("vulnparse_pin.utils.webhook_delivery.requests.post", _fake_post)

    result = emit_configured_webhooks(
        ctx=ctx,
        scan_result=scan,
        scanner_input=Path("scan.nessus"),
        output_paths={"json": tmp_path / "out.json", "runmanifest": tmp_path / "manifest.json"},
    )

    assert result == {"sent": 1, "failed": 0, "spooled": 0, "skipped": 0}
    assert captured["url"] == "https://hooks.example.org/vpp"
    assert captured["allow_redirects"] is False
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["X-VPP-Signature"].startswith("sha256=")
    assert headers["X-VPP-Key-Id"] == "primary"
    assert headers["X-VPP-Nonce"]
    body = captured["data"].decode("utf-8")
    assert '"oal_filter_applied":"P1"' in body
    assert '"top_findings"' in body
    ledger_entries = ctx.services.ledger.snapshot().entries
    reason_codes = [entry.why.reason_code for entry in ledger_entries]
    assert "WEBHOOK_EMIT_STARTED" in reason_codes
    assert "WEBHOOK_EMIT_SUCCEEDED" in reason_codes


def test_emit_configured_webhooks_spools_failed_delivery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    webhook_cfg = WebhookRuntimeConfig(
        enabled=True,
        endpoints=(WebhookEndpointConfig(url="https://hooks.example.org/vpp", oal_filter="P1"),),
        allow_spool=True,
    )
    ctx = _make_ctx(tmp_path, webhook_cfg)
    scan = _make_scan()
    monkeypatch.setenv("VP_WEBHOOK_HMAC_KEY", "super-secret")

    def _fake_post(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr("vulnparse_pin.utils.webhook_delivery.requests.post", _fake_post)

    result = emit_configured_webhooks(
        ctx=ctx,
        scan_result=scan,
        scanner_input=Path("scan.nessus"),
        output_paths={"json": tmp_path / "out.json", "runmanifest": tmp_path / "manifest.json"},
    )

    assert result["sent"] == 0
    assert result["failed"] == 1
    assert result["spooled"] == 1
    spool_dir = tmp_path / "out" / "webhook_spool"
    assert spool_dir.exists()
    assert list(spool_dir.glob("webhook_*.json"))
    reason_codes = [entry.why.reason_code for entry in ctx.services.ledger.snapshot().entries]
    assert "WEBHOOK_EMIT_FAILED" in reason_codes
    assert "WEBHOOK_EMIT_SPOOLED_FOR_RETRY" in reason_codes


def test_emit_configured_webhooks_records_disabled_skip(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path, WebhookRuntimeConfig(enabled=False))
    scan = _make_scan()

    result = emit_configured_webhooks(
        ctx=ctx,
        scan_result=scan,
        scanner_input=Path("scan.nessus"),
        output_paths={"json": tmp_path / "out.json"},
    )

    assert result == {"sent": 0, "failed": 0, "spooled": 0, "skipped": 1}
    reason_codes = [entry.why.reason_code for entry in ctx.services.ledger.snapshot().entries]
    assert reason_codes == ["WEBHOOK_EMIT_SKIPPED_DISABLED"]


def test_run_output_and_summary_captures_webhook_events_in_runmanifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    webhook_cfg = WebhookRuntimeConfig(
        enabled=True,
        endpoints=(WebhookEndpointConfig(url="https://hooks.example.org/vpp", oal_filter="P1"),),
    )
    ctx = _make_ctx(tmp_path, webhook_cfg)
    scan = _make_scan()
    monkeypatch.setenv("VP_WEBHOOK_HMAC_KEY", "super-secret")

    class _Resp:
        status_code = 202
        url = "https://hooks.example.org/vpp"

        def raise_for_status(self) -> None:
            return None

    monkeypatch.setattr("vulnparse_pin.utils.webhook_delivery.requests.post", lambda *args, **kwargs: _Resp())

    runmanifest_path = tmp_path / "out" / "result_runmanifest.json"
    args = SimpleNamespace(
        output=None,
        output_csv=None,
        output_all=None,
        presentation=False,
        overlay_mode="flatten",
        pretty_print=False,
        csv_profile="full",
    )

    rc = run_output_and_summary(
        args=args,
        ctx=ctx,
        scan_result=scan,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        json_output=None,
        csv_output=None,
        md_output=None,
        md_tech_output=None,
        runmanifest_output=runmanifest_path,
        scanner_input=Path("scan.nessus"),
        csv_sanitization_enabled=True,
        kev_source=None,
        epss_source=None,
        start_time=0.0,
        write_output_fn=lambda *args, **kwargs: None,
        print_summary_banner_fn=lambda *args, **kwargs: None,
        json_default_fn=str,
        format_runtime_fn=lambda _: "0s",
    )

    assert rc == 0
    manifest = verify_runmanifest_file(runmanifest_path)
    reason_codes = [entry["why"]["reason_code"] for entry in manifest["decision_ledger"]["entries"]]
    assert "WEBHOOK_EMIT_STARTED" in reason_codes
    assert "WEBHOOK_EMIT_SUCCEEDED" in reason_codes


def test_run_output_default_json_omits_scoring_overlay_without_presentation(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path, WebhookRuntimeConfig(enabled=False))
    scan = _make_scan()
    finding = scan.assets[0].findings[0]
    finding.raw_risk_score = 11.5
    finding.risk_score = 7.2
    finding.risk_band = "Critical"
    finding.score_trace = {"source": "test"}

    captured: dict[str, object] = {}

    def _capture_write(_ctx, *, data, file_path, pretty_print):
        captured["data"] = data

    args = SimpleNamespace(
        output=str(tmp_path / "out.json"),
        output_csv=None,
        output_all=None,
        presentation=False,
        overlay_mode="flatten",
        pretty_print=False,
        csv_profile="full",
    )

    rc = run_output_and_summary(
        args=args,
        ctx=ctx,
        scan_result=scan,
        sources={"exploitdb": False, "kev": False, "epss": False, "nvd": "Disabled", "stats": {}},
        json_output=tmp_path / "out.json",
        csv_output=None,
        md_output=None,
        md_tech_output=None,
        runmanifest_output=None,
        scanner_input=Path("scan.nessus"),
        csv_sanitization_enabled=True,
        kev_source=None,
        epss_source=None,
        start_time=0.0,
        write_output_fn=_capture_write,
        print_summary_banner_fn=lambda *args, **kwargs: None,
        json_default_fn=str,
        format_runtime_fn=lambda _: "0s",
    )

    assert rc == 0
    out = captured.get("data")
    assert isinstance(out, dict)
    findings = out["assets"][0]["findings"]
    assert isinstance(findings, list)
    out_finding = findings[0]
    assert "raw_risk_score" not in out_finding
    assert "risk_score" not in out_finding
    assert "risk_band" not in out_finding
    assert "score_trace" not in out_finding