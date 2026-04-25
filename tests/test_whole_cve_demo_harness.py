from __future__ import annotations

import copy
from pathlib import Path
from importlib import resources

from vulnparse_pin.core.apppaths import AppPaths
from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.passes.Scoring.scoringPass import ScoringPass
from vulnparse_pin.io.pfhandler import PermFileHandler
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser
from vulnparse_pin.utils.logger import LoggerWrapper


def _ctx(tmp_path: Path) -> RunContext:
    logger = LoggerWrapper(log_file=str(tmp_path / "whole-cve-harness.log"))
    pfh = PermFileHandler(
        logger,
        root_dir=tmp_path,
        allowed_roots=[tmp_path],
        enforce_roots_on_read=False,
        enforce_roots_on_write=False,
    )
    return RunContext(paths=AppPaths.resolve(portable=True), pfh=pfh, logger=logger)


def _policy() -> ScoringPolicyV1:
    return ScoringPolicyV1(
        epss_scale=1.0,
        epss_min=0.0,
        epss_max=1.0,
        kev_evd=1.0,
        exploit_evd=1.0,
        band_critical=10.0,
        band_high=7.0,
        band_medium=4.0,
        band_low=1.0,
        asset_aggregation="max",
        w_epss_high=1.0,
        w_epss_medium=1.0,
        w_kev=1.0,
        w_exploit=1.0,
        max_raw_risk=10.0,
        max_op_risk=10.0,
    )


def _load_packaged_demo_scan(ctx: RunContext) -> ScanResult:
    ref = resources.files("vulnparse_pin.resources").joinpath("openvas_updated_test.xml")
    with resources.as_file(ref) as sample_path:
        parser = OpenVASXMLParser(ctx, filepath=str(sample_path))
        return parser.parse()


def _flatten_findings(scan: ScanResult):
    return [finding for asset in scan.assets for finding in asset.findings]


def _unique_findings_by_scoring_key(scan: ScanResult) -> list[Finding]:
    """Mirror scoring behavior: last finding wins for duplicate finding_id keys."""
    by_id: dict[str, Finding] = {}
    for finding in _flatten_findings(scan):
        by_id[finding.finding_id] = finding
    return list(by_id.values())


def _first_valid_cve(existing: list[str], fallback: str) -> str:
    for item in existing:
        text = str(item or "").strip().upper()
        if text.startswith("CVE-"):
            return text
    return fallback


def _inject_multi_cve_analysis(scan: ScanResult, target_count: int = 30) -> list[str]:
    findings = _unique_findings_by_scoring_key(scan)
    chosen = findings[:target_count]
    mutated_ids: list[str] = []

    for idx, finding in enumerate(chosen):
        primary = _first_valid_cve(finding.cves or [], f"CVE-2026-{7000 + idx}")
        secondary = f"CVE-2025-{8100 + idx}"
        tertiary = f"CVE-2024-{9100 + idx}"

        finding.enrichment_source_cve = primary
        finding.cve_analysis = [
            {
                "cve_id": primary,
                "resolved_cvss_score": 9.3,
                "resolved_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "epss_score": 0.74,
                "cisa_kev": (idx % 5 == 0),
                "exploit_available": (idx % 3 == 0),
                "summary": "primary contributor",
                "selected_for_display": True,
            },
            {
                "cve_id": secondary,
                "resolved_cvss_score": 7.2,
                "resolved_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                "epss_score": 0.33,
                "cisa_kev": False,
                "exploit_available": True,
                "summary": "secondary contributor",
            },
            {
                "cve_id": tertiary,
                "resolved_cvss_score": 5.4,
                "resolved_cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                "epss_score": 0.09,
                "cisa_kev": False,
                "exploit_available": False,
                "summary": "tertiary contributor",
            },
        ]
        mutated_ids.append(finding.finding_id)

    return mutated_ids


def test_whole_cve_scoring_harness_on_packaged_openvas_demo_sample(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    scoring = ScoringPass(_policy(), parallel_threshold=10_000)

    baseline_scan = _load_packaged_demo_scan(ctx)
    mutated_scan = copy.deepcopy(baseline_scan)
    mutated_ids = _inject_multi_cve_analysis(mutated_scan, target_count=30)

    assert len(mutated_ids) == 30

    baseline_result = scoring.run(ctx, baseline_scan)
    mutated_result = scoring.run(ctx, mutated_scan)

    baseline_scored = baseline_result.data["scored_findings"]
    mutated_scored = mutated_result.data["scored_findings"]

    assert len(baseline_scored) >= 30
    assert len(mutated_scored) >= 30

    improved = 0
    whole_cve_reason_count = 0

    for finding in _unique_findings_by_scoring_key(mutated_scan):
        if finding.finding_id not in mutated_ids:
            continue

        score_trace = finding.score_trace or {}
        assert score_trace.get("aggregation_mode") == "stacked_decay"
        assert int(score_trace.get("cve_count", 0) or 0) >= 3
        assert int(score_trace.get("included_contributors", 0) or 0) >= 3
        assert float(score_trace.get("aggregate_cve_raw_score", 0.0) or 0.0) > 0.0

        contributors = score_trace.get("contributors") or []
        assert len(contributors) >= 3
        assert contributors[0].get("primary_contributor") is True

        scored_payload = mutated_scored[finding.finding_id]
        if "Whole-of-CVEs Aggregated" in str(scored_payload.get("reason", "")):
            whole_cve_reason_count += 1

        baseline_raw = float(baseline_scored[finding.finding_id]["raw_score"])
        mutated_raw = float(scored_payload["raw_score"])
        if mutated_raw > baseline_raw:
            improved += 1

    # We expect broad uplift when whole-of-CVEs context is injected across 30 findings.
    assert whole_cve_reason_count == 30
    assert improved >= 25
