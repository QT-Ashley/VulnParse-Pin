from __future__ import annotations

from types import SimpleNamespace

from vulnparse_pin.utils.markdown_report import _generate_executive_report, _generate_technical_report


def _build_summary(immediate_cves: list[str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        overview={
            "total_assets": 2,
            "total_findings": 5,
            "average_asset_risk": 4.2,
            "exploitable_findings": 3,
            "kev_listed_findings": 1,
            "scan_timestamp": "2026-04-17T12:00:00Z",
        },
        risk_distribution={
            "by_risk_band": {
                "Critical": 1,
                "High": 2,
                "Medium": 1,
                "Low": 1,
                "Informational": 0,
            },
            "total_scored": 5,
        },
        top_risks=[
            {
                "cve": "CVE-2026-0001",
                "finding_risk_score": 9.7,
                "risk_band": "Critical",
                "exploit_available": True,
                "kev_listed": True,
                "epss_score": 0.82,
                "cvss_base_score": 9.8,
                "occurrence_count": 4,
                "aggregated_cve_count": 3,
                "aggregated_exploitable_cve_count": 2,
                "aggregated_kev_cve_count": 1,
            }
        ],
        remediation_priorities={
            "immediate_action": 1 if immediate_cves else 0,
            "high_priority": 2,
            "medium_priority": 1,
            "immediate_cves": immediate_cves or [],
        },
        asset_summary={
            "total_assets": 2,
            "assets": [
                {
                    "asset_id": "asset-1",
                    "ip": "10.0.0.1",
                    "hostname": "host-1",
                    "criticality": "High",
                    "total_findings": 3,
                    "risk_score": 7.1,
                    "critical_findings": 1,
                    "high_findings": 1,
                    "top_cve": "CVE-2026-0001",
                }
            ],
        },
        finding_summary={
            "by_severity": {
                "Critical": 1,
                "High": 2,
                "Medium": 1,
                "Low": 1,
                "Informational": 0,
            },
            "total": 5,
        },
        enrichment_metrics={
            "total_findings": 5,
            "total_cves": 6,
            "enriched_findings": 5,
            "enrichment_coverage": 1.0,
        },
    )


def test_executive_report_includes_aggregated_risk_columns() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])

    md = _generate_executive_report(_scan=None, summary=summary)

    assert "Agg CVEs" in md
    assert "Agg Exploitable" in md
    assert "Agg KEV" in md
    assert "Aggregation Context" in md


def test_executive_report_handles_no_immediate_cves() -> None:
    summary = _build_summary(immediate_cves=[])

    md = _generate_executive_report(_scan=None, summary=summary)

    assert "No immediate-action CVEs detected" in md


def test_technical_report_includes_aggregated_risk_columns() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])

    md = _generate_technical_report(_scan=None, summary=summary)

    assert "Agg CVEs" in md
    assert "Agg Exploitable" in md
    assert "Agg KEV" in md
    assert "whole-of-CVEs aggregation breadth" in md


def test_markdown_reports_include_ghsa_visibility_metrics() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])
    scan = SimpleNamespace(
        assets=[
            SimpleNamespace(
                findings=[
                    SimpleNamespace(references=["https://github.com/advisories/GHSA-abcd-1234-efgh"]),
                    SimpleNamespace(references=[]),
                ]
            )
        ]
    )

    executive = _generate_executive_report(_scan=scan, summary=summary)
    technical = _generate_technical_report(_scan=scan, summary=summary)

    assert "GHSA Advisory Matches" in executive
    assert "GHSA Advisory Matches" in technical
    assert "GitHub Security Advisories (GHSA)" in technical
