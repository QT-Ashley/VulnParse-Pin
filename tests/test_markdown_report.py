from __future__ import annotations

from types import SimpleNamespace

from vulnparse_pin.utils.markdown_report import _generate_executive_report, _generate_technical_report


class _DerivedShim:
    def __init__(self, passes: dict):
        self._passes = passes

    def get(self, key: str):
        return self._passes.get(key)


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

    assert "Finding Agg CVEs" in md
    assert "Agg Exploitable" in md
    assert "Agg KEV" in md
    assert "Aggregation Context" in md


def test_executive_report_includes_quality_sections() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])

    md = _generate_executive_report(_scan=None, summary=summary)

    assert "Decision Context" in md
    assert "Data Quality Scorecard" in md
    assert "Attack Capability Snapshot" in md
    assert "Remediation Plan by Time Horizon" in md
    assert "Risk Concentration" in md


def test_executive_report_handles_no_immediate_cves() -> None:
    summary = _build_summary(immediate_cves=[])

    md = _generate_executive_report(_scan=None, summary=summary)

    assert "No immediate-action CVEs detected" in md


def test_technical_report_includes_aggregated_risk_columns() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])

    md = _generate_technical_report(_scan=None, summary=summary)

    assert "Finding Agg CVEs" in md
    assert "Agg Exploitable" in md
    assert "Agg KEV" in md
    assert "whole-of-CVEs aggregation breadth" in md


def test_technical_report_includes_quality_sections() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])

    md = _generate_technical_report(_scan=None, summary=summary)

    assert "Tie-Break Explainability" in md
    assert "Attack Capability Evidence" in md
    assert "Analyst Caveats" in md
    assert "Trust and Provenance" in md


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


def test_markdown_reports_render_aci_metrics_when_available() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])
    scan = SimpleNamespace(
        assets=[],
        derived=_DerivedShim(
            {
                "ACI@1.0": SimpleNamespace(
                    data={
                        "metrics": {
                            "total_findings": 20,
                            "inferred_findings": 12,
                            "coverage_ratio": 0.6,
                            "uplifted_findings": 5,
                            "capabilities_detected": {
                                "remote_execution": 7,
                                "credential_access": 5,
                            },
                            "chain_candidates_detected": {
                                "chain_initial_to_credential": 3,
                            },
                            "confidence_buckets": {"low": 2, "medium": 6, "high": 4},
                        }
                    }
                )
            }
        ),
    )

    executive = _generate_executive_report(_scan=scan, summary=summary)
    technical = _generate_technical_report(_scan=scan, summary=summary)

    assert "ACI Available | Yes" in executive
    assert "remote_execution" in executive
    assert "Coverage Ratio | 60.0%" in executive

    assert "Attack Capability Evidence" in technical
    assert "remote_execution" in technical
    assert "chain_initial_to_credential" in technical
    assert "| High | 4 |" in technical


def test_markdown_reports_include_top_asset_finding_capability_mapping() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])
    scan = SimpleNamespace(
        assets=[
            SimpleNamespace(
                asset_id="asset-1",
                hostname="host-1",
                ip_address="10.0.0.1",
                findings=[
                    SimpleNamespace(
                        finding_id="F-100",
                        title="Demo Finding Title",
                        exploit_available=False,
                        cisa_kev=False,
                    )
                ],
            )
        ],
        derived=_DerivedShim(
            {
                "TopN@1.0": SimpleNamespace(
                    data={
                        "assets": [{
                            "asset_id": "asset-1",
                            "rank": 1,
                            "inference": {
                                "externally_facing_inferred": True,
                                "public_service_ports_inferred": True,
                                "confidence": "high",
                            },
                        }],
                        "findings_by_asset": {
                            "asset-1": [
                                {
                                    "finding_id": "F-100",
                                    "risk_band": "Critical",
                                    "score": 9.8,
                                }
                            ]
                        },
                    }
                ),
                "ACI@1.0": SimpleNamespace(
                    data={
                        "finding_semantics": {
                            "F-100": {
                                "capabilities": ["remote_execution", "credential_access"],
                                "chain_candidates": ["Initial access and credential theft pathway"],
                                "confidence": 0.86,
                            }
                        },
                        "metrics": {
                            "total_findings": 1,
                            "inferred_findings": 1,
                            "coverage_ratio": 1.0,
                            "uplifted_findings": 1,
                            "capabilities_detected": {"remote_execution": 1},
                            "chain_candidates_detected": {"chain_initial_to_credential": 1},
                            "confidence_buckets": {"low": 0, "medium": 0, "high": 1},
                        },
                    }
                ),
            }
        ),
    )

    executive = _generate_executive_report(_scan=scan, summary=summary)
    technical = _generate_technical_report(_scan=scan, summary=summary)

    assert "Top Assets: Findings to Inferred Capabilities" in executive
    assert "Top Asset Capability Mapping" in technical
    assert "host-1 / 10.0.0.1" in executive
    assert "host-1 / 10.0.0.1" in technical
    assert "F-100" in executive
    assert "F-100" in technical
    assert "Demo Finding Title" in executive
    assert "Demo Finding Title" in technical
    assert "F-100 (Demo Finding Title)" in executive
    assert "F-100 (Demo Finding Title)" in technical
    assert "remote_execution, credential_access" in executive
    assert "remote_execution, credential_access" in technical
    assert "OAL = Operational Action Lane" in executive
    assert "OAL = Operational Action Lane" in technical
    assert "| Finding (ID / Title) | Risk Band | Finding Risk | Inferred Capabilities | Chain Candidates | Confidence | OAL |" in executive
    assert "| Finding (ID / Title) | Risk Band | Finding Risk | Inferred Capabilities | Chain Candidates | Confidence | OAL |" in technical
    assert "OAL-2 High-Confidence Chain Path" in executive
    assert "OAL-2 High-Confidence Chain Path" in technical
    assert "Context Tags:" in executive
    assert "Context Tags:" in technical
    assert "Externally-Facing Inferred" in executive
    assert "Public-Service Ports Inferred" in executive
    assert "Exposure Confidence: High" in technical
    assert "Criticality: High" in technical
    assert "Top Risk Concentration" in executive
    assert "perform due diligence" in executive
    assert "due diligence" in technical


def test_markdown_reports_explain_zero_aci_inference() -> None:
    summary = _build_summary(immediate_cves=[])
    scan = SimpleNamespace(
        assets=[
            SimpleNamespace(
                findings=[
                    SimpleNamespace(
                        title="General exposure rating only",
                        description="Administrative endpoint observed",
                        plugin_output=None,
                        references=[],
                    )
                ]
            )
        ],
        derived=_DerivedShim(
            {
                "ACI@1.0": SimpleNamespace(
                    data={
                        "metrics": {
                            "total_findings": 1,
                            "inferred_findings": 0,
                            "coverage_ratio": 0.0,
                            "uplifted_findings": 0,
                            "capabilities_detected": {},
                            "chain_candidates_detected": {},
                            "confidence_buckets": {"low": 1, "medium": 0, "high": 0},
                        }
                    }
                )
            }
        ),
    )
    args = SimpleNamespace(no_kev=True, no_epss=True, no_exploit=True, no_nvd=True, ghsa=None)

    executive = _generate_executive_report(_scan=scan, summary=summary, args=args)
    technical = _generate_technical_report(_scan=scan, summary=summary, args=args)

    assert "ACI zero-inference diagnostic:" in executive
    assert "Enrichment inputs were disabled for: KEV, EPSS, Exploit-DB, NVD, GHSA." in executive
    assert "Finding text did not contain stronger exploit semantics" in executive

    assert "### Zero-Inference Diagnostic" in technical
    assert "Enrichment inputs were disabled for: KEV, EPSS, Exploit-DB, NVD, GHSA." in technical
    assert "Finding text did not contain stronger exploit semantics" in technical


def test_markdown_reports_note_when_all_mapped_findings_are_none_inferred() -> None:
    summary = _build_summary(immediate_cves=[])
    scan = SimpleNamespace(
        assets=[
            SimpleNamespace(
                asset_id="asset-1",
                hostname="host-1",
                ip_address="10.0.0.1",
                findings=[],
            )
        ],
        derived=_DerivedShim(
            {
                "TopN@1.0": SimpleNamespace(
                    data={
                        "assets": [{"asset_id": "asset-1", "rank": 1}],
                        "findings_by_asset": {
                            "asset-1": [
                                {
                                    "finding_id": "F-200",
                                    "risk_band": "Medium",
                                    "score": 5.5,
                                }
                            ]
                        },
                    }
                ),
                "ACI@1.0": SimpleNamespace(
                    data={
                        "finding_semantics": {
                            "F-200": {
                                "capabilities": [],
                                "chain_candidates": [],
                                "confidence": 0.0,
                            }
                        },
                        "metrics": {
                            "total_findings": 1,
                            "inferred_findings": 0,
                            "coverage_ratio": 0.0,
                            "uplifted_findings": 0,
                            "capabilities_detected": {},
                            "chain_candidates_detected": {},
                            "confidence_buckets": {"low": 1, "medium": 0, "high": 0},
                        },
                    }
                ),
            }
        ),
    )

    executive = _generate_executive_report(_scan=scan, summary=summary)
    technical = _generate_technical_report(_scan=scan, summary=summary)

    marker = "all mapped entries are `None inferred`"
    assert marker in executive
    assert marker in technical


def test_markdown_reports_use_topn_inference_for_oal1_and_context_tags() -> None:
    summary = _build_summary(immediate_cves=["CVE-2026-0001"])
    scan = SimpleNamespace(
        assets=[
            SimpleNamespace(
                asset_id="asset-1",
                hostname="host-1",
                ip_address="10.0.0.1",
                findings=[SimpleNamespace(finding_id="F-300", exploit_available=True, cisa_kev=False)],
            )
        ],
        derived=_DerivedShim(
            {
                "TopN@1.0": SimpleNamespace(
                    data={
                        "assets": [{
                            "asset_id": "asset-1",
                            "rank": 1,
                            "inference": {
                                "externally_facing_inferred": True,
                                "public_service_ports_inferred": True,
                                "confidence": "medium",
                            },
                        }],
                        "findings_by_asset": {
                            "asset-1": [
                                {
                                    "finding_id": "F-300",
                                    "risk_band": "Critical",
                                    "score": 9.9,
                                }
                            ]
                        },
                    }
                ),
                "ACI@1.0": SimpleNamespace(
                    data={
                        "finding_semantics": {
                            "F-300": {
                                "capabilities": [],
                                "chain_candidates": [],
                                "confidence": 0.0,
                            }
                        },
                        "metrics": {
                            "total_findings": 1,
                            "inferred_findings": 0,
                            "coverage_ratio": 0.0,
                            "uplifted_findings": 0,
                            "capabilities_detected": {},
                            "chain_candidates_detected": {},
                            "confidence_buckets": {"low": 1, "medium": 0, "high": 0},
                        },
                    }
                ),
            }
        ),
    )

    executive = _generate_executive_report(_scan=scan, summary=summary)
    technical = _generate_technical_report(_scan=scan, summary=summary)

    assert "OAL-1 Immediate Exploitable" in executive
    assert "OAL-1 Immediate Exploitable" in technical
    assert "Externally-Facing Inferred" in executive
    assert "Public-Service Ports Inferred" in technical
    assert "Contains OAL-1 Findings" in executive


def test_markdown_reports_render_lightweight_oal2_priority_tags() -> None:
    summary = _build_summary(immediate_cves=[])
    scan = SimpleNamespace(
        assets=[
            SimpleNamespace(
                asset_id="asset-1",
                hostname="host-1",
                ip_address="10.0.0.1",
                findings=[
                    SimpleNamespace(finding_id="F-401", title="Chain candidate finding", exploit_available=False, cisa_kev=False),
                    SimpleNamespace(finding_id="F-402", title="Exploitable finding", exploit_available=True, cisa_kev=False),
                ],
            )
        ],
        derived=_DerivedShim(
            {
                "TopN@1.0": SimpleNamespace(
                    data={
                        "assets": [{
                            "asset_id": "asset-1",
                            "rank": 1,
                            "inference": {
                                "externally_facing_inferred": True,
                                "public_service_ports_inferred": True,
                                "confidence": "high",
                            },
                        }],
                        "findings_by_asset": {
                            "asset-1": [
                                {"finding_id": "F-401", "risk_band": "High", "score": 8.7},
                                {"finding_id": "F-402", "risk_band": "High", "score": 8.6},
                            ]
                        },
                    }
                ),
                "ACI@1.0": SimpleNamespace(
                    data={
                        "finding_semantics": {
                            "F-401": {
                                "capabilities": ["credential_access", "lateral_movement"],
                                "chain_candidates": ["Credential-assisted lateral movement pathway"],
                                "confidence": 0.92,
                            },
                            "F-402": {
                                "capabilities": [],
                                "chain_candidates": [],
                                "confidence": 0.0,
                            },
                        },
                        "metrics": {
                            "total_findings": 2,
                            "inferred_findings": 1,
                            "coverage_ratio": 0.5,
                            "uplifted_findings": 1,
                            "capabilities_detected": {"credential_access": 1, "lateral_movement": 1},
                            "chain_candidates_detected": {"chain_credential_to_lateral": 1},
                            "confidence_buckets": {"low": 1, "medium": 0, "high": 1},
                        },
                    }
                ),
            }
        ),
    )

    executive = _generate_executive_report(_scan=scan, summary=summary)
    technical = _generate_technical_report(_scan=scan, summary=summary)

    assert "Contains OAL-2 Findings" in executive
    assert "OAL-2 Priority: Immediate Analyst Validation" in executive
    assert "OAL-2 Chain-Corroborated" in executive
    assert "OAL-2 Coexists With OAL-1" in executive
    assert "OAL-2 Priority: Immediate Analyst Validation" in technical
    assert "OAL-2 tag legend:" in executive
    assert "OAL-2 tag legend:" in technical
