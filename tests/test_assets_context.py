# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

import pytest

from vulnparse_pin.core.assets_context import (
    AssetContextMatcher,
    DecisionsRegistry,
    upsert_decision,
)
from vulnparse_pin.core.id import (
    canonicalize_target_key,
    make_asset_id,
    make_asset_id_v2,
    make_finding_base_canon,
    make_finding_id,
    make_finding_id_v2,
)


def test_v1_and_v2_canonical_ids() -> None:
    # V1 helpers remain intact
    aid_v1 = make_asset_id("10.0.0.1", "web01")
    assert aid_v1.startswith("aid_v1_")
    canon_v1 = make_finding_base_canon(aid_v1, "nessus:100", "tcp", "443", "Test")
    fid_v1 = make_finding_id(canon_v1)
    assert fid_v1.startswith("fid_v1_")

    # V2 canonicalization across FQDN/IPv6/URI/image
    k_host_1 = canonicalize_target_key(hostname="WEB-01.Prod.Local.")
    k_host_2 = canonicalize_target_key(hostname="web-01.prod.local")
    assert k_host_1 == k_host_2 == "host=web-01.prod.local"

    k_v6_1 = canonicalize_target_key(ip="2001:0db8:0000:0000:0000:0000:0000:0001")
    k_v6_2 = canonicalize_target_key(ip="2001:db8::1")
    assert k_v6_1 == k_v6_2 == "ip=2001:db8::1"

    k_uri_1 = canonicalize_target_key(target_uri="HTTPS://App.Example.COM:443/v1/")
    k_uri_2 = canonicalize_target_key(target_uri="https://app.example.com/v1")
    assert k_uri_1 == k_uri_2 == "uri=https://app.example.com/v1"

    k_img_1 = canonicalize_target_key(image_or_repo="docker.io/library/NGINX:1.25")
    k_img_2 = canonicalize_target_key(image_or_repo="nginx:1.25")
    assert k_img_1 == k_img_2 == "image=nginx:1.25"

    expected_aid = "aid_v2_" + hashlib.sha256(f"vpp:asset:v2|{k_host_1}".encode("utf-8")).hexdigest()[:20]
    assert make_asset_id_v2(k_host_1) == expected_aid

    expected_fid = "fid_v2_" + hashlib.sha256(f"vpp:finding:v2|asset={expected_aid}|key=cve=CVE-2024-1".encode("utf-8")).hexdigest()[:20]
    assert make_finding_id_v2(expected_aid, "cve=CVE-2024-1") == expected_fid


def test_asset_context_matcher_strict_precedence_and_cidr_longest_prefix(tmp_path: Path) -> None:
    assets_yaml = tmp_path / "assets.yaml"
    assets_yaml.write_text(
        """
version: v2
defaults:
  criticality: low
  internet_facing: false
  owner: unassigned
rules:
  - id: broad-glob
    hostnames: ["*.corp.local"]
    criticality: low
    internet_facing: false
  - id: specific-glob
    hostnames: ["api-prod-*.corp.local"]
    criticality: high
    internet_facing: true
  - id: corp-vpc
    cidrs: ["10.20.0.0/16"]
    criticality: medium
    internet_facing: false
  - id: dmz-subnet
    cidrs: ["10.20.1.0/24"]
    criticality: high
    internet_facing: true
  - id: exact-host
    hostnames: ["exact-01.corp.local"]
    criticality: critical
    internet_facing: true
  - id: aliased-service
    asset_id: aid_v2_checkout_canonical
    aliases:
      - 10.20.1.50
      - api-prod-01.corp.local
      - https://checkout.acme.com
      - ghcr.io/acme/checkout:2.0
    cidrs: ["10.20.1.0/24"]
    criticality: critical
    internet_facing: true
    owner: payments-team
    env: [prod, pci]
    tags:
      service: checkout
""",
        encoding="utf-8",
    )

    matcher = AssetContextMatcher.from_file(assets_yaml)

    # 1. Explicit alias wins over exact/CIDR/glob and links image + IP + URL + hostname
    r_ip = matcher.resolve(ip="10.20.1.50")
    r_host = matcher.resolve(hostname="API-PROD-01.CORP.LOCAL.")
    r_uri = matcher.resolve(target_uri="https://CHECKOUT.ACME.COM:443/")
    r_img = matcher.resolve(image_or_repo="GHCR.IO/Acme/checkout:2.0")
    assert r_ip.asset_id == r_host.asset_id == r_uri.asset_id == r_img.asset_id == "aid_v2_checkout_canonical"
    assert r_ip.match_tier == "alias"
    assert r_ip.inventory_status == "matched"
    assert r_ip.declared_criticality == "critical"
    assert r_ip.owner == "payments-team"
    assert r_ip.env_tags == ("prod", "pci")

    # 2. Exact FQDN beats CIDR (/24) and glob (*.corp.local)
    r_exact = matcher.resolve(ip="10.20.1.99", hostname="exact-01.corp.local")
    assert r_exact.matched_rule_id == "exact-host"
    assert r_exact.match_tier == "exact"

    # 3. Longest-prefix CIDR (/24 beats /16) beats glob (*.corp.local)
    r_cidr_24 = matcher.resolve(ip="10.20.1.25", hostname="api-prod-99.corp.local")
    assert r_cidr_24.matched_rule_id == "dmz-subnet"
    assert r_cidr_24.match_tier == "cidr"

    r_cidr_16 = matcher.resolve(ip="10.20.55.10", hostname="worker-01.corp.local")
    assert r_cidr_16.matched_rule_id == "corp-vpc"
    assert r_cidr_16.match_tier == "cidr"

    # 4. Glob specificity (api-prod-*.corp.local beats *.corp.local)
    r_glob_spec = matcher.resolve(ip="192.168.5.5", hostname="api-prod-canary.corp.local")
    assert r_glob_spec.matched_rule_id == "specific-glob"
    assert r_glob_spec.match_tier == "glob"

    r_glob_broad = matcher.resolve(ip="192.168.5.6", hostname="intranet.corp.local")
    assert r_glob_broad.matched_rule_id == "broad-glob"
    assert r_glob_broad.match_tier == "glob"

    # 5. Unmatched -> shadow asset with default criticality and internet_facing=None
    r_shadow = matcher.resolve(ip="198.51.100.77", hostname="rogue-box.external.net")
    assert r_shadow.inventory_status == "unmatched_shadow"
    assert r_shadow.declared_criticality == "low"
    assert r_shadow.internet_facing is None
    assert r_shadow.matched_rule_id is None
    assert r_shadow.match_tier == "unmatched"


def test_assets_and_decisions_schema_validation_rejects_unknown_keys() -> None:
    with pytest.raises(ValueError, match="Assets config schema validation failed"):
        AssetContextMatcher({"version": "v2", "unexpected_root_field": True})

    with pytest.raises(ValueError, match="Decisions config schema validation failed"):
        DecisionsRegistry.from_dict(
            {
                "version": "v2",
                "decisions": [
                    {
                        "id": "dec-1",
                        "cve_or_rule_id": "CVE-2024-1111",
                        "status": "deferred",
                        "rationale": "Test",
                        "bogus_key": 123,
                    }
                ],
            }
        )


def test_decisions_registry_evaluation_and_invalidation(tmp_path: Path) -> None:
    decisions_yaml = tmp_path / "decisions.yaml"
    decisions_yaml.write_text(
        """
version: v2
decisions:
  - id: dec-cve-01
    asset_id: aid_v2_checkout_canonical
    cve_or_rule_id: CVE-2024-1234
    status: deferred
    rationale: Mitigating WAF rule deployed while upgrading library.
    owner: appsec
    created_at: 2026-01-01
    expires_at: 2026-06-30
    assumptions:
      in_kev: false
      max_epss: 0.25
      max_epss_percentile: 0.80
      internet_facing: false
      max_cvss: 8.5
  - id: dec-rule-02
    asset_pattern: "*.internal.corp"
    cve_or_rule_id: "nuclei:swagger-ui-exposed"
    status: accepted
    rationale: Internal-only developer docs.
    expires_at: 2026-12-31
    assumptions:
      internet_facing: false
""",
        encoding="utf-8",
    )

    registry = DecisionsRegistry.from_file(decisions_yaml)
    asset_ctx = {"asset_id": "aid_v2_checkout_canonical", "internet_facing": False}

    # Valid when within expiry and all assumptions hold
    ev_valid = registry.evaluate(
        asset_ctx,
        {
            "primary_cve": "CVE-2024-1234",
            "in_kev": False,
            "epss_score": 0.12,
            "epss_percentile": 0.65,
            "cvss_score": 7.5,
        },
        now_utc=datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert ev_valid.matched is True
    assert ev_valid.status == "valid"
    assert ev_valid.decision_id == "dec-cve-01"
    assert ev_valid.decision_status == "deferred"
    assert ev_valid.violated_predicates == ()

    # Invalidated across ALL predicates when assumptions drift & date expires
    ev_bad = registry.evaluate(
        {"asset_id": "aid_v2_checkout_canonical", "internet_facing": True},
        {
            "primary_cve": "CVE-2024-1234",
            "in_kev": True,
            "epss_score": 0.72,
            "epss_percentile": 0.96,
            "cvss_score": 9.8,
        },
        now_utc=datetime(2026, 7, 1, 0, 0, tzinfo=timezone.utc),
    )
    assert ev_bad.matched is True
    assert ev_bad.status == "invalidated"
    assert set(ev_bad.violated_predicates) == {
        "expired",
        "kev_flipped",
        "epss_exceeded",
        "epss_percentile_exceeded",
        "exposure_flipped",
        "cvss_exceeded",
    }

    # Non-CVE scanner rule / template matching via asset_pattern
    ev_rule = registry.evaluate(
        {"asset_id": "aid_v2_other", "hostname": "dev-portal.internal.corp", "internet_facing": False},
        {"primary_cve": None, "scanner_sig": "nuclei:swagger-ui-exposed"},
        now_utc="2026-06-01T00:00:00Z",
    )
    assert ev_rule.matched is True
    assert ev_rule.status == "valid"
    assert ev_rule.decision_id == "dec-rule-02"


def test_upsert_decision_preserves_comments_and_updates_in_place(tmp_path: Path) -> None:
    dec_path = tmp_path / "decisions.yaml"
    dec_path.write_text(
        "# Security team triage registry\n"
        "version: v2\n"
        "decisions:\n"
        "  - id: dec-1\n"
        "    asset_id: aid_v2_1234\n"
        "    cve_or_rule_id: CVE-2024-5555\n"
        "    status: deferred\n"
        "    rationale: Initial review.\n",
        encoding="utf-8",
    )

    # Update existing entry in-place
    upsert_decision(
        dec_path,
        {
            "id": "dec-1",
            "asset_id": "aid_v2_1234",
            "cve_or_rule_id": "CVE-2024-5555",
            "status": "mitigated",
            "rationale": "Compensating control verified.",
            "assumptions": {"in_kev": False, "max_epss": 0.5},
        },
    )
    # Append second entry
    upsert_decision(
        dec_path,
        {
            "id": "dec-2",
            "asset_pattern": "staging-*",
            "cve_or_rule_id": "nuclei:test-banner",
            "status": "accepted",
            "rationale": "Staging environment.",
        },
    )

    raw_text = dec_path.read_text(encoding="utf-8")
    assert "# Security team triage registry" in raw_text

    reg = DecisionsRegistry.from_file(dec_path)
    assert len(reg.entries) == 2
    assert reg.entries[0].id == "dec-1"
    assert reg.entries[0].status == "mitigated"
    assert reg.entries[1].id == "dec-2"

    # Invalid entry rejected without corrupting file
    with pytest.raises(ValueError, match="Decision entry schema validation failed"):
        upsert_decision(
            dec_path,
            {
                "id": "dec-bad",
                "cve_or_rule_id": "CVE-2024-0001",
                "status": "invalid_status",
                "rationale": "Bad.",
            },
        )
    reg_after = DecisionsRegistry.from_file(dec_path)
    assert len(reg_after.entries) == 2


def test_run_context_per_run_enrichment_stats_and_v2_schemas(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from importlib import resources
    import json
    from ruamel.yaml import YAML

    from vulnparse_pin.core.apppaths import AppPaths
    from vulnparse_pin.core.classes.dataclass import (
        Asset,
        Finding,
        RunContext,
        ScanMetaData,
        ScanResult,
        Services,
    )
    from vulnparse_pin.core.config_validator import ConfigValidator
    from vulnparse_pin.io.pfhandler import PermFileHandler
    from vulnparse_pin.utils.enrichment_stats import EnrichmentStats, get_enrichment_stats, stats as global_stats
    from vulnparse_pin.utils.schema_validate import validate_runmanifest_schema, validate_scan_result_schema

    # Per-run EnrichmentStats vs global fallback
    per_run_stats = EnrichmentStats()
    per_run_stats.kev_hits = 7
    assert global_stats.kev_hits != 7 or global_stats is not per_run_stats

    paths = AppPaths.resolve(portable=True)
    logger = SimpleNamespace(
        debug=lambda *a, **k: None,
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        error=lambda *a, **k: None,
        exception=lambda *a, **k: None,
    )
    pfh = PermFileHandler(logger=logger)

    # Backward-compatible Services / RunContext without v2 kwargs
    legacy_services = Services()
    legacy_ctx = RunContext(paths=paths, pfh=pfh, logger=logger, services=legacy_services)
    assert get_enrichment_stats(legacy_ctx) is global_stats
    assert legacy_ctx.db is None
    assert legacy_ctx.run_id is None

    # Per-run Services propagating to RunContext
    v2_services = Services(enrichment_stats=per_run_stats, run_id="run-v2-test")
    v2_ctx = RunContext(paths=paths, pfh=pfh, logger=logger, services=v2_services)
    assert get_enrichment_stats(v2_ctx) is per_run_stats
    assert v2_ctx.run_id == "run-v2-test"

    # ScanResult v2 schema validation (raw_risk_score up to 25.0, cwe_ids/cvss_provenance/epss_percentile, fidelity_tier)
    finding = Finding(
        finding_id="fid_v2_1234567890abcdef",
        vuln_id="CVE-2024-1234",
        title="Test",
        description="desc",
        severity="Critical",
        cves=["CVE-2024-1234"],
        raw_risk_score=18.5,
        fidelity_tier="high",
        cve_analysis=[
            {
                "cve_id": "CVE-2024-1234",
                "cwe_ids": ["CWE-79"],
                "cvss_provenance": "NVD",
                "cvss_version": "4.0",
                "epss_percentile": 0.991,
            }
        ],
    )
    scan = ScanResult(
        scan_metadata=ScanMetaData(
            source="Nessus",
            scan_date=datetime.now(timezone.utc),
            asset_count=1,
            vulnerability_count=1,
        ),
        assets=[Asset(hostname="host-1", ip_address="10.0.0.1", findings=[finding])],
    )
    validate_scan_result_schema(scan)

    # Global config v2 schema validation
    yaml = YAML(typ="safe", pure=True)
    cfg_v2 = yaml.load(resources.files("vulnparse_pin.resources").joinpath("config.yaml").read_text(encoding="utf-8"))
    cfg_v2["version"] = "v2"
    cfg_v2["profile"] = "bod_26_04"
    cfg_v2["signal_reliability"] = {"enabled": True, "weights": {"credentialed_host": 1.0}}
    cfg_v2["enrichment"]["osv_source"] = "/tmp/osv"
    ConfigValidator._validate_schema(cfg_v2, "config.schema.json", label="Global config")

    # RunManifest v2 schema fields
    manifest_v2 = {
        "manifest_version": "2.0",
        "runmanifest_mode": "compact",
        "run_id": "run-v2-test",
        "profile": "bod_26_04",
        "assets_sha256": "sha256:aaa",
        "decisions_sha256": "sha256:bbb",
        "generated_at_utc": "2026-06-01T00:00:00Z",
        "runtime": {"vulnparse_version": "2.0.0", "python_version": "3.12.3", "platform": "linux"},
        "inputs": {"target_path": "scan.nessus", "target_sha256": "sha256:ccc"},
        "config_hashes": {
            "config_yaml_sha256": "sha256:1",
            "scoring_json_sha256": "sha256:2",
            "tn_triage_json_sha256": "sha256:3",
            "assets_sha256": "sha256:aaa",
            "decisions_sha256": "sha256:bbb",
        },
        "outputs": {"json": None, "csv": None, "executive_markdown": None, "technical_markdown": None},
        "enrichment_summary": {
            "kev_enabled": True,
            "epss_enabled": True,
            "nvd_enabled": "Enabled",
            "exploit_enabled": True,
            "osv_enabled": True,
            "stats": {},
        },
        "pass_summaries": [],
        "decision_ledger": {"chain_version": "1.0", "entry_count": 0, "chain_root": "sha256:0", "entries": []},
        "verification": {"canonicalization": "json-c14n-v1", "volatile_fields_excluded": [], "manifest_digest": "sha256:0"},
    }
    validate_runmanifest_schema(manifest_v2)

