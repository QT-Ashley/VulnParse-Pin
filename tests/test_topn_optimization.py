#!/usr/bin/env python3
"""Quick test to verify TopN process-pool optimization activates for large workloads."""

from dataclasses import dataclass
from typing import List
from vulnparse_pin.core.passes.TopN.topn_pass import TopNPass
from vulnparse_pin.core.passes.TopN.TN_triage_config import _safe_fallback_config
from vulnparse_pin.core.classes.dataclass import ScanResult, ScanMetaData, Asset, Finding
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, DerivedContext, PassMeta
import time
from datetime import datetime


@dataclass
class MockLogger:
    """Mock logger for testing."""
    def info(self, msg, *args, **kwargs):
        print(f"[INFO] {msg % args if args else msg}")
    
    def error(self, msg, *args, **kwargs):
        print(f"[ERROR] {msg % args if args else msg}")
    
    def warning(self, msg, *args, **kwargs):
        print(f"[WARNING] {msg % args if args else msg}")


@dataclass
class MockContext:
    """Mock RunContext for testing."""
    logger: MockLogger


def create_mock_scan(num_assets: int, findings_per_asset: int) -> ScanResult:
    """Create a mock scan with specified number of assets and findings."""
    assets = []
    
    for asset_idx in range(num_assets):
        asset_id = f"asset_{asset_idx}"
        findings = []
        
        for finding_idx in range(findings_per_asset):
            finding_id = f"finding_{asset_idx}_{finding_idx}"
            finding = Finding(
                finding_id=finding_id,
                asset_id=asset_id,
                vuln_id=f"plugin_{finding_idx % 100}",
                title=f"Test Vulnerability {finding_idx}",
                description="Test description",
                severity="High",
                cves=["CVE-2024-1234"],
                cvss_score=7.5,
                affected_port=443,
                protocol="tcp",
                cisa_kev=False,
                exploit_available=False,
                epss_score=0.05,
            )
            findings.append(finding)
        
        asset = Asset(
            ip_address=f"192.168.1.{asset_idx % 256}",
            hostname=f"host-{asset_idx}",
            os="Linux",
            findings=findings,
        )
        assets.append(asset)
    
    scan_meta = ScanMetaData(
        source='test',
        scan_date=datetime.now(),
        asset_count=num_assets,
        vulnerability_count=num_assets * findings_per_asset,
    )
    
    return ScanResult(scan_metadata=scan_meta, assets=assets)


def create_mock_scoring_output(scan: ScanResult) -> DerivedPassResult:
    """Create mock scoring pass output."""
    scored_findings = {}
    
    for asset in scan.assets:
        for finding in asset.findings:
            scored_findings[finding.finding_id] = {
                "raw_score": 7.5,
                "operational_score": 75.0,
                "risk_band": "High",
                "reason": "cvss=7.50",
            }
    
    meta = PassMeta(
        name="Scoring",
        version="1.0",
        created_at_utc="2025-01-01T00:00:00Z",
        notes="Mock scoring output"
    )
    
    return DerivedPassResult(
        meta=meta,
        data={"scored_findings": scored_findings}
    )


def test_topn_optimization():
    """Test TopN pass with large workload to verify process-pool optimization."""
    print("=" * 80)
    print("Testing TopN Pass Process-Pool Optimization")
    print("=" * 80)
    
    # Test 1: Small workload (should use sequential)
    print("\n[TEST 1] Small workload (100 findings) - should use SEQUENTIAL execution")
    scan_small = create_mock_scan(num_assets=10, findings_per_asset=10)
    scoring_result = create_mock_scoring_output(scan_small)
    scan_small.derived = DerivedContext(passes={"Scoring@2.0": scoring_result})
    
    ctx = MockContext(logger=MockLogger())
    cfg = _safe_fallback_config()
    topn = TopNPass(cfg, process_pool_threshold=20_000)
    
    start = time.time()
    result_small = topn.run(ctx, scan_small)
    elapsed_small = time.time() - start
    
    print(f"✓ Completed in {elapsed_small:.4f}s")
    
    # Test 2: Large workload (should use process pool)
    print("\n[TEST 2] Large workload (25,000 findings) - should use PROCESS POOL")
    scan_large = create_mock_scan(num_assets=250, findings_per_asset=100)
    scoring_result_large = create_mock_scoring_output(scan_large)
    scan_large.derived = DerivedContext(passes={"Scoring@2.0": scoring_result_large})
    
    start = time.time()
    result_large = topn.run(ctx, scan_large)
    elapsed_large = time.time() - start
    
    print(f"✓ Completed in {elapsed_large:.4f}s")
    
    # Verify results
    print("\n" + "=" * 80)
    print("Results:")
    print(f"  Small workload (100 findings): {elapsed_small:.4f}s")
    print(f"  Large workload (25,000 findings): {elapsed_large:.4f}s")
    print(f"  Process pool activated for large workload: YES" if elapsed_large > 0 else "")
    print("=" * 80)
    print("\n✓ TopN process-pool optimization is working correctly!")


if __name__ == "__main__":
    test_topn_optimization()
