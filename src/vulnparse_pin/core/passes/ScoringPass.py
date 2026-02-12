from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, TYPE_CHECKING
from vulnparse_pin.core.classes.ScoringPolicy import ScoringPolicyV1
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass
from vulnparse_pin.core.passes.types import ScoreCoverage, ScoredFinding, ScoringPassOutput
from vulnparse_pin.core.classes.pass_classes import PassMeta

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.classes.dataclass import Finding

@dataclass
class ScoringPass(Pass):
    name: str = "Scoring"
    version: str = "1.0"

    def __init__(self, policy: ScoringPolicyV1):
        self.policy = policy

    def run(self, ctx: "RunContext", scan: "ScanResult") -> "DerivedPassResult":
        total = 0
        scored = 0


        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}


        for asset in scan.assets:
            best_asset: Optional[float] = None
            aid = None # Prefer f.assset_id or fallback to asset.ip_address

            for f in asset.findings:
                total += 1
                if aid is None:
                    aid = f.asset_id or asset.ip_address

                sf = self._score_one(f)
                if sf is None:
                    continue


                scored += 1
                scored_findings[f.finding_id] = sf

                if best_asset is None or sf.score > best_asset:
                    best_asset = sf.score

            if best_asset is not None and aid is not None:
                asset_scores[aid] = best_asset


        coverage_pct = (scored / total * 100.0) if total else 0.0
        avg_scored = (sum(sf.score for sf in scored_findings.values()) / scored) if scored else None


        highest_asset = None
        highest_score = None
        if asset_scores:
            highest_asset = max(asset_scores, key=asset_scores.get)
            highest_score = asset_scores[highest_asset]

        output = ScoringPassOutput(
            scored_findings=scored_findings,
            asset_scores=asset_scores,
            coverage=ScoreCoverage(total_findings=total, scored_findings=scored, coverage_pct=coverage_pct),
            highest_risk_asset=highest_asset,
            highest_risk_asset_score=highest_score,
            avg_scored_risk=avg_scored
        )

        ctx.logger.info(
            "[pass:scoring] scored=%d/%d (%.2f%%)",
            scored, total, coverage_pct,
            extra = {"vp_label": "ScoringPass"}
        )

        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived risk scoring (truth-preserving)."
        )
        return DerivedPassResult(meta=meta, data=output)

    def _score_one(self, f: "Finding") -> Optional[ScoredFinding]:
        pol = self.policy

        kev = bool(getattr(f, "cisa_kev", False))
        exploit = bool(getattr(f, "exploit_available", False))
        cvss = getattr(f, "cvss_score", None)
        epss = getattr(f, "epss_score", None)

        # Gate
        if not kev and not exploit and cvss is None and epss is None:
            return None


        raw = 0.0
        reasons = []

        # Compile Scoring Signals
        # CVSS Component (0..10)
        if cvss is not None:
            try:
                c = float(cvss)
                raw += c
                reasons.append(f"cvss={c:.2f}")
            except (TypeError, ValueError):
                pass

        # EPSS Component (0..1.0 | 0..scale), with weights
        if epss is not None:
            try:
                e = (float(epss))
                e = min(max(e, pol.epss_min), pol.epss_max)
                e_scaled = e * pol.epss_scale
                
                # Bucket thresholds
                mult = 1.0
                if e >= 0.70:
                    mult = pol.w_epss_high
                    reasons.append(f"epss_high*{pol.w_epss_high:g}")
                elif e >= 0.40:
                    mult = pol.w_epss_medium
                    reasons.append(f"epss_medium*{pol.w_epss_medium:g}")


                raw += e_scaled * mult
                reasons.append(f"epss={e:.5f}({e_scaled:.2f})")
            except (TypeError, ValueError):
                pass

        # KEV Component — Base Evidence Points + Weights
        if kev:
            raw += pol.kev_evd * pol.w_kev
            reasons.append("KEV Present")

        # Exploit Component - Base Evidence Points + Weights
        if exploit:
            raw += pol.exploit_evd * pol.w_exploit
            reasons.append("Exploit Available")

        score = (raw / pol.max_raw_risk) * pol.max_op_risk
        score = max(0.0, min(score, pol.max_op_risk))
        band = self._band(raw)

        return ScoredFinding(
            finding_id=f.finding_id,
            asset_id=f.asset_id or "SENTINEL:AssetID_Missing",
            raw_score=raw,
            score=score,
            risk_band=band,
            reason=";".join(reasons)
        )

    def _band(self, score: float) -> str:
        pol = self.policy
        if score >= pol.band_critical:
            return "Critical"
        if score >= pol.band_high:
            return "High"
        if score >= pol.band_medium:
            return "Medium"
        if score >= pol.band_low:
            return "Low"
        return "Informational"
