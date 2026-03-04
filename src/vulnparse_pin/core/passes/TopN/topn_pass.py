from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
import ipaddress

from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, PassMeta
from vulnparse_pin.core.passes.types import (
    ExposureInference,
    RankedAssetRef,
    RankedFindingRef,
    TopNPassOutput
)
from vulnparse_pin.core.passes.TopN.TN_triage_semantics import TNTriageConfig, ParsedPredicate

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.passes.types import ScoredFinding
    from vulnparse_pin.core.passes.TopN.TN_triage_semantics import ConfidenceThreshold

# -------------------------------------------
# Observation View
# -------------------------------------------

@dataclass(frozen=True)
class AssetObservation:
    asset_id: str
    ip: Optional[str]
    hostname: Optional[str]
    open_ports: Tuple[int, ...]


# -------------------------------------------
# TopN Pass
# -------------------------------------------

class TopNPass:
    name = "TopN"
    version: str = "1.0"

    def __init__(self, triage_cfg: TNTriageConfig) -> None:
        self.cfg = triage_cfg

    def run(self, ctx: "RunContext", scan: "ScanResult") -> "ScanResult":
        """
        Consumes scan result to include previous derived passes data.
        Produces:
         - topn derived key = TopNPassOutput
        """
        # 0 retrieve Scoring pass output for scoring results
        scoring = self._get_scoring_output(scan)                    # Returns Scoring Pass DerivedPassResult
        if scoring is None:
            ctx.logger.error("Missing scoring output; cannot rank.", extra={"vp_label": "TopNPass"})
            return scan

        # 1 Build lookup index
        asset_to_findings = self._index_findings_by_asset(scan)     # { asset_id: [fid, fid, fid] }

        # 2 Compute inference per asset
        inference_by_asset: Dict[str, ExposureInference] = {}
        for asset_id, _ in asset_to_findings.items(): #TODO: VERIFY
            obs = self._collect_asset_observation(scan, asset_id, finding_ids=asset_to_findings[asset_id])
            if obs is None:
                continue
            inference_by_asset[asset_id] = self._infer_exposure(obs)

        # 3 Rank findings per asset
        findings_by_asset_ranked: Dict[str, Tuple[RankedFindingRef, ...]] = {}
        rank_basis = self.cfg.topn.rank_basis
        for asset_id, fids, in asset_to_findings.items():
            ranked = self._rank_findings_for_asset(
                scan=scan,
                scoring=scoring,
                asset_id=asset_id,
                finding_ids=fids,
                rank_basis=rank_basis,
                max_findings=self.cfg.topn.max_findings_per_asset,
            )
            findings_by_asset_ranked[asset_id] = ranked

        # 4 Rank assets via Top-K (K=len(decay))
        ranked_assets = self._rank_assets(
            scan=scan,
            scoring=scoring,
            asset_to_findings=asset_to_findings,
            inference_by_asset=inference_by_asset,
            rank_basis=rank_basis,
        )

        # trim to max_assets
        ranked_assets = ranked_assets[: self.cfg.topn.max_assets]

        # 5 Optional global top findings
        global_top: Tuple[RankedFindingRef, ...] = ()
        if self.cfg.topn.include_global_top_findings:
            global_top = self._rank_global_findings(
                scan=scan,
                scoring=scoring,
                asset_to_findings=asset_to_findings,
                rank_basis=rank_basis,
                max_findings=self.cfg.topn.global_top_findings
            )

        output = TopNPassOutput(
            rank_basis=rank_basis,
            k=self.cfg.topn.k,
            decay=self.cfg.topn.decay,
            assets=tuple(ranked_assets),
            findings_by_asset=findings_by_asset_ranked,
            global_top_findings=global_top,
        )

        # 6 Write out
        ctx.logger.info("Produced %d ranked assets", len(output.assets), extra={"vp_label": "TopNPass"})

        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived TopN Asset and Findings rankings."
        )
        return DerivedPassResult(meta=meta, data=asdict(output))

    # -------------------------------------------
    # Core Plugs
    # -------------------------------------------

    def _get_scoring_output(self, scan: "ScanResult") -> DerivedPassResult | None:
        try:
            return scan.derived.passes["Scoring@1.0"]
        except Exception:
            return None

    def _index_findings_by_asset(self, scan: "ScanResult") -> dict[str, List[str]]:
        maps: Dict[str, List[str]] = {}
        for asset in scan.assets:
            for finding in asset.findings:
                maps.setdefault(finding.asset_id, []).append(finding.finding_id)
            for aid, _ in maps.items(): # TODO:VERIFY
                maps[aid].sort()
            return maps

    def _get_finding_score_record(self, scoring: "DerivedPassResult", finding_id: str) -> Optional[Dict[str, "ScoredFinding"]]:
        """
        Returns an obj/dict with:
         - raw_score: float
         - operational_score: float
         - band: str
         - reasons: tuple[str]
        """
        data = getattr(scoring, "data", None)

        if isinstance(data, dict):
            scored = data.get("scored_findings", {})
            if isinstance(scored, dict):
                return scored.get(finding_id)
            return None

        # fallback
        scored = getattr(data, "scored_findings", None)
        if isinstance(scored, dict):
            return scored.get(finding_id)

    def _collect_asset_observation(self, scan: "ScanResult", asset_id: str, *, finding_ids: List[str]) -> Optional[AssetObservation]:
        """
        Collect ip, hostname, and observed open ports for the given asset_id.
        """
        asset = None
        for a in scan.assets:
            for f in a.findings:
                if f.asset_id:
                    asset = a
                    break

        ip = getattr(asset, "ip", None) if asset else None
        hostname = getattr(asset, "hostname", None) if asset else None

        # Gather open ports
        ports: List[int] = []
        for fid in finding_ids:
            f = self._get_finding_by_id(scan, fid)
            if not f:
                continue
            p = getattr(f, "affected_port", None)
            if isinstance(p, int):
                ports.append(p)

        ports = sorted(set(ports))
        return AssetObservation(asset_id=asset_id, ip=ip, hostname=hostname, open_ports=tuple(ports))

    def _get_finding_by_id(self, scan: "ScanResult", finding_id: str) -> Optional[Any]:
        for a in scan.assets:
            for f in a.findings:
                if f.finding_id == finding_id:
                    return f
        return None


    # -------------------------------------------
    # Ranking Core
    # -------------------------------------------

    def _rank_findings_for_asset(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_id: str,
        finding_ids: List[str],
        rank_basis: str,
        max_findings: int,
    ) -> tuple[RankedFindingRef, ...]:

        rows: List[Tuple[float, str, RankedFindingRef]] = []


        for fid in finding_ids:
            rec = self._get_finding_score_record(scoring, fid)
            if rec is None:
                continue

            raw = float(rec.get("raw_score", 0.0))
            op = float(rec.get("operational_score", raw))
            score = raw if rank_basis == "raw" else op

            band = str(rec.get("risk_band", "unknown"))
            reasons = tuple(rec.get("reason", ()).strip().split(";"))

            f = self._get_finding_by_id(scan, fid)
            port = getattr(f, "affected_port", None) if f else None
            proto = getattr(f, "protocol", None) if f else None
            plugin_id = getattr(f, "vuln_id", None) if f else None

            ref = RankedFindingRef(
                finding_id=fid,
                asset_id=asset_id,
                rank=0,
                score_basis=rank_basis,
                score=score,
                risk_band=band,
                reasons=reasons,
                port=port if isinstance(port, int) else None,
                proto=str(proto) if proto is not None else None,
                plugin_id=str(plugin_id) if plugin_id is not None else None
            )
            # Sort ley: score descending, then fid
            rows.append((score, fid, ref))

        rows.sort(key=lambda x: (-x[0], x[1]))

        output: List[RankedFindingRef] = []
        for i, (_, _, ref) in enumerate(rows[:max_findings], start=1):
            output.append(_replace_rank(ref, i))
        return tuple(output)


    def _rank_assets(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        inference_by_asset: Dict[str, ExposureInference],
        rank_basis: str,
    ) -> List[RankedAssetRef]:
        decay = self.cfg.topn.decay
        k = self.cfg.topn.k

        rows: List[Tuple[float, int, int, str, RankedAssetRef]] = []


        for asset_id, fids, in asset_to_findings.items():
            scores: List[float] = []
            crit_high = 0
            scorable_count = 0

            for fid in fids:
                rec = self._get_finding_score_record(scoring, fid)
                if rec is None:
                    continue

                raw = float(rec.get("raw_score", 0.0))
                op = float(rec.get ("operational_score", raw))
                score = raw if rank_basis == "raw" else op
                scores.append(score)
                scorable_count += 1

                band = str(rec.get("risk_band", "unknown")).lower()
                if band in ("critical", "high"):
                    crit_high += 1

            scores.sort(reverse=True)
            top_scores = tuple(scores[:k])
            # weighted aggregatio
            asset_score = 0.0
            for i, s in enumerate(top_scores):
                asset_score += s * decay[i]

            ref = RankedAssetRef(
                asset_id=asset_id,
                rank=0,
                score_basis=rank_basis,
                score=asset_score,
                top_scores=top_scores,
                scored_findings=scorable_count,
                inference=inference_by_asset.get(asset_id)
            )

            # tie-break: asset_score desc, band count desc, scorable count desc, asset id asc
            rows.append((asset_score, crit_high, scorable_count, asset_id, ref))

        rows.sort(key=lambda x: (-x[0], -x[1], -x[2], x[3]))

        output: List[RankedAssetRef] = []
        for i, (_, _, _, _, ref) in enumerate(rows, start=1):
            output.append(_replace_rank(ref, i))
        return output


    def _rank_global_findings(
        self,
        *,
        scan: "ScanResult",
        scoring: "DerivedPassResult",
        asset_to_findings: Dict[str, List[str]],
        rank_basis: str,
        max_findings: int,
    ) -> Tuple[RankedFindingRef, ...]:

        rows: List[Tuple[float, str, str, RankedFindingRef]] = []


        for asset_id, fids in asset_to_findings.items():
            for fid in fids:
                rec = self._get_finding_score_record(scoring, fid)
                if rec is None:
                    continue

                raw = float(rec.get("raw_score", 0.0))
                op = float(rec.get("operational_score", raw))
                score = raw if rank_basis == "raw" else op
                band = str(rec.get("risk_band", "unknown"))
                reasons = tuple(rec.get("reason", ()).strip().split(";"))

                f = self._get_finding_by_id(scan, fid)
                port = getattr(f, "affected_port", None) if f else None
                proto = getattr(f, "protocol", None) if f else None
                plugin_id = getattr(f, "vuln_id", None) if f else None

                ref = RankedFindingRef(
                    finding_id=fid,
                    asset_id=asset_id,
                    rank=0,
                    score_basis=rank_basis,
                    score=score,
                    risk_band=band,
                    reasons=reasons,
                    port=port if isinstance(port, int) else None,
                    proto=str(proto) if proto is not None else None,
                    plugin_id=str(plugin_id) if plugin_id is not None else None,
                )

                rows.append((score, asset_id, fid, ref))

            rows.sort(key=lambda x: (-x[0], x[1], x[2]))

            output: List[RankedFindingRef] = []
            for i, (_, _, _, ref) in enumerate(rows[:max_findings], start=1):
                output.append(_replace_rank(ref, i))
            return tuple(output)

    # -------------------------------------------
    # Inference execution
    # -------------------------------------------

    def _infer_exposure(self, obs: AssetObservation) -> ExposureInference:
        score = 0
        evidence: List[str] = []
        hit_tags = set()

        ip = (obs.ip or "").strip()
        hostname = (obs.hostname or "").strip().lower()
        ports_set = set(obs.open_ports)

        for rule in self.cfg.inference.rules:
            if not rule.enabled:
                continue
            if self._predicate_matches(rule.predicate, ip, hostname, ports_set):
                score += rule.weight
                hit_tags.add(rule.tag)
                ev = rule.evidence.strip() if rule.evidence else f"{rule.rule_id} ({rule.weight:+d})"
                evidence.append(ev)

        confidence = _bucket_confidence(score, self.cfg.inference.confidence_thresholds)

        externally = ("externally_facing" in hit_tags) and (confidence in ("medium", "high"))
        public_ports = "public_service_ports" in hit_tags

        #evidence order
        evidence_sorted = tuple(sorted(evidence))

        return ExposureInference(
            exposure_score=int(score),
            confidence=confidence,
            externally_facing_inferred=externally,
            public_service_ports_inferred=public_ports,
            evidence=evidence_sorted
        )

    def _predicate_matches(self, pred: ParsedPredicate, ip: str, hostname: str, ports_set: set[int]) -> bool:
        name = pred.name

        if name == "ip_is_public":
            return _is_public_ip(ip)
        if name == "ip_is_private":
            return _is_private_ip(ip)
        if name == "any_port_in_public_list":
            return any(p in self.cfg.inference.public_service_ports_set for p in ports_set)
        if name == "port_in":
            return any(p in ports_set for p in pred.ports)
        if name == "hostname_contains_any":
            return any(tok in hostname for tok in pred.tokens)

        return False


# -------------------------------------------
# Small Helpers
# -------------------------------------------

def _replace_rank(obj: Dict, rank: int) -> Any:
    d = obj.__dict__.copy()
    d["rank"] = rank
    return obj.__class__(**d)

def _bucket_confidence(score: int, thresholds: "ConfidenceThreshold") -> str:
    if score >= thresholds.high:
        return "high"
    if score >= thresholds.medium:
        return "medium"
    return "low"

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except Exception:
        return False

def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except Exception:
        return False
