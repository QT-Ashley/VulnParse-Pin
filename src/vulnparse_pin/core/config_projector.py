# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple, TYPE_CHECKING

from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.config_source import ConfigSource, RawConfigPayloads
from vulnparse_pin.core.config_validator import (
    DEFAULT_EPSS_BREAKPOINTS,
    DEFAULT_SIGNAL_RELIABILITY_WEIGHTS,
    normalize_triage_profile,
)

if TYPE_CHECKING:
    from vulnparse_pin.core.config_validator import ConfigValidationResult


_DEFAULT_BREAKPOINTS_TUPLE: Tuple[Tuple[float, float], ...] = tuple(
    (float(x), float(y)) for x, y in DEFAULT_EPSS_BREAKPOINTS
)

_DEFAULT_EXPOSURE_TRACK: Dict[str, Any] = {
    "severity_base": {
        "critical": 8.5,
        "high": 7.0,
        "medium": 4.5,
        "low": 2.0,
        "informational": 0.5,
        "info": 0.5,
    },
    "aci_high_impact_caps": (
        "remote_execution",
        "command_execution",
        "auth_bypass",
        "sql_injection",
        "privilege_escalation",
        "initial_access",
        "deserialization",
        "ssrf",
    ),
    "aci_high_impact_bonus": 3.5,
    "aci_exposure_bonus": 2.0,
    "aci_chain_bonus": 1.0,
    "cwe_high_impact_bonus": 1.5,
    "exposure_bonus": 1.5,
}


@dataclass(frozen=True)
class SignalReliabilityPolicy:
    """Typed reliability weighting policy keyed by scanner detection_mode."""
    enabled: bool = True
    weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_SIGNAL_RELIABILITY_WEIGHTS))

    def weight_for(
        self,
        detection_mode: Optional[str],
        *,
        ingestion_confidence: Optional[float] = None,
        explicit_reliability: Optional[float] = None,
    ) -> float:
        if not self.enabled:
            return 1.0
        if detection_mode:
            key = str(detection_mode).strip().lower()
            if key in self.weights:
                return float(self.weights[key])
        if explicit_reliability is not None:
            return max(0.0, min(2.0, float(explicit_reliability)))
        if ingestion_confidence is not None:
            return max(0.0, min(1.0, float(ingestion_confidence)))
        return 0.70


@dataclass(frozen=True)
class TriagePolicyV2:
    """Typed v2 triage policy covering default and BOD 26-04 SSVC profiles."""
    default_profile: str = "default"
    static_sast_p1_cap: bool = True
    enabled: bool = True
    sla_days: Dict[str, int] = field(
        default_factory=lambda: {
            "3-day + Forensic Triage": 3,
            "14-day": 14,
            "60-day": 60,
        }
    )


@dataclass(frozen=True)
class ACIPolicyV2:
    """Typed v2 Attack Capability Inference policy."""
    enabled: bool = True
    exposure_track_enabled: bool = True
    non_cve_uplift_weight: float = 1.0
    min_confidence: float = 0.6
    max_uplift: float = 2.0
    asset_uplift_weight: float = 0.5
    token_mode: str = "merge"


@dataclass(frozen=True)
class ScoringPolicyV2:
    """Typed v2 dual-track scoring policy (Track A cve_threat + Track B exposure_weakness)."""
    version: str = "v2"
    epss_breakpoints: Tuple[Tuple[float, float], ...] = _DEFAULT_BREAKPOINTS_TUPLE
    epss_scale: float = 5.0
    epss_min: float = 0.0
    epss_max: float = 1.0
    epss_use_percentile: bool = True
    epss_high_cutoff: float = 0.10
    epss_medium_cutoff: float = 0.04
    epss_percentile_high_cutoff: float = 0.95
    epss_percentile_medium_cutoff: float = 0.90

    kev_points: float = 4.5
    verified_exploit_points: float = 2.0
    verified_exploit_with_kev_points: float = 0.5
    heuristic_exploit_points: float = 0.0

    exposure_bonus: float = 1.25
    criticality_bonuses: Dict[str, float] = field(
        default_factory=lambda: {
            "critical": 1.0,
            "high": 0.5,
            "medium": 0.0,
            "low": -0.25,
        }
    )

    max_raw_risk: float = 16.0
    max_operational_risk: float = 10.0

    bands: Dict[str, float] = field(
        default_factory=lambda: {
            "critical": 12.8,
            "high": 9.6,
            "medium": 6.4,
            "low": 3.2,
        }
    )

    asset_aggregation: str = "max"
    cve_aggregation_mode: str = "stacked_decay"
    cve_aggregation_decay: float = 0.35
    cve_aggregation_max_contributors: int = 8

    signal_reliability: SignalReliabilityPolicy = field(default_factory=SignalReliabilityPolicy)
    exposure_track: Dict[str, Any] = field(default_factory=lambda: dict(_DEFAULT_EXPOSURE_TRACK))
    nmap_port_bonus: float = 0.0

    def to_v1_policy(self) -> ScoringPolicyV1:
        """Convert to ScoringPolicyV1 for legacy PassRunner / ScanResult callers."""
        return ScoringPolicyV1(
            epss_scale=self.epss_scale,
            epss_min=self.epss_min,
            epss_max=self.epss_max,
            kev_evd=self.kev_points,
            exploit_evd=self.verified_exploit_points,
            band_critical=float(self.bands.get("critical", 12.8)),
            band_high=float(self.bands.get("high", 9.6)),
            band_medium=float(self.bands.get("medium", 6.4)),
            band_low=float(self.bands.get("low", 3.2)),
            asset_aggregation=self.asset_aggregation,
            w_epss_high=1.0,
            w_epss_medium=1.0,
            w_kev=1.0,
            w_exploit=1.0,
            max_raw_risk=self.max_raw_risk,
            max_op_risk=self.max_operational_risk,
            cve_aggregation_mode=self.cve_aggregation_mode,
            cve_aggregation_decay=self.cve_aggregation_decay,
            cve_aggregation_max_contributors=self.cve_aggregation_max_contributors,
            nmap_port_bonus=self.nmap_port_bonus,
        )


@dataclass(frozen=True)
class VppConfigV2:
    """Typed top-level v2 runtime policy projected from global, scoring, and topN configs."""
    version: str
    source_version: str
    profile: str
    nvd_start_year: int
    nvd_end_year: Optional[int]
    osv_enabled: bool
    osv_source: Optional[str]
    summary_top_n: int
    signal_reliability: SignalReliabilityPolicy
    scoring: ScoringPolicyV2
    triage: TriagePolicyV2
    aci: ACIPolicyV2
    nmap_port_tiebreak_enabled: bool = True
    nmap_scoring_port_bonus: float = 0.0


@dataclass(frozen=True)
class RuntimeConfigBundle:
    """
    Represents final typed runtime configuration bundle ready for use.
    Preserves backward-compatible dict attributes alongside typed v2 policies.
    """
    global_config: dict
    scoring_config: dict
    topn_config: dict
    v2_config: Optional[VppConfigV2] = None
    scoring_policy: Optional[ScoringPolicyV2] = None
    triage_policy: Optional[TriagePolicyV2] = None
    aci_policy: Optional[ACIPolicyV2] = None
    signal_reliability: Optional[SignalReliabilityPolicy] = None

    @property
    def v2(self) -> Optional[VppConfigV2]:
        return self.v2_config


def _build_signal_reliability(
    global_cfg: Mapping[str, Any],
    scoring_cfg: Mapping[str, Any],
) -> SignalReliabilityPolicy:
    merged = dict(DEFAULT_SIGNAL_RELIABILITY_WEIGHTS)
    enabled = True

    enrichment = global_cfg.get("enrichment")
    if isinstance(enrichment, Mapping) and isinstance(enrichment.get("signal_reliability"), Mapping):
        esr = enrichment["signal_reliability"]
        if "enabled" in esr:
            enabled = bool(esr["enabled"])
        raw_w = esr.get("weights") if isinstance(esr.get("weights"), Mapping) else esr
        for k, v in raw_w.items():
            if k != "enabled" and isinstance(v, (int, float)):
                merged[str(k).strip().lower()] = float(v)

    root_sr = global_cfg.get("signal_reliability")
    if isinstance(root_sr, Mapping):
        if "enabled" in root_sr:
            enabled = bool(root_sr["enabled"])
        raw_w = root_sr.get("weights") if isinstance(root_sr.get("weights"), Mapping) else root_sr
        for k, v in raw_w.items():
            if k != "enabled" and isinstance(v, (int, float)):
                merged[str(k).strip().lower()] = float(v)

    score_sr = scoring_cfg.get("signal_reliability")
    if isinstance(score_sr, Mapping):
        if "enabled" in score_sr and root_sr is None:
            enabled = bool(score_sr["enabled"])
        raw_w = score_sr.get("weights") if isinstance(score_sr.get("weights"), Mapping) else {}
        for k, v in raw_w.items():
            if isinstance(v, (int, float)) and (root_sr is None or k not in (root_sr.get("weights") or {})):
                merged[str(k).strip().lower()] = float(v)

    return SignalReliabilityPolicy(enabled=enabled, weights=merged)


def build_scoring_policy_v2(
    scoring_cfg: Mapping[str, Any],
    global_cfg: Optional[Mapping[str, Any]] = None,
) -> ScoringPolicyV2:
    """Construct ScoringPolicyV2 from validated/projected scoring and global config dicts."""
    gcfg = global_cfg or {}
    epss = scoring_cfg.get("epss") or {}
    evp = scoring_cfg.get("evidence_points") or {}
    bands_raw = scoring_cfg.get("bands") or {}
    agg = scoring_cfg.get("aggregation") or {}
    ceiling = scoring_cfg.get("risk_ceiling") or {}
    nmap_ctx = gcfg.get("nmap_ctx") or {}

    raw_bps = epss.get("breakpoints")
    if isinstance(raw_bps, (list, tuple)) and len(raw_bps) >= 2:
        bps = tuple((float(p[0]), float(p[1])) for p in raw_bps)
    else:
        bps = _DEFAULT_BREAKPOINTS_TUPLE

    verified_pts = float(evp.get("verified_exploit", evp.get("exploit", 2.0)))
    verified_with_kev = float(evp.get("verified_exploit_with_kev", 0.5))
    sig_rel = _build_signal_reliability(gcfg, scoring_cfg)

    exp_track = dict(_DEFAULT_EXPOSURE_TRACK)
    if isinstance(scoring_cfg.get("exposure_track"), Mapping):
        for k, v in scoring_cfg["exposure_track"].items():
            if k == "severity_base" and isinstance(v, Mapping):
                sb = dict(exp_track["severity_base"])
                sb.update({str(sk).lower(): float(sv) for sk, sv in v.items()})
                exp_track["severity_base"] = sb
            else:
                exp_track[k] = v

    return ScoringPolicyV2(
        version=str(scoring_cfg.get("version") or "v2"),
        epss_breakpoints=bps,
        epss_scale=float(epss.get("scale", 5.0)),
        epss_min=float(epss.get("min", 0.0)),
        epss_max=float(epss.get("max", 1.0)),
        epss_use_percentile=bool(epss.get("use_percentile", True)),
        epss_high_cutoff=float(epss.get("high_cutoff", 0.10)),
        epss_medium_cutoff=float(epss.get("medium_cutoff", 0.04)),
        epss_percentile_high_cutoff=float(epss.get("percentile_high_cutoff", 0.95)),
        epss_percentile_medium_cutoff=float(epss.get("percentile_medium_cutoff", 0.90)),
        kev_points=float(evp.get("kev", 4.5)),
        verified_exploit_points=verified_pts,
        verified_exploit_with_kev_points=verified_with_kev,
        heuristic_exploit_points=float(evp.get("heuristic_exploit", 0.0)),
        max_raw_risk=float(ceiling.get("max_raw_risk", 16.0)),
        max_operational_risk=float(ceiling.get("max_operational_risk", 10.0)),
        bands={
            "critical": float(bands_raw.get("critical", 12.8)),
            "high": float(bands_raw.get("high", 9.6)),
            "medium": float(bands_raw.get("medium", 6.4)),
            "low": float(bands_raw.get("low", 3.2)),
        },
        asset_aggregation=str(agg.get("asset_score", "max")),
        cve_aggregation_mode=str(agg.get("finding_cve_score", "stacked_decay")),
        cve_aggregation_decay=float(agg.get("finding_cve_decay", 0.35)),
        cve_aggregation_max_contributors=int(agg.get("finding_cve_max_contributors", 8)),
        signal_reliability=sig_rel,
        exposure_track=exp_track,
        nmap_port_bonus=float(nmap_ctx.get("scoring_port_bonus", 0.0) or 0.0),
    )


def _build_triage_policy_v2(global_cfg: Mapping[str, Any], topn_cfg: Mapping[str, Any]) -> TriagePolicyV2:
    triage_block = global_cfg.get("triage") if isinstance(global_cfg.get("triage"), Mapping) else {}
    tp_block = topn_cfg.get("triage_policy") if isinstance(topn_cfg.get("triage_policy"), Mapping) else {}

    raw_prof = (
        triage_block.get("default_profile")
        or global_cfg.get("profile")
        or tp_block.get("profile")
        or "default"
    )
    default_profile = normalize_triage_profile(raw_prof)
    static_sast_p1_cap = bool(triage_block.get("static_sast_p1_cap", True))
    enabled = bool(tp_block.get("enabled", True))
    sla_days = {
        "3-day + Forensic Triage": 3,
        "14-day": 14,
        "60-day": 60,
    }
    if isinstance(tp_block.get("sla_days"), Mapping):
        for k, v in tp_block["sla_days"].items():
            sla_days[str(k)] = int(v)

    return TriagePolicyV2(
        default_profile=default_profile,
        static_sast_p1_cap=static_sast_p1_cap,
        enabled=enabled,
        sla_days=sla_days,
    )


def _build_aci_policy_v2(topn_cfg: Mapping[str, Any]) -> ACIPolicyV2:
    aci = topn_cfg.get("aci") if isinstance(topn_cfg.get("aci"), Mapping) else {}
    return ACIPolicyV2(
        enabled=bool(aci.get("enabled", True)),
        exposure_track_enabled=bool(aci.get("exposure_track_enabled", True)),
        non_cve_uplift_weight=float(aci.get("non_cve_uplift_weight", 1.0)),
        min_confidence=float(aci.get("min_confidence", 0.6)),
        max_uplift=float(aci.get("max_uplift", 2.0)),
        asset_uplift_weight=float(aci.get("asset_uplift_weight", 0.5)),
        token_mode=str(aci.get("token_mode", "merge")),
    )


class ConfigProjector:
    """
    Config projector: converts validated payloads into typed runtime bundles.
    """

    @staticmethod
    def from_dicts(
        global_config: Mapping[str, Any],
        scoring_config: Mapping[str, Any],
        topn_config: Mapping[str, Any],
        *,
        source_version: Optional[str] = None,
    ) -> RuntimeConfigBundle:
        g_dict = dict(global_config)
        s_dict = dict(scoring_config)
        t_dict = dict(topn_config)

        sig_rel = _build_signal_reliability(g_dict, s_dict)
        scoring_pol = build_scoring_policy_v2(s_dict, g_dict)
        triage_pol = _build_triage_policy_v2(g_dict, t_dict)
        aci_pol = _build_aci_policy_v2(t_dict)

        feeds = ((g_dict.get("feed_cache") or {}).get("feeds") or {}) if isinstance(g_dict.get("feed_cache"), Mapping) else {}
        nvd_cfg = feeds.get("nvd") if isinstance(feeds.get("nvd"), Mapping) else {}
        osv_cfg = feeds.get("osv") if isinstance(feeds.get("osv"), Mapping) else {}
        enrich_cfg = g_dict.get("enrichment") if isinstance(g_dict.get("enrichment"), Mapping) else {}
        summary_cfg = g_dict.get("summary") if isinstance(g_dict.get("summary"), Mapping) else {}
        nmap_cfg = g_dict.get("nmap_ctx") if isinstance(g_dict.get("nmap_ctx"), Mapping) else {}

        raw_end_year = nvd_cfg.get("end_year")
        end_year = int(raw_end_year) if raw_end_year is not None else None

        v2_cfg = VppConfigV2(
            version=str(g_dict.get("version") or "v2"),
            source_version=str(source_version or g_dict.get("version") or "v2"),
            profile=triage_pol.default_profile,
            nvd_start_year=int(nvd_cfg.get("start_year", 2002)),
            nvd_end_year=end_year,
            osv_enabled=bool(osv_cfg.get("enabled", True)),
            osv_source=enrich_cfg.get("osv_source"),
            summary_top_n=int(summary_cfg.get("top_n_findings", 20)),
            signal_reliability=sig_rel,
            scoring=scoring_pol,
            triage=triage_pol,
            aci=aci_pol,
            nmap_port_tiebreak_enabled=bool(nmap_cfg.get("port_tiebreak_enabled", True)),
            nmap_scoring_port_bonus=float(nmap_cfg.get("scoring_port_bonus", 0.0) or 0.0),
        )

        return RuntimeConfigBundle(
            global_config=g_dict,
            scoring_config=s_dict,
            topn_config=t_dict,
            v2_config=v2_cfg,
            scoring_policy=scoring_pol,
            triage_policy=triage_pol,
            aci_policy=aci_pol,
            signal_reliability=sig_rel,
        )

    @staticmethod
    def project(validation: "ConfigValidationResult") -> RuntimeConfigBundle:
        """
        Project validated payloads into RuntimeConfigBundle with typed v2 policies.
        """
        return ConfigProjector.from_dicts(
            validation.normalized.global_config,
            validation.normalized.scoring_config,
            validation.normalized.topn_config,
            source_version=getattr(validation, "source_version", "v2"),
        )

    @staticmethod
    def load_packaged_default_bundle() -> RuntimeConfigBundle:
        """Load and project packaged default v2 config bundle."""
        payloads: RawConfigPayloads = ConfigSource.load_packaged_defaults()
        return ConfigProjector.from_dicts(
            payloads.global_config,
            payloads.scoring_config,
            payloads.topn_config,
            source_version="v2",
        )
