from dataclasses import dataclass

@dataclass(frozen=True)
class ScoringPolicyV1:
    epss_scale: float
    epss_min: float
    epss_max: float

    kev_evd: float
    exploit_evd: float

    band_critical: float
    band_high: float
    band_medium: float
    band_low: float

    asset_aggregation: str

    w_epss_high: float
    w_epss_medium: float
    w_kev: float
    w_exploit: float

    max_raw_risk: float
    max_op_risk: float
