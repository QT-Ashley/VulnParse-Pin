

def determine_triage_priority(severity: str, epss_score: float, cisa_kev: bool, exploit_available: bool) -> str:
    if cisa_kev:
        return "Critical"
    elif exploit_available and epss_score > 0.7:
        return "High"
    elif severity in ["Critical", "High"] and epss_score > 0.5:
        return "High"
    elif epss_score > 0.5 or exploit_available:
        return "Medium"
    else:
        return "Low"