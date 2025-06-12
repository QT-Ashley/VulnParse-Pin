

def determine_triage_priority(severity: str, cvss_score: float, epss_score: float, cisa_kev: bool, exploit_available: bool) -> str:
    '''
    Function to determine and assign a criticality level to an Asset.
    
    Args:
        severity: str
        cvss_score: float
        epss_score: float
        cisa_kev: bool
        exploit_available: bool
        
    Returns:
        [str]
    '''
    if cisa_kev or exploit_available:
        return "Critical"
    elif cvss_score >= 9.0:
        return "Critical"
    elif severity == "High" and epss_score >= 0.7:
        return "Critical"
    elif exploit_available and epss_score > 0.7 and severity in ["Critical", "High", "Medium"]:
        return "Critical"
    elif exploit_available and (epss_score > 0.7 or cvss_score > 7.0):
        return "High"
    elif severity in ["Critical", "High"] and epss_score > 0.5 or cvss_score >= 7.0:
        return "High"
    elif epss_score > 0.5 or exploit_available:
        return "Medium"
    elif cvss_score >= 4.0:
        return "Medium"
    elif severity == "Medium":
        return "Medium"
    else:
        return "Low"