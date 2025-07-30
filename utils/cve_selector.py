from typing import Dict, List, Optional


def select_authoritative_cve(cve_list: List[str], nvd_data: Dict[str, Dict]) -> Optional[str]:
    def get_score(cve):
        entry = nvd_data.get(cve, {})
        vector = entry.get("cvss_vector", "")
        base_score = entry.get("cvss_score", 0)
        if isinstance(vector, str):
            cvss_version = 3 if "CVSS:3" in vector else (2 if "CVSS:2" in vector else 0)
        else:
            cvss_version = 0
        epss = entry.get("epss_score", 0)
        kev = entry.get("cisa_kev", False)
        exploit = entry.get("exploit_available", False)
        return (
            kev,
            exploit,
            epss,
            cvss_version,
            base_score
        )
        
    scored = [(cve, get_score(cve)) for cve in cve_list if cve in nvd_data]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[0][0] if scored else None