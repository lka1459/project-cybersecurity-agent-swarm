import re
from typing import Dict

class SeverityAgent:
    def __init__(self) -> None:
        pass


    def severity_score(self, cve_text: str, classification_result: Dict[str, str | float]) -> Dict[str, float]:
        severity_regex: re.Pattern = r'\bSeverity: \b(\w+)'
        cvss_regex: re.Pattern = r'\bCVSS Score: \b([+-]?\d+\.\d+)'

        cvss_score: float = float((re.search(cvss_regex, cve_text)).group(1))
        severity: str  = (re.search(severity_regex, cve_text)).group(1).title()

        threat_type: str = classification_result["threat_type"]
        reason: str = f"The {threat_type} threat has a severity of {severity.lower()} because because it has a CVSS score of {cvss_score}."

        return  {
            "severity": severity,
            "cvss_score": cvss_score,
            "reason": reason,
        }
    
    def __str__(self) -> str:
        return "Severity Agent that identities the severity of a vulnerabilty."