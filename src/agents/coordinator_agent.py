from typing import Dict, List

class CoordinatorAgent:
    def __init__(self, threat_agent, severity_agent, mitigation_agent):
        self.threat_agent = threat_agent
        self.severity_agent = severity_agent
        self.mitigation_agent = mitigation_agent

    def analyse(self, cve_text: str) -> Dict[str, Dict[str, object]]:
        threat = self.threat_agent.classify(cve_text)
        severity = self.severity_agent.severity_score(cve_text, threat)
        mitigation = self.mitigation_agent.recommend(cve_text, threat, severity)

        return {
            "classification_result": threat,
            "severity": severity,
            "mitigation": mitigation
        }
    
    def format_report(self, cve_text: str) -> str:
        results: Dict[str, Dict[str, object]] = self.analyse(cve_text)
        threat_type: str = results['classification_result']['threat_type']
        confidence: float = results['classification_result']['confidence']
        severity: str = results['severity']['severity']
        cvss_score: float = results['severity']['cvss_score']
        reason: str = results['severity']['reason']
        recommended_actions: List[str] = results['mitigation']['recommended_action']
        recommended_output: str = ""
        
        for index, action in  enumerate(recommended_actions):
            recommended_output += f"{index + 1}. {action}\n"

        return f"""Threat Intelligence Summary

Threat Type: {threat_type}
Confidence: {confidence}

Severity: {severity}
CVSS Score: {cvss_score}

Reason:
{reason}

Recommended Actions:
{recommended_output}"""


    def __str__(self) -> str:
        return "Coordinator Agent that coordinates other agents."