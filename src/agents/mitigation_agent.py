from typing import Dict

class MitigationAgent:
     def __init__(self) -> None:
        self.mitigation_templates = {
    "Remote Code Execution": [
        "Apply vendor patches or upgrade the affected software immediately.",
        "Restrict external access to the vulnerable service.",
        "Monitor logs for unusual command execution or process activity."
    ],

    "SQL Injection": [
        "Use parameterised queries or prepared statements.",
        "Validate and sanitise all user input.",
        "Review database permissions and restrict unnecessary access."
    ],

    "Cross-site Scripting (XSS)": [
        "Sanitise and validate user-generated content.",
        "Implement output encoding and Content Security Policy (CSP).",
        "Restrict execution of untrusted browser scripts."
    ],

    "Denial of Service (DOS)": [
        "Implement rate limiting and traffic filtering.",
        "Patch vulnerable services and monitor system resource usage.",
        "Deploy network protections such as firewalls or DDoS mitigation services."
    ],

    "Authentication Bypass": [
        "Strengthen authentication and session validation mechanisms.",
        "Require proper credential verification before granting access.",
        "Review password reset and login workflows for security weaknesses."
    ],

    "Privilege Escalation": [
        "Restrict administrative privileges and apply least-privilege principles.",
        "Patch vulnerable software components immediately.",
        "Monitor systems for suspicious privilege changes or unauthorised access."
    ],

    "Credential Exposure": [
        "Rotate exposed passwords, API keys, and authentication tokens immediately.",
        "Remove plaintext credentials from files or configuration systems.",
        "Restrict file permissions and review access logs for suspicious activity."
    ],

    "Information Disclosure": [
        "Restrict public access to sensitive files and configuration data.",
        "Patch systems leaking sensitive information.",
        "Review logs and monitor for unauthorised information access attempts."
    ],

    "Directory Traversal": [
        "Validate and sanitise file path input parameters.",
        "Restrict file system access permissions.",
        "Block path traversal sequences such as '../' in user input."
    ],

    "Brute Force": [
        "Implement account lockout or login rate limiting.",
        "Require strong password policies and multi-factor authentication.",
        "Monitor failed login attempts and suspicious authentication activity."
    ],

    "DNS Poisoning": [
        "Restrict unauthorised DNS updates and zone transfers.",
        "Enable DNSSEC where possible.",
        "Monitor DNS traffic for spoofed or malicious responses."
    ],

    "Buffer Overflow": [
        "Patch vulnerable applications immediately.",
        "Validate input lengths and implement memory safety protections.",
        "Monitor systems for crashes, abnormal behaviour, or exploitation attempts."
    ],

    "IP Spoofing": [
        "Implement ingress and egress packet filtering.",
        "Restrict trust relationships based solely on IP addresses.",
        "Monitor network traffic for suspicious or spoofed packets."
    ],

    "Unknown": [
        "Review the vulnerability manually for further investigation.",
        "Monitor affected systems for suspicious behaviour.",
        "Apply relevant vendor patches and security updates where possible."
    ]
}
     
     def recommend(self, cve_text: str, classification_result: Dict[str, str | float], severity_result: Dict[str, str | float]) -> Dict[str, str | list[str]]:
         if severity_result['severity'] == "Critical" or severity_result['severity'] == "High":
             priority: str = "Immediate"
         elif severity_result['severity'] == "Medium":
             priority: str = "Moderate"
         elif severity_result['severity'] == "Low":
             priority: str = "Low"
         else:
             priority: str = f"Unknown: {severity_result['severity']}"
             
         threat_type: str = classification_result['threat_type']

         recommended_action: Dict[str] = self.mitigation_templates[threat_type]
     
         return {
                "priority": priority,
                "recommended_action": recommended_action, 
                "reason": f"The vulnerability is classified as {threat_type} and rated {severity_result['severity']}.",
            }
     
     def __str__(self) -> str:
         return "Mitigation Agent that calls tools and recommends strategies"
 
