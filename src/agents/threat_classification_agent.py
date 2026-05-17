import numpy as np
from typing import Dict, List
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

model: SentenceTransformer = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

class ThreatClassificationAgent:
    def __init__(self) -> None:
        self.threats: Dict[str, str] = {
    "SQL Injection": "vulnerability allowing attackers to manipulate SQL database queries through unsanitised user input",
    "Cross-site Scripting (XSS)": "cross-site scripting vulnerability involving malicious script injection and execution in a user's browser",
    "Denial of Service (DOS)": "Denial of Service vulnerabilities involving service exhaustion, malformed packet crashes, server instability, resource exhaustion, or disruption of system availability",
    "Authentication Bypass": "vulnerability allowing attackers to gain unauthorised access without valid authentication credentials, bypass login checks, reset passwords, modify passwords, or access protected functions without proper verification",
    "Privilege Escalation": "vulnerability allowing attackers to gain elevated permissions or administrative access",
    "Remote Code Execution": "vulnerability allowing attackers to remotely execute arbitrary code or system commands on a target machine",
    "Credential Exposure": "vulnerability exposing plaintext passwords, authentication credentials, tokens, or other sensitive login information",
    "Information Disclosure": "vulnerability allowing attackers to access or leak sensitive system, configuration, or user information",
    "Directory Traversal": "vulnerability allowing attackers to access arbitrary files or directories outside intended system paths through path traversal techniques",
    "Brute Force": "vulnerability allowing attackers to repeatedly guess usernames, passwords, or credentials due to weak login protections, missing lockout, or no delay after failed authentication attempts",
    "DNS Poisoning": "vulnerability involving DNS poisoning, spoofed DNS responses, malicious DNS updates, unauthorised name resolution modification, cache poisoning, or redirection of network traffic through manipulated DNS records",
    "Buffer Overflow": "memory corruption vulnerability involving buffer overflow, heap overflow, stack overflow, or overly long input causing code execution, crash, or control-flow manipulation",
    "IP Spoofing": "vulnerability allowing attackers to spoof IP addresses, impersonate trusted hosts, or bypass network-based trust controls"
    }
        self.keys: List[str] = list(self.threats.keys())

    def classify(self, cve_text: str) -> Dict[str, float]:
        input_embeddings: np.array = model.encode(cve_text)
        output_embeddings: np.array = model.encode(list(self.threats.values()))

        input_embeddings: np.array = input_embeddings.reshape(1,-1)
      
        similarity: np.ndarray = cosine_similarity(input_embeddings, output_embeddings)
        one_row: np.ndarray = similarity[0]
        idx: int = one_row.argmax()
        confidence: float = float(one_row[idx])

        if confidence < 0.4:
            return {
                "threat_type": "Unknown",
                "confidence": round(confidence, 3)
            }
        else:
            return {
                "threat_type": self.keys[idx],
                "confidence": round(confidence, 3)
            }    
        
    def __str__(self) -> str:
        return "Threat Classification Agent"