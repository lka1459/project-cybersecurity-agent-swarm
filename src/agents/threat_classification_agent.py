import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

df = pd.read_json(
    "../../data/threat_intel_dataset.jsonl",
    lines=True
)

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

class ThreatClassificationAgent:
    def __init__(self):
        self.threats = {
    "SQL Injection": "vulnerability allowing attackers to manipulate SQL database queries through unsanitised user input",
    "XSS": "cross-site scripting vulnerability involving malicious script injection and execution in a user's browser",
    "Denial of Service": "vulnerability allowing attackers to exhaust resources, crash systems, or disrupt service availability",
    "Authentication Bypass": "vulnerability allowing attackers to gain unauthorised access without valid authentication credentials",
    "Privilege Escalation": "vulnerability allowing attackers to gain elevated permissions or administrative access",
    "Remote Code Execution": "vulnerability allowing attackers to remotely execute arbitrary code or system commands on a target machine"
}

    def classify(self, cve_text):
        input_embeddings = model.encode(cve_text)
        output_embeddings = model.encode(list(self.threats.values()))

        input_embeddings = input_embeddings.reshape(1,-1)
      
        similarity = cosine_similarity(input_embeddings, output_embeddings)
        one_row = similarity[0]
        idx = one_row.argmax()
        e = list(self.threats.keys())
        return e[idx]
    
    def __str__(self):
        return "Threat Classification Agent"
    
agent = ThreatClassificationAgent()

x = 4
result = agent.classify(df.loc[x, "input"])
print(result)