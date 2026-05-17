# Multi-Agent Cybersecurity Threat Intelligence System

## Overview

This project is a multi-agent NLP-based cybersecurity threat intelligence system designed to analyse raw CVE (Common Vulnerabilities and Exposures) data and generate structured threat analysis outputs.

The system uses multiple specialised AI agents that collaborate together to classify cybersecurity threats, analyse severity, recommend mitigations, and generate threat intelligence reports.

The project explores modern NLP techniques including:

* Semantic embeddings
* Vector similarity search
* Retrieval-Augmented Generation (RAG)
* Agent-based workflows
* Threat classification using NLP
* Cybersecurity threat intelligence automation

---

## Project Goal

The aim of this project is to simulate an AI-powered Security Operations Centre (SOC) workflow capable of analysing vulnerability information and assisting cybersecurity analysts with automated threat assessment.

The system is designed around the concept of specialised agents, where each agent performs a specific cybersecurity reasoning task.

---

## Planned Agent Architecture

### Threat Classification Agent

Responsible for identifying the likely cybersecurity threat category from raw CVE text using semantic similarity.

Implemented using:

- Sentence Transformers (`all-MiniLM-L6-v2`)
- Cosine similarity
- Confidence thresholding

Supported threat categories include:

- SQL Injection
- Cross-site Scripting (XSS)
- Denial of Service (DOS)
- Authentication Bypass
- Privilege Escalation
- Remote Code Execution
- Credential Exposure
- Information Disclosure
- Directory Traversal
- Brute Force
- DNS Poisoning
- Buffer Overflow
- IP Spoofing
- Unknown

### Severity Agent

Determines the severity level of vulnerabilities using CVSS scores and contextual reasoning.

Implemented using:

- Regex-based extraction
- CVSS score parsing
- Severity classification
- Contextual reasoning generation

Extracted fields:

- CVSS Score
- Severity Level
- Severity Explanation

---

### Mitigation Agent

Responsible for generating remediation recommendations based on threat classification and severity.

Implemented using:

- Rule-based mitigation templates
- Severity-based response prioritisation
- Threat-aware remediation logic

Outputs include:

- Response priority
- Recommended mitigation actions
- Mitigation reasoning

---


### Coordinator Agent

Combines outputs from all agents into a final structured threat intelligence report.

Workflow:

```text
Raw CVE Input
    ↓
Threat Classification Agent
    ↓
Severity Agent
    ↓
Mitigation Agent
    ↓
Coordinator Agent
    ↓
Final Threat Intelligence Report
```

---

## Technologies Used

- Python
- Sentence Transformers
- HuggingFace Transformers
- Scikit-learn
- Pandas
- NumPy
- PyTorch
- Regular Expressions (Regex)

---

## Dataset

This project uses a synthetic cybersecurity threat intelligence dataset based on real-world CVE data.

Dataset structure:

* `instruction` → task prompt
* `input` → raw CVE vulnerability data
* `output` → structured threat intelligence report

Dataset format:

* JSONL

---

## Example Output

Example generated report:

```text
Threat Intelligence Summary

Threat Type: Remote Code Execution
Confidence: 0.842

Severity: Critical
CVSS Score: 9.8

Reason:
The Remote Code Execution threat has a severity of critical because of its CVSS score of 9.8.

Recommended Actions:
1. Apply vendor patches or upgrade affected software immediately.
2. Restrict external access to the vulnerable service.
3. Monitor logs for suspicious command execution activity.
```

---

## Project Structure

```text
project-root/
│
├── data/
│   └── threat_intel_dataset.jsonl
│
├── src/
│   ├── main.py
│   └── agents/
│       ├── threat_classification_agent.py
│       ├── severity_agent.py
│       ├── mitigation_agent.py
│       └── coordinator_agent.py
│
├── notebooks/
│   └── experiment.ipynb
│
├── requirements.txt
└── README.md
```

---

## Running the Project

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the system:

```bash
python src/main.py
```

---