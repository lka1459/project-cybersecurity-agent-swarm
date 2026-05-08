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

Responsible for identifying the type of cybersecurity vulnerability.

Example classifications:

* SQL Injection
* Remote Code Execution
* Cross-Site Scripting (XSS)
* Privilege Escalation
* Authentication Bypass
* Denial of Service

### Severity Agent

Determines the severity level of vulnerabilities using CVSS scores and contextual reasoning.

### Mitigation Agent

Generates remediation recommendations and mitigation strategies.

### Detection Rule Agent

Produces detection logic and potential monitoring rules.

### Coordinator Agent

Combines outputs from all agents into a final structured threat intelligence report.

---

## Technologies Used

* Python
* LangChain
* HuggingFace Transformers
* Sentence Transformers
* Scikit-learn
* FAISS
* PyTorch
* Pandas
* NumPy

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

## Current Progress

### Completed

* Initial project architecture
* Threat Classification Agent prototype
* Semantic similarity classification using sentence embeddings
* GitHub project setup

### In Progress

* Severity analysis agent
* Retrieval system using embeddings
* Multi-agent orchestration workflow

---

## Future Improvements

* Retrieval-Augmented Generation (RAG)
* FAISS vector database integration
* Improved semantic threat classification
* Streamlit frontend/dashboard
* Automated report generation
* Similar CVE retrieval system

---

## Running the Project

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the project:

```bash
python src/main.py
```

---

## Disclaimer

This project is developed for educational and research purposes only.
