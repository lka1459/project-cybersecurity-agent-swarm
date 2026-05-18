from __future__ import annotations

import concurrent.futures
import html
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

import pandas as pd

from agents.coordinator_agent import CoordinatorAgent
from agents.mitigation_agent import MitigationAgent
from agents.severity_agent import SeverityAgent
from agents.threat_classification_agent import ThreatClassificationAgent
from llm_client import LocalLLMClient


ALLOWED_THREAT_TYPES: List[str] = [
    "SQL Injection",
    "Cross-site Scripting (XSS)",
    "Denial of Service (DOS)",
    "Authentication Bypass",
    "Privilege Escalation",
    "Remote Code Execution",
    "Credential Exposure",
    "Information Disclosure",
    "Directory Traversal",
    "Brute Force",
    "DNS Poisoning",
    "Buffer Overflow",
    "IP Spoofing",
    "Access Control Bypass",
    "Command Injection",
    "Port Scanning / Proxy Abuse",
    "Memory Corruption",
    "File Inclusion",
    "Insecure Update / Supply Chain",
    "Unknown",
]

ORIGINAL_THREAT_TYPES: List[str] = [
    "SQL Injection",
    "Cross-site Scripting (XSS)",
    "Denial of Service (DOS)",
    "Authentication Bypass",
    "Privilege Escalation",
    "Remote Code Execution",
    "Credential Exposure",
    "Information Disclosure",
    "Directory Traversal",
    "Brute Force",
    "DNS Poisoning",
    "Buffer Overflow",
    "IP Spoofing",
    "Unknown",
]

OLD_CATEGORY_MAP: Dict[str, str] = {
    "Access Control Bypass": "Authentication Bypass",
    "Command Injection": "Remote Code Execution",
    "Port Scanning / Proxy Abuse": "Unknown",
    "Memory Corruption": "Buffer Overflow",
    "File Inclusion": "Directory Traversal",
    "Insecure Update / Supply Chain": "Unknown",
}

EVIDENCE_PATTERNS: Dict[str, List[str]] = {
    "SQL Injection": [r"\bsql injection\b"],
    "Cross-site Scripting (XSS)": [r"cross[- ]site scripting", r"\bxss\b"],
    "Denial of Service (DOS)": [r"denial of service", r"\bdos\b"],
    "Authentication Bypass": [
        r"authentication bypass",
        r"bypass authentication",
        r"bypass a protection mechanism",
    ],
    "Access Control Bypass": [
        r"bypass intended acls?",
        r"access control bypass",
        r"authorization bypass",
        r"bypass access controls?",
        r"bypass intended access restrictions?",
    ],
    "Remote Code Execution": [
        r"remote code execution",
        r"remote command execution",
        r"execute arbitrary code",
        r"execute arbitrary commands?",
        r"execute arbitrary os commands?",
    ],
    "Command Injection": [
        r"command injection",
        r"shell metacharacters?",
        r"inject arbitrary commands?",
        r"malformed .*command",
    ],
    "Directory Traversal": [r"directory traversal", r"path traversal"],
    "File Inclusion": [r"file inclusion", r"remote file inclusion", r"local file inclusion"],
    "Brute Force": [r"brute force", r"password guessing"],
    "DNS Poisoning": [r"dns poisoning", r"dns spoofing", r"cache poisoning"],
    "Buffer Overflow": [r"buffer overflow", r"heap overflow", r"stack overflow"],
    "Memory Corruption": [r"memory corruption", r"use after free", r"invalid memory"],
    "IP Spoofing": [r"ip spoofing"],
    "Port Scanning / Proxy Abuse": [r"port scan", r"port scanning", r"use .* as a proxy", r"proxy abuse"],
    "Insecure Update / Supply Chain": [
        r"insecure update",
        r"without cryptograph",
        r"update integrity",
        r"supply chain",
        r"download files",
    ],
}

EXPECTED_LABEL_PATTERNS: Dict[str, List[str]] = {
    **EVIDENCE_PATTERNS,
    "Privilege Escalation": [
        r"privilege escalation",
        r"gain privileges",
        r"gain additional privileges",
        r"root privileges",
        r"elevated permissions",
    ],
    "Credential Exposure": [
        r"credential exposure",
        r"plaintext password",
        r"hardcoded credentials",
        r"credentials in files",
    ],
    "Information Disclosure": [
        r"information disclosure",
        r"sensitive information",
        r"obtain sensitive",
        r"leak",
    ],
}

OLD_EXPECTED_LABEL_PATTERNS: Dict[str, List[str]] = {
    "SQL Injection": [r"sql injection"],
    "Cross-site Scripting (XSS)": [r"cross[- ]site scripting", r"\bxss\b"],
    "Denial of Service (DOS)": [r"denial of service", r"\bdos\b", r"service exhaustion"],
    "Authentication Bypass": [
        r"authentication bypass",
        r"bypass authentication",
        r"access control bypass",
        r"bypass intended acls?",
        r"bypass a protection mechanism",
    ],
    "Privilege Escalation": [
        r"privilege escalation",
        r"gain privileges",
        r"gain additional privileges",
        r"root privileges",
        r"elevated permissions",
    ],
    "Remote Code Execution": [
        r"remote code execution",
        r"\brce\b",
        r"remote command execution",
        r"execute arbitrary code",
        r"execute arbitrary commands?",
        r"execute arbitrary os commands?",
        r"command injection",
    ],
    "Credential Exposure": [
        r"credential exposure",
        r"plaintext password",
        r"hardcoded credentials",
        r"credentials in files",
    ],
    "Information Disclosure": [
        r"information disclosure",
        r"sensitive information",
        r"obtain sensitive",
        r"leak",
    ],
    "Directory Traversal": [
        r"directory traversal",
        r"path traversal",
        r"file inclusion",
        r"arbitrary files",
    ],
    "Brute Force": [r"brute force", r"password guessing"],
    "DNS Poisoning": [r"dns poisoning", r"dns spoofing", r"cache poisoning"],
    "Buffer Overflow": [
        r"buffer overflow",
        r"heap overflow",
        r"stack overflow",
        r"memory corruption",
    ],
    "IP Spoofing": [r"ip spoofing"],
}

FEW_SHOT_EXAMPLES: List[Dict[str, Any]] = [
    {
        "cve_clue": "Buffer overflow allows remote attackers to execute arbitrary commands.",
        "baseline": "Buffer Overflow",
        "primary_threat_type": "Remote Code Execution",
        "secondary_threat_types": ["Buffer Overflow"],
        "reasoning": "Execution impact takes priority, while buffer overflow remains the mechanism.",
    },
    {
        "cve_clue": "Default permissions of /dev/kmem allows IP spoofing.",
        "baseline": "Unknown",
        "primary_threat_type": "IP Spoofing",
        "secondary_threat_types": [],
        "reasoning": "The CVE explicitly names IP spoofing.",
    },
    {
        "cve_clue": "Administrator password is plaintext in a world-readable file and allows attackers to gain privileges.",
        "baseline": "Privilege Escalation",
        "primary_threat_type": "Privilege Escalation",
        "secondary_threat_types": ["Credential Exposure", "Information Disclosure"],
        "reasoning": "Keep the dataset-style impact as primary, while recording credential exposure as secondary.",
    },
    {
        "cve_clue": "Server verbose debug mode lets attackers use the service as a proxy for port scanning.",
        "baseline": "Unknown",
        "primary_threat_type": "Port Scanning / Proxy Abuse",
        "secondary_threat_types": [],
        "reasoning": "The service is abused as a proxy to scan ports rather than directly disclose data.",
    },
    {
        "cve_clue": "CUPS case-sensitive Location directive allows attackers to bypass intended ACLs.",
        "baseline": "Unknown",
        "primary_threat_type": "Access Control Bypass",
        "secondary_threat_types": [],
        "reasoning": "The core issue is bypassing access control lists.",
    },
    {
        "cve_clue": "LiveUpdate does not verify update integrity, allowing code execution through DNS spoofing.",
        "baseline": "DNS Poisoning",
        "primary_threat_type": "Remote Code Execution",
        "secondary_threat_types": ["DNS Poisoning", "Insecure Update / Supply Chain"],
        "reasoning": "The impact is code execution, with DNS spoofing and insecure update integrity as mechanisms.",
    },
]


class HybridThreatWorkflow:
    def __init__(
        self,
        threat_agent: ThreatClassificationAgent,
        severity_agent: SeverityAgent,
        mitigation_agent: MitigationAgent,
        llm_client: LocalLLMClient,
        revision_threshold: float = 0.4,
    ) -> None:
        self.threat_agent = threat_agent
        self.severity_agent = severity_agent
        self.mitigation_agent = mitigation_agent
        self.llm_client = llm_client
        self.revision_threshold = revision_threshold

    def analyse(self, cve_text: str) -> Dict[str, Any]:
        baseline_classification = self.threat_agent.classify(cve_text)
        baseline_severity = self.severity_agent.severity_score(cve_text, baseline_classification)
        baseline_mitigation = self.mitigation_agent.recommend(
            cve_text,
            baseline_classification,
            baseline_severity,
        )

        review = self._review_with_llm(
            cve_text,
            baseline_classification,
            baseline_severity,
            baseline_mitigation,
        )
        validated_review = self._validate_review(
            cve_text,
            baseline_classification,
            baseline_mitigation,
            review,
        )

        final_classification = {
            "threat_type": validated_review["threat_type"],
            "secondary_threat_types": validated_review["secondary_threat_types"],
            "baseline_threat_type": baseline_classification["threat_type"],
            "baseline_confidence": baseline_classification["confidence"],
            "llm_confidence": validated_review["llm_confidence"],
            "review_decision": validated_review["decision"],
            "review_reasoning": validated_review["reasoning"],
            "guardrail_errors": validated_review["guardrail_errors"],
            "strong_evidence_categories": sorted(self.strong_evidence_categories(cve_text)),
        }
        final_severity = {
            **baseline_severity,
            "reason": self._severity_reason(
                final_classification["threat_type"],
                baseline_severity["severity"],
                baseline_severity["cvss_score"],
                validated_review["reasoning"],
            ),
        }
        final_mitigation = {
            **baseline_mitigation,
            "recommended_action": validated_review["recommended_actions"],
            "reason": (
                f"The vulnerability is classified as {final_classification['threat_type']} "
                f"and rated {final_severity['severity']}."
            ),
        }

        return {
            "baseline": {
                "classification_result": baseline_classification,
                "severity": baseline_severity,
                "mitigation": baseline_mitigation,
            },
            "classification_result": final_classification,
            "severity": final_severity,
            "mitigation": final_mitigation,
            "llm_review": review,
        }

    def format_report(self, cve_text: str) -> str:
        return format_hybrid_report(self.analyse(cve_text))

    def _review_with_llm(
        self,
        cve_text: str,
        baseline_classification: Dict[str, Any],
        baseline_severity: Dict[str, Any],
        baseline_mitigation: Dict[str, Any],
    ) -> Dict[str, Any]:
        prompt = {
            "task": "Review and enrich a deterministic cybersecurity classification. Return JSON only.",
            "allowed_threat_categories": ALLOWED_THREAT_TYPES,
            "rules": [
                "Keep the deterministic baseline unless the CVE text clearly supports a better allowed category.",
                "When both mechanism and impact apply, use the highest-impact outcome as primary and put mechanisms in secondary_threat_types.",
                "For example, buffer overflow plus execute arbitrary code should be Remote Code Execution primary and Buffer Overflow secondary.",
                "If revising, cite the evidence in one short reasoning sentence.",
                "Do not invent CVSS scores, affected products, references, or exploit steps.",
                "Recommended actions must be defensive, concise, and actionable.",
            ],
            "few_shot_examples": FEW_SHOT_EXAMPLES,
            "baseline": baseline_classification,
            "severity": baseline_severity,
            "mitigation": baseline_mitigation,
            "cve_text": cve_text,
            "return_schema": {
                "decision": "accept_baseline or revise_baseline",
                "threat_type": "one allowed category exactly",
                "secondary_threat_types": ["zero to three allowed categories that are also relevant"],
                "llm_confidence": "number from 0 to 1",
                "reasoning": "one short sentence",
                "recommended_actions": ["three defensive actions"],
            },
        }
        return self.llm_client.chat_json(
            messages=[
                {"role": "system", "content": "You return only valid JSON. No markdown."},
                {"role": "user", "content": json.dumps(prompt)},
            ],
            max_tokens=320,
            temperature=0.0,
            retries=1,
        )

    def _validate_review(
        self,
        cve_text: str,
        baseline_classification: Dict[str, Any],
        baseline_mitigation: Dict[str, Any],
        review: Dict[str, Any],
    ) -> Dict[str, Any]:
        guardrail_errors: List[str] = []
        decision = review.get("decision")
        threat_type = review.get("threat_type")
        secondary_threat_types = review.get("secondary_threat_types")
        llm_confidence = review.get("llm_confidence")
        reasoning = str(review.get("reasoning", "")).strip()
        recommended_actions = review.get("recommended_actions")

        if decision not in {"accept_baseline", "revise_baseline"}:
            guardrail_errors.append("invalid decision")
            decision = "accept_baseline"

        if threat_type not in ALLOWED_THREAT_TYPES:
            guardrail_errors.append("invalid threat_type")
            threat_type = baseline_classification["threat_type"]

        secondary_threat_types = self._valid_secondary_threat_types(secondary_threat_types, str(threat_type))
        secondary_threat_types = self._merge_secondary_evidence(
            secondary_threat_types,
            self.strong_evidence_categories(cve_text),
            str(threat_type),
        )

        if not isinstance(llm_confidence, (int, float)) or not 0 <= llm_confidence <= 1:
            guardrail_errors.append("invalid llm_confidence")
            llm_confidence = None

        if not self._valid_actions(recommended_actions):
            guardrail_errors.append("invalid recommended_actions")
            recommended_actions = baseline_mitigation["recommended_action"]

        if decision == "revise_baseline" and not self.revision_allowed(
            cve_text,
            baseline_classification,
            str(threat_type),
        ):
            guardrail_errors.append("revision blocked")
            decision = "accept_baseline"
            threat_type = baseline_classification["threat_type"]

        if decision == "accept_baseline":
            threat_type = baseline_classification["threat_type"]
            secondary_threat_types = self._valid_secondary_threat_types(
                secondary_threat_types,
                str(threat_type),
            )
            secondary_threat_types = self._merge_secondary_evidence(
                secondary_threat_types,
                self.strong_evidence_categories(cve_text),
                str(threat_type),
            )

        return {
            "decision": decision,
            "threat_type": threat_type,
            "secondary_threat_types": secondary_threat_types,
            "llm_confidence": round(float(llm_confidence), 3) if llm_confidence is not None else None,
            "reasoning": reasoning,
            "recommended_actions": list(recommended_actions)[:3],
            "guardrail_errors": guardrail_errors,
        }

    def revision_allowed(
        self,
        cve_text: str,
        baseline_classification: Dict[str, Any],
        proposed_threat_type: str,
    ) -> bool:
        if baseline_classification["threat_type"] == "Unknown":
            return True
        if float(baseline_classification["confidence"]) < self.revision_threshold:
            return True
        return proposed_threat_type in self.strong_evidence_categories(cve_text)

    @staticmethod
    def _valid_secondary_threat_types(threat_types: Any, primary_threat_type: str) -> List[str]:
        if not isinstance(threat_types, list):
            return []

        valid: List[str] = []
        for threat_type in threat_types:
            if (
                isinstance(threat_type, str)
                and threat_type in ALLOWED_THREAT_TYPES
                and threat_type != "Unknown"
                and threat_type != primary_threat_type
                and threat_type not in valid
            ):
                valid.append(threat_type)
        return valid[:3]

    @staticmethod
    def _merge_secondary_evidence(
        secondary_threat_types: List[str],
        evidence_categories: Set[str],
        primary_threat_type: str,
    ) -> List[str]:
        merged = list(secondary_threat_types)
        for category in sorted(evidence_categories):
            if (
                category != primary_threat_type
                and category != "Unknown"
                and category not in merged
            ):
                merged.append(category)
        return merged[:3]

    @staticmethod
    def strong_evidence_categories(cve_text: str) -> Set[str]:
        text = cve_text.lower()
        categories: Set[str] = set()
        for category, patterns in EVIDENCE_PATTERNS.items():
            if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns):
                categories.add(category)
        return categories

    @staticmethod
    def _valid_actions(actions: Any) -> bool:
        return (
            isinstance(actions, list)
            and len(actions) >= 3
            and all(isinstance(action, str) and action.strip() for action in actions)
        )

    @staticmethod
    def _severity_reason(threat_type: str, severity: str, cvss_score: float, review_reasoning: str) -> str:
        reason = f"The {threat_type} threat has a severity of {severity.lower()} because it has a CVSS score of {cvss_score}."
        if review_reasoning:
            return f"{reason} LLM review note: {review_reasoning}"
        return reason


def format_hybrid_report(results: Dict[str, Any]) -> str:
    classification = results["classification_result"]
    severity = results["severity"]
    mitigation = results["mitigation"]
    recommended_actions = "\n".join(
        f"{index + 1}. {action}" for index, action in enumerate(mitigation["recommended_action"])
    )
    guardrails = classification["guardrail_errors"]
    guardrail_output = ", ".join(guardrails) if guardrails else "None"
    secondary = classification["secondary_threat_types"]
    secondary_output = ", ".join(secondary) if secondary else "None"

    return f"""Threat Intelligence Summary

Threat Type: {classification['threat_type']}
Secondary Threat Types: {secondary_output}
Baseline Threat Type: {classification['baseline_threat_type']}
Baseline Confidence: {classification['baseline_confidence']}
LLM Review Decision: {classification['review_decision']}
LLM Review Confidence: {classification['llm_confidence']}

Severity: {severity['severity']}
CVSS Score: {severity['cvss_score']}

Reason:
{severity['reason']}

Recommended Actions:
{recommended_actions}

Guardrails:
{guardrail_output}"""


def build_workflow(llm_client: LocalLLMClient | None = None) -> HybridThreatWorkflow:
    return HybridThreatWorkflow(
        threat_agent=ThreatClassificationAgent(),
        severity_agent=SeverityAgent(),
        mitigation_agent=MitigationAgent(),
        llm_client=llm_client or LocalLLMClient(),
    )


def original_report(cve_text: str) -> str:
    coordinator = CoordinatorAgent(
        threat_agent=ThreatClassificationAgent(),
        severity_agent=SeverityAgent(),
        mitigation_agent=MitigationAgent(),
    )
    return coordinator.format_report(cve_text)


def run_pilot(
    df: pd.DataFrame,
    workflow: HybridThreatWorkflow,
    limit: int,
    workers: int,
    output_dir: Path,
) -> Dict[str, Any]:
    started = time.perf_counter()
    records = list(df.head(limit).iterrows())
    baseline_started = time.perf_counter()
    baseline_items = [baseline_item(index, row, workflow) for index, row in records]
    baseline_seconds = time.perf_counter() - baseline_started

    llm_started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        comparisons = list(executor.map(lambda item: pilot_item(item, workflow), baseline_items))
    llm_seconds = time.perf_counter() - llm_started

    summary = summarize_pilot(comparisons, workers, baseline_seconds, llm_seconds, time.perf_counter() - started)
    write_pilot_outputs(comparisons, summary, output_dir, limit)
    return summary


def run_batch(
    df: pd.DataFrame,
    workflow: HybridThreatWorkflow,
    workers: int,
    output_path: Path,
    limit: int | None = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    records = list((df.head(limit) if limit else df).iterrows())
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda item: batch_item(item, workflow), records))

    with output_path.open("w", encoding="utf-8") as file:
        for result in results:
            file.write(json.dumps(result) + "\n")

    return {
        "records": len(results),
        "workers": workers,
        "output_path": str(output_path),
        "seconds": round(time.perf_counter() - started, 2),
        "fallbacks": sum(1 for item in results if item["fallback"]),
    }


def evaluate_reports(df: pd.DataFrame, report_path: Path) -> Dict[str, Any]:
    reports = list(iter_jsonl(report_path))
    expanded_baseline_hits = 0
    expanded_hybrid_primary_hits = 0
    expanded_hybrid_hits = 0
    old_baseline_hits = 0
    old_hybrid_primary_hits = 0
    old_hybrid_hits = 0
    fallbacks = 0

    for item in reports:
        row_index = item["row_index"]
        expected = expected_categories(df.loc[row_index, "output"])
        old_expected = old_expected_categories(df.loc[row_index, "output"])
        fallbacks += int(item.get("fallback", False))

        results = item["results"]
        if "classification_result" not in results:
            continue

        classification = results["classification_result"]
        baseline = results["baseline"]["classification_result"]["threat_type"]
        primary = classification["threat_type"]
        secondary = set(classification.get("secondary_threat_types", []))

        expanded_baseline_hits += int(baseline in expected)
        expanded_hybrid_primary_hits += int(primary in expected)
        expanded_hybrid_hits += int(bool(({primary} | secondary) & expected))

        old_baseline = to_old_category(baseline)
        old_primary = to_old_category(primary)
        old_secondary = to_old_categories(secondary)
        old_baseline_hits += int(old_baseline in old_expected)
        old_hybrid_primary_hits += int(old_primary in old_expected)
        old_hybrid_hits += int(bool(({old_primary} | old_secondary) & old_expected))

    total = len(reports)
    return {
        "reports": total,
        "fallbacks": fallbacks,
        "report_path": str(report_path),
        "expanded_eval": {
            "baseline_accuracy": round(expanded_baseline_hits / total, 4) if total else 0.0,
            "hybrid_primary_accuracy": round(expanded_hybrid_primary_hits / total, 4) if total else 0.0,
            "hybrid_accuracy_primary_or_secondary": round(expanded_hybrid_hits / total, 4) if total else 0.0,
            "baseline_correct": expanded_baseline_hits,
            "hybrid_primary_correct": expanded_hybrid_primary_hits,
            "hybrid_primary_or_secondary_correct": expanded_hybrid_hits,
        },
        "old_compatible_eval": {
            "baseline_accuracy": round(old_baseline_hits / total, 4) if total else 0.0,
            "hybrid_primary_accuracy": round(old_hybrid_primary_hits / total, 4) if total else 0.0,
            "hybrid_accuracy_primary_or_secondary": round(old_hybrid_hits / total, 4) if total else 0.0,
            "baseline_correct": old_baseline_hits,
            "hybrid_primary_correct": old_hybrid_primary_hits,
            "hybrid_primary_or_secondary_correct": old_hybrid_hits,
        },
    }


def format_evaluation_report(df: pd.DataFrame, report_path: Path) -> str:
    reports = list(iter_jsonl(report_path))
    total = len(reports)
    errors = sum(1 for item in reports if item.get("fallback", False))

    predicted_distribution: Counter[str] = Counter()
    expected_distribution: Counter[str] = Counter()
    severity_distribution: Counter[str] = Counter()
    priority_distribution: Counter[str] = Counter()
    baseline_confidences: List[float] = []
    llm_confidences: List[float] = []

    compared = 0
    baseline_correct = 0
    hybrid_primary_correct = 0
    hybrid_broad_correct = 0
    unknown_predictions = 0
    review_decisions: Counter[str] = Counter()
    revision_blocked = 0

    for item in reports:
        row_index = item["row_index"]
        results = item.get("results", {})
        expected = old_expected_primary_category(df.loc[row_index, "output"])
        expected_distribution[expected] += 1

        if "classification_result" not in results:
            continue

        classification = results["classification_result"]
        baseline = results["baseline"]["classification_result"]
        severity = results["severity"]
        mitigation = results["mitigation"]

        primary = to_old_category(classification["threat_type"])
        secondary = to_old_categories(classification.get("secondary_threat_types", []))
        baseline_type = to_old_category(baseline["threat_type"])

        predicted_distribution[primary] += 1
        severity_distribution[str(severity["severity"])] += 1
        priority_distribution[str(mitigation["priority"])] += 1
        review_decisions[str(classification.get("review_decision", "Unknown"))] += 1
        revision_blocked += int("revision blocked" in classification.get("guardrail_errors", []))

        if primary == "Unknown":
            unknown_predictions += 1

        if isinstance(baseline.get("confidence"), (int, float)):
            baseline_confidences.append(float(baseline["confidence"]))
        if isinstance(classification.get("llm_confidence"), (int, float)):
            llm_confidences.append(float(classification["llm_confidence"]))

        if expected != "Unknown":
            compared += 1
            baseline_correct += int(baseline_type == expected)
            hybrid_primary_correct += int(primary == expected)
            hybrid_broad_correct += int(expected in ({primary} | secondary))

    lines = [
        "Evaluation Results",
        "",
        f"Total entries processed: {total}",
        f"Errors: {errors}",
        "Model: all-MiniLM-L6-v2 baseline + local vLLM qwen3.6-27b-awq reviewer",
        "Confidence threshold: 0.4",
        "",
        "--- Threat Classification Distribution ---",
        *format_distribution(predicted_distribution, total),
        "",
        "--- Expected Distribution (normalised from dataset) ---",
        *format_distribution(expected_distribution, total),
        "",
        "--- Baseline Confidence Scores ---",
        *format_scores(baseline_confidences),
        "",
        "--- LLM Review Confidence Scores ---",
        *format_scores(llm_confidences),
        "",
        "--- Severity Distribution ---",
        *format_distribution(severity_distribution, total),
        "",
        "--- Priority Distribution ---",
        *format_distribution(priority_distribution, total),
        "",
        "--- Review Decisions ---",
        *format_distribution(review_decisions, total),
        f"Revision blocked by guardrail: {revision_blocked} ({percent(revision_blocked, total)})",
        "",
        "--- Classification Accuracy (old-compatible evaluation) ---",
        f"Compared: {compared} entries ({total - compared} excluded as Unknown in expected)",
        f"Baseline correct: {baseline_correct}",
        f"Baseline accuracy: {percent(baseline_correct, compared)}",
        f"Hybrid primary correct: {hybrid_primary_correct}",
        f"Hybrid primary accuracy: {percent(hybrid_primary_correct, compared)}",
        f"Hybrid primary/secondary correct: {hybrid_broad_correct}",
        f"Hybrid primary/secondary accuracy: {percent(hybrid_broad_correct, compared)}",
        f"Unknown classifications: {unknown_predictions} ({percent(unknown_predictions, total)})",
    ]
    return "\n".join(lines)


def write_evaluation_artifacts(report_text: str, output_dir: Path) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    text_path = output_dir / "evaluation_report.txt"
    html_path = output_dir / "evaluation_report.html"
    text_path.write_text(report_text + "\n", encoding="utf-8")
    html_path.write_text(render_evaluation_html(report_text), encoding="utf-8")
    return {
        "text": str(text_path),
        "html": str(html_path),
    }


def render_evaluation_html(report_text: str) -> str:
    escaped = html.escape(report_text)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Hybrid Threat Intelligence Evaluation</title>
  <style>
    body {{
      margin: 0;
      padding: 28px;
      background: #f4f4f4;
      color: #d7e8c5;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    pre {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 24px 28px;
      background: #242424;
      border: 1px solid #333;
      line-height: 1.55;
      font-size: 15px;
      white-space: pre-wrap;
    }}
  </style>
</head>
<body>
<pre>{escaped}</pre>
</body>
</html>
"""


def format_distribution(counter: Counter[str], total: int) -> List[str]:
    if not counter:
        return ["  None"]
    width = max(len(label) for label in counter)
    return [
        f"  {label + ':':<{width + 2}} {count:>5} ({percent(count, total)})"
        for label, count in counter.most_common()
    ]


def format_scores(scores: List[float]) -> List[str]:
    if not scores:
        return ["  Mean: n/a", "  Min:  n/a", "  Max:  n/a"]
    return [
        f"  Mean: {sum(scores) / len(scores):.3f}",
        f"  Min:  {min(scores):.3f}",
        f"  Max:  {max(scores):.3f}",
    ]


def percent(count: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{(count / total) * 100:.1f}%"


def baseline_item(index: int, row: pd.Series, workflow: HybridThreatWorkflow) -> Dict[str, Any]:
    cve_text = row["input"]
    baseline_classification = workflow.threat_agent.classify(cve_text)
    baseline_severity = workflow.severity_agent.severity_score(cve_text, baseline_classification)
    baseline_mitigation = workflow.mitigation_agent.recommend(
        cve_text,
        baseline_classification,
        baseline_severity,
    )
    expected = expected_categories(row["output"])
    old_expected = old_expected_categories(row["output"])
    old_baseline_type = to_old_category(baseline_classification["threat_type"])

    return {
        "row_index": int(index),
        "input": cve_text,
        "output": row["output"],
        "expected_categories": sorted(expected),
        "old_expected_categories": sorted(old_expected),
        "baseline": {
            "classification_result": baseline_classification,
            "severity": baseline_severity,
            "mitigation": baseline_mitigation,
        },
        "baseline_correct": baseline_classification["threat_type"] in expected,
        "old_baseline_correct": old_baseline_type in old_expected,
    }


def pilot_item(item: Dict[str, Any], workflow: HybridThreatWorkflow) -> Dict[str, Any]:
    cve_text = item["input"]
    baseline = item["baseline"]
    fallback = False
    try:
        review = workflow._review_with_llm(
            cve_text,
            baseline["classification_result"],
            baseline["severity"],
            baseline["mitigation"],
        )
        validated = workflow._validate_review(
            cve_text,
            baseline["classification_result"],
            baseline["mitigation"],
            review,
        )
    except Exception as exc:
        fallback = True
        review = {"error": f"{type(exc).__name__}: {exc}"}
        validated = {
            "decision": "fallback_error",
            "threat_type": baseline["classification_result"]["threat_type"],
            "secondary_threat_types": [],
            "llm_confidence": None,
            "reasoning": "",
            "recommended_actions": baseline["mitigation"]["recommended_action"],
            "guardrail_errors": [type(exc).__name__],
        }

    expected = set(item["expected_categories"])
    hybrid_labels = {validated["threat_type"], *validated["secondary_threat_types"]}
    old_expected = set(item["old_expected_categories"])
    old_baseline_type = to_old_category(baseline["classification_result"]["threat_type"])
    old_hybrid_primary = to_old_category(validated["threat_type"])
    old_hybrid_secondary = {
        to_old_category(threat_type) for threat_type in validated["secondary_threat_types"]
    }
    comparison = {
        "row_index": item["row_index"],
        "expected_categories": item["expected_categories"],
        "old_expected_categories": item["old_expected_categories"],
        "baseline_type": baseline["classification_result"]["threat_type"],
        "baseline_confidence": baseline["classification_result"]["confidence"],
        "baseline_correct": item["baseline_correct"],
        "old_baseline_type": old_baseline_type,
        "old_baseline_correct": item["old_baseline_correct"],
        "hybrid_type": validated["threat_type"],
        "hybrid_secondary_types": validated["secondary_threat_types"],
        "hybrid_llm_confidence": validated["llm_confidence"],
        "hybrid_primary_correct": validated["threat_type"] in expected,
        "hybrid_correct": bool(hybrid_labels & expected),
        "old_hybrid_type": old_hybrid_primary,
        "old_hybrid_secondary_types": sorted(old_hybrid_secondary - {"Unknown"}),
        "old_hybrid_primary_correct": old_hybrid_primary in old_expected,
        "old_hybrid_correct": bool(({old_hybrid_primary} | old_hybrid_secondary) & old_expected),
        "review_decision": validated["decision"],
        "guardrail_errors": validated["guardrail_errors"],
        "fallback": fallback,
        "llm_review": review,
    }
    comparison["fixed_by_hybrid"] = not comparison["baseline_correct"] and comparison["hybrid_correct"]
    comparison["regressed_by_hybrid"] = comparison["baseline_correct"] and not comparison["hybrid_correct"]
    comparison["old_fixed_by_hybrid"] = (
        not comparison["old_baseline_correct"] and comparison["old_hybrid_correct"]
    )
    comparison["old_regressed_by_hybrid"] = (
        comparison["old_baseline_correct"] and not comparison["old_hybrid_correct"]
    )
    return comparison


def batch_item(item: tuple[int, pd.Series], workflow: HybridThreatWorkflow) -> Dict[str, Any]:
    index, row = item
    cve_text = row["input"]
    fallback = False
    try:
        results = workflow.analyse(cve_text)
        report = format_hybrid_report(results)
    except Exception as exc:
        fallback = True
        report = original_report(cve_text)
        results = {"error": f"{type(exc).__name__}: {exc}"}

    return {
        "row_index": int(index),
        "cve_id": extract_cve_id(cve_text),
        "fallback": fallback,
        "results": results,
        "report": report,
    }


def summarize_pilot(
    comparisons: List[Dict[str, Any]],
    workers: int,
    baseline_seconds: float,
    llm_seconds: float,
    total_seconds: float,
) -> Dict[str, Any]:
    total = len(comparisons)
    baseline_hits = sum(item["baseline_correct"] for item in comparisons)
    hybrid_hits = sum(item["hybrid_correct"] for item in comparisons)
    hybrid_primary_hits = sum(item["hybrid_primary_correct"] for item in comparisons)
    old_baseline_hits = sum(item["old_baseline_correct"] for item in comparisons)
    old_hybrid_hits = sum(item["old_hybrid_correct"] for item in comparisons)
    old_hybrid_primary_hits = sum(item["old_hybrid_primary_correct"] for item in comparisons)
    return {
        "records": total,
        "workers": workers,
        "baseline_accuracy": round(baseline_hits / total, 4) if total else 0.0,
        "hybrid_accuracy": round(hybrid_hits / total, 4) if total else 0.0,
        "hybrid_primary_accuracy": round(hybrid_primary_hits / total, 4) if total else 0.0,
        "old_eval_baseline_accuracy": round(old_baseline_hits / total, 4) if total else 0.0,
        "old_eval_hybrid_accuracy": round(old_hybrid_hits / total, 4) if total else 0.0,
        "old_eval_hybrid_primary_accuracy": round(old_hybrid_primary_hits / total, 4) if total else 0.0,
        "baseline_correct": baseline_hits,
        "hybrid_correct": hybrid_hits,
        "hybrid_primary_correct": hybrid_primary_hits,
        "old_eval_baseline_correct": old_baseline_hits,
        "old_eval_hybrid_correct": old_hybrid_hits,
        "old_eval_hybrid_primary_correct": old_hybrid_primary_hits,
        "fixed_by_hybrid": sum(item["fixed_by_hybrid"] for item in comparisons),
        "regressions": sum(item["regressed_by_hybrid"] for item in comparisons),
        "old_eval_fixed_by_hybrid": sum(item["old_fixed_by_hybrid"] for item in comparisons),
        "old_eval_regressions": sum(item["old_regressed_by_hybrid"] for item in comparisons),
        "accepted_revisions": sum(item["review_decision"] == "revise_baseline" for item in comparisons),
        "blocked_revisions": sum("revision blocked" in item["guardrail_errors"] for item in comparisons),
        "fallbacks": sum(item["fallback"] for item in comparisons),
        "baseline_seconds": round(baseline_seconds, 2),
        "llm_seconds": round(llm_seconds, 2),
        "total_seconds": round(total_seconds, 2),
    }


def write_pilot_outputs(
    comparisons: List[Dict[str, Any]],
    summary: Dict[str, Any],
    output_dir: Path,
    limit: int,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    comparison_path = output_dir / f"pilot_comparison_{limit}.jsonl"
    summary_path = output_dir / f"pilot_summary_{limit}.json"

    with comparison_path.open("w", encoding="utf-8") as file:
        for item in comparisons:
            file.write(json.dumps(item) + "\n")

    with summary_path.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)
        file.write("\n")


def expected_categories(output: str) -> Set[str]:
    match = re.search(r"Vulnerability Type:\**\s*([^\n]+)", output, flags=re.IGNORECASE)
    text = (match.group(1) if match else output[:700]).lower()
    categories: Set[str] = set()
    for category, patterns in EXPECTED_LABEL_PATTERNS.items():
        if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns):
            categories.add(category)
    return categories or {"Unknown"}


def old_expected_categories(output: str) -> Set[str]:
    match = re.search(r"Vulnerability Type:\**\s*([^\n]+)", output, flags=re.IGNORECASE)
    text = (match.group(1) if match else output[:700]).lower()
    categories: Set[str] = set()
    for category, patterns in OLD_EXPECTED_LABEL_PATTERNS.items():
        if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns):
            categories.add(category)
    return categories or {"Unknown"}


def old_expected_primary_category(output: str) -> str:
    match = re.search(r"Vulnerability Type:\**\s*([^\n]+)", output, flags=re.IGNORECASE)
    text = (match.group(1) if match else output[:700]).lower()
    for category, patterns in OLD_EXPECTED_LABEL_PATTERNS.items():
        if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns):
            return category
    return "Unknown"


def to_old_category(threat_type: str) -> str:
    if threat_type in ORIGINAL_THREAT_TYPES:
        return threat_type
    return OLD_CATEGORY_MAP.get(threat_type, "Unknown")


def to_old_categories(threat_types: Iterable[str]) -> Set[str]:
    return {to_old_category(threat_type) for threat_type in threat_types}


def extract_cve_id(cve_text: str) -> str:
    match = re.search(r"CVE ID:\s*([A-Z0-9-]+)", cve_text)
    return match.group(1) if match else "Unknown"


def clamp_workers(requested_workers: int) -> int:
    return max(1, min(int(requested_workers), 4))


def print_summary(summary: Dict[str, Any]) -> None:
    print(json.dumps(summary, indent=2))


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                yield json.loads(line)
