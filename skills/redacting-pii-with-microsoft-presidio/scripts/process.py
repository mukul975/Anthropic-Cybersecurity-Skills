#!/usr/bin/env python3
"""
Microsoft Presidio PII Detection and Redaction CLI Tool.

Audits files or text for sensitive personal data (PII/PHI) and applies
configurable anonymization strategies (masking, replacement, hashing, or deletion).
"""

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

# Check if presidio packages are present
try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


@dataclass
class Finding:
    entity_type: str
    start: int
    end: int
    confidence: float
    original_text: str
    replacement_text: str


@dataclass
class AuditReport:
    timestamp: str
    status: str
    engine: str
    policy: str
    threshold: float
    total_findings: int
    findings_by_type: Dict[str, int]
    findings: List[Dict[str, Any]]
    raw_length: int
    sanitized_length: int


class StandaloneFallbackEngine:
    """Fallback engine using regex patterns when presidio packages are not yet installed."""

    PATTERNS = {
        "EMAIL_ADDRESS": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), 0.95),
        "PHONE_NUMBER": (re.compile(r"\b(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?\d{3}[-. ]?\d{4}\b"), 0.85),
        "US_SSN": (re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.90),
        "CREDIT_CARD": (re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"), 0.85),
        "IP_ADDRESS": (re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"), 0.90),
    }

    def analyze(self, text: str, threshold: float = 0.6) -> List[Dict[str, Any]]:
        results = []
        for entity_type, (regex, base_score) in self.PATTERNS.items():
            if base_score < threshold:
                continue
            for match in regex.finditer(text):
                results.append({
                    "entity_type": entity_type,
                    "start": match.start(),
                    "end": match.end(),
                    "score": base_score,
                    "text": match.group(0),
                })
        return sorted(results, key=lambda x: x["start"])


def apply_transformation(val: str, policy: str, entity_type: str) -> str:
    """Transform sensitive text value according to selected policy."""
    if policy == "mask":
        if len(val) <= 4:
            return "*" * len(val)
        return val[:2] + ("*" * (len(val) - 4)) + val[-2:]
    elif policy == "hash":
        return hashlib.sha256(val.encode("utf-8")).hexdigest()[:16]
    elif policy == "redact":
        return ""
    else:  # replace
        return f"[{entity_type}]"


def run_redaction_pipeline(text: str, policy: str, threshold: float) -> tuple[str, AuditReport]:
    """Execute analysis and anonymization pipeline."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    findings: List[Finding] = []
    findings_by_type: Dict[str, int] = {}

    if PRESIDIO_AVAILABLE:
        analyzer = AnalyzerEngine()
        anonymizer = AnonymizerEngine()

        analyzer_results = analyzer.analyze(text=text, language="en", score_threshold=threshold)
        operators = {}

        if policy == "mask":
            operators["DEFAULT"] = OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 4, "from_back": True})
        elif policy == "hash":
            operators["DEFAULT"] = OperatorConfig("hash", {"hash_type": "sha256"})
        elif policy == "redact":
            operators["DEFAULT"] = OperatorConfig("redact", {})
        else:
            operators["DEFAULT"] = OperatorConfig("replace", {"new_value": "[REDACTED]"})

        anonymized = anonymizer.anonymize(text=text, analyzer_results=analyzer_results, operators=operators)
        sanitized_text = anonymized.text

        for res in analyzer_results:
            orig = text[res.start:res.end]
            rep = apply_transformation(orig, policy, res.entity_type)
            findings.append(Finding(
                entity_type=res.entity_type,
                start=res.start,
                end=res.end,
                confidence=res.score,
                original_text=orig,
                replacement_text=rep,
            ))
            findings_by_type[res.entity_type] = findings_by_type.get(res.entity_type, 0) + 1

        engine_name = "Microsoft Presidio (Engine + spaCy)"
    else:
        fallback = StandaloneFallbackEngine()
        raw_results = fallback.analyze(text, threshold=threshold)
        
        # Sort in reverse order to apply string slice substitutions safely
        sanitized_text = text
        for item in sorted(raw_results, key=lambda x: x["start"], reverse=True):
            s, e = item["start"], item["end"]
            orig = text[s:e]
            rep = apply_transformation(orig, policy, item["entity_type"])
            sanitized_text = sanitized_text[:s] + rep + sanitized_text[e:]
            findings.append(Finding(
                entity_type=item["entity_type"],
                start=s,
                end=e,
                confidence=item["score"],
                original_text=orig,
                replacement_text=rep,
            ))
            findings_by_type[item["entity_type"]] = findings_by_type.get(item["entity_type"], 0) + 1

        # Re-sort findings chronologically
        findings.sort(key=lambda x: x.start)
        engine_name = "Presidio Standalone Fallback (Regex-Pattern Engine)"

    report = AuditReport(
        timestamp=now,
        status="COMPLETED",
        engine=engine_name,
        policy=policy,
        threshold=threshold,
        total_findings=len(findings),
        findings_by_type=findings_by_type,
        findings=[asdict(f) for f in findings],
        raw_length=len(text),
        sanitized_length=len(sanitized_text),
    )

    return sanitized_text, report


def main():
    parser = argparse.ArgumentParser(description="Redact PII with Microsoft Presidio")
    parser.add_argument("--input", "-i", help="Path to input text or log file, or raw string")
    parser.add_argument("--output", "-o", help="Path to destination output file")
    parser.add_argument("--report", "-r", help="Path to output JSON audit report")
    parser.add_argument("--policy", "-p", choices=["replace", "mask", "hash", "redact"], default="mask",
                        help="Anonymization strategy (default: mask)")
    parser.add_argument("--threshold", "-t", type=float, default=0.6,
                        help="Confidence threshold 0.0 - 1.0 (default: 0.6)")
    parser.add_argument("--demo", action="store_true", help="Run with demonstration PII sample")

    args = parser.parse_args()

    if args.demo or not args.input:
        sample_text = (
            "URGENT: Customer Alice Walker (SSN: 123-45-6789) reported unauthorized charges on card "
            "4532-1234-5678-9012. Direct email: alice.walker@example.com, Phone: +1 (555) 234-5678. "
            "Connected from IP 198.51.100.24."
        )
        print("[*] Running demonstration redaction pipeline...")
        sanitized, report = run_redaction_pipeline(sample_text, policy=args.policy, threshold=args.threshold)
        print("\n--- Original Input ---")
        print(sample_text)
        print("\n--- Sanitized Output ---")
        print(sanitized)
        print("\n--- Audit Summary ---")
        print(json.dumps(asdict(report), indent=2))
        return 0

    if os.path.isfile(args.input):
        with open(args.input, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = args.input

    sanitized, report = run_redaction_pipeline(content, policy=args.policy, threshold=args.threshold)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(sanitized)
        print(f"[+] Sanitized content written to: {args.output}")
    else:
        print("\n--- Sanitized Output ---")
        print(sanitized)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2)
        print(f"[+] Audit report written to: {args.report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
