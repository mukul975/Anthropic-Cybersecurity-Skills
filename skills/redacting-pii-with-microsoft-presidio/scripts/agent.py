#!/usr/bin/env python3
"""Agent for automating PII auditing and redaction with Microsoft Presidio.

Orchestrates entity discovery, policy enforcement, custom recognizer registration,
and compliance artifact reporting across data assets.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


class PresidioRedactionAgent:
    """Automated agent coordinating PII identification and data de-identification."""

    def __init__(self, output_dir: str = "./presidio_audit", threshold: float = 0.6):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.threshold = threshold

        if PRESIDIO_AVAILABLE:
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()
        else:
            self.analyzer = None
            self.anonymizer = None

    def add_custom_regex_recognizer(self, entity_name: str, regex: str, score: float = 0.8,
                                    context: Optional[List[str]] = None) -> bool:
        """Register a domain-specific pattern recognizer into the active analyzer."""
        if not PRESIDIO_AVAILABLE:
            return False

        pattern = Pattern(name=f"{entity_name}_pattern", regex=regex, score=score)
        recognizer = PatternRecognizer(
            supported_entity=entity_name,
            patterns=[pattern],
            context=context or [],
            supported_language="en"
        )
        self.analyzer.registry.add_recognizer(recognizer)
        return True

    def sanitize_text(self, text: str, policy: str = "mask") -> Dict[str, Any]:
        """Audit and anonymize a single text payload."""
        now = datetime.now(timezone.utc).isoformat()

        if PRESIDIO_AVAILABLE:
            results = self.analyzer.analyze(text=text, language="en", score_threshold=self.threshold)
            operators = {}
            if policy == "mask":
                operators["DEFAULT"] = OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 4, "from_back": True})
            elif policy == "hash":
                operators["DEFAULT"] = OperatorConfig("hash", {"hash_type": "sha256"})
            elif policy == "redact":
                operators["DEFAULT"] = OperatorConfig("redact", {})
            else:
                operators["DEFAULT"] = OperatorConfig("replace", {"new_value": "[REDACTED]"})

            anonymized = self.anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
            sanitized_text = anonymized.text

            findings = [
                {
                    "entity": r.entity_type,
                    "confidence": r.score,
                    "start": r.start,
                    "end": r.end,
                    "matched": text[r.start:r.end]
                }
                for r in results
            ]
        else:
            # Fallback basic scan
            import re
            findings = []
            sanitized_text = text
            regex_map = {
                "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
                "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                "PHONE_NUMBER": re.compile(r"\b(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
            }
            for entity, pattern in regex_map.items():
                for m in pattern.finditer(text):
                    findings.append({
                        "entity": entity,
                        "confidence": 0.85,
                        "start": m.start(),
                        "end": m.end(),
                        "matched": m.group(0)
                    })
            for f in sorted(findings, key=lambda x: x["start"], reverse=True):
                s, e = f["start"], f["end"]
                sanitized_text = sanitized_text[:s] + f"[{f['entity']}]" + sanitized_text[e:]

        return {
            "timestamp": now,
            "policy": policy,
            "threshold": self.threshold,
            "findings_count": len(findings),
            "findings": findings,
            "sanitized_text": sanitized_text,
        }

    def audit_file(self, file_path: str, policy: str = "mask") -> Path:
        """Scan a file, write redacted copy, and save JSON audit record."""
        p = Path(file_path)
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()

        result = self.sanitize_text(content, policy=policy)

        # Write sanitized file
        sanitized_path = self.output_dir / f"sanitized_{p.name}"
        with open(sanitized_path, "w", encoding="utf-8") as f:
            f.write(result["sanitized_text"])

        # Write audit summary
        audit_path = self.output_dir / f"audit_{p.stem}.json"
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        return audit_path


def main():
    agent = PresidioRedactionAgent()
    demo_sample = (
        "Internal Note: Lead investigator John Doe (john.doe@security.internal) reviewed "
        "incident dossier for user account with SSN 000-12-3456."
    )
    result = agent.sanitize_text(demo_sample, policy="replace")
    print(f"[*] Findings detected: {result['findings_count']}")
    print(f"[*] Sanitized output: {result['sanitized_text']}")


if __name__ == "__main__":
    main()
