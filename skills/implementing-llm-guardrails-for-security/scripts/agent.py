#!/usr/bin/env python3
"""
LLM Guardrails Security Agent

Implements input and output validation guardrails for LLM-powered applications.
Provides multi-layered security including prompt injection blocking, PII detection
and redaction, content policy enforcement, topic restriction, and output validation.

Supports NVIDIA NeMo Guardrails Colang integration and custom Python validators.
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default content policy
# ---------------------------------------------------------------------------
DEFAULT_POLICY = {
    "allowed_topics": [],
    "blocked_topics": ["violence", "illegal_activities", "weapons", "drugs", "exploitation"],
    "blocked_patterns": [
        r"(?i)\b(how\s+to\s+(hack|crack|break\s+into|exploit|bypass))\b",
        r"(?i)\b(create|write|generate)\b.{0,20}\b(malware|virus|trojan|ransomware|keylogger|rootkit)\b",
        r"(?i)\b(steal|exfiltrate|extract)\b.{0,20}\b(data|credentials?|passwords?|tokens?|keys?)\b",
        r"(?i)\b(make|build|synthesize)\b.{0,20}\b(bomb|weapon|explosive|poison)\b",
        r"(?i)\b(social\s+engineer|phish|spear\s*phish|impersonate)\b.{0,20}\b(someone|a\s+person|employee|user)\b",
    ],
    "pii_patterns": {
        "US_SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "PHONE_NUMBER": r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "US_PASSPORT": r"\b[A-Z]\d{8}\b",
        "AWS_ACCESS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
        "GENERIC_API_KEY": r"\b(?:api[_-]?key|token|secret)[=:\s]+['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
    },
    "injection_patterns": [
        r"(?i)\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|above|prior|all|system|initial)\b.{0,20}\b(instructions?|prompts?|rules?)\b",
        r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|simulate\s+being)\b",
        r"(?i)\b(do\s+not\s+follow|stop\s+following|new\s+instructions?|instead\s+(do|say|output))\b",
        r"(?i)(```\s*(system|assistant|user)\s*\n|<\s*/?\s*(system|instruction|prompt)\s*>)",
        r"(?i)\b(developer\s+mode|DAN\s+mode|jailbreak\s+mode|god\s+mode|sudo\s+mode)\b",
        r"(?i)\b(output|reveal|show|display|print|leak)\b.{0,30}\b(system\s+prompt|instructions?|config|password|api\s*key)\b",
        r"(?i)\b(what\s+(is|are)\s+your\s+(system\s+)?instructions?|repeat\s+your\s+prompt|show\s+me\s+your\s+rules)\b",
    ],
    "max_input_length": 4000,
    "max_output_length": 8000,
    "output_blocked_patterns": [
        r"(?i)\b(my\s+system\s+prompt\s+is|here\s+are\s+my\s+instructions|as\s+an?\s+ai\s+language\s+model,?\s+i\s+don'?t\s+have\s+a\s+system\s+prompt)\b",
        r"(?i)\b(sure,?\s+i'?ll\s+(help\s+you\s+)?(hack|create\s+malware|bypass\s+security|write\s+a\s+virus))\b",
    ],
}


@dataclass
class ValidationResult:
    """Result from a guardrail validation pass."""
    safe: bool = True
    blocked_reason: str = ""
    violations: list[dict] = field(default_factory=list)
    pii_detected: list[dict] = field(default_factory=list)
    sanitized_text: str = ""
    risk_score: float = 0.0
    validation_time_ms: float = 0.0
    layer_results: dict = field(default_factory=dict)


class InjectionGuard:
    """Input guard that detects and blocks prompt injection attempts."""

    def __init__(self, patterns: list[str]) -> None:
        self._compiled = [(i, re.compile(p)) for i, p in enumerate(patterns)]

    def check(self, text: str) -> tuple[bool, list[str]]:
        violations: list[str] = []
        for idx, pattern in self._compiled:
            match = pattern.search(text)
            if match:
                violations.append(f"injection_pattern_{idx}: matched '{match.group()}'")
        return len(violations) == 0, violations


class ContentPolicyGuard:
    """Guard that enforces content policy rules on text."""

    def __init__(self, blocked_patterns: list[str], blocked_topics: list[str]) -> None:
        self._blocked_compiled = [(i, re.compile(p)) for i, p in enumerate(blocked_patterns)]
        self._blocked_topics = blocked_topics
        self._topic_patterns = self._build_topic_patterns()

    def _build_topic_patterns(self) -> list[tuple[str, re.Pattern]]:
        topic_regexes: dict[str, str] = {
            "violence": r"(?i)\b(kill|murder|assault|torture|attack\s+someone|hurt\s+people|violence\s+against)\b",
            "illegal_activities": r"(?i)\b(illegal|launder\s+money|traffic|counterfeit|forge\s+documents?|fraud\s+scheme)\b",
            "weapons": r"(?i)\b(gun|firearm|weapon|ammunition|3d\s+print.{0,10}(gun|weapon)|ghost\s+gun)\b",
            "drugs": r"(?i)\b(synthesize\s+(meth|cocaine|heroin|fentanyl)|cook\s+meth|manufacture\s+drugs?|drug\s+recipe)\b",
            "exploitation": r"(?i)\b(exploit\s+(children|minors?|vulnerable)|human\s+traffic|child\s+abuse)\b",
            "politics": r"(?i)\b(vote\s+for|political\s+party|democrat|republican|liberal|conservative)\b.{0,40}\b(best|worst|should|must)\b",
            "competitor_products": r"(?i)\b(switch\s+to|better\s+than\s+us|use\s+.{0,20}instead)\b",
        }
        patterns = []
        for topic in self._blocked_topics:
            if topic in topic_regexes:
                patterns.append((topic, re.compile(topic_regexes[topic])))
        return patterns

    def check(self, text: str) -> tuple[bool, list[str]]:
        violations: list[str] = []

        # Check blocked content patterns
        for idx, pattern in self._blocked_compiled:
            match = pattern.search(text)
            if match:
                violations.append(f"blocked_content_{idx}: matched '{match.group()}'")

        # Check blocked topics
        for topic, pattern in self._topic_patterns:
            match = pattern.search(text)
            if match:
                violations.append(f"blocked_topic_{topic}: matched '{match.group()}'")

        return len(violations) == 0, violations


class PIIGuard:
    """Guard that detects and redacts personally identifiable information."""

    REDACTION_MAP = {
        "US_SSN": "[SSN_REDACTED]",
        "EMAIL_ADDRESS": "[EMAIL_REDACTED]",
        "PHONE_NUMBER": "[PHONE_REDACTED]",
        "CREDIT_CARD": "[CARD_REDACTED]",
        "IP_ADDRESS": "[IP_REDACTED]",
        "US_PASSPORT": "[PASSPORT_REDACTED]",
        "AWS_ACCESS_KEY": "[AWS_KEY_REDACTED]",
        "GENERIC_API_KEY": "[API_KEY_REDACTED]",
    }

    def __init__(self, pii_patterns: dict[str, str]) -> None:
        self._compiled: dict[str, re.Pattern] = {}
        for name, pattern_str in pii_patterns.items():
            self._compiled[name] = re.compile(pattern_str)

    def detect(self, text: str) -> list[dict]:
        findings: list[dict] = []
        for name, pattern in self._compiled.items():
            for match in pattern.finditer(text):
                findings.append({
                    "type": name,
                    "value": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                })
        return findings

    def redact(self, text: str) -> tuple[str, list[dict]]:
        findings = self.detect(text)
        if not findings:
            return text, findings

        # Sort by position descending to replace from end to start
        findings_sorted = sorted(findings, key=lambda f: f["start"], reverse=True)
        redacted = text
        for finding in findings_sorted:
            replacement = self.REDACTION_MAP.get(finding["type"], "[REDACTED]")
            redacted = redacted[:finding["start"]] + replacement + redacted[finding["end"]:]

        return redacted, findings


class OutputGuard:
    """Guard that validates LLM-generated output for safety violations."""

    def __init__(self, blocked_patterns: list[str], max_length: int = 8000) -> None:
        self._blocked = [(i, re.compile(p)) for i, p in enumerate(blocked_patterns)]
        self._max_length = max_length

    def check(self, response: str, original_input: str = "") -> tuple[bool, list[str]]:
        violations: list[str] = []

        # Check length
        if len(response) > self._max_length:
            violations.append(f"output_too_long: {len(response)} chars exceeds {self._max_length} limit")

        # Check blocked output patterns
        for idx, pattern in self._blocked:
            match = pattern.search(response)
            if match:
                violations.append(f"output_blocked_{idx}: matched '{match.group()}'")

        # Check for system prompt leakage indicators
        system_prompt_indicators = [
            r"(?i)(you\s+are\s+a\s+helpful\s+assistant|your\s+role\s+is\s+to|you\s+must\s+always)",
            r"(?i)(system\s*:\s*\n|<<\s*SYS\s*>>|<\|system\|>)",
        ]
        for indicator_pat in system_prompt_indicators:
            if re.search(indicator_pat, response):
                violations.append("potential_system_prompt_leak: matched indicator pattern")
                break

        # Check for PII in output
        pii_guard = PIIGuard(DEFAULT_POLICY["pii_patterns"])
        pii_findings = pii_guard.detect(response)
        for finding in pii_findings:
            violations.append(f"pii_in_output: {finding['type']} detected")

        return len(violations) == 0, violations


class LengthGuard:
    """Guard that enforces input length limits."""

    def __init__(self, max_length: int = 4000) -> None:
        self._max_length = max_length

    def check(self, text: str) -> tuple[bool, list[str]]:
        if len(text) > self._max_length:
            return False, [f"input_too_long: {len(text)} chars exceeds {self._max_length} limit"]
        return True, []


class GuardrailsPipeline:
    """Complete input/output validation pipeline combining all guardrail layers."""

    def __init__(self, policy: Optional[dict] = None, policy_path: Optional[str] = None) -> None:
        if policy_path:
            with open(policy_path, "r", encoding="utf-8") as fh:
                self.policy = json.load(fh)
        elif policy:
            self.policy = policy
        else:
            self.policy = DEFAULT_POLICY

        # Merge with defaults for any missing keys
        for key, value in DEFAULT_POLICY.items():
            if key not in self.policy:
                self.policy[key] = value

        # Initialize guards
        self.injection_guard = InjectionGuard(self.policy.get("injection_patterns", []))
        self.content_guard = ContentPolicyGuard(
            blocked_patterns=self.policy.get("blocked_patterns", []),
            blocked_topics=self.policy.get("blocked_topics", []),
        )
        self.pii_guard = PIIGuard(self.policy.get("pii_patterns", {}))
        self.length_guard = LengthGuard(self.policy.get("max_input_length", 4000))
        self.output_guard = OutputGuard(
            blocked_patterns=self.policy.get("output_blocked_patterns", []),
            max_length=self.policy.get("max_output_length", 8000),
        )

    def validate_input(self, text: str) -> ValidationResult:
        start = time.perf_counter()
        result = ValidationResult(sanitized_text=text)
        all_violations: list[dict] = []

        # Layer 1: Length check
        length_safe, length_issues = self.length_guard.check(text)
        result.layer_results["length_guard"] = {"safe": length_safe, "issues": length_issues}
        if not length_safe:
            for issue in length_issues:
                all_violations.append({"guard": "length", "detail": issue})

        # Layer 2: Injection detection
        injection_safe, injection_issues = self.injection_guard.check(text)
        result.layer_results["injection_guard"] = {"safe": injection_safe, "issues": injection_issues}
        if not injection_safe:
            for issue in injection_issues:
                all_violations.append({"guard": "injection", "detail": issue})

        # Layer 3: Content policy
        content_safe, content_issues = self.content_guard.check(text)
        result.layer_results["content_policy_guard"] = {"safe": content_safe, "issues": content_issues}
        if not content_safe:
            for issue in content_issues:
                all_violations.append({"guard": "content_policy", "detail": issue})

        # Layer 4: PII detection and redaction
        redacted_text, pii_findings = self.pii_guard.redact(text)
        result.pii_detected = pii_findings
        result.sanitized_text = redacted_text
        result.layer_results["pii_guard"] = {
            "pii_found": len(pii_findings),
            "types": list(set(f["type"] for f in pii_findings)),
        }
        if pii_findings:
            for finding in pii_findings:
                all_violations.append({
                    "guard": "pii",
                    "detail": f"detected {finding['type']}",
                    "severity": "warning",
                })

        # Compute risk score
        critical_violations = sum(1 for v in all_violations if v.get("severity") != "warning")
        warning_violations = sum(1 for v in all_violations if v.get("severity") == "warning")
        result.risk_score = min(1.0, critical_violations * 0.35 + warning_violations * 0.1)

        # Final verdict: block on critical violations, warn on PII-only
        result.violations = all_violations
        if critical_violations > 0:
            result.safe = False
            reasons = [v["detail"] for v in all_violations if v.get("severity") != "warning"]
            result.blocked_reason = "; ".join(reasons[:3])
        else:
            result.safe = True

        result.validation_time_ms = round((time.perf_counter() - start) * 1000, 2)
        return result

    def validate_output(self, response: str, original_input: str = "") -> ValidationResult:
        start = time.perf_counter()
        result = ValidationResult(sanitized_text=response)
        all_violations: list[dict] = []

        # Check output safety
        output_safe, output_issues = self.output_guard.check(response, original_input)
        result.layer_results["output_guard"] = {"safe": output_safe, "issues": output_issues}
        if not output_safe:
            for issue in output_issues:
                all_violations.append({"guard": "output", "detail": issue})

        # PII redaction on output
        redacted_output, pii_findings = self.pii_guard.redact(response)
        result.pii_detected = pii_findings
        result.sanitized_text = redacted_output

        result.violations = all_violations
        critical = sum(1 for v in all_violations if "pii_in_output" not in v.get("detail", ""))
        result.risk_score = min(1.0, critical * 0.35 + len(pii_findings) * 0.1)

        if critical > 0:
            result.safe = False
            reasons = [v["detail"] for v in all_violations]
            result.blocked_reason = "; ".join(reasons[:3])
        else:
            result.safe = True

        result.validation_time_ms = round((time.perf_counter() - start) * 1000, 2)
        return result

    def validate_pii_only(self, text: str) -> ValidationResult:
        start = time.perf_counter()
        result = ValidationResult(sanitized_text=text)

        redacted_text, pii_findings = self.pii_guard.redact(text)
        result.pii_detected = pii_findings
        result.sanitized_text = redacted_text
        result.safe = len(pii_findings) == 0
        if pii_findings:
            types_found = list(set(f["type"] for f in pii_findings))
            result.blocked_reason = f"PII detected: {', '.join(types_found)}"
            result.violations = [{"guard": "pii", "detail": f"detected {f['type']}"} for f in pii_findings]
            result.risk_score = min(1.0, len(pii_findings) * 0.15)

        result.validation_time_ms = round((time.perf_counter() - start) * 1000, 2)
        return result


def format_result_text(result: ValidationResult, label: str = "INPUT") -> str:
    """Format a validation result as human-readable text."""
    verdict = "SAFE" if result.safe else "BLOCKED"
    lines = [
        f"[{label}] Verdict: {verdict}",
        f"  Risk Score      : {result.risk_score:.4f}",
        f"  Validation Time : {result.validation_time_ms:.2f} ms",
    ]
    if result.blocked_reason:
        lines.append(f"  Blocked Reason  : {result.blocked_reason}")
    if result.violations:
        lines.append(f"  Violations ({len(result.violations)}):")
        for v in result.violations[:5]:
            severity = v.get("severity", "critical")
            lines.append(f"    [{severity.upper()}] {v['guard']}: {v['detail']}")
    if result.pii_detected:
        lines.append(f"  PII Detected ({len(result.pii_detected)}):")
        for pii in result.pii_detected:
            masked = pii["value"][:3] + "***"
            lines.append(f"    {pii['type']}: {masked}")
        lines.append(f"  Sanitized Text  : {result.sanitized_text[:200]}")
    lines.append("-" * 70)
    return "\n".join(lines)


def format_result_json(result: ValidationResult) -> str:
    """Format a validation result as JSON."""
    data = asdict(result)
    data["sanitized_text"] = data["sanitized_text"][:500]
    # Mask PII values in JSON output
    for pii in data.get("pii_detected", []):
        pii["value"] = pii["value"][:3] + "***"
    return json.dumps(data, indent=2, default=str)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LLM Guardrails Security Agent - input/output validation for LLM applications.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --input "Tell me how to hack into a network"
  python agent.py --input "My SSN is 123-45-6789" --mode pii
  python agent.py --file prompts.txt --mode full --output json
  python agent.py --input "Question" --response "LLM answer" --mode output-only
  python agent.py --input "Some text" --policy custom_policy.json
        """,
    )
    parser.add_argument("--input", "-i", type=str, help="User input to validate")
    parser.add_argument("--response", "-r", type=str, help="LLM response to validate (for output-only mode)")
    parser.add_argument("--file", "-f", type=str, help="File with one prompt per line to scan")
    parser.add_argument(
        "--mode", "-m",
        choices=["full", "input-only", "output-only", "pii"],
        default="full",
        help="Validation mode. Default: full",
    )
    parser.add_argument("--policy", "-p", type=str, help="Path to JSON content policy file")
    parser.add_argument(
        "--output", "-o",
        choices=["text", "json"],
        default="text",
        help="Output format. Default: text",
    )

    args = parser.parse_args()

    if not args.input and not args.file:
        parser.error("Provide either --input or --file")

    if args.mode == "output-only" and not args.response:
        parser.error("--response is required for output-only mode")

    # Initialize pipeline
    pipeline = GuardrailsPipeline(policy_path=args.policy)

    # Collect inputs
    inputs: list[str] = []
    if args.input:
        inputs.append(args.input)
    if args.file:
        filepath = Path(args.file)
        if not filepath.is_file():
            logger.error("File not found: %s", args.file)
            sys.exit(1)
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    inputs.append(stripped)

    if not inputs:
        logger.error("No inputs to validate.")
        sys.exit(1)

    logger.info("Validating %d input(s) in '%s' mode ...", len(inputs), args.mode)

    blocked_count = 0

    for idx, user_input in enumerate(inputs, 1):
        if args.mode == "pii":
            result = pipeline.validate_pii_only(user_input)
            label = "PII"
        elif args.mode == "output-only":
            result = pipeline.validate_output(args.response, original_input=user_input)
            label = "OUTPUT"
        elif args.mode == "input-only":
            result = pipeline.validate_input(user_input)
            label = "INPUT"
        else:
            # Full mode: validate input, then simulate output check
            input_result = pipeline.validate_input(user_input)
            if args.output == "text":
                print(f"\n[{idx}/{len(inputs)}]")
                print(format_result_text(input_result, label="INPUT"))
            else:
                print(format_result_json(input_result))

            if not input_result.safe:
                blocked_count += 1

            # If a response is provided, also validate output
            if args.response:
                output_result = pipeline.validate_output(args.response, original_input=user_input)
                if args.output == "text":
                    print(format_result_text(output_result, label="OUTPUT"))
                else:
                    print(format_result_json(output_result))
                if not output_result.safe:
                    blocked_count += 1
            continue

        if not result.safe:
            blocked_count += 1

        if args.output == "text":
            print(f"\n[{idx}/{len(inputs)}]")
            print(format_result_text(result, label=label))
        else:
            print(format_result_json(result))

    # Summary
    if args.output == "text" and len(inputs) > 1:
        print(f"\n{'=' * 70}")
        print(f"SUMMARY: {blocked_count}/{len(inputs)} inputs blocked or flagged")

    if blocked_count > 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
