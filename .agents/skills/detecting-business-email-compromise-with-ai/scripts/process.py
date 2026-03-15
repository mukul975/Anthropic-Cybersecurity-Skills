#!/usr/bin/env python3
"""
AI-Powered BEC Detection Engine

Combines NLP analysis, behavioral scoring, and impersonation
detection to identify Business Email Compromise attacks.

Usage:
    python process.py detect --email-json email.json --baseline-file baselines.json
    python process.py train-baseline --email-log emails.json --output baselines.json
"""

import argparse
import json
import re
import sys
import math
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter


@dataclass
class BECAIResult:
    """AI-powered BEC detection result."""
    from_address: str = ""
    subject: str = ""
    impostor_score: float = 0.0
    nlp_score: float = 0.0
    behavioral_score: float = 0.0
    intent_class: str = ""
    overall_score: float = 0.0
    is_bec: bool = False
    confidence: float = 0.0
    action: str = ""
    indicators: list = field(default_factory=list)


# NLP feature patterns
URGENCY_PATTERNS = [
    (r'\burgent(ly)?\b', 3), (r'\bimmediately\b', 3), (r'\basap\b', 3),
    (r'\btime.?sensitive\b', 2), (r'\btoday\b', 1), (r'\bright\s+now\b', 2),
    (r'\bdeadline\b', 1), (r'\boverdue\b', 2), (r'\bcritical\b', 2),
]

SECRECY_PATTERNS = [
    (r'\bconfidential\b', 2), (r'\bdo\s+not\s+(share|tell|discuss)\b', 3),
    (r'\bkeep.*between\s+us\b', 3), (r'\bquietly\b', 2),
    (r'\bdon.t\s+mention\b', 2), (r'\bprivate\s+matter\b', 2),
]

FINANCIAL_PATTERNS = [
    (r'\bwire\s+transfer\b', 3), (r'\binvoice\b', 2), (r'\bpayment\b', 2),
    (r'\bbank\s+(account|details|transfer)\b', 3), (r'\bgift\s+card\b', 4),
    (r'\bbitcoin\b', 3), (r'\baccount\s+number\b', 2), (r'\bswift\b', 2),
]

AUTHORITY_PATTERNS = [
    (r'\bi\s+need\s+you\s+to\b', 2), (r'\bi.m\s+in\s+a\s+meeting\b', 3),
    (r'\bhandle\s+this\b', 2), (r'\bi\s+authorize\b', 2),
    (r'\bapproved\s+by\s+me\b', 3), (r'\bdon.t\s+call\b', 2),
]


def compute_nlp_score(text: str) -> tuple:
    """Compute NLP-based BEC score from email text."""
    text_lower = text.lower()
    scores = {"urgency": 0, "secrecy": 0, "financial": 0, "authority": 0}
    indicators = []

    for pattern, weight in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            scores["urgency"] += weight
            indicators.append(f"Urgency: {pattern}")

    for pattern, weight in SECRECY_PATTERNS:
        if re.search(pattern, text_lower):
            scores["secrecy"] += weight
            indicators.append(f"Secrecy: {pattern}")

    for pattern, weight in FINANCIAL_PATTERNS:
        if re.search(pattern, text_lower):
            scores["financial"] += weight
            indicators.append(f"Financial: {pattern}")

    for pattern, weight in AUTHORITY_PATTERNS:
        if re.search(pattern, text_lower):
            scores["authority"] += weight
            indicators.append(f"Authority: {pattern}")

    total = sum(scores.values())
    normalized = min(total / 25.0, 1.0)  # Normalize to 0-1

    # Determine intent
    intent = "unknown"
    if scores["financial"] > 3:
        intent = "payment_request"
    elif scores["authority"] > 3 and scores["urgency"] > 2:
        intent = "directive"
    elif scores["secrecy"] > 2:
        intent = "sensitive_request"

    return normalized, intent, indicators


def compute_impostor_score(email_data: dict, vip_list: list = None) -> tuple:
    """Check for sender impersonation."""
    score = 0.0
    indicators = []

    from_name = email_data.get("from_display_name", "").lower()
    from_email = email_data.get("from", "")
    reply_to = email_data.get("reply_to", "")

    from_domain = ""
    match = re.search(r'@([\w.-]+)', from_email)
    if match:
        from_domain = match.group(1).lower()

    # VIP name match from external domain
    if vip_list:
        for vip in vip_list:
            vip_name = vip.get("name", "").lower()
            vip_domain = vip.get("domain", "").lower()
            if vip_name and vip_name in from_name:
                if from_domain and vip_domain and from_domain != vip_domain:
                    score += 0.5
                    indicators.append(
                        f"Display name '{from_name}' matches VIP from external domain"
                    )

    # Reply-to mismatch
    if reply_to:
        reply_domain = ""
        match = re.search(r'@([\w.-]+)', reply_to)
        if match:
            reply_domain = match.group(1).lower()
        if reply_domain and from_domain and reply_domain != from_domain:
            score += 0.3
            indicators.append(f"Reply-to domain mismatch: {reply_domain} vs {from_domain}")

    return min(score, 1.0), indicators


def compute_behavioral_score(email_data: dict, baseline: dict) -> tuple:
    """Score behavioral anomalies against baseline."""
    score = 0.0
    indicators = []

    sender = email_data.get("from", "")
    recipient = email_data.get("to", "")
    hour = email_data.get("send_hour", -1)

    sender_baseline = baseline.get(sender, {})

    # Check if first-time sender to this recipient
    known_recipients = sender_baseline.get("recipients", [])
    if recipient and known_recipients and recipient not in known_recipients:
        score += 0.3
        indicators.append("First-time communication with this recipient")

    # Check unusual sending time
    typical_hours = sender_baseline.get("typical_hours", [])
    if hour >= 0 and typical_hours and hour not in typical_hours:
        score += 0.2
        indicators.append(f"Unusual sending hour: {hour}:00")

    # Check if request type is unusual for sender
    typical_topics = sender_baseline.get("typical_topics", [])
    subject = email_data.get("subject", "").lower()
    if typical_topics:
        financial = any(w in subject for w in ["payment", "wire", "invoice", "transfer"])
        if financial and "financial" not in typical_topics:
            score += 0.3
            indicators.append("Financial request from sender who doesn't typically discuss finances")

    return min(score, 1.0), indicators


def detect_bec_ai(email_data: dict, baseline: dict = None,
                  vip_list: list = None) -> BECAIResult:
    """Run full AI BEC detection pipeline."""
    result = BECAIResult()
    result.from_address = email_data.get("from", "")
    result.subject = email_data.get("subject", "")

    body = email_data.get("body", "")
    full_text = f"{result.subject} {body}"

    # NLP analysis
    result.nlp_score, result.intent_class, nlp_indicators = compute_nlp_score(full_text)
    result.indicators.extend(nlp_indicators)

    # Impostor detection
    result.impostor_score, imp_indicators = compute_impostor_score(email_data, vip_list or [])
    result.indicators.extend(imp_indicators)

    # Behavioral analysis
    if baseline:
        result.behavioral_score, beh_indicators = compute_behavioral_score(
            email_data, baseline
        )
        result.indicators.extend(beh_indicators)

    # Weighted aggregate score
    weights = {"nlp": 0.35, "impostor": 0.40, "behavioral": 0.25}
    result.overall_score = (
        result.nlp_score * weights["nlp"] +
        result.impostor_score * weights["impostor"] +
        result.behavioral_score * weights["behavioral"]
    )
    result.confidence = min(result.overall_score * 1.2, 1.0)

    # Classification
    if result.overall_score >= 0.7:
        result.is_bec = True
        result.action = "AUTO-QUARANTINE + SOC alert"
    elif result.overall_score >= 0.5:
        result.is_bec = True
        result.action = "WARNING BANNER + analyst queue"
    elif result.overall_score >= 0.3:
        result.action = "WARNING BANNER only"
    else:
        result.action = "DELIVER normally"

    return result


def train_baseline(emails: list) -> dict:
    """Build behavioral baselines from historical email data."""
    baselines = defaultdict(lambda: {
        "recipients": set(),
        "typical_hours": [],
        "typical_topics": set(),
        "email_count": 0,
    })

    for email in emails:
        sender = email.get("from", "")
        if not sender:
            continue

        b = baselines[sender]
        b["email_count"] += 1

        recipient = email.get("to", "")
        if recipient:
            b["recipients"].add(recipient)

        hour = email.get("send_hour", -1)
        if hour >= 0:
            b["typical_hours"].append(hour)

        subject = email.get("subject", "").lower()
        if any(w in subject for w in ["payment", "wire", "invoice"]):
            b["typical_topics"].add("financial")
        if any(w in subject for w in ["meeting", "schedule", "calendar"]):
            b["typical_topics"].add("scheduling")

    # Convert sets to lists for JSON serialization
    result = {}
    for sender, data in baselines.items():
        hours = data["typical_hours"]
        unique_hours = list(set(hours)) if hours else []
        result[sender] = {
            "recipients": list(data["recipients"]),
            "typical_hours": unique_hours,
            "typical_topics": list(data["typical_topics"]),
            "email_count": data["email_count"],
        }

    return result


def main():
    parser = argparse.ArgumentParser(description="AI-Powered BEC Detection")
    subparsers = parser.add_subparsers(dest="command")

    detect_parser = subparsers.add_parser("detect", help="Detect BEC in email")
    detect_parser.add_argument("--email-json", required=True)
    detect_parser.add_argument("--baseline-file")
    detect_parser.add_argument("--vip-file")

    train_parser = subparsers.add_parser("train-baseline", help="Train behavioral baseline")
    train_parser.add_argument("--email-log", required=True)
    train_parser.add_argument("--output", required=True)

    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "detect":
        with open(args.email_json) as f:
            email_data = json.load(f)
        baseline = {}
        if args.baseline_file:
            with open(args.baseline_file) as f:
                baseline = json.load(f)
        vip_list = []
        if args.vip_file:
            with open(args.vip_file) as f:
                vip_list = json.load(f)

        result = detect_bec_ai(email_data, baseline, vip_list)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"BEC Score: {result.overall_score:.0%}")
            print(f"Is BEC: {'YES' if result.is_bec else 'No'}")
            print(f"Intent: {result.intent_class}")
            print(f"Action: {result.action}")
            if result.indicators:
                print("Indicators:")
                for ind in result.indicators:
                    print(f"  - {ind}")

    elif args.command == "train-baseline":
        with open(args.email_log) as f:
            emails = json.load(f)
        baseline = train_baseline(emails)
        with open(args.output, 'w') as f:
            json.dump(baseline, f, indent=2)
        print(f"Baseline trained for {len(baseline)} senders")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
