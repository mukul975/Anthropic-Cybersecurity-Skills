#!/usr/bin/env python3
"""BEC detection agent - analyzes email headers and content for Business Email Compromise indicators.

Parses email headers for spoofing signals, checks DMARC/SPF/DKIM alignment,
detects urgency language patterns, and flags financial request anomalies.
"""

import argparse
import email
import json
import re
import sys
from email import policy
from pathlib import Path

BEC_URGENCY_PATTERNS = [
    r"\b(urgent|immediately|asap|right away|time.?sensitive)\b",
    r"\b(confidential|do not share|keep this between us|don't tell)\b",
    r"\b(wire transfer|bank transfer|payment|invoice|routing number)\b",
    r"\b(gift card|bitcoin|crypto|western union|moneygram)\b",
    r"\b(ceo|cfo|president|director) (asked|requested|needs|wants)\b",
    r"\b(change.*(bank|account|payment)|new.*(bank|account|routing))\b",
    r"\b(act now|deadline today|end of day|before close)\b",
]

EXECUTIVE_TITLES = ["ceo", "cfo", "coo", "cto", "president", "chairman",
                    "managing director", "vice president", "vp", "director"]


def parse_email_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return email.message_from_file(f, policy=policy.default)


def check_spf_dkim_dmarc(msg):
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    auth_results = msg.get("Authentication-Results", "")
    if "spf=pass" in auth_results.lower():
        results["spf"] = "pass"
    elif "spf=fail" in auth_results.lower():
        results["spf"] = "fail"
    if "dkim=pass" in auth_results.lower():
        results["dkim"] = "pass"
    elif "dkim=fail" in auth_results.lower():
        results["dkim"] = "fail"
    if "dmarc=pass" in auth_results.lower():
        results["dmarc"] = "pass"
    elif "dmarc=fail" in auth_results.lower():
        results["dmarc"] = "fail"
    return results


def check_display_name_spoofing(msg, vip_names):
    from_header = msg.get("From", "")
    match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
    if not match:
        return None
    display_name = match.group(1).strip().lower()
    email_addr = match.group(2).strip().lower()
    for vip in vip_names:
        if vip.lower() in display_name:
            domain = email_addr.split("@")[-1] if "@" in email_addr else ""
            return {"display_name": display_name, "email": email_addr,
                    "matched_vip": vip, "domain": domain,
                    "indicator": "Display name matches VIP but email may be external"}
    return None


def check_reply_to_mismatch(msg):
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    if not reply_to:
        return None
    from_match = re.search(r'<([^>]+)>', from_addr) or re.search(r'(\S+@\S+)', from_addr)
    reply_match = re.search(r'<([^>]+)>', reply_to) or re.search(r'(\S+@\S+)', reply_to)
    if from_match and reply_match:
        from_email = from_match.group(1).lower()
        reply_email = reply_match.group(1).lower()
        from_domain = from_email.split("@")[-1]
        reply_domain = reply_email.split("@")[-1]
        if from_domain != reply_domain:
            return {"from": from_email, "reply_to": reply_email,
                    "indicator": "Reply-To domain differs from From domain"}
    return None


def detect_urgency_language(body):
    matches = []
    for pattern in BEC_URGENCY_PATTERNS:
        found = re.findall(pattern, body, re.IGNORECASE)
        if found:
            matches.extend(found)
    return matches


def calculate_bec_score(auth, spoofing, reply_mismatch, urgency_matches):
    score = 0
    if auth.get("spf") == "fail":
        score += 25
    if auth.get("dkim") == "fail":
        score += 20
    if auth.get("dmarc") == "fail":
        score += 30
    if spoofing:
        score += 35
    if reply_mismatch:
        score += 25
    score += min(len(urgency_matches) * 10, 40)
    return min(score, 100)


def analyze_email(filepath, vip_names):
    msg = parse_email_file(filepath)
    body = msg.get_body(preferencelist=("plain", "html"))
    body_text = body.get_content() if body else ""

    auth = check_spf_dkim_dmarc(msg)
    spoofing = check_display_name_spoofing(msg, vip_names)
    reply_mismatch = check_reply_to_mismatch(msg)
    urgency = detect_urgency_language(body_text)
    score = calculate_bec_score(auth, spoofing, reply_mismatch, urgency)

    risk = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW"

    return {
        "file": str(filepath),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "authentication": auth,
        "display_name_spoofing": spoofing,
        "reply_to_mismatch": reply_mismatch,
        "urgency_indicators": urgency,
        "bec_score": score,
        "risk_level": risk,
    }


def main():
    parser = argparse.ArgumentParser(description="BEC Email Analyzer")
    parser.add_argument("--email-file", required=True, help="Path to .eml file")
    parser.add_argument("--vip-names", nargs="+", default=[], help="VIP display names to check")
    parser.add_argument("--scan-dir", help="Scan all .eml files in directory")
    args = parser.parse_args()

    results = []
    if args.scan_dir:
        for eml in Path(args.scan_dir).glob("*.eml"):
            results.append(analyze_email(str(eml), args.vip_names))
    else:
        results.append(analyze_email(args.email_file, args.vip_names))

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
