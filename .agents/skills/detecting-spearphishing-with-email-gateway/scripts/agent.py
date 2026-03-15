#!/usr/bin/env python3
"""Agent for detecting spearphishing emails using email gateway log analysis."""

import argparse
import email
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from email import policy


EXECUTIVE_TITLES = [
    "ceo", "cfo", "cto", "cio", "coo", "president", "director",
    "vp", "vice president", "managing director", "partner",
]
URGENCY_KEYWORDS = [
    "urgent", "immediate", "asap", "right away", "time sensitive",
    "confidential", "do not share", "wire transfer", "bank account",
    "update payment", "invoice attached", "past due",
]
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".lnk", ".iso", ".img", ".dll", ".msi",
}


def parse_email_headers(eml_path):
    """Extract security-relevant headers from an email."""
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    headers = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "received_spf": msg.get("Received-SPF", ""),
        "dkim_signature": msg.get("DKIM-Signature", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "message_id": msg.get("Message-ID", ""),
    }
    return headers, msg


def check_authentication(headers):
    """Verify SPF, DKIM, DMARC authentication results."""
    issues = []
    auth_results = headers.get("authentication_results", "").lower()
    if "spf=fail" in auth_results or "spf=softfail" in auth_results:
        issues.append("SPF validation failed")
    if "dkim=fail" in auth_results:
        issues.append("DKIM validation failed")
    if "dmarc=fail" in auth_results:
        issues.append("DMARC validation failed")
    if not headers.get("dkim_signature"):
        issues.append("No DKIM signature present")
    from_domain = re.search(r"@([\w.-]+)", headers.get("from", ""))
    reply_domain = re.search(r"@([\w.-]+)", headers.get("reply_to", ""))
    if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
        issues.append(f"Reply-To domain mismatch: {reply_domain.group(1)} vs {from_domain.group(1)}")
    return issues


def check_content_indicators(msg):
    """Analyze email body for spearphishing content indicators."""
    indicators = []
    body = ""
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)
            if payload:
                body += payload.decode("utf-8", errors="replace")

    body_lower = body.lower()
    for kw in URGENCY_KEYWORDS:
        if kw in body_lower:
            indicators.append(f"Urgency keyword: '{kw}'")

    urls = re.findall(r'https?://[^\s<>"\']+', body)
    for url in urls[:10]:
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            indicators.append(f"URL with IP address: {url[:80]}")
        if len(url) > 100:
            indicators.append(f"Unusually long URL: {url[:80]}...")

    attachments = []
    for part in msg.walk():
        fname = part.get_filename()
        if fname:
            ext = os.path.splitext(fname)[1].lower()
            attachments.append(fname)
            if ext in SUSPICIOUS_EXTENSIONS:
                indicators.append(f"Suspicious attachment: {fname}")
            if ".." in fname or ext == ".exe.pdf":
                indicators.append(f"Double extension: {fname}")

    return indicators, attachments


def analyze_email(eml_path):
    """Full spearphishing analysis of a single email."""
    headers, msg = parse_email_headers(eml_path)
    auth_issues = check_authentication(headers)
    content_indicators, attachments = check_content_indicators(msg)

    all_indicators = auth_issues + content_indicators
    score = len(all_indicators) * 15
    risk = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"

    return {
        "file": eml_path,
        "from": headers["from"],
        "to": headers["to"],
        "subject": headers["subject"],
        "auth_issues": auth_issues,
        "content_indicators": content_indicators,
        "attachments": attachments,
        "risk_score": min(score, 100),
        "risk_level": risk,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect spearphishing via email gateway analysis"
    )
    parser.add_argument("input", help=".eml file or directory")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] Spearphishing Detection Agent")
    results = []

    if os.path.isdir(args.input):
        for root, _, files in os.walk(args.input):
            for f in files:
                if f.lower().endswith(".eml"):
                    results.append(analyze_email(os.path.join(root, f)))
    else:
        results.append(analyze_email(args.input))

    flagged = [r for r in results if r["risk_level"] in ("HIGH", "CRITICAL")]
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "emails_scanned": len(results),
        "spearphishing_detected": len(flagged),
        "results": results,
    }

    print(f"[*] Scanned {len(results)} emails, {len(flagged)} flagged")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
