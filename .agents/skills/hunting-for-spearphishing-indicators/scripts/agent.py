#!/usr/bin/env python3
"""Agent for hunting spearphishing indicators across email and endpoint logs."""

import json
import argparse
import re
from datetime import datetime
from pathlib import Path


SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".iso", ".img", ".lnk", ".dll", ".msi", ".wsf",
]

MACRO_EXTENSIONS = [".xlsm", ".docm", ".pptm", ".xlsb"]

PHISHING_URL_PATTERNS = [
    r"https?://bit\.ly/", r"https?://tinyurl\.com/",
    r"https?://[^/]*login[^/]*\.", r"https?://[^/]*signin[^/]*\.",
    r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
    r"https?://[^/]*\.top/", r"https?://[^/]*\.xyz/",
]

URGENCY_KEYWORDS = [
    "urgent", "immediate action", "account suspended", "verify your",
    "password expired", "click here immediately", "security alert",
    "unauthorized access", "confirm your identity",
]


def load_email_logs(log_path):
    """Load email logs from JSON lines file."""
    entries = []
    with open(log_path) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def check_attachment_risk(filename):
    """Assess risk of email attachment by extension."""
    lower = filename.lower()
    if any(lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        return "CRITICAL"
    if any(lower.endswith(ext) for ext in MACRO_EXTENSIONS):
        return "HIGH"
    if lower.endswith(".html") or lower.endswith(".htm"):
        return "HIGH"
    if lower.endswith(".zip") or lower.endswith(".rar") or lower.endswith(".7z"):
        return "MEDIUM"
    return "LOW"


def detect_suspicious_attachments(emails):
    """Find emails with dangerous attachment types."""
    findings = []
    for email in emails:
        attachments = email.get("attachments", [])
        for att in attachments:
            name = att if isinstance(att, str) else att.get("filename", "")
            risk = check_attachment_risk(name)
            if risk in ("CRITICAL", "HIGH"):
                findings.append({
                    "subject": email.get("subject", ""),
                    "sender": email.get("from", email.get("sender", "")),
                    "recipient": email.get("to", email.get("recipient", "")),
                    "timestamp": email.get("timestamp", email.get("date", "")),
                    "attachment": name,
                    "risk": risk,
                    "category": "suspicious_attachment",
                })
    return findings


def detect_phishing_urls(emails):
    """Detect phishing URLs in email body or links."""
    findings = []
    for email in emails:
        body = email.get("body", email.get("content", ""))
        urls = email.get("urls", [])
        text = body + " " + " ".join(urls) if urls else body
        for pattern in PHISHING_URL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for url in matches:
                findings.append({
                    "subject": email.get("subject", ""),
                    "sender": email.get("from", email.get("sender", "")),
                    "recipient": email.get("to", email.get("recipient", "")),
                    "url": url[:200],
                    "pattern": pattern,
                    "severity": "HIGH",
                    "category": "phishing_url",
                })
    return findings


def detect_urgency_lures(emails):
    """Detect social engineering urgency keywords."""
    findings = []
    for email in emails:
        subject = email.get("subject", "")
        body = email.get("body", email.get("content", ""))
        text = (subject + " " + body).lower()
        matched = [kw for kw in URGENCY_KEYWORDS if kw in text]
        if len(matched) >= 2:
            findings.append({
                "subject": email.get("subject", ""),
                "sender": email.get("from", email.get("sender", "")),
                "recipient": email.get("to", email.get("recipient", "")),
                "keywords_matched": matched,
                "severity": "MEDIUM",
                "category": "urgency_lure",
            })
    return findings


def detect_sender_spoofing(emails):
    """Detect display name vs envelope sender mismatches."""
    findings = []
    for email in emails:
        display_from = email.get("from", email.get("sender", ""))
        envelope = email.get("envelope_from", email.get("return_path", ""))
        if display_from and envelope:
            display_domain = re.search(r"@([\w.-]+)", display_from)
            envelope_domain = re.search(r"@([\w.-]+)", envelope)
            if display_domain and envelope_domain:
                if display_domain.group(1).lower() != envelope_domain.group(1).lower():
                    findings.append({
                        "display_from": display_from,
                        "envelope_from": envelope,
                        "recipient": email.get("to", email.get("recipient", "")),
                        "subject": email.get("subject", ""),
                        "severity": "HIGH",
                        "category": "sender_spoofing",
                    })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Spearphishing Indicator Hunter")
    parser.add_argument("--email-log", required=True, help="JSON lines email log")
    parser.add_argument("--output", default="spearphishing_hunt_report.json")
    parser.add_argument("--action", choices=[
        "attachments", "urls", "urgency", "spoofing", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    emails = load_email_logs(args.email_log)
    report = {"generated_at": datetime.utcnow().isoformat(), "total_emails": len(emails),
              "findings": {}}
    print(f"[+] Loaded {len(emails)} email entries")

    if args.action in ("attachments", "full_analysis"):
        f = detect_suspicious_attachments(emails)
        report["findings"]["suspicious_attachments"] = f
        print(f"[+] Suspicious attachments: {len(f)}")

    if args.action in ("urls", "full_analysis"):
        f = detect_phishing_urls(emails)
        report["findings"]["phishing_urls"] = f
        print(f"[+] Phishing URLs: {len(f)}")

    if args.action in ("urgency", "full_analysis"):
        f = detect_urgency_lures(emails)
        report["findings"]["urgency_lures"] = f
        print(f"[+] Urgency lure emails: {len(f)}")

    if args.action in ("spoofing", "full_analysis"):
        f = detect_sender_spoofing(emails)
        report["findings"]["sender_spoofing"] = f
        print(f"[+] Sender spoofing detected: {len(f)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
