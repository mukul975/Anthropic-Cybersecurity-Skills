#!/usr/bin/env python3
"""Phishing Reporting Button Workflow Agent - Processes user-reported phishing emails via button integration."""

import json
import logging
import argparse
import re
import hashlib
from datetime import datetime
from email import policy
from email.parser import BytesParser

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SUSPICIOUS_PATTERNS = [
    re.compile(r"urgent|immediate action|verify your account|click here now", re.IGNORECASE),
    re.compile(r"password.*expir|account.*suspend|unusual.*activity", re.IGNORECASE),
    re.compile(r"wire transfer|bitcoin|gift card|western union", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE),
]

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def parse_reported_email(eml_path):
    """Parse a reported phishing email from .eml file."""
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    headers = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "message_id": msg.get("Message-ID", ""),
        "received": [str(h) for h in msg.get_all("Received", [])],
    }
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                body = part.get_content()
                break
            elif ct == "text/html" and not body:
                body = part.get_content()
    else:
        body = msg.get_content()
    attachments = []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            content = part.get_payload(decode=True)
            attachments.append({"filename": fn, "size": len(content) if content else 0,
                                "sha256": hashlib.sha256(content).hexdigest() if content else ""})
    logger.info("Parsed email: subject='%s', %d attachments", headers["subject"], len(attachments))
    return {"headers": headers, "body": body[:5000], "attachments": attachments}


def analyze_email(parsed):
    """Analyze reported email for phishing indicators."""
    findings = []
    score = 0
    headers = parsed["headers"]
    body = parsed.get("body", "")
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    if reply_to and reply_to != from_addr:
        findings.append({"indicator": "Reply-To mismatch", "detail": f"From: {from_addr}, Reply-To: {reply_to}", "weight": 20})
        score += 20
    auth_results = headers.get("authentication_results", "")
    if "spf=fail" in auth_results.lower() or "dkim=fail" in auth_results.lower():
        findings.append({"indicator": "Email authentication failure", "detail": auth_results[:200], "weight": 25})
        score += 25
    for pat in SUSPICIOUS_PATTERNS:
        matches = pat.findall(body)
        if matches:
            findings.append({"indicator": "Suspicious language", "detail": matches[0][:100], "weight": 10})
            score += 10
    urls = URL_PATTERN.findall(body)
    suspicious_urls = [u for u in urls if any(kw in u.lower() for kw in [".tk", ".ml", ".ga", "bit.ly",
                       "tinyurl", "redirect", "login", "verify", "secure-"])]
    if suspicious_urls:
        findings.append({"indicator": "Suspicious URLs", "detail": suspicious_urls[:5], "weight": 15})
        score += 15 * len(suspicious_urls[:3])
    for att in parsed.get("attachments", []):
        fn = att["filename"].lower()
        if any(fn.endswith(ext) for ext in [".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".hta", ".iso", ".img"]):
            findings.append({"indicator": "Dangerous attachment", "detail": att["filename"], "weight": 30})
            score += 30
    verdict = "phishing" if score >= 50 else "suspicious" if score >= 25 else "benign"
    return {"score": min(score, 100), "verdict": verdict, "findings": findings, "url_count": len(urls),
            "attachment_count": len(parsed.get("attachments", []))}


def check_urls_virustotal(urls, api_key):
    """Check extracted URLs against VirusTotal."""
    results = []
    for url in urls[:5]:
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                                headers={"x-apikey": api_key}, timeout=10)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                results.append({"url": url, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)})
        except requests.RequestException:
            results.append({"url": url, "error": "lookup_failed"})
    return results


def create_ticket(analysis, parsed, ticketing_url=None, api_key=None):
    """Create incident ticket from analysis results."""
    ticket = {
        "title": f"Phishing Report: {parsed['headers'].get('subject', 'No Subject')[:80]}",
        "severity": "high" if analysis["verdict"] == "phishing" else "medium" if analysis["verdict"] == "suspicious" else "low",
        "description": f"User-reported phishing email. Verdict: {analysis['verdict']} (score: {analysis['score']})",
        "indicators": [f["indicator"] for f in analysis["findings"]],
        "reported_from": parsed["headers"].get("to", ""),
        "suspicious_sender": parsed["headers"].get("from", ""),
    }
    if ticketing_url and api_key:
        try:
            resp = requests.post(f"{ticketing_url}/api/v2/tickets",
                                 headers={"Authorization": f"Bearer {api_key}"}, json=ticket, timeout=10)
            ticket["ticket_id"] = resp.json().get("id")
        except requests.RequestException:
            ticket["ticket_id"] = "creation_failed"
    return ticket


def generate_report(parsed, analysis, ticket):
    """Generate phishing report workflow report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "email_subject": parsed["headers"].get("subject", ""),
        "sender": parsed["headers"].get("from", ""),
        "analysis": analysis,
        "ticket": ticket,
    }
    print(f"PHISHING REPORT: {analysis['verdict'].upper()} (score={analysis['score']}), "
          f"{len(analysis['findings'])} indicators")
    return report


def main():
    parser = argparse.ArgumentParser(description="Phishing Reporting Button Workflow Agent")
    parser.add_argument("--eml-file", required=True, help="Path to reported .eml file")
    parser.add_argument("--vt-key", help="VirusTotal API key for URL checks")
    parser.add_argument("--output", default="phishing_report.json")
    args = parser.parse_args()

    parsed = parse_reported_email(args.eml_file)
    analysis = analyze_email(parsed)
    ticket = create_ticket(analysis, parsed)
    report = generate_report(parsed, analysis, ticket)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
