#!/usr/bin/env python3
"""Phishing Incident Response Agent - Analyzes phishing emails and automates response actions."""

import json
import re
import email
import hashlib
import logging
import argparse
from email import policy
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def parse_email_file(eml_path):
    """Parse an EML file and extract header and body information."""
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    parsed = {
        "subject": msg["Subject"],
        "from": msg["From"],
        "to": msg["To"],
        "date": msg["Date"],
        "message_id": msg["Message-ID"],
        "return_path": msg["Return-Path"],
        "reply_to": msg["Reply-To"],
        "received_headers": msg.get_all("Received", []),
        "authentication_results": msg.get("Authentication-Results", ""),
        "spf": "",
        "dkim": "",
        "dmarc": "",
    }
    auth_results = parsed["authentication_results"]
    if "spf=pass" in auth_results:
        parsed["spf"] = "pass"
    elif "spf=fail" in auth_results:
        parsed["spf"] = "fail"
    if "dkim=pass" in auth_results:
        parsed["dkim"] = "pass"
    elif "dkim=fail" in auth_results:
        parsed["dkim"] = "fail"
    if "dmarc=pass" in auth_results:
        parsed["dmarc"] = "pass"
    elif "dmarc=fail" in auth_results:
        parsed["dmarc"] = "fail"

    logger.info("Parsed email: Subject='%s' From='%s'", parsed["subject"], parsed["from"])
    return parsed, msg


def extract_urls(msg):
    """Extract all URLs from email body."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                body += part.get_content()
    else:
        body = msg.get_content()
    urls = re.findall(r'https?://[^\s"\'<>]+', body)
    unique_urls = list(set(urls))
    logger.info("Extracted %d unique URLs", len(unique_urls))
    return unique_urls


def extract_attachments(msg):
    """Extract and hash email attachments."""
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            content = part.get_payload(decode=True)
            if content:
                sha256 = hashlib.sha256(content).hexdigest()
                md5 = hashlib.md5(content).hexdigest()
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size": len(content),
                    "sha256": sha256,
                    "md5": md5,
                })
                logger.info("Attachment: %s (SHA256: %s)", filename, sha256[:16])
    return attachments


def check_url_virustotal(url, api_key):
    """Check URL reputation on VirusTotal."""
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    resp = requests.get(vt_url, headers=headers, timeout=30)
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    return {"url": url, "error": resp.status_code}


def check_url_urlscan(url):
    """Submit URL to urlscan.io for analysis."""
    resp = requests.post(
        "https://urlscan.io/api/v1/scan/",
        json={"url": url, "visibility": "private"},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 200:
        return resp.json()
    return {"url": url, "error": resp.status_code}


def check_hash_virustotal(file_hash, api_key):
    """Check file hash reputation on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        return {
            "hash": file_hash,
            "malicious": attrs["last_analysis_stats"].get("malicious", 0),
            "threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
        }
    return {"hash": file_hash, "status": "not_found"}


def assess_phishing_severity(parsed_email, url_results, attachment_results):
    """Assess overall severity of the phishing email."""
    severity = "Low"
    indicators = []
    if parsed_email.get("spf") == "fail":
        indicators.append("SPF failed")
        severity = "Medium"
    if parsed_email.get("dkim") == "fail":
        indicators.append("DKIM failed")
        severity = "Medium"
    if parsed_email.get("dmarc") == "fail":
        indicators.append("DMARC failed")
        severity = "Medium"
    for url_result in url_results:
        if url_result.get("malicious", 0) > 0:
            indicators.append(f"Malicious URL: {url_result['url'][:50]}")
            severity = "Critical"
    for att_result in attachment_results:
        if att_result.get("malicious", 0) > 0:
            indicators.append(f"Malicious attachment: {att_result['hash'][:16]}")
            severity = "Critical"
    return {"severity": severity, "indicators": indicators}


def generate_phishing_report(parsed_email, urls, attachments, url_results, att_results, assessment):
    """Generate phishing incident response report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "email_headers": parsed_email,
        "urls_found": urls,
        "attachments": attachments,
        "url_analysis": url_results,
        "attachment_analysis": att_results,
        "severity_assessment": assessment,
    }
    print(f"PHISHING IR REPORT - Severity: {assessment['severity']}")
    print(f"URLs: {len(urls)}, Attachments: {len(attachments)}, Indicators: {len(assessment['indicators'])}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Phishing Incident Response Agent")
    parser.add_argument("--eml", required=True, help="Path to EML file")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--output", default="phishing_ir_report.json")
    args = parser.parse_args()

    parsed, msg = parse_email_file(args.eml)
    urls = extract_urls(msg)
    attachments = extract_attachments(msg)

    url_results = []
    if args.vt_key:
        for url in urls[:10]:
            url_results.append(check_url_virustotal(url, args.vt_key))

    att_results = []
    if args.vt_key:
        for att in attachments:
            att_results.append(check_hash_virustotal(att["sha256"], args.vt_key))

    assessment = assess_phishing_severity(parsed, url_results, att_results)
    report = generate_phishing_report(parsed, urls, attachments, url_results, att_results, assessment)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
