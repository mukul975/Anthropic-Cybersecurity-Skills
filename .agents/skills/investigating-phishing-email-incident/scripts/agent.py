#!/usr/bin/env python3
"""
Phishing Email Investigation Agent
Analyzes reported phishing emails by parsing headers, checking URL/attachment
reputation via VirusTotal and URLScan.io, and identifying impacted recipients.
"""

import email
import email.policy
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone

import requests


VT_API_KEY = ""  # Set via environment or config
URLSCAN_API_KEY = ""  # Set via environment or config


def parse_email_headers(eml_path: str) -> dict:
    """Parse an .eml file and extract investigation-relevant headers."""
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    auth_results = msg.get("Authentication-Results", "")
    spf_match = re.search(r"spf=(\w+)", auth_results)
    dkim_match = re.search(r"dkim=(\w+)", auth_results)
    dmarc_match = re.search(r"dmarc=(\w+)", auth_results)

    received_chain = []
    for hdr in reversed(msg.get_all("Received", [])):
        received_chain.append(hdr.strip()[:200])

    return {
        "from": msg["From"],
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": msg["Subject"],
        "message_id": msg["Message-ID"],
        "date": msg["Date"],
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "spf": spf_match.group(1) if spf_match else "not found",
        "dkim": dkim_match.group(1) if dkim_match else "not found",
        "dmarc": dmarc_match.group(1) if dmarc_match else "not found",
        "received_chain": received_chain,
    }


def extract_urls_from_email(eml_path: str) -> list[str]:
    """Extract all URLs from email body."""
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")

    url_pattern = re.compile(r'https?://[^\s<>"\')\]]+')
    return list(set(url_pattern.findall(body)))


def check_url_urlscan(url: str, api_key: str) -> dict:
    """Submit URL to URLScan.io for analysis."""
    if not api_key:
        return {"error": "URLSCAN_API_KEY not set"}

    resp = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers={"API-Key": api_key, "Content-Type": "application/json"},
        json={"url": url, "visibility": "unlisted"},
        timeout=30,
    )
    if resp.status_code == 200:
        data = resp.json()
        return {"uuid": data.get("uuid", ""), "result_url": data.get("result", "")}
    return {"error": f"URLScan returned {resp.status_code}: {resp.text[:200]}"}


def check_url_virustotal(url: str, api_key: str) -> dict:
    """Check URL reputation on VirusTotal."""
    if not api_key:
        return {"error": "VT_API_KEY not set"}

    resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers={"x-apikey": api_key},
        data={"url": url},
        timeout=30,
    )
    if resp.status_code == 200:
        analysis_id = resp.json().get("data", {}).get("id", "")
        time.sleep(15)
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": api_key},
            timeout=30,
        )
        if result.status_code == 200:
            stats = result.json().get("data", {}).get("attributes", {}).get("stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0)}
    return {"error": f"VT returned {resp.status_code}"}


def hash_attachment(filepath: str) -> dict:
    """Calculate MD5 and SHA-256 hashes for an attachment."""
    with open(filepath, "rb") as f:
        content = f.read()
    return {
        "filename": filepath,
        "size_bytes": len(content),
        "md5": hashlib.md5(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def check_hash_virustotal(file_hash: str, api_key: str) -> dict:
    """Look up file hash on VirusTotal."""
    if not api_key:
        return {"error": "VT_API_KEY not set"}

    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": api_key},
        timeout=30,
    )
    if resp.status_code == 200:
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "detection_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "unknown"),
            "malicious": stats.get("malicious", 0),
            "total_engines": sum(stats.values()),
        }
    return {"error": f"Hash not found or VT error: {resp.status_code}"}


def generate_ioc_list(headers: dict, urls: list[str], attachments: list[dict]) -> dict:
    """Compile indicators of compromise from the investigation."""
    iocs = {"domains": set(), "ips": set(), "urls": urls, "hashes": []}

    for url in urls:
        domain_match = re.search(r"https?://([^/]+)", url)
        if domain_match:
            iocs["domains"].add(domain_match.group(1))

    if headers.get("x_originating_ip"):
        iocs["ips"].add(headers["x_originating_ip"].strip("[]"))

    for att in attachments:
        iocs["hashes"].append({"md5": att["md5"], "sha256": att["sha256"]})

    iocs["domains"] = sorted(iocs["domains"])
    iocs["ips"] = sorted(iocs["ips"])
    return iocs


def generate_report(headers: dict, urls: list[str], iocs: dict) -> str:
    """Generate phishing investigation report."""
    lines = [
        f"PHISHING INCIDENT REPORT",
        "=" * 50,
        f"Report Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"From: {headers['from']}",
        f"Return-Path: {headers['return_path']}",
        f"Subject: {headers['subject']}",
        f"SPF: {headers['spf']}  DKIM: {headers['dkim']}  DMARC: {headers['dmarc']}",
        "",
        f"URLs Found: {len(urls)}",
    ]
    for u in urls[:10]:
        lines.append(f"  - {u}")
    lines.extend(["", f"IOC Domains: {', '.join(iocs['domains'])}",
                   f"IOC IPs: {', '.join(iocs['ips'])}",
                   f"IOC Hashes: {len(iocs['hashes'])}"])
    return "\n".join(lines)


if __name__ == "__main__":
    import os
    VT_API_KEY = os.getenv("VT_API_KEY", VT_API_KEY)
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", URLSCAN_API_KEY)

    eml_path = sys.argv[1] if len(sys.argv) > 1 else "phishing_sample.eml"

    print(f"[*] Analyzing phishing email: {eml_path}")
    headers = parse_email_headers(eml_path)
    urls = extract_urls_from_email(eml_path)

    print(f"[*] Found {len(urls)} URLs in email body")
    for url in urls[:5]:
        if URLSCAN_API_KEY:
            result = check_url_urlscan(url, URLSCAN_API_KEY)
            print(f"  URLScan: {result}")

    iocs = generate_ioc_list(headers, urls, [])
    report = generate_report(headers, urls, iocs)
    print(report)

    output = f"phishing_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(output, "w") as f:
        json.dump({"headers": headers, "urls": urls, "iocs": iocs}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
