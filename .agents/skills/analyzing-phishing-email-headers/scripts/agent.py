#!/usr/bin/env python3
"""Phishing email header analysis agent.

Parses email headers to detect spoofing, authentication failures,
suspicious routing, and phishing indicators.
"""

import os
import sys
import json
import re
import email
import email.utils
from datetime import datetime
from collections import OrderedDict


def parse_email_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return email.message_from_string(f.read())


def extract_received_chain(msg):
    chain = []
    for header in msg.get_all("Received", []):
        entry = {"raw": header.strip()[:300]}
        from_match = re.search(r"from\s+([\w.-]+)", header)
        by_match = re.search(r"by\s+([\w.-]+)", header)
        ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", header)
        date_match = re.search(r";\s*(.+)$", header)
        if from_match:
            entry["from_host"] = from_match.group(1)
        if by_match:
            entry["by_host"] = by_match.group(1)
        if ip_match:
            entry["ip"] = ip_match.group(1)
        if date_match:
            entry["date"] = date_match.group(1).strip()[:60]
        chain.append(entry)
    return chain


def check_spf(msg):
    spf_headers = msg.get_all("Received-SPF", [])
    auth_results = msg.get("Authentication-Results", "")
    result = {"status": "none", "details": ""}
    for h in spf_headers:
        h_lower = h.lower()
        if "pass" in h_lower:
            result = {"status": "pass", "details": h[:200]}
        elif "fail" in h_lower or "softfail" in h_lower:
            result = {"status": "fail", "details": h[:200]}
        elif "neutral" in h_lower:
            result = {"status": "neutral", "details": h[:200]}
    if "spf=" in auth_results.lower():
        spf_match = re.search(r"spf=(\w+)", auth_results, re.IGNORECASE)
        if spf_match:
            result["auth_result_spf"] = spf_match.group(1)
    return result


def check_dkim(msg):
    auth_results = msg.get("Authentication-Results", "")
    dkim_sig = msg.get("DKIM-Signature", "")
    result = {"status": "none", "domain": ""}
    if "dkim=" in auth_results.lower():
        dkim_match = re.search(r"dkim=(\w+)", auth_results, re.IGNORECASE)
        if dkim_match:
            result["status"] = dkim_match.group(1)
    if dkim_sig:
        d_match = re.search(r"d=([\w.-]+)", dkim_sig)
        if d_match:
            result["domain"] = d_match.group(1)
    return result


def check_dmarc(msg):
    auth_results = msg.get("Authentication-Results", "")
    result = {"status": "none"}
    if "dmarc=" in auth_results.lower():
        dmarc_match = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)
        if dmarc_match:
            result["status"] = dmarc_match.group(1)
    return result


def extract_urls(msg):
    urls = set()
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="replace")
    urls.update(re.findall(r"https?://[^\s<>\"')\]]+", body))
    href_urls = re.findall(r'href=["\']([^"\']+)["\']', body)
    urls.update(u for u in href_urls if u.startswith("http"))
    return sorted(urls)


def detect_display_name_spoofing(msg):
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    findings = []
    name, addr = email.utils.parseaddr(from_header)
    if name and addr:
        if re.search(r"@", name):
            findings.append({
                "type": "email_in_display_name",
                "detail": f"Display name contains email: {name}",
            })
    if reply_to:
        _, reply_addr = email.utils.parseaddr(reply_to)
        if reply_addr and addr and reply_addr.lower() != addr.lower():
            findings.append({
                "type": "reply_to_mismatch",
                "detail": f"From: {addr} vs Reply-To: {reply_addr}",
            })
    return findings


def detect_phishing_indicators(msg, urls):
    indicators = []
    subject = msg.get("Subject", "").lower()
    urgency = ["urgent", "immediate", "action required", "suspended",
               "verify", "expires today", "click here", "limited time"]
    for word in urgency:
        if word in subject:
            indicators.append({
                "type": "urgency_subject", "keyword": word, "severity": "MEDIUM",
            })
            break
    for url in urls:
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
            indicators.append({
                "type": "ip_url", "url": url[:100], "severity": "HIGH",
            })
        if len(url) > 200:
            indicators.append({
                "type": "long_url", "url_length": len(url), "severity": "MEDIUM",
            })
    x_mailer = msg.get("X-Mailer", "")
    if x_mailer and any(s in x_mailer.lower() for s in ["phpmailer", "swiftmailer"]):
        indicators.append({
            "type": "suspicious_mailer", "mailer": x_mailer, "severity": "MEDIUM",
        })
    return indicators


def generate_report(filepath, msg):
    received = extract_received_chain(msg)
    spf = check_spf(msg)
    dkim = check_dkim(msg)
    dmarc = check_dmarc(msg)
    urls = extract_urls(msg)
    spoofing = detect_display_name_spoofing(msg)
    phishing = detect_phishing_indicators(msg, urls)
    return {
        "file": filepath,
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_hops": len(received),
        "received_chain": received,
        "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "urls_found": len(urls),
        "urls": urls[:20],
        "spoofing_indicators": spoofing,
        "phishing_indicators": phishing,
        "verdict": "SUSPICIOUS" if (phishing or spoofing or
                   spf.get("status") == "fail") else "CLEAN",
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Phishing Email Header Analysis Agent")
    print("SPF/DKIM/DMARC, spoofing detection, URL extraction")
    print("=" * 60)

    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target or not os.path.exists(target):
        print("\n[DEMO] Usage: python agent.py <email.eml>")
        sys.exit(0)

    msg = parse_email_file(target)
    report = generate_report(target, msg)

    print(f"\n[*] Subject: {report['subject']}")
    print(f"[*] From: {report['from']}")
    print(f"[*] Date: {report['date']}")
    print(f"[*] Received hops: {report['received_hops']}")

    auth = report["authentication"]
    print(f"\n--- Authentication ---")
    print(f"  SPF:   {auth['spf']['status']}")
    print(f"  DKIM:  {auth['dkim']['status']}")
    print(f"  DMARC: {auth['dmarc']['status']}")

    print(f"\n--- URLs ({report['urls_found']}) ---")
    for u in report["urls"][:5]:
        print(f"  {u[:80]}")

    print(f"\n--- Indicators ---")
    for i in report["phishing_indicators"] + report["spoofing_indicators"]:
        print(f"  [{i.get('severity','INFO')}] {i['type']}: {i.get('detail', i.get('keyword', ''))}")

    print(f"\n[*] Verdict: {report['verdict']}")
