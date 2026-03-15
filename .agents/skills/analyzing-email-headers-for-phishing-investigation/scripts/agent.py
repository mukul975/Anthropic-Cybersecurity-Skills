#!/usr/bin/env python3
"""Email header analysis agent for phishing investigation and sender verification."""

import email
import email.utils
import re
import hashlib
import os
import sys
import subprocess
import json
from email import policy


def parse_email_file(eml_path):
    """Parse an EML file and extract key header fields."""
    with open(eml_path, "r", errors="replace") as f:
        msg = email.message_from_file(f, policy=policy.default)
    headers = {
        "from": str(msg["From"] or ""),
        "to": str(msg["To"] or ""),
        "subject": str(msg["Subject"] or ""),
        "date": str(msg["Date"] or ""),
        "message_id": str(msg["Message-ID"] or ""),
        "reply_to": str(msg["Reply-To"] or ""),
        "return_path": str(msg["Return-Path"] or ""),
        "x_mailer": str(msg["X-Mailer"] or ""),
        "x_originating_ip": str(msg["X-Originating-IP"] or ""),
    }
    return msg, headers


def extract_received_chain(msg):
    """Extract and parse the Received header chain (bottom-up = chronological)."""
    received_headers = msg.get_all("Received") or []
    hops = []
    ip_pattern = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
    for i, header in enumerate(reversed(received_headers)):
        ips = ip_pattern.findall(header)
        hops.append({
            "hop": i + 1,
            "header": header.strip()[:200],
            "ips": ips,
        })
    return hops


def extract_authentication_results(msg):
    """Extract SPF, DKIM, and DMARC results from Authentication-Results headers."""
    auth_results = msg.get_all("Authentication-Results") or []
    received_spf = str(msg.get("Received-SPF", ""))
    dkim_sig = str(msg.get("DKIM-Signature", ""))
    results = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "raw_authentication_results": [],
        "received_spf": received_spf,
        "has_dkim_signature": bool(dkim_sig),
    }
    for ar in auth_results:
        results["raw_authentication_results"].append(ar.strip())
        ar_lower = ar.lower()
        if "spf=" in ar_lower:
            spf_match = re.search(r"spf=(\w+)", ar_lower)
            if spf_match:
                results["spf"] = spf_match.group(1)
        if "dkim=" in ar_lower:
            dkim_match = re.search(r"dkim=(\w+)", ar_lower)
            if dkim_match:
                results["dkim"] = dkim_match.group(1)
        if "dmarc=" in ar_lower:
            dmarc_match = re.search(r"dmarc=(\w+)", ar_lower)
            if dmarc_match:
                results["dmarc"] = dmarc_match.group(1)
    return results


def check_from_replyto_mismatch(headers):
    """Detect mismatch between From and Reply-To addresses."""
    from_addr = email.utils.parseaddr(headers["from"])[1].lower()
    reply_to = headers["reply_to"]
    if reply_to:
        reply_addr = email.utils.parseaddr(reply_to)[1].lower()
        if reply_addr and from_addr != reply_addr:
            return True, from_addr, reply_addr
    return False, from_addr, None


def extract_urls(msg):
    """Extract all URLs from the email body."""
    body = msg.get_body(preferencelist=("html", "plain"))
    urls = []
    if body:
        content = body.get_content()
        urls = list(set(re.findall(r"https?://[^\s<>\"']+", content)))
    return urls


def detect_url_mismatch(msg):
    """Detect hyperlinks where display text differs from actual href."""
    body = msg.get_body(preferencelist=("html",))
    mismatches = []
    if body:
        content = body.get_content()
        href_pattern = re.findall(
            r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', content, re.DOTALL
        )
        for href, text in href_pattern:
            display_urls = re.findall(r"https?://[^\s<]+", text)
            if display_urls:
                for display_url in display_urls:
                    if display_url.rstrip("/") != href.rstrip("/"):
                        mismatches.append({
                            "display_url": display_url,
                            "actual_url": href,
                        })
    return mismatches


def extract_attachments(msg, output_dir=None):
    """Extract and hash all email attachments."""
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unnamed_attachment"
            content = part.get_payload(decode=True)
            if content:
                sha256 = hashlib.sha256(content).hexdigest()
                md5 = hashlib.md5(content).hexdigest()
                att_info = {
                    "filename": filename,
                    "size": len(content),
                    "sha256": sha256,
                    "md5": md5,
                    "content_type": part.get_content_type(),
                }
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                    filepath = os.path.join(output_dir, filename)
                    with open(filepath, "wb") as f:
                        f.write(content)
                    att_info["saved_to"] = filepath
                attachments.append(att_info)
    return attachments


def dns_lookup(domain, record_type="TXT"):
    """Perform DNS lookup for SPF/DKIM/DMARC records."""
    cmd = f"dig {record_type} {domain} +short"
    stdout, _, rc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                    timeout=10).stdout, "", 0
    return stdout.strip() if stdout else ""


def check_domain_spf(domain):
    """Look up the SPF record for a domain."""
    return dns_lookup(domain, "TXT")


def check_domain_dmarc(domain):
    """Look up the DMARC record for a domain."""
    return dns_lookup(f"_dmarc.{domain}", "TXT")


def generate_phishing_indicators(headers, auth, hops, url_mismatches, attachments):
    """Compile a list of phishing indicators from the analysis."""
    indicators = []
    mismatch, from_addr, reply_addr = check_from_replyto_mismatch(headers)
    if mismatch:
        indicators.append(f"From/Reply-To mismatch: {from_addr} vs {reply_addr}")
    if auth["spf"] in ("fail", "softfail"):
        indicators.append(f"SPF {auth['spf']}")
    if auth["dkim"] == "fail" or not auth["has_dkim_signature"]:
        indicators.append("DKIM failed or missing")
    if auth["dmarc"] in ("fail", "none"):
        indicators.append(f"DMARC {auth['dmarc']}")
    if url_mismatches:
        indicators.append(f"{len(url_mismatches)} URL display/href mismatches detected")
    for att in attachments:
        if any(att["filename"].endswith(ext) for ext in [".exe", ".scr", ".vbs", ".js",
               ".docm", ".xlsm", ".bat", ".ps1", ".hta"]):
            indicators.append(f"Suspicious attachment: {att['filename']}")
    return indicators


if __name__ == "__main__":
    print("=" * 60)
    print("Email Header Phishing Analysis Agent")
    print("SPF/DKIM/DMARC validation, URL analysis, attachment extraction")
    print("=" * 60)

    eml_file = sys.argv[1] if len(sys.argv) > 1 else None

    if eml_file and os.path.exists(eml_file):
        print(f"\n[*] Analyzing: {eml_file}")
        msg, headers = parse_email_file(eml_file)
        print(f"  From:    {headers['from']}")
        print(f"  To:      {headers['to']}")
        print(f"  Subject: {headers['subject']}")
        print(f"  Date:    {headers['date']}")

        hops = extract_received_chain(msg)
        print(f"\n[*] Delivery path: {len(hops)} hops")
        for hop in hops:
            print(f"  Hop {hop['hop']}: IPs={hop['ips']}")

        auth = extract_authentication_results(msg)
        print(f"\n[*] Authentication: SPF={auth['spf']} DKIM={auth['dkim']} DMARC={auth['dmarc']}")

        urls = extract_urls(msg)
        print(f"\n[*] URLs found: {len(urls)}")
        url_mismatches = detect_url_mismatch(msg)
        for m in url_mismatches:
            print(f"  [!] MISMATCH: Display='{m['display_url']}' Actual='{m['actual_url']}'")

        attachments = extract_attachments(msg)
        print(f"\n[*] Attachments: {len(attachments)}")
        for att in attachments:
            print(f"  {att['filename']} ({att['size']} bytes) SHA256={att['sha256'][:16]}...")

        indicators = generate_phishing_indicators(headers, auth, hops, url_mismatches, attachments)
        if indicators:
            print(f"\n[!] PHISHING INDICATORS:")
            for ind in indicators:
                print(f"  - {ind}")
    else:
        print(f"\n[DEMO] Usage: python agent.py <email.eml>")
        print("[*] Provide an EML file for phishing analysis.")
