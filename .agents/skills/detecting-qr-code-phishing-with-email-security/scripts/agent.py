#!/usr/bin/env python3
"""Agent for detecting QR code phishing (quishing) in email attachments and bodies."""

import argparse
import base64
import email
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from email import policy
from urllib.parse import urlparse

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as qr_decode
    HAS_QR = True
except ImportError:
    HAS_QR = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".info", ".online", ".site", ".icu",
}

PHISHING_KEYWORDS = [
    "verify", "account", "suspended", "confirm", "urgent", "expire",
    "password", "login", "credential", "security", "update", "click",
    "immediate", "unauthorized", "invoice",
]


def extract_images_from_eml(eml_path):
    """Extract image attachments and inline images from an .eml file."""
    images = []
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type.startswith("image/"):
            payload = part.get_payload(decode=True)
            if payload:
                ext = content_type.split("/")[1].split(";")[0]
                fname = part.get_filename() or f"inline_image.{ext}"
                images.append({"filename": fname, "data": payload, "type": content_type})
    return images, msg


def decode_qr_from_bytes(image_data):
    """Decode QR codes from raw image bytes."""
    if not HAS_QR:
        return []
    import io
    img = Image.open(io.BytesIO(image_data))
    results = qr_decode(img)
    return [r.data.decode("utf-8", errors="replace") for r in results]


def analyze_url(url):
    """Score a URL for phishing risk indicators."""
    indicators = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            indicators.append(f"Suspicious TLD: {tld}")
            break

    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        indicators.append("URL uses IP address instead of domain")

    if len(domain) > 40:
        indicators.append(f"Unusually long domain: {len(domain)} chars")

    if domain.count(".") > 3:
        indicators.append(f"Many subdomains: {domain.count('.')} dots")

    if parsed.scheme == "http":
        indicators.append("Uses HTTP instead of HTTPS")

    path = parsed.path + (parsed.query or "")
    for kw in PHISHING_KEYWORDS:
        if kw in path.lower():
            indicators.append(f"Phishing keyword in URL path: '{kw}'")
            break

    return {
        "url": url,
        "domain": domain,
        "indicators": indicators,
        "risk_score": min(len(indicators) * 25, 100),
    }


def analyze_email(eml_path):
    """Full QR phishing analysis of an email file."""
    results = {
        "file": eml_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "images_found": 0,
        "qr_codes_found": 0,
        "urls_extracted": [],
        "phishing_indicators": [],
        "risk_level": "LOW",
    }

    images, msg = extract_images_from_eml(eml_path)
    results["images_found"] = len(images)
    results["subject"] = msg.get("Subject", "")
    results["from"] = msg.get("From", "")

    subject_lower = results["subject"].lower()
    for kw in PHISHING_KEYWORDS:
        if kw in subject_lower:
            results["phishing_indicators"].append(f"Phishing keyword in subject: '{kw}'")

    all_urls = []
    for img_info in images:
        decoded = decode_qr_from_bytes(img_info["data"])
        for url in decoded:
            if url.startswith(("http://", "https://")):
                analysis = analyze_url(url)
                all_urls.append(analysis)

    results["qr_codes_found"] = len(all_urls)
    results["urls_extracted"] = all_urls

    max_risk = max((u["risk_score"] for u in all_urls), default=0)
    if max_risk >= 75:
        results["risk_level"] = "CRITICAL"
    elif max_risk >= 50:
        results["risk_level"] = "HIGH"
    elif max_risk >= 25:
        results["risk_level"] = "MEDIUM"

    return results


def scan_directory(dir_path):
    """Scan a directory for .eml files and analyze each."""
    all_results = []
    for root, _, files in os.walk(dir_path):
        for fname in files:
            if fname.lower().endswith(".eml"):
                fpath = os.path.join(root, fname)
                result = analyze_email(fpath)
                all_results.append(result)
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="Detect QR code phishing (quishing) in emails"
    )
    parser.add_argument("input", help="Path to .eml file or directory of .eml files")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] QR Code Phishing Detection Agent")
    print(f"[*] QR decoding available: {HAS_QR}")

    if os.path.isdir(args.input):
        results = scan_directory(args.input)
    else:
        results = [analyze_email(args.input)]

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "files_scanned": len(results),
        "qr_phishing_detected": sum(1 for r in results if r["risk_level"] in ("HIGH", "CRITICAL")),
        "results": results,
    }

    if args.verbose:
        for r in results:
            print(f"\n  File: {r['file']}")
            print(f"  Subject: {r.get('subject', 'N/A')}")
            print(f"  Images: {r['images_found']}, QR codes: {r['qr_codes_found']}")
            print(f"  Risk: {r['risk_level']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
