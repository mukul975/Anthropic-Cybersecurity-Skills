#!/usr/bin/env python3
"""Agent for implementing and monitoring endpoint DLP controls."""

import json
import argparse
import re
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict


SENSITIVE_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Private Key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "API Key": r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
}

SENSITIVE_EXTENSIONS = [
    ".pem", ".key", ".pfx", ".p12", ".kdbx", ".env",
    ".sql", ".bak", ".dump", ".mdb",
]


def scan_file_for_sensitive_data(file_path):
    """Scan a single file for sensitive data patterns."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(1024 * 1024)
    except (OSError, PermissionError):
        return None
    matches = {}
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        found = re.findall(pattern, content)
        if found:
            matches[pattern_name] = len(found)
    ext = Path(file_path).suffix.lower()
    is_sensitive_ext = ext in SENSITIVE_EXTENSIONS
    if not matches and not is_sensitive_ext:
        return None
    return {
        "file": str(file_path),
        "matches": matches,
        "sensitive_extension": is_sensitive_ext,
        "file_size": Path(file_path).stat().st_size,
        "severity": "CRITICAL" if "Private Key" in matches or "AWS Key" in matches
                    else "HIGH" if matches else "MEDIUM",
    }


def scan_directory(dir_path, max_files=10000):
    """Scan a directory for files containing sensitive data."""
    findings = []
    count = 0
    for filepath in Path(dir_path).rglob("*"):
        if filepath.is_file() and count < max_files:
            count += 1
            result = scan_file_for_sensitive_data(filepath)
            if result:
                findings.append(result)
    return sorted(findings, key=lambda x: x["severity"])


def monitor_usb_transfers(event_log_path):
    """Monitor file transfers to USB/removable devices."""
    findings = []
    with open(event_log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            dest = entry.get("destination", entry.get("target_path", "")).lower()
            if any(ind in dest for ind in ["removable", "usb", "external"]):
                findings.append({
                    "timestamp": entry.get("timestamp", ""),
                    "user": entry.get("user", ""),
                    "file": entry.get("file_path", entry.get("source", "")),
                    "destination": dest,
                    "size_bytes": entry.get("size", entry.get("bytes", 0)),
                    "severity": "HIGH",
                    "channel": "USB",
                })
    return findings


def monitor_cloud_uploads(event_log_path):
    """Monitor file uploads to cloud storage services."""
    cloud_domains = ["drive.google.com", "dropbox.com", "onedrive.live.com",
                     "box.com", "wetransfer.com", "mega.nz"]
    findings = []
    with open(event_log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = entry.get("url", entry.get("destination", "")).lower()
            if any(domain in url for domain in cloud_domains):
                findings.append({
                    "timestamp": entry.get("timestamp", ""),
                    "user": entry.get("user", ""),
                    "url": url[:200],
                    "file": entry.get("file_name", entry.get("filename", "")),
                    "severity": "HIGH",
                    "channel": "cloud_upload",
                })
    return findings


def generate_dlp_policy():
    """Generate endpoint DLP policy recommendations."""
    return {
        "data_classification": ["PII", "Financial", "Credentials", "Source Code"],
        "channels_monitored": ["USB", "Cloud Storage", "Email Attachments",
                               "Clipboard", "Print", "Screen Capture"],
        "actions": {
            "PII_to_USB": "block_and_notify",
            "credentials_to_cloud": "block_and_alert_soc",
            "source_code_to_email": "encrypt_and_log",
            "financial_to_print": "log_and_watermark",
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Endpoint DLP Controls Agent")
    parser.add_argument("--scan-dir", help="Directory to scan for sensitive data")
    parser.add_argument("--usb-log", help="USB transfer event log")
    parser.add_argument("--cloud-log", help="Cloud upload event log")
    parser.add_argument("--output", default="endpoint_dlp_report.json")
    parser.add_argument("--action", choices=["scan", "usb", "cloud", "policy", "full"],
                        default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("scan", "full") and args.scan_dir:
        findings = scan_directory(args.scan_dir)
        report["findings"]["sensitive_data_scan"] = findings
        print(f"[+] Sensitive files found: {len(findings)}")

    if args.action in ("usb", "full") and args.usb_log:
        findings = monitor_usb_transfers(args.usb_log)
        report["findings"]["usb_transfers"] = findings
        print(f"[+] USB transfer events: {len(findings)}")

    if args.action in ("cloud", "full") and args.cloud_log:
        findings = monitor_cloud_uploads(args.cloud_log)
        report["findings"]["cloud_uploads"] = findings
        print(f"[+] Cloud upload events: {len(findings)}")

    if args.action in ("policy", "full"):
        policy = generate_dlp_policy()
        report["findings"]["dlp_policy"] = policy
        print("[+] DLP policy generated")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
