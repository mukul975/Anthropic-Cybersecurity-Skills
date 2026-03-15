#!/usr/bin/env python3
"""Agent for analyzing intercepted mobile app traffic via mitmproxy for security testing."""

import json
import argparse
import sys
import os
import re
from datetime import datetime
from urllib.parse import urlparse


def load_har_file(har_path):
    """Load and parse an HTTP Archive (HAR) file from proxy capture."""
    with open(har_path) as f:
        data = json.load(f)
    entries = data.get("log", {}).get("entries", [])
    print(f"[*] Loaded {len(entries)} requests from {har_path}")
    return entries


def find_insecure_requests(entries):
    """Identify HTTP (non-HTTPS) requests from mobile app."""
    findings = []
    for e in entries:
        url = e.get("request", {}).get("url", "")
        if url.startswith("http://"):
            findings.append({"url": url, "method": e["request"].get("method"),
                             "issue": "Cleartext HTTP request", "severity": "HIGH"})
    print(f"\n[*] Insecure HTTP requests: {len(findings)}")
    for f in findings[:10]:
        print(f"  [!] {f['method']} {f['url'][:80]}")
    return findings


def detect_sensitive_data_leakage(entries):
    """Scan request/response bodies for sensitive data patterns."""
    patterns = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)\d{12}\b",
        "api_key": r"(?:api[_-]?key|apikey|token)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_-]{20,})",
        "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    }
    findings = []
    for e in entries:
        url = e.get("request", {}).get("url", "")
        body = e.get("request", {}).get("postData", {}).get("text", "")
        resp_body = e.get("response", {}).get("content", {}).get("text", "")
        combined = f"{body} {resp_body}"
        for name, pattern in patterns.items():
            matches = re.findall(pattern, combined)
            if matches:
                findings.append({"url": url[:80], "data_type": name,
                                 "count": len(matches), "severity": "HIGH"})
    print(f"\n[*] Sensitive data leakage findings: {len(findings)}")
    for f in findings[:10]:
        print(f"  [!] {f['data_type']} in {f['url']} ({f['count']} occurrences)")
    return findings


def check_auth_headers(entries):
    """Analyze authentication headers and token handling."""
    findings = []
    for e in entries:
        headers = {h["name"].lower(): h["value"] for h in e.get("request", {}).get("headers", [])}
        url = e.get("request", {}).get("url", "")
        if "authorization" in headers:
            auth = headers["authorization"]
            if auth.startswith("Basic "):
                findings.append({"url": url[:80], "issue": "Basic auth over network",
                                 "severity": "HIGH"})
            elif auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1]
                if len(token) < 20:
                    findings.append({"url": url[:80], "issue": "Short bearer token",
                                     "severity": "MEDIUM"})
        resp_headers = {h["name"].lower(): h["value"]
                        for h in e.get("response", {}).get("headers", [])}
        if "set-cookie" in resp_headers:
            cookie = resp_headers["set-cookie"]
            if "secure" not in cookie.lower() or "httponly" not in cookie.lower():
                findings.append({"url": url[:80], "issue": "Cookie missing Secure/HttpOnly",
                                 "severity": "MEDIUM"})
    print(f"\n[*] Auth/cookie findings: {len(findings)}")
    return findings


def check_certificate_pinning(entries):
    """Check for certificate pinning indicators in traffic."""
    domains = set()
    for e in entries:
        url = e.get("request", {}).get("url", "")
        parsed = urlparse(url)
        if parsed.scheme == "https":
            domains.add(parsed.hostname)
    print(f"\n[*] HTTPS domains contacted: {len(domains)}")
    for d in sorted(domains)[:20]:
        print(f"  {d}")
    print("  [*] Note: Certificate pinning bypass verified by successful interception")
    return list(domains)


def check_api_security_headers(entries):
    """Check API response security headers."""
    findings = []
    checked_hosts = set()
    for e in entries:
        url = e.get("request", {}).get("url", "")
        host = urlparse(url).hostname
        if host in checked_hosts:
            continue
        checked_hosts.add(host)
        resp_headers = {h["name"].lower(): h["value"]
                        for h in e.get("response", {}).get("headers", [])}
        missing = []
        for hdr in ["strict-transport-security", "x-content-type-options",
                     "x-frame-options", "content-security-policy"]:
            if hdr not in resp_headers:
                missing.append(hdr)
        if missing:
            findings.append({"host": host, "missing_headers": missing, "severity": "MEDIUM"})
    print(f"\n[*] Security header findings: {len(findings)}")
    return findings


def generate_report(all_findings, output_path):
    """Generate mobile traffic analysis report."""
    report = {"analysis_date": datetime.now().isoformat(), "total_findings": len(all_findings),
              "findings": all_findings}
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Mobile Traffic Interception Analysis Agent")
    parser.add_argument("action", choices=["analyze", "insecure", "leakage", "auth", "full"])
    parser.add_argument("--har", required=True, help="Path to HAR file from proxy capture")
    parser.add_argument("-o", "--output", default="mobile_traffic_report.json")
    args = parser.parse_args()

    entries = load_har_file(args.har)
    findings = []
    if args.action in ("insecure", "full"):
        findings.extend(find_insecure_requests(entries))
    if args.action in ("leakage", "full"):
        findings.extend(detect_sensitive_data_leakage(entries))
    if args.action in ("auth", "full"):
        findings.extend(check_auth_headers(entries))
    if args.action in ("analyze", "full"):
        check_certificate_pinning(entries)
        findings.extend(check_api_security_headers(entries))
    if args.action == "full":
        generate_report(findings, args.output)


if __name__ == "__main__":
    main()
