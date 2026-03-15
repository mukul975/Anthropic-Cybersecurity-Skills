#!/usr/bin/env python3
# For authorized testing only
"""API rate limiting bypass testing agent."""

import json
import sys
import argparse
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "192.168.1.1"},
    {"X-Forwarded-Host": "localhost"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
]


def detect_rate_limit_headers(url, auth_header=None):
    """Send initial request and extract rate limit response headers."""
    headers = {"User-Agent": "RateLimit-Tester/1.0"}
    if auth_header:
        headers["Authorization"] = auth_header
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        rate_headers = {}
        for key in resp.headers:
            lower = key.lower()
            if any(rl in lower for rl in ["ratelimit", "rate-limit", "x-rate",
                                           "retry-after", "x-ratelimit"]):
                rate_headers[key] = resp.headers[key]
        return {
            "url": url,
            "status": resp.status_code,
            "rate_limit_headers": rate_headers,
            "has_rate_limiting": len(rate_headers) > 0,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def test_header_bypass(url, auth_header=None, request_count=30):
    """Test rate limit bypass via IP spoofing headers."""
    findings = []
    base_headers = {"User-Agent": "RateLimit-Tester/1.0"}
    if auth_header:
        base_headers["Authorization"] = auth_header

    for i in range(request_count):
        try:
            resp = requests.get(url, headers=base_headers, timeout=5)
            if resp.status_code == 429:
                baseline_hit = i + 1
                break
        except Exception:
            pass
    else:
        findings.append({
            "test": "baseline",
            "issue": f"No rate limit hit after {request_count} requests",
            "severity": "HIGH",
        })
        return findings

    for bypass in BYPASS_HEADERS:
        test_headers = {**base_headers, **bypass}
        header_name = list(bypass.keys())[0]
        success_count = 0
        for i in range(10):
            bypass[header_name] = f"10.{i}.{i}.{i}"
            test_headers = {**base_headers, **bypass}
            try:
                resp = requests.get(url, headers=test_headers, timeout=5)
                if resp.status_code != 429:
                    success_count += 1
            except Exception:
                pass

        if success_count > 5:
            findings.append({
                "test": "header_bypass",
                "header": header_name,
                "issue": f"Rate limit bypassed using {header_name} header ({success_count}/10 successful)",
                "severity": "HIGH",
            })
    return findings


def test_method_bypass(url, auth_header=None):
    """Test if rate limiting applies across HTTP methods."""
    methods = ["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"]
    findings = []
    headers = {"User-Agent": "RateLimit-Tester/1.0"}
    if auth_header:
        headers["Authorization"] = auth_header

    method_results = {}
    for method in methods:
        try:
            resp = requests.request(method, url, headers=headers, timeout=5)
            method_results[method] = resp.status_code
        except Exception:
            method_results[method] = "error"

    rate_limited = [m for m, s in method_results.items() if s == 429]
    not_limited = [m for m, s in method_results.items() if isinstance(s, int) and s != 429]

    if rate_limited and not_limited:
        findings.append({
            "test": "method_bypass",
            "rate_limited": rate_limited,
            "not_limited": not_limited,
            "issue": f"Rate limit not applied to methods: {', '.join(not_limited)}",
            "severity": "MEDIUM",
        })
    return findings


def test_path_bypass(url, auth_header=None):
    """Test rate limit bypass via URL path manipulation."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path

    path_variations = [
        path + "/",
        path + "?",
        path + "#",
        path.upper(),
        path + "%20",
        path + ";",
        path.replace("/", "//"),
        path + "/.",
        path + "/..",
    ]

    findings = []
    headers = {"User-Agent": "RateLimit-Tester/1.0"}
    if auth_header:
        headers["Authorization"] = auth_header

    for variant in path_variations:
        test_url = f"{parsed.scheme}://{parsed.netloc}{variant}"
        try:
            resp = requests.get(test_url, headers=headers, timeout=5, allow_redirects=False)
            if resp.status_code not in (429, 404, 301, 302):
                findings.append({
                    "test": "path_bypass",
                    "original": path,
                    "variant": variant,
                    "status": resp.status_code,
                    "issue": f"Path variation '{variant}' bypasses rate limit (status {resp.status_code})",
                    "severity": "MEDIUM",
                })
        except Exception:
            pass
    return findings


def test_encoding_bypass(url, auth_header=None):
    """Test rate limit bypass via parameter encoding variations."""
    from urllib.parse import urlparse, parse_qs, urlencode
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    findings = []
    headers = {"User-Agent": "RateLimit-Tester/1.0"}
    if auth_header:
        headers["Authorization"] = auth_header

    null_byte_url = url + "%00"
    try:
        resp = requests.get(null_byte_url, headers=headers, timeout=5)
        if resp.status_code != 429:
            findings.append({
                "test": "null_byte_bypass",
                "status": resp.status_code,
                "issue": "Null byte appended bypasses rate limit",
                "severity": "HIGH",
            })
    except Exception:
        pass

    return findings


def run_audit(args):
    """Execute API rate limiting bypass audit."""
    print(f"\n{'='*60}")
    print(f"  API RATE LIMITING BYPASS TESTING")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}
    all_findings = []

    detection = detect_rate_limit_headers(args.url, args.auth)
    report["rate_limit_detection"] = detection
    print(f"--- RATE LIMIT DETECTION ---")
    print(f"  URL: {detection.get('url','')}")
    print(f"  Has Rate Limiting: {detection.get('has_rate_limiting', False)}")
    for k, v in detection.get("rate_limit_headers", {}).items():
        print(f"  {k}: {v}")

    if args.test_headers:
        header_findings = test_header_bypass(args.url, args.auth, args.request_count)
        all_findings.extend(header_findings)
        print(f"\n--- HEADER BYPASS ({len(header_findings)} findings) ---")
        for f in header_findings:
            print(f"  [{f['severity']}] {f['issue']}")

    if args.test_methods:
        method_findings = test_method_bypass(args.url, args.auth)
        all_findings.extend(method_findings)
        print(f"\n--- METHOD BYPASS ({len(method_findings)} findings) ---")
        for f in method_findings:
            print(f"  [{f['severity']}] {f['issue']}")

    if args.test_paths:
        path_findings = test_path_bypass(args.url, args.auth)
        all_findings.extend(path_findings)
        print(f"\n--- PATH BYPASS ({len(path_findings)} findings) ---")
        for f in path_findings:
            print(f"  [{f['severity']}] {f['issue']}")

    report["findings"] = all_findings
    report["total_findings"] = len(all_findings)
    return report


def main():
    parser = argparse.ArgumentParser(description="API Rate Limiting Bypass Tester")
    parser.add_argument("--url", required=True, help="Target API endpoint URL")
    parser.add_argument("--auth", help="Authorization header value")
    parser.add_argument("--request-count", type=int, default=30,
                        help="Requests for baseline detection (default: 30)")
    parser.add_argument("--test-headers", action="store_true", help="Test header-based bypasses")
    parser.add_argument("--test-methods", action="store_true", help="Test HTTP method bypasses")
    parser.add_argument("--test-paths", action="store_true", help="Test URL path bypasses")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
