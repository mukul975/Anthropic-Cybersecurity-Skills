#!/usr/bin/env python3
"""Agent for testing CORS misconfiguration vulnerabilities during authorized assessments."""

import requests
import json
import sys
import argparse
import urllib3
from datetime import datetime
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


EVIL_ORIGINS = [
    "https://evil.com",
    "null",
    "http://localhost",
    "http://localhost:3000",
    "http://127.0.0.1",
]


def build_dynamic_origins(target_domain):
    """Generate domain-specific bypass origins for testing."""
    return [
        f"https://evil.{target_domain}",
        f"https://{target_domain}.evil.com",
        f"https://evil{target_domain}",
        f"http://{target_domain}",
        f"https://sub.{target_domain}",
    ]


def test_origin_reflection(url, origins, cookies=None):
    """Test if server reflects arbitrary Origin headers."""
    print(f"\n[*] Testing origin reflection on {url}")
    findings = []
    for origin in origins:
        try:
            headers = {"Origin": origin}
            resp = requests.get(url, headers=headers, cookies=cookies,
                                timeout=10, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao and acao != "":
                reflected = acao == origin
                creds = acac.lower() == "true"
                severity = "CRITICAL" if reflected and creds else (
                    "HIGH" if reflected else "INFO")
                if reflected:
                    findings.append({
                        "url": url, "origin": origin, "acao": acao,
                        "credentials": creds, "severity": severity,
                    })
                    cred_str = " + credentials" if creds else ""
                    print(f"  [{'!' if severity != 'INFO' else '+'}] Origin '{origin}' -> "
                          f"ACAO: {acao}{cred_str} [{severity}]")
        except requests.RequestException:
            continue
    return findings


def test_preflight(url, origin="https://evil.com"):
    """Test OPTIONS preflight request handling."""
    print(f"\n[*] Testing preflight (OPTIONS) on {url}")
    findings = []
    methods_to_test = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    for method in methods_to_test:
        try:
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            }
            resp = requests.options(url, headers=headers, timeout=10, verify=False)
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            acah = resp.headers.get("Access-Control-Allow-Headers", "")
            max_age = resp.headers.get("Access-Control-Max-Age", "")
            if method in acam:
                print(f"  [+] {method} allowed in preflight")
            if max_age and int(max_age) > 86400:
                findings.append({
                    "url": url, "issue": "excessive_max_age",
                    "max_age": max_age, "severity": "MEDIUM",
                })
                print(f"  [!] Max-Age too long: {max_age}s (>86400)")
        except requests.RequestException:
            continue
    return findings


def test_wildcard_with_credentials(url):
    """Test for wildcard CORS with credentials (invalid but sometimes misconfigured)."""
    print(f"\n[*] Testing wildcard + credentials on {url}")
    try:
        resp = requests.get(url, headers={"Origin": "https://any.com"},
                            timeout=10, verify=False)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            print(f"  [!] CRITICAL: Wildcard (*) with credentials=true")
            return [{"url": url, "issue": "wildcard_with_credentials", "severity": "CRITICAL"}]
        elif acao == "*":
            print(f"  [+] Wildcard (*) without credentials (acceptable for public APIs)")
    except requests.RequestException:
        pass
    return []


def test_null_origin(url, cookies=None):
    """Test if null Origin is accepted (exploitable via sandboxed iframes)."""
    print(f"\n[*] Testing null origin on {url}")
    try:
        resp = requests.get(url, headers={"Origin": "null"}, cookies=cookies,
                            timeout=10, verify=False)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "null":
            creds = acac.lower() == "true"
            severity = "HIGH" if creds else "MEDIUM"
            print(f"  [!] Null origin accepted (credentials: {creds}) [{severity}]")
            return [{"url": url, "issue": "null_origin_accepted",
                      "credentials": creds, "severity": severity}]
        else:
            print(f"  [+] Null origin not reflected")
    except requests.RequestException:
        pass
    return []


def test_internal_origins(url, cookies=None):
    """Test if internal/development origins are trusted."""
    print(f"\n[*] Testing internal origins on {url}")
    internal = [
        "http://localhost", "http://localhost:3000", "http://localhost:8080",
        "http://127.0.0.1", "http://10.0.0.1", "http://192.168.1.1",
    ]
    findings = []
    for origin in internal:
        try:
            resp = requests.get(url, headers={"Origin": origin}, cookies=cookies,
                                timeout=10, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == origin:
                findings.append({"url": url, "origin": origin, "severity": "MEDIUM"})
                print(f"  [!] Internal origin accepted: {origin}")
        except requests.RequestException:
            continue
    return findings


def scan_endpoints(base_url, endpoints, token=None):
    """Scan multiple endpoints for CORS issues."""
    all_findings = []
    cookies = None
    headers_auth = {"Authorization": f"Bearer {token}"} if token else {}
    domain = urlparse(base_url).netloc
    dynamic_origins = build_dynamic_origins(domain)
    test_origins = EVIL_ORIGINS + dynamic_origins

    for endpoint in endpoints:
        url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        all_findings.extend(test_origin_reflection(url, test_origins))
        all_findings.extend(test_null_origin(url))
        all_findings.extend(test_wildcard_with_credentials(url))
        all_findings.extend(test_preflight(url))
        all_findings.extend(test_internal_origins(url))
    return all_findings


def generate_report(findings, output_path):
    """Generate CORS misconfiguration assessment report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "by_severity": {},
        "findings": findings,
    }
    for f in findings:
        sev = f.get("severity", "INFO")
        report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report saved to {output_path}")
    for sev, count in report["by_severity"].items():
        print(f"  {sev}: {count}")


def main():
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Testing Agent")
    parser.add_argument("base_url", help="Base URL of the target")
    parser.add_argument("--endpoints", nargs="+",
                        default=["/api/user/profile", "/api/users", "/api/account"])
    parser.add_argument("--token", help="Bearer token for authenticated testing")
    parser.add_argument("-o", "--output", default="cors_report.json")
    args = parser.parse_args()

    print(f"[*] CORS Misconfiguration Assessment")
    print(f"[*] Target: {args.base_url}")
    findings = scan_endpoints(args.base_url, args.endpoints, args.token)
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
