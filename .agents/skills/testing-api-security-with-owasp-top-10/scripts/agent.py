#!/usr/bin/env python3
"""Agent for automated API security testing against OWASP API Security Top 10."""

import requests
import json
import sys
import argparse
import urllib3
from datetime import datetime
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def test_bola(base_url, token, endpoints, id_range=(1, 20)):
    """Test for Broken Object Level Authorization (API1)."""
    print("\n[*] Testing API1: Broken Object Level Authorization (BOLA)...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for endpoint in endpoints:
        for obj_id in range(id_range[0], id_range[1]):
            url = urljoin(base_url, endpoint.replace("{id}", str(obj_id)))
            try:
                resp = requests.get(url, headers=headers, timeout=10, verify=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    findings.append({
                        "risk": "API1-BOLA", "url": url, "status": resp.status_code,
                        "body_length": len(resp.text), "severity": "CRITICAL",
                    })
                    print(f"  [!] VULNERABLE: GET {url} -> {resp.status_code} ({len(resp.text)} bytes)")
            except requests.RequestException:
                continue
    return findings


def test_broken_auth(base_url, login_endpoint="/api/v1/auth/login", attempts=50):
    """Test for Broken Authentication (API2) - rate limiting on login."""
    print("\n[*] Testing API2: Broken Authentication (rate limiting)...")
    url = urljoin(base_url, login_endpoint)
    findings = []
    rate_limited = False
    for i in range(1, attempts + 1):
        try:
            resp = requests.post(url, json={"email": "test@test.com", "password": f"wrong{i}"},
                                 timeout=10, verify=False)
            if resp.status_code == 429:
                print(f"  [+] Rate limited at attempt {i}")
                rate_limited = True
                break
        except requests.RequestException:
            break
    if not rate_limited:
        findings.append({
            "risk": "API2-BROKEN_AUTH", "url": url, "severity": "HIGH",
            "detail": f"No rate limiting after {attempts} failed login attempts",
        })
        print(f"  [!] No rate limiting after {attempts} attempts")
    return findings


def test_data_exposure(base_url, token, endpoints):
    """Test for Broken Object Property Level Authorization (API3)."""
    print("\n[*] Testing API3: Excessive Data Exposure...")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    sensitive_fields = ["password", "password_hash", "ssn", "credit_card", "secret",
                        "api_key", "token", "internal_id", "salt"]
    findings = []
    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    data_str = json.dumps(data).lower()
                    exposed = [f for f in sensitive_fields if f in data_str]
                    if exposed:
                        findings.append({
                            "risk": "API3-DATA_EXPOSURE", "url": url,
                            "exposed_fields": exposed, "severity": "HIGH",
                        })
                        print(f"  [!] {url}: Exposes {exposed}")
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            continue
    return findings


def test_mass_assignment(base_url, token, endpoint, payload_extras):
    """Test for mass assignment vulnerabilities."""
    print("\n[*] Testing API3: Mass Assignment...")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = urljoin(base_url, endpoint)
    findings = []
    for field, value in payload_extras.items():
        try:
            resp = requests.patch(url, headers=headers, json={field: value},
                                  timeout=10, verify=False)
            if resp.status_code in (200, 201):
                resp_data = resp.json() if resp.text else {}
                if str(value) in json.dumps(resp_data):
                    findings.append({
                        "risk": "API3-MASS_ASSIGNMENT", "url": url,
                        "field": field, "value": value, "severity": "CRITICAL",
                    })
                    print(f"  [!] VULNERABLE: Field '{field}' accepted with value '{value}'")
        except requests.RequestException:
            continue
    return findings


def test_security_headers(base_url):
    """Test for Security Misconfiguration (API8)."""
    print("\n[*] Testing API8: Security Misconfiguration (headers)...")
    findings = []
    try:
        resp = requests.get(base_url, timeout=10, verify=False)
        required_headers = {
            "Strict-Transport-Security": "HSTS",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "clickjacking protection",
            "Content-Security-Policy": "CSP",
        }
        for header, desc in required_headers.items():
            if header.lower() not in {k.lower(): v for k, v in resp.headers.items()}:
                findings.append({
                    "risk": "API8-MISCONFIGURATION", "header": header,
                    "detail": f"Missing {desc}", "severity": "MEDIUM",
                })
                print(f"  [!] Missing: {header} ({desc})")
            else:
                print(f"  [+] Present: {header}")
    except requests.RequestException as e:
        print(f"  [-] Error: {e}")
    return findings


def test_cors(base_url, endpoints):
    """Test CORS configuration on API endpoints."""
    print("\n[*] Testing CORS configuration...")
    findings = []
    evil_origins = ["https://evil.com", "null", "http://localhost"]
    for endpoint in endpoints[:3]:
        url = urljoin(base_url, endpoint)
        for origin in evil_origins:
            try:
                resp = requests.get(url, headers={"Origin": origin}, timeout=10, verify=False)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin and acac.lower() == "true":
                    findings.append({
                        "risk": "CORS_MISCONFIGURATION", "url": url,
                        "origin": origin, "severity": "HIGH",
                    })
                    print(f"  [!] {url}: Reflects origin '{origin}' with credentials")
            except requests.RequestException:
                continue
    return findings


def test_api_versions(base_url, path_prefix="/api"):
    """Test for Improper Inventory Management (API9)."""
    print("\n[*] Testing API9: Improper Inventory Management...")
    findings = []
    versions = ["v0", "v1", "v2", "v3", "v4", "beta", "internal", "admin", "debug"]
    for v in versions:
        url = urljoin(base_url, f"{path_prefix}/{v}/users")
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code not in (404, 000):
                findings.append({"risk": "API9-INVENTORY", "url": url, "status": resp.status_code})
                print(f"  [+] {v}: {resp.status_code}")
        except requests.RequestException:
            continue
    return findings


def generate_report(all_findings, output_path):
    """Generate OWASP API Security assessment report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "by_severity": {},
        "findings": all_findings,
    }
    for f in all_findings:
        sev = f.get("severity", "INFO")
        report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report saved to {output_path}")
    print(f"[*] Total findings: {len(all_findings)}")
    for sev, count in report["by_severity"].items():
        print(f"  {sev}: {count}")


def main():
    parser = argparse.ArgumentParser(description="OWASP API Security Top 10 Testing Agent")
    parser.add_argument("base_url", help="Base URL of the API (e.g., https://api.target.com)")
    parser.add_argument("--token", help="Bearer token for authentication")
    parser.add_argument("--endpoints", nargs="+", default=["/api/v1/users/{id}", "/api/v1/orders/{id}"])
    parser.add_argument("--login-endpoint", default="/api/v1/auth/login")
    parser.add_argument("-o", "--output", default="api_security_report.json")
    args = parser.parse_args()

    print(f"[*] OWASP API Security Top 10 Assessment")
    print(f"[*] Target: {args.base_url}")
    all_findings = []
    all_findings.extend(test_security_headers(args.base_url))
    all_findings.extend(test_cors(args.base_url, args.endpoints))
    all_findings.extend(test_api_versions(args.base_url))
    all_findings.extend(test_broken_auth(args.base_url, args.login_endpoint))
    if args.token:
        all_findings.extend(test_bola(args.base_url, args.token, args.endpoints))
        all_findings.extend(test_data_exposure(args.base_url, args.token, args.endpoints))
        all_findings.extend(test_mass_assignment(args.base_url, args.token, args.endpoints[0],
                                                  {"role": "admin", "is_admin": True}))
    generate_report(all_findings, args.output)


if __name__ == "__main__":
    main()
