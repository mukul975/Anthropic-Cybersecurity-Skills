#!/usr/bin/env python3
"""
Harbor Container Registry Security Auditor

Audits Harbor registry configuration for security best practices
including scanning policies, content trust, RBAC, and TLS.
"""

import json
import sys
import urllib.request
import urllib.error
import ssl
import base64
from dataclasses import dataclass, field


@dataclass
class HarborFinding:
    category: str
    title: str
    severity: str
    details: str
    remediation: str


@dataclass
class HarborAuditReport:
    findings: list = field(default_factory=list)
    harbor_url: str = ""
    projects_audited: int = 0


def harbor_api_call(base_url: str, endpoint: str, username: str, password: str) -> dict:
    """Call Harbor API and return JSON response."""
    url = f"{base_url}/api/v2.0{endpoint}"
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Basic {credentials}")
    req.add_header("Content-Type", "application/json")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"[!] API call failed for {endpoint}: {e}")
        return {}


def audit_projects(base_url: str, username: str, password: str, report: HarborAuditReport):
    """Audit all projects for security configurations."""
    projects = harbor_api_call(base_url, "/projects?page=1&page_size=100", username, password)
    if not projects:
        return

    for project in projects:
        name = project.get("name", "unknown")
        metadata = project.get("metadata", {})
        report.projects_audited += 1

        # Check auto-scan
        if metadata.get("auto_scan") != "true":
            report.findings.append(HarborFinding(
                category="Scanning",
                title=f"Auto-scan disabled for project: {name}",
                severity="HIGH",
                details="Images pushed to this project are not automatically scanned",
                remediation=f"Enable auto_scan for project '{name}'"
            ))

        # Check vulnerability prevention
        if metadata.get("prevent_vul") != "true":
            report.findings.append(HarborFinding(
                category="Scanning",
                title=f"Vulnerability prevention disabled for project: {name}",
                severity="HIGH",
                details="Vulnerable images can be pulled from this project",
                remediation=f"Enable prevent_vul for project '{name}'"
            ))

        # Check content trust
        if metadata.get("enable_content_trust") != "true" and metadata.get("enable_content_trust_cosign") != "true":
            report.findings.append(HarborFinding(
                category="Content Trust",
                title=f"Content trust not enforced for project: {name}",
                severity="MEDIUM",
                details="Unsigned images can be used from this project",
                remediation=f"Enable content trust (Cosign) for project '{name}'"
            ))

        # Check public visibility
        if metadata.get("public") == "true":
            report.findings.append(HarborFinding(
                category="Access Control",
                title=f"Project is publicly accessible: {name}",
                severity="MEDIUM",
                details="Anyone can pull images from this project",
                remediation=f"Set project '{name}' to private unless intentionally public"
            ))


def audit_system_config(base_url: str, username: str, password: str, report: HarborAuditReport):
    """Audit system-level Harbor configuration."""
    config = harbor_api_call(base_url, "/configurations", username, password)
    if not config:
        return

    # Check auth mode
    auth_mode = config.get("auth_mode", {}).get("value", "db_auth")
    if auth_mode == "db_auth":
        report.findings.append(HarborFinding(
            category="Authentication",
            title="Using local database authentication",
            severity="MEDIUM",
            details="Harbor uses local DB auth instead of enterprise IdP",
            remediation="Configure OIDC or LDAP authentication"
        ))

    # Check self-registration
    self_reg = config.get("self_registration", {}).get("value", False)
    if self_reg:
        report.findings.append(HarborFinding(
            category="Authentication",
            title="Self-registration is enabled",
            severity="HIGH",
            details="Anyone can create an account on this Harbor instance",
            remediation="Disable self-registration in Harbor configuration"
        ))


def print_report(report: HarborAuditReport):
    print("\n" + "=" * 70)
    print("HARBOR REGISTRY SECURITY AUDIT")
    print("=" * 70)
    print(f"Harbor URL:         {report.harbor_url}")
    print(f"Projects Audited:   {report.projects_audited}")
    print(f"Findings:           {len(report.findings)}")
    print("=" * 70)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        findings = [f for f in report.findings if f.severity == sev]
        if findings:
            print(f"\n{sev} ({len(findings)}):")
            for f in findings:
                print(f"  [{f.category}] {f.title}")
                print(f"    Fix: {f.remediation}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Harbor Registry Security Auditor")
    parser.add_argument("--url", required=True, help="Harbor URL (e.g., https://harbor.example.com)")
    parser.add_argument("--username", default="admin", help="Harbor admin username")
    parser.add_argument("--password", required=True, help="Harbor admin password")
    args = parser.parse_args()

    report = HarborAuditReport(harbor_url=args.url)

    print(f"[*] Auditing Harbor at {args.url}")
    audit_projects(args.url, args.username, args.password, report)
    audit_system_config(args.url, args.username, args.password, report)
    print_report(report)

    with open("harbor_audit_report.json", "w") as f:
        json.dump({
            "harbor_url": report.harbor_url,
            "findings": [{"category": f.category, "title": f.title,
                         "severity": f.severity, "remediation": f.remediation}
                        for f in report.findings]
        }, f, indent=2)
    print("\n[*] Report saved to harbor_audit_report.json")


if __name__ == "__main__":
    main()
