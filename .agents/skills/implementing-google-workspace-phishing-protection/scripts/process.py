#!/usr/bin/env python3
"""
Google Workspace Phishing Protection Auditor

Audits Google Workspace Gmail safety settings configuration
and generates compliance recommendations.

Usage:
    python process.py audit --config-file gws_config.json
    python process.py check-auth --domain example.com
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


@dataclass
class GWSSecurityAudit:
    """Google Workspace security configuration audit."""
    domain: str = ""
    spoofing_protection: bool = False
    employee_name_spoofing: bool = False
    enhanced_predelivery: bool = False
    attachment_protection: dict = field(default_factory=dict)
    enhanced_safe_browsing: bool = False
    security_sandbox: bool = False
    app_enrolled_users: int = 0
    spf_configured: bool = False
    dkim_configured: bool = False
    dmarc_configured: bool = False
    dmarc_policy: str = ""
    score: int = 0
    max_score: int = 100
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


def audit_gws_config(config: dict) -> GWSSecurityAudit:
    """Audit Google Workspace Gmail safety configuration."""
    audit = GWSSecurityAudit()
    audit.domain = config.get("domain", "")

    safety = config.get("safety_settings", {})

    # Spoofing protection
    audit.spoofing_protection = safety.get("domain_spoofing_protection", False)
    if audit.spoofing_protection:
        audit.score += 15
    else:
        audit.findings.append("Domain spoofing protection not enabled")
        audit.recommendations.append(
            "Enable 'Protect against domain spoofing based on similar domain names'"
        )

    audit.employee_name_spoofing = safety.get("employee_name_spoofing", False)
    if audit.employee_name_spoofing:
        audit.score += 10
    else:
        audit.findings.append("Employee name spoofing protection not enabled")
        audit.recommendations.append(
            "Enable 'Protect against spoofing of employee names'"
        )

    # Pre-delivery scanning
    audit.enhanced_predelivery = safety.get("enhanced_predelivery_scanning", False)
    if audit.enhanced_predelivery:
        audit.score += 15
    else:
        audit.findings.append("Enhanced pre-delivery scanning not enabled")

    # Attachment protection
    att = safety.get("attachment_protection", {})
    audit.attachment_protection = att
    att_score = 0
    if att.get("encrypted_attachments", False):
        att_score += 5
    if att.get("script_attachments", False):
        att_score += 5
    if att.get("anomalous_types", False):
        att_score += 5
    audit.score += att_score
    if att_score < 15:
        audit.findings.append("Not all attachment protection options enabled")

    # Enhanced Safe Browsing
    audit.enhanced_safe_browsing = safety.get("enhanced_safe_browsing", False)
    if audit.enhanced_safe_browsing:
        audit.score += 10
    else:
        audit.findings.append("Enhanced Safe Browsing not enabled (off by default)")
        audit.recommendations.append(
            "Enable Enhanced Safe Browsing in Admin Console > Security"
        )

    # Security Sandbox
    audit.security_sandbox = safety.get("security_sandbox", False)
    if audit.security_sandbox:
        audit.score += 10
    else:
        audit.findings.append("Gmail Security Sandbox not enabled (requires Enterprise license)")

    # Advanced Protection Program
    audit.app_enrolled_users = config.get("app_enrolled_users", 0)
    if audit.app_enrolled_users > 0:
        audit.score += 10
    else:
        audit.recommendations.append(
            "Enroll super admins and executives in Advanced Protection Program"
        )

    # Authentication
    auth = config.get("authentication", {})
    audit.spf_configured = auth.get("spf", False)
    audit.dkim_configured = auth.get("dkim", False)
    audit.dmarc_configured = auth.get("dmarc", False)
    audit.dmarc_policy = auth.get("dmarc_policy", "none")

    if audit.spf_configured:
        audit.score += 5
    if audit.dkim_configured:
        audit.score += 5
    if audit.dmarc_configured:
        audit.score += 5
        if audit.dmarc_policy == "reject":
            audit.score += 10
        elif audit.dmarc_policy == "quarantine":
            audit.score += 5

    return audit


def check_google_auth(domain: str) -> dict:
    """Check SPF, DKIM, DMARC for Google Workspace domain."""
    result = {"domain": domain, "spf": False, "dkim": False, "dmarc": False, "issues": []}

    if not HAS_DNS:
        result["issues"].append("dnspython not installed")
        return result

    # SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if 'v=spf1' in txt and '_spf.google.com' in txt:
                result["spf"] = True
                break
        if not result["spf"]:
            result["issues"].append("SPF does not include _spf.google.com")
    except Exception:
        result["issues"].append("No SPF record found")

    # DKIM (Google default selector)
    try:
        dns.resolver.resolve(f"google._domainkey.{domain}", 'TXT')
        result["dkim"] = True
    except Exception:
        result["issues"].append("DKIM not configured for 'google' selector")

    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if 'v=DMARC1' in txt:
                result["dmarc"] = True
                import re
                policy = re.search(r'p=(\w+)', txt)
                result["dmarc_policy"] = policy.group(1) if policy else "unknown"
                break
    except Exception:
        result["issues"].append("No DMARC record found")

    return result


def main():
    parser = argparse.ArgumentParser(description="Google Workspace Phishing Protection Auditor")
    subparsers = parser.add_subparsers(dest="command")

    audit_parser = subparsers.add_parser("audit", help="Audit GWS security config")
    audit_parser.add_argument("--config-file", required=True)

    auth_parser = subparsers.add_parser("check-auth", help="Check email authentication")
    auth_parser.add_argument("--domain", required=True)

    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "audit":
        with open(args.config_file) as f:
            config = json.load(f)
        result = audit_gws_config(config)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"Security Score: {result.score}/{result.max_score}")
            if result.findings:
                print(f"\nFindings ({len(result.findings)}):")
                for i, f_item in enumerate(result.findings, 1):
                    print(f"  {i}. {f_item}")
            if result.recommendations:
                print(f"\nRecommendations ({len(result.recommendations)}):")
                for i, rec in enumerate(result.recommendations, 1):
                    print(f"  {i}. {rec}")

    elif args.command == "check-auth":
        result = check_google_auth(args.domain)
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
