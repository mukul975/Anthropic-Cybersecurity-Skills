#!/usr/bin/env python3
"""Agent for auditing and configuring Google Workspace SAML SSO."""

import json
import argparse
import subprocess
import re
from datetime import datetime
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    x509 = None


def parse_saml_certificate(cert_path):
    """Parse and validate an IdP SAML signing certificate."""
    if not x509:
        return {"error": "cryptography library not available"}
    with open(cert_path, "rb") as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data)
    now = datetime.utcnow()
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": str(cert.not_valid_before_utc),
        "not_after": str(cert.not_valid_after_utc),
        "serial": str(cert.serial_number),
        "key_size": cert.public_key().key_size if hasattr(cert.public_key(), "key_size") else None,
        "expired": cert.not_valid_after_utc.replace(tzinfo=None) < now,
        "days_until_expiry": (cert.not_valid_after_utc.replace(tzinfo=None) - now).days,
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
    }


def audit_sso_config(config_path):
    """Audit Google Workspace SSO configuration."""
    with open(config_path) as f:
        config = json.load(f)
    findings = []
    sso = config.get("sso", config)

    if not sso.get("sso_enabled", sso.get("enabled", False)):
        findings.append({"issue": "SSO not enabled", "severity": "HIGH"})

    sign_in_url = sso.get("sign_in_page_url", sso.get("sso_url", ""))
    if sign_in_url and not sign_in_url.startswith("https://"):
        findings.append({"issue": "SSO sign-in URL not HTTPS", "severity": "CRITICAL"})

    sign_out_url = sso.get("sign_out_page_url", sso.get("logout_url", ""))
    if not sign_out_url:
        findings.append({"issue": "Sign-out URL not configured", "severity": "MEDIUM"})

    cert_path = sso.get("verification_certificate", sso.get("certificate_path", ""))
    if cert_path and Path(cert_path).exists():
        cert_info = parse_saml_certificate(cert_path)
        if cert_info.get("expired"):
            findings.append({"issue": "IdP certificate expired", "severity": "CRITICAL",
                             "detail": cert_info})
        elif cert_info.get("days_until_expiry", 999) < 30:
            findings.append({"issue": f"IdP cert expires in {cert_info['days_until_expiry']} days",
                             "severity": "HIGH", "detail": cert_info})
        key_size = cert_info.get("key_size", 0)
        if key_size and key_size < 2048:
            findings.append({"issue": f"Weak IdP cert key size: {key_size}", "severity": "HIGH"})
    elif not cert_path:
        findings.append({"issue": "No verification certificate configured", "severity": "CRITICAL"})

    if not sso.get("use_domain_specific_issuer", True):
        findings.append({"issue": "Domain-specific issuer not enabled", "severity": "MEDIUM"})

    if sso.get("allow_password_auth_when_sso_enabled", True):
        findings.append({"issue": "Password auth still allowed alongside SSO", "severity": "MEDIUM",
                         "recommendation": "Disable direct password login for SSO users"})

    if not findings:
        findings.append({"issue": "No issues found", "severity": "INFO"})
    return findings


def generate_saml_config(idp_entity_id, sso_url, slo_url, cert_path, domain):
    """Generate Google Workspace SAML SSO configuration."""
    return {
        "sso_enabled": True,
        "sign_in_page_url": sso_url,
        "sign_out_page_url": slo_url,
        "change_password_url": f"https://{idp_entity_id}/change-password",
        "verification_certificate": cert_path,
        "use_domain_specific_issuer": True,
        "domain": domain,
        "saml_settings": {
            "idp_entity_id": idp_entity_id,
            "sp_entity_id": f"google.com/a/{domain}",
            "acs_url": f"https://accounts.google.com/samlrp/acs?rpid=RPID",
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def audit_sso_login_activity(log_path):
    """Audit SSO login activity for anomalies."""
    with open(log_path) as f:
        events = json.load(f)
    items = events if isinstance(events, list) else events.get("events", [])
    total = len(items)
    failures = [e for e in items if e.get("status") in ("failed", "error", "FAILED")]
    sso_logins = [e for e in items if e.get("auth_method") == "saml_sso"]
    password_logins = [e for e in items if e.get("auth_method") == "password"]
    return {
        "total_logins": total,
        "sso_logins": len(sso_logins),
        "password_logins": len(password_logins),
        "sso_adoption_rate": round(len(sso_logins) / total * 100, 1) if total else 0,
        "failures": len(failures),
        "failure_rate": round(len(failures) / total * 100, 1) if total else 0,
        "recent_failures": failures[:10],
    }


def main():
    parser = argparse.ArgumentParser(description="Google Workspace SSO Agent")
    parser.add_argument("--config", help="SSO config JSON to audit")
    parser.add_argument("--cert", help="IdP SAML certificate PEM file")
    parser.add_argument("--login-log", help="Login activity log JSON")
    parser.add_argument("--action", choices=["audit", "cert", "activity", "generate", "full"],
                        default="full")
    parser.add_argument("--idp-url", help="IdP SSO URL")
    parser.add_argument("--domain", help="Google Workspace domain")
    parser.add_argument("--output", default="gws_sso_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("audit", "full") and args.config:
        findings = audit_sso_config(args.config)
        report["results"]["audit"] = findings
        issues = sum(1 for f in findings if f["severity"] not in ("INFO",))
        print(f"[+] SSO audit: {issues} issues found")

    if args.action in ("cert", "full") and args.cert:
        cert_info = parse_saml_certificate(args.cert)
        report["results"]["certificate"] = cert_info
        status = "EXPIRED" if cert_info.get("expired") else "VALID"
        print(f"[+] Certificate: {status}, expires in {cert_info.get('days_until_expiry')} days")

    if args.action in ("activity", "full") and args.login_log:
        activity = audit_sso_login_activity(args.login_log)
        report["results"]["activity"] = activity
        print(f"[+] SSO adoption: {activity['sso_adoption_rate']}%")

    if args.action == "generate" and args.idp_url and args.domain:
        config = generate_saml_config("idp", args.idp_url, "", args.cert or "", args.domain)
        report["results"]["generated_config"] = config
        print("[+] SAML config generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
