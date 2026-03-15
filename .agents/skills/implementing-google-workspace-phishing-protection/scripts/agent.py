#!/usr/bin/env python3
"""Agent for auditing Google Workspace phishing and malware protection settings."""

import json
import argparse
import subprocess
from datetime import datetime
from collections import Counter


def gam_command(args_list):
    """Run a GAM (Google Apps Manager) command."""
    cmd = ["gam"] + args_list
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def get_gmail_safety_settings(domain):
    """Retrieve Gmail safety settings via Admin SDK (simulated via GAM)."""
    stdout, stderr, rc = gam_command(["print", "gmailsettings", "domain", domain])
    if rc != 0:
        return {"error": stderr}
    return {"raw_settings": stdout}


def audit_phishing_protection(config_path):
    """Audit Google Workspace phishing protection configuration."""
    with open(config_path) as f:
        config = json.load(f)
    findings = []
    safety = config.get("gmail_safety", config.get("safety_settings", {}))

    checks = {
        "spoofing_similar_domains": {
            "key": "protect_against_similar_domain_spoofing",
            "description": "Protect against domain spoofing (similar names)",
            "severity": "HIGH",
        },
        "employee_name_spoofing": {
            "key": "protect_against_employee_name_spoofing",
            "description": "Protect against employee name spoofing",
            "severity": "HIGH",
        },
        "inbound_domain_spoofing": {
            "key": "protect_against_inbound_domain_spoofing",
            "description": "Protect against inbound domain spoofing",
            "severity": "CRITICAL",
        },
        "enhanced_pre_delivery_scanning": {
            "key": "enhanced_pre_delivery_scanning",
            "description": "Enhanced pre-delivery message scanning",
            "severity": "HIGH",
        },
        "attachment_protection": {
            "key": "attachment_protection_enabled",
            "description": "Attachment protection (encrypted/scripts)",
            "severity": "HIGH",
        },
        "links_and_external_images": {
            "key": "identify_links_behind_shortened_urls",
            "description": "Identify links behind shortened URLs",
            "severity": "MEDIUM",
        },
        "unauthenticated_email_warning": {
            "key": "show_warning_for_unauthenticated_email",
            "description": "Show warning for unauthenticated emails",
            "severity": "MEDIUM",
        },
        "safe_browsing_enhanced": {
            "key": "enhanced_safe_browsing",
            "description": "Enhanced Safe Browsing enabled",
            "severity": "HIGH",
        },
    }

    for check_name, check_info in checks.items():
        enabled = safety.get(check_info["key"], False)
        findings.append({
            "control": check_info["description"],
            "enabled": enabled,
            "status": "COMPLIANT" if enabled else "NON_COMPLIANT",
            "severity": "INFO" if enabled else check_info["severity"],
        })

    quarantine = safety.get("quarantine_action", "")
    if quarantine not in ("quarantine", "reject"):
        findings.append({
            "control": "Quarantine action for detected threats",
            "current": quarantine or "not configured",
            "status": "NON_COMPLIANT",
            "severity": "HIGH",
            "recommendation": "Set action to quarantine or reject",
        })

    return findings


def audit_dmarc_alignment(dmarc_report_path):
    """Analyze DMARC aggregate report for alignment issues."""
    with open(dmarc_report_path) as f:
        report = json.load(f)
    records = report if isinstance(report, list) else report.get("records", [])
    total = len(records)
    aligned = sum(1 for r in records if r.get("dkim_aligned") and r.get("spf_aligned"))
    failures = [r for r in records if not r.get("dkim_aligned") or not r.get("spf_aligned")]
    return {
        "total_records": total,
        "aligned": aligned,
        "alignment_rate": round(aligned / total * 100, 1) if total else 0,
        "top_failures": failures[:10],
    }


def analyze_phishing_incidents(incident_log_path):
    """Analyze phishing incident log for patterns."""
    with open(incident_log_path) as f:
        incidents = json.load(f)
    items = incidents if isinstance(incidents, list) else incidents.get("incidents", [])
    by_type = Counter(i.get("type", "unknown") for i in items)
    by_action = Counter(i.get("action_taken", "unknown") for i in items)
    clicked = sum(1 for i in items if i.get("user_clicked", False))
    reported = sum(1 for i in items if i.get("user_reported", False))
    return {
        "total_incidents": len(items),
        "by_type": dict(by_type),
        "by_action": dict(by_action),
        "click_rate": round(clicked / len(items) * 100, 1) if items else 0,
        "report_rate": round(reported / len(items) * 100, 1) if items else 0,
    }


def generate_recommended_settings():
    """Generate recommended Google Workspace phishing protection settings."""
    return {
        "gmail_safety": {
            "protect_against_similar_domain_spoofing": True,
            "protect_against_employee_name_spoofing": True,
            "protect_against_inbound_domain_spoofing": True,
            "enhanced_pre_delivery_scanning": True,
            "attachment_protection_enabled": True,
            "identify_links_behind_shortened_urls": True,
            "scan_linked_images": True,
            "show_warning_for_unauthenticated_email": True,
            "enhanced_safe_browsing": True,
            "quarantine_action": "quarantine",
            "move_to_spam_on_spoofing": True,
        },
        "advanced_protection_program": {
            "enabled_for_high_privilege_users": True,
            "target_groups": ["executives", "finance", "it-admins"],
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Google Workspace Phishing Protection Agent")
    parser.add_argument("--config", help="Workspace safety config JSON to audit")
    parser.add_argument("--dmarc-report", help="DMARC aggregate report JSON")
    parser.add_argument("--incidents", help="Phishing incident log JSON")
    parser.add_argument("--action", choices=["audit", "dmarc", "incidents",
                                              "recommend", "full"], default="full")
    parser.add_argument("--output", default="gws_phishing_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("audit", "full") and args.config:
        findings = audit_phishing_protection(args.config)
        report["results"]["audit"] = findings
        non_comp = sum(1 for f in findings if f.get("status") == "NON_COMPLIANT")
        print(f"[+] Audit: {len(findings)} controls, {non_comp} non-compliant")

    if args.action in ("dmarc", "full") and args.dmarc_report:
        result = audit_dmarc_alignment(args.dmarc_report)
        report["results"]["dmarc"] = result
        print(f"[+] DMARC alignment: {result['alignment_rate']}%")

    if args.action in ("incidents", "full") and args.incidents:
        result = analyze_phishing_incidents(args.incidents)
        report["results"]["incidents"] = result
        print(f"[+] Incidents: {result['total_incidents']}, click rate: {result['click_rate']}%")

    if args.action in ("recommend", "full"):
        settings = generate_recommended_settings()
        report["results"]["recommended"] = settings
        print("[+] Recommended settings generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
