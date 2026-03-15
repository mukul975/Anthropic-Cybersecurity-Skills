#!/usr/bin/env python3
"""Agent for performing power grid cybersecurity assessment based on NERC CIP standards."""

import json
import argparse
import csv
from datetime import datetime
from pathlib import Path


NERC_CIP_STANDARDS = {
    "CIP-002": {"title": "BES Cyber System Categorization", "checks": [
        "All BES cyber systems identified and categorized",
        "Impact ratings (High/Medium/Low) assigned to all assets",
        "Annual review of BES cyber system list completed",
    ]},
    "CIP-003": {"title": "Security Management Controls", "checks": [
        "Cybersecurity policy documented and approved",
        "Senior manager designated for CIP compliance",
        "Annual policy review completed",
    ]},
    "CIP-004": {"title": "Personnel & Training", "checks": [
        "Security awareness training completed for all personnel",
        "Background checks on personnel with authorized access",
        "Access revocation within 24 hours of termination",
    ]},
    "CIP-005": {"title": "Electronic Security Perimeter", "checks": [
        "Electronic Security Perimeter (ESP) defined",
        "All external routable connectivity through EAP",
        "Inbound/outbound access permissions documented",
        "Interactive remote access uses encryption and MFA",
    ]},
    "CIP-006": {"title": "Physical Security", "checks": [
        "Physical Security Perimeter (PSP) defined",
        "Physical access control systems operational",
        "Visitor escort and logging procedures in place",
    ]},
    "CIP-007": {"title": "System Security Management", "checks": [
        "Ports and services documentation current",
        "Security patches evaluated within 35 days",
        "Malicious code prevention deployed",
        "Security event monitoring enabled",
    ]},
    "CIP-008": {"title": "Incident Reporting", "checks": [
        "Cyber security incident response plan documented",
        "Incident response plan tested annually",
        "Reportable incidents notified to E-ISAC within 1 hour",
    ]},
    "CIP-009": {"title": "Recovery Plans", "checks": [
        "Recovery plans for BES cyber systems documented",
        "Recovery plans tested annually",
        "Backup media stored securely",
    ]},
    "CIP-010": {"title": "Configuration Change Management", "checks": [
        "Baseline configurations documented",
        "Change management process for cyber systems",
        "Vulnerability assessments performed at least every 15 months",
    ]},
    "CIP-011": {"title": "Information Protection", "checks": [
        "BES Cyber System Information (BCSI) identified",
        "BCSI storage locations protected",
        "BCSI disposal procedures documented",
    ]},
    "CIP-013": {"title": "Supply Chain Risk Management", "checks": [
        "Supply chain risk management plan documented",
        "Vendor risk assessments performed",
        "Software integrity verification procedures",
    ]},
}


def generate_assessment_template(output_file=None):
    """Generate NERC CIP compliance assessment template."""
    rows = []
    for std_id, std in NERC_CIP_STANDARDS.items():
        for i, check in enumerate(std["checks"], 1):
            rows.append({
                "standard": std_id, "title": std["title"],
                "check_id": f"{std_id}-{i:02d}", "requirement": check,
                "status": "", "evidence": "", "gap": "", "remediation": "",
            })
    if output_file:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    return {"total_checks": len(rows), "standards": list(NERC_CIP_STANDARDS.keys()), "output": output_file}


def assess_compliance(assessment_csv):
    """Score NERC CIP compliance from completed assessment."""
    with open(assessment_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    by_standard = {}
    total_pass = 0
    total_fail = 0
    for row in rows:
        std = row.get("standard", "")
        status = row.get("status", "").lower()
        is_pass = status in ("pass", "compliant", "yes", "met")
        is_fail = status in ("fail", "non-compliant", "no", "not met", "gap")
        by_standard.setdefault(std, {"pass": 0, "fail": 0, "total": 0})
        by_standard[std]["total"] += 1
        if is_pass:
            by_standard[std]["pass"] += 1
            total_pass += 1
        elif is_fail:
            by_standard[std]["fail"] += 1
            total_fail += 1
    for std in by_standard:
        d = by_standard[std]
        d["compliance_pct"] = round(d["pass"] / max(d["total"], 1) * 100, 1)
    gaps = [row for row in rows if row.get("status", "").lower() in ("fail", "non-compliant", "no", "not met", "gap")]
    return {
        "total_requirements": len(rows), "passed": total_pass, "failed": total_fail,
        "overall_compliance": round(total_pass / max(len(rows), 1) * 100, 1),
        "by_standard": by_standard,
        "gaps": [{"standard": g.get("standard"), "check": g.get("check_id"),
                  "requirement": g.get("requirement", "")[:150],
                  "gap": g.get("gap", "")[:150]} for g in gaps[:20]],
    }


def assess_esp_security(firewall_csv):
    """Assess Electronic Security Perimeter configuration."""
    with open(firewall_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rules = list(reader)
    findings = []
    for rule in rules:
        action = rule.get("action", "").lower()
        src = rule.get("source", rule.get("src", ""))
        dst = rule.get("destination", rule.get("dst", ""))
        if action == "allow" and src.lower() in ("any", "0.0.0.0/0"):
            findings.append({"rule": rule.get("id", rule.get("name", "")), "issue": "ALLOW_FROM_ANY", "severity": "CRITICAL"})
        if action == "allow" and rule.get("protocol", "").lower() in ("any", "all"):
            findings.append({"rule": rule.get("id", ""), "issue": "ALLOW_ANY_PROTOCOL", "severity": "HIGH"})
    has_default_deny = any(r.get("action", "").lower() in ("deny", "drop") and r.get("source", "").lower() in ("any", "0.0.0.0/0")
                          for r in rules)
    if not has_default_deny:
        findings.append({"issue": "NO_DEFAULT_DENY", "severity": "CRITICAL"})
    return {
        "total_rules": len(rules),
        "findings": findings[:20],
        "default_deny": has_default_deny,
        "esp_compliance": "PASS" if not findings else "FAIL",
    }


def main():
    parser = argparse.ArgumentParser(description="Power Grid Cybersecurity Assessment Agent (NERC CIP)")
    sub = parser.add_subparsers(dest="command")
    t = sub.add_parser("template", help="Generate NERC CIP assessment template")
    t.add_argument("--output", help="Output CSV file")
    a = sub.add_parser("assess", help="Score compliance assessment")
    a.add_argument("--csv", required=True)
    e = sub.add_parser("esp", help="Assess Electronic Security Perimeter")
    e.add_argument("--firewall-csv", required=True)
    args = parser.parse_args()
    if args.command == "template":
        result = generate_assessment_template(args.output)
    elif args.command == "assess":
        result = assess_compliance(args.csv)
    elif args.command == "esp":
        result = assess_esp_security(args.firewall_csv)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
