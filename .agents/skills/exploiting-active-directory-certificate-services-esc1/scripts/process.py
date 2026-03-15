#!/usr/bin/env python3
"""
AD CS ESC1 Vulnerability Assessment Script

Parses Certipy output to identify ESC1-vulnerable certificate templates
and generates an assessment report. For authorized red team engagements only.
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path


ESC1_DANGEROUS_EKUS = [
    "1.3.6.1.5.5.7.3.2",    # Client Authentication
    "1.3.6.1.5.2.3.4",      # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "2.5.29.37.0",           # Any Purpose
]

EKU_NAMES = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
}


def load_certipy_output(filepath: str) -> dict:
    """Load Certipy JSON output file."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading Certipy output: {e}")
        return {}


def check_esc1_conditions(template: dict) -> dict:
    """Check if a certificate template is vulnerable to ESC1."""
    result = {
        "template_name": template.get("Template Name", template.get("name", "Unknown")),
        "vulnerable": False,
        "conditions_met": [],
        "conditions_not_met": [],
        "risk_level": "low"
    }

    # Condition 1: ENROLLEE_SUPPLIES_SUBJECT flag
    name_flag = template.get("msPKI-Certificate-Name-Flag", "")
    enrollee_supplies = False
    if isinstance(name_flag, str):
        enrollee_supplies = "ENROLLEE_SUPPLIES_SUBJECT" in name_flag.upper()
    elif isinstance(name_flag, int):
        enrollee_supplies = (name_flag & 1) != 0

    if enrollee_supplies:
        result["conditions_met"].append("ENROLLEE_SUPPLIES_SUBJECT enabled")
    else:
        result["conditions_not_met"].append("ENROLLEE_SUPPLIES_SUBJECT not enabled")

    # Condition 2: Client Authentication EKU
    ekus = template.get("pkiExtendedKeyUsage", template.get("Extended Key Usage", []))
    if isinstance(ekus, str):
        ekus = [ekus]
    has_auth_eku = any(eku in ESC1_DANGEROUS_EKUS for eku in ekus)
    no_ekus = len(ekus) == 0  # No EKU = any purpose

    if has_auth_eku or no_ekus:
        eku_desc = "No EKU (any purpose)" if no_ekus else "Client Authentication EKU present"
        result["conditions_met"].append(eku_desc)
    else:
        result["conditions_not_met"].append("No authentication-capable EKU")

    # Condition 3: Enrollment rights for low-privileged users
    enrollment_rights = template.get("Enrollment Rights", template.get("permissions", {}))
    low_priv_enroll = False
    low_priv_groups = [
        "Domain Users", "Authenticated Users", "Everyone",
        "Domain Computers", "Users"
    ]

    if isinstance(enrollment_rights, dict):
        for entity, rights in enrollment_rights.items():
            if any(group.lower() in entity.lower() for group in low_priv_groups):
                if "Enroll" in str(rights):
                    low_priv_enroll = True
                    break
    elif isinstance(enrollment_rights, list):
        for entry in enrollment_rights:
            if any(group.lower() in str(entry).lower() for group in low_priv_groups):
                low_priv_enroll = True
                break

    if low_priv_enroll:
        result["conditions_met"].append("Low-privileged group has Enroll rights")
    else:
        result["conditions_not_met"].append("No low-privileged enrollment rights found")

    # Condition 4: No manager approval
    enrollment_flag = template.get("msPKI-Enrollment-Flag", 0)
    requires_approval = False
    if isinstance(enrollment_flag, int):
        requires_approval = (enrollment_flag & 2) != 0  # CT_FLAG_PEND_ALL_REQUESTS
    elif isinstance(enrollment_flag, str):
        requires_approval = "PEND_ALL_REQUESTS" in enrollment_flag.upper()

    if not requires_approval:
        result["conditions_met"].append("No manager approval required")
    else:
        result["conditions_not_met"].append("Manager approval required")

    # Determine vulnerability
    if enrollee_supplies and (has_auth_eku or no_ekus) and low_priv_enroll and not requires_approval:
        result["vulnerable"] = True
        result["risk_level"] = "critical"
    elif enrollee_supplies and (has_auth_eku or no_ekus):
        result["risk_level"] = "high"

    return result


def generate_esc1_report(certipy_data: dict) -> str:
    """Generate ESC1 vulnerability assessment report."""
    report_lines = [
        "=" * 70,
        "AD CS ESC1 Vulnerability Assessment Report",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 70,
        ""
    ]

    templates = certipy_data.get("Certificate Templates", {})
    if not templates:
        templates = certipy_data.get("templates", {})

    vulnerable_templates = []
    high_risk_templates = []

    for name, template_data in templates.items():
        if isinstance(template_data, dict):
            template_data["name"] = name
            assessment = check_esc1_conditions(template_data)

            if assessment["vulnerable"]:
                vulnerable_templates.append(assessment)
            elif assessment["risk_level"] == "high":
                high_risk_templates.append(assessment)

    report_lines.append(f"Total Templates Analyzed: {len(templates)}")
    report_lines.append(f"ESC1 Vulnerable (Critical): {len(vulnerable_templates)}")
    report_lines.append(f"Partially Vulnerable (High): {len(high_risk_templates)}")
    report_lines.append("")

    if vulnerable_templates:
        report_lines.append("[CRITICAL] ESC1 Vulnerable Templates:")
        report_lines.append("-" * 50)
        for t in vulnerable_templates:
            report_lines.append(f"  Template: {t['template_name']}")
            report_lines.append(f"  Risk Level: {t['risk_level'].upper()}")
            report_lines.append("  Conditions Met:")
            for cond in t["conditions_met"]:
                report_lines.append(f"    [+] {cond}")
            report_lines.append("")

    if high_risk_templates:
        report_lines.append("[HIGH] Partially Vulnerable Templates:")
        report_lines.append("-" * 50)
        for t in high_risk_templates:
            report_lines.append(f"  Template: {t['template_name']}")
            report_lines.append("  Conditions Met:")
            for cond in t["conditions_met"]:
                report_lines.append(f"    [+] {cond}")
            report_lines.append("  Conditions Not Met:")
            for cond in t["conditions_not_met"]:
                report_lines.append(f"    [-] {cond}")
            report_lines.append("")

    report_lines.append("=" * 70)
    report_lines.append("Remediation Recommendations:")
    report_lines.append("  1. Disable ENROLLEE_SUPPLIES_SUBJECT on all vulnerable templates")
    report_lines.append("  2. Enable manager approval for certificate issuance")
    report_lines.append("  3. Restrict enrollment rights to specific security groups")
    report_lines.append("  4. Enable CA audit logging (Event IDs 4886, 4887)")
    report_lines.append("  5. Monitor for certificates with mismatched SAN fields")
    report_lines.append("=" * 70)

    return "\n".join(report_lines)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python process.py <certipy_output.json>")
        print("  Parses Certipy JSON output and identifies ESC1 vulnerabilities")
        return

    certipy_file = sys.argv[1]
    certipy_data = load_certipy_output(certipy_file)

    if not certipy_data:
        print("No data loaded. Ensure the file is valid Certipy JSON output.")
        return

    report = generate_esc1_report(certipy_data)
    print(report)

    report_file = f"esc1_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
