#!/usr/bin/env python3
"""NERC CIP Compliance Agent - audits critical infrastructure against NERC CIP standards."""

import json
import argparse
import logging
import subprocess
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NERC_CIP_CONTROLS = {
    "CIP-002": {"name": "BES Cyber System Categorization", "checks": [
        "asset_inventory_complete", "impact_ratings_assigned", "annual_review_documented"
    ]},
    "CIP-003": {"name": "Security Management Controls", "checks": [
        "cyber_security_policy_exists", "senior_manager_designated", "delegation_documented"
    ]},
    "CIP-004": {"name": "Personnel and Training", "checks": [
        "security_awareness_training", "role_based_training", "personnel_risk_assessment",
        "access_revocation_process"
    ]},
    "CIP-005": {"name": "Electronic Security Perimeters", "checks": [
        "esp_defined", "eap_controls_configured", "remote_access_encrypted",
        "interactive_remote_access_mfa"
    ]},
    "CIP-006": {"name": "Physical Security", "checks": [
        "physical_security_plan", "visitor_control_program", "psp_access_monitoring"
    ]},
    "CIP-007": {"name": "System Security Management", "checks": [
        "ports_services_minimized", "patch_management_process", "malware_prevention",
        "security_event_monitoring", "system_access_controls"
    ]},
    "CIP-008": {"name": "Incident Reporting and Response", "checks": [
        "incident_response_plan", "incident_response_testing", "reporting_procedures"
    ]},
    "CIP-009": {"name": "Recovery Plans", "checks": [
        "recovery_plans_exist", "backup_procedures", "recovery_testing_annual"
    ]},
    "CIP-010": {"name": "Configuration Change Management", "checks": [
        "baseline_configurations", "change_management_process", "vulnerability_assessments"
    ]},
    "CIP-011": {"name": "Information Protection", "checks": [
        "information_classification", "bcsi_protection", "bcsi_disposal"
    ]},
    "CIP-013": {"name": "Supply Chain Risk Management", "checks": [
        "supply_chain_plan", "vendor_risk_assessment", "vendor_notification_process"
    ]},
}


def check_esp_controls(target_ip=None):
    """Check Electronic Security Perimeter controls via network scan."""
    findings = []
    if target_ip:
        cmd = ["nmap", "-sS", "-p", "1-1024", "--open", target_ip, "-oX", "-"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        open_ports = result.stdout.count("state=\"open\"")
        if open_ports > 10:
            findings.append({"control": "CIP-005", "issue": f"{open_ports} open ports on ESP boundary",
                           "severity": "high"})
    return findings


def check_system_hardening():
    """Check CIP-007 system hardening controls."""
    findings = []
    svc_cmd = ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"]
    result = subprocess.run(svc_cmd, capture_output=True, text=True)
    service_count = len([l for l in result.stdout.split("\n") if ".service" in l])
    if service_count > 50:
        findings.append({"control": "CIP-007-R1", "issue": f"{service_count} running services (minimize unused)",
                        "severity": "medium"})
    patch_cmd = ["apt", "list", "--upgradable"] if subprocess.run(["which", "apt"], capture_output=True).returncode == 0 else ["yum", "check-update"]
    result = subprocess.run(patch_cmd, capture_output=True, text=True)
    pending = len([l for l in result.stdout.split("\n") if l.strip() and not l.startswith("Listing")])
    if pending > 0:
        findings.append({"control": "CIP-007-R2", "issue": f"{pending} pending security patches",
                        "severity": "high"})
    return findings


def audit_compliance_status(evidence_file=None):
    """Audit compliance status against all NERC CIP controls."""
    evidence = {}
    if evidence_file:
        with open(evidence_file) as f:
            evidence = json.load(f)
    results = {}
    for cip_id, control in NERC_CIP_CONTROLS.items():
        check_results = {}
        for check in control["checks"]:
            status = evidence.get(cip_id, {}).get(check, "not_assessed")
            check_results[check] = status
        passed = sum(1 for v in check_results.values() if v == "pass")
        total = len(check_results)
        results[cip_id] = {
            "name": control["name"],
            "checks": check_results,
            "passed": passed,
            "total": total,
            "compliance_rate": round(passed / max(total, 1) * 100, 1),
        }
    return results


def generate_report(compliance, esp_findings, hardening_findings):
    total_checks = sum(r["total"] for r in compliance.values())
    total_passed = sum(r["passed"] for r in compliance.values())
    all_findings = esp_findings + hardening_findings
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "framework": "NERC CIP v6/v7",
        "overall_compliance_rate": round(total_passed / max(total_checks, 1) * 100, 1),
        "total_controls_assessed": total_checks,
        "total_passed": total_passed,
        "cip_standard_results": compliance,
        "technical_findings": all_findings,
        "high_severity_findings": len([f for f in all_findings if f.get("severity") == "high"]),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="NERC CIP Compliance Audit Agent")
    parser.add_argument("--evidence-file", help="JSON evidence file with control assessment results")
    parser.add_argument("--target-ip", help="ESP boundary IP to scan")
    parser.add_argument("--skip-hardening", action="store_true", help="Skip system hardening checks")
    parser.add_argument("--output", default="nerc_cip_report.json")
    args = parser.parse_args()

    compliance = audit_compliance_status(args.evidence_file)
    esp_findings = check_esp_controls(args.target_ip) if args.target_ip else []
    hardening = check_system_hardening() if not args.skip_hardening else []
    report = generate_report(compliance, esp_findings, hardening)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("NERC CIP compliance: %.1f%% (%d/%d), %d findings",
                report["overall_compliance_rate"], report["total_passed"],
                report["total_controls_assessed"], len(report["technical_findings"]))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
