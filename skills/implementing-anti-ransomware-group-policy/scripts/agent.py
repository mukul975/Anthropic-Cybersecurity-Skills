#!/usr/bin/env python3
"""Anti-ransomware Group Policy audit and configuration agent.

Audits Windows endpoints for GPO-based ransomware defenses including AppLocker
rules, Controlled Folder Access, Attack Surface Reduction rules, and network
restriction settings. Generates compliance reports against recommended baselines.
"""

import json
import os
import subprocess
import sys
from datetime import datetime

APPLOCKER_DENY_PATHS = [
    "%USERPROFILE%\\AppData\\Local\\Temp\\*",
    "%USERPROFILE%\\AppData\\Roaming\\*",
    "%USERPROFILE%\\Downloads\\*",
    "%TEMP%\\*",
    "%USERPROFILE%\\Desktop\\*",
]

ASR_RULES = {
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": {
        "name": "Block executable content from email client and webmail",
        "recommended": "Block",
        "category": "Email protection",
    },
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": {
        "name": "Block all Office applications from creating child processes",
        "recommended": "Block",
        "category": "Office protection",
    },
    "3B576869-A4EC-4529-8536-B80A7769E899": {
        "name": "Block Office applications from creating executable content",
        "recommended": "Block",
        "category": "Office protection",
    },
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": {
        "name": "Block Office applications from injecting code into other processes",
        "recommended": "Block",
        "category": "Office protection",
    },
    "D3E037E1-3EB8-44C8-A917-57927947596D": {
        "name": "Block JavaScript or VBScript from launching downloaded executable content",
        "recommended": "Block",
        "category": "Script protection",
    },
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": {
        "name": "Block execution of potentially obfuscated scripts",
        "recommended": "Block",
        "category": "Script protection",
    },
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": {
        "name": "Block Win32 API calls from Office macros",
        "recommended": "Block",
        "category": "Macro protection",
    },
    "01443614-CD74-433A-B99E-2ECDC07BFC25": {
        "name": "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
        "recommended": "Block",
        "category": "Execution protection",
    },
}

CFA_RECOMMENDED_FOLDERS = [
    "Documents", "Desktop", "Pictures", "Videos", "Music", "Favorites",
]

GPO_CHECKS = {
    "applocker_enabled": {
        "description": "AppLocker Application Control is enabled",
        "check_command": ["powershell", "-Command",
                          "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | "
                          "ConvertTo-Json -Depth 3"],
        "priority": "Critical",
    },
    "cfa_enabled": {
        "description": "Controlled Folder Access is enabled",
        "check_command": ["powershell", "-Command",
                          "(Get-MpPreference).EnableControlledFolderAccess"],
        "priority": "Critical",
    },
    "asr_rules": {
        "description": "Attack Surface Reduction rules are configured",
        "check_command": ["powershell", "-Command",
                          "(Get-MpPreference).AttackSurfaceReductionRules_Ids"],
        "priority": "High",
    },
    "asr_actions": {
        "description": "ASR rule actions (0=Disabled,1=Block,2=Audit,6=Warn)",
        "check_command": ["powershell", "-Command",
                          "(Get-MpPreference).AttackSurfaceReductionRules_Actions"],
        "priority": "High",
    },
    "smbv1_disabled": {
        "description": "SMBv1 protocol is disabled",
        "check_command": ["powershell", "-Command",
                          "(Get-SmbServerConfiguration).EnableSMB1Protocol"],
        "priority": "Critical",
    },
    "autoplay_disabled": {
        "description": "AutoPlay is disabled",
        "check_command": ["powershell", "-Command",
                          "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows"
                          "\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun "
                          "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoDriveTypeAutoRun"],
        "priority": "Medium",
    },
}


def run_check(check_name, check_info):
    """Run a single GPO compliance check."""
    result = {
        "check": check_name,
        "description": check_info["description"],
        "priority": check_info["priority"],
        "status": "unknown",
        "output": "",
    }

    try:
        proc = subprocess.run(
            check_info["check_command"],
            capture_output=True, text=True, timeout=30,
        )
        output = proc.stdout.strip()
        result["output"] = output
        result["return_code"] = proc.returncode

        if proc.returncode != 0:
            result["status"] = "error"
            result["error"] = proc.stderr.strip()
        elif output:
            result["status"] = "data_retrieved"
        else:
            result["status"] = "empty_response"

    except FileNotFoundError:
        result["status"] = "not_available"
        result["error"] = "PowerShell not found or command not available"
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = "Check timed out after 30 seconds"

    return result


def assess_asr_compliance(asr_ids_output, asr_actions_output):
    """Assess ASR rule compliance against recommended baseline."""
    active_ids = [line.strip() for line in asr_ids_output.split("\n") if line.strip()]
    active_actions = [line.strip() for line in asr_actions_output.split("\n") if line.strip()]

    assessment = {"total_recommended": len(ASR_RULES), "enabled": 0,
                  "blocking": 0, "audit_only": 0, "missing": [], "details": []}

    id_action_map = {}
    for i, rule_id in enumerate(active_ids):
        action = active_actions[i] if i < len(active_actions) else "0"
        id_action_map[rule_id.upper()] = action

    for rule_id, rule_info in ASR_RULES.items():
        action = id_action_map.get(rule_id.upper(), None)
        if action is None:
            assessment["missing"].append({"id": rule_id, "name": rule_info["name"]})
            status = "NOT CONFIGURED"
        elif action == "1":
            assessment["enabled"] += 1
            assessment["blocking"] += 1
            status = "BLOCK"
        elif action == "2":
            assessment["enabled"] += 1
            assessment["audit_only"] += 1
            status = "AUDIT"
        elif action == "6":
            assessment["enabled"] += 1
            status = "WARN"
        else:
            status = "DISABLED"

        assessment["details"].append({
            "id": rule_id,
            "name": rule_info["name"],
            "category": rule_info["category"],
            "status": status,
            "recommended": rule_info["recommended"],
        })

    assessment["compliance_pct"] = round(
        (assessment["blocking"] / assessment["total_recommended"]) * 100, 1
    )
    return assessment


def generate_gpo_report():
    """Generate a full GPO anti-ransomware compliance report."""
    report = {
        "title": "Anti-Ransomware Group Policy Compliance Report",
        "generated": datetime.now().isoformat(),
        "hostname": os.environ.get("COMPUTERNAME", "unknown"),
        "checks": {},
        "overall_score": 0,
    }

    print("[*] Running GPO compliance checks...")
    for check_name, check_info in GPO_CHECKS.items():
        print(f"  Checking: {check_info['description']}...")
        result = run_check(check_name, check_info)
        report["checks"][check_name] = result

    # ASR compliance assessment
    asr_ids = report["checks"].get("asr_rules", {}).get("output", "")
    asr_actions = report["checks"].get("asr_actions", {}).get("output", "")
    if asr_ids:
        report["asr_assessment"] = assess_asr_compliance(asr_ids, asr_actions)

    # Calculate overall score
    score = 0
    total = len(GPO_CHECKS)
    for check_name, result in report["checks"].items():
        if result["status"] == "data_retrieved" and result.get("output"):
            score += 1
    report["overall_score"] = round((score / total) * 100, 1)

    return report


def generate_remediation_script(report):
    """Generate PowerShell remediation commands for failed checks."""
    lines = [
        "# Anti-Ransomware GPO Remediation Script",
        "# Generated: " + datetime.now().isoformat(),
        "# Run as Administrator in elevated PowerShell",
        "",
    ]

    cfa = report.get("checks", {}).get("cfa_enabled", {})
    if cfa.get("output", "").strip() != "1":
        lines.append("# Enable Controlled Folder Access")
        lines.append("Set-MpPreference -EnableControlledFolderAccess Enabled")
        lines.append("")

    smbv1 = report.get("checks", {}).get("smbv1_disabled", {})
    if smbv1.get("output", "").strip().lower() == "true":
        lines.append("# Disable SMBv1")
        lines.append("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")
        lines.append("")

    asr = report.get("asr_assessment", {})
    for rule in asr.get("details", []):
        if rule["status"] in ("NOT CONFIGURED", "DISABLED", "AUDIT"):
            lines.append(f"# Enable ASR rule: {rule['name']}")
            lines.append(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {rule['id']} "
                          f"-AttackSurfaceReductionRules_Actions Enabled")
            lines.append("")

    lines.append("# Disable AutoPlay")
    lines.append('Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion'
                  '\\Policies\\Explorer" -Name NoDriveTypeAutoRun -Value 255')

    return "\n".join(lines)


if __name__ == "__main__":
    print("=" * 60)
    print("Anti-Ransomware Group Policy Audit Agent")
    print("AppLocker, CFA, ASR rules, network restrictions")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python agent.py audit              Run full GPO compliance audit")
        print("  python agent.py asr                Check ASR rule status only")
        print("  python agent.py remediate          Generate remediation script")
        print("  python agent.py baseline           Show recommended baseline")
        sys.exit(0)

    command = sys.argv[1]

    if command == "audit":
        report = generate_gpo_report()
        print("\n--- GPO Compliance Report ---")
        print(f"  Hostname: {report['hostname']}")
        print(f"  Overall Score: {report['overall_score']}%")
        for name, result in report["checks"].items():
            status = result["status"]
            icon = "[+]" if status == "data_retrieved" else "[!]"
            print(f"  {icon} {result['description']}: {status}")
        output_file = "gpo_audit_report.json"
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Full report saved to: {output_file}")

    elif command == "asr":
        print("\n--- Recommended ASR Rules for Ransomware Prevention ---")
        for rule_id, rule in ASR_RULES.items():
            print(f"  [{rule['category']:20s}] {rule['name']}")
            print(f"    GUID: {rule_id}")
            print(f"    Recommended: {rule['recommended']}")

    elif command == "remediate":
        report = generate_gpo_report()
        script = generate_remediation_script(report)
        output_file = "remediate_ransomware_gpo.ps1"
        with open(output_file, "w") as f:
            f.write(script)
        print(f"\n[+] Remediation script saved to: {output_file}")
        print(f"\n{script}")

    elif command == "baseline":
        print("\n--- Recommended Anti-Ransomware GPO Baseline ---")
        print("\nAppLocker Deny Paths:")
        for path in APPLOCKER_DENY_PATHS:
            print(f"  DENY: {path}")
        print(f"\nASR Rules ({len(ASR_RULES)} recommended):")
        for rule_id, rule in ASR_RULES.items():
            print(f"  {rule_id}: {rule['name']}")
        print("\nControlled Folder Access Protected Folders:")
        for folder in CFA_RECOMMENDED_FOLDERS:
            print(f"  {folder}")

    else:
        print(f"[!] Unknown command: {command}")
