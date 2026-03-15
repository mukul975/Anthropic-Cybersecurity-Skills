#!/usr/bin/env python3
"""Agent for auditing Windows endpoints against CIS Benchmark hardening controls."""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_ps(command, timeout=15):
    """Run PowerShell command and return output."""
    try:
        return subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", command],
            text=True, errors="replace", timeout=timeout
        ).strip()
    except subprocess.SubprocessError:
        return ""


def check_password_policy():
    """CIS 1.1 — Password Policy."""
    findings = []
    result = run_ps("net accounts")
    for line in result.splitlines():
        if "Minimum password length" in line:
            val = int(line.split(":")[-1].strip())
            if val < 14:
                findings.append({"check": "1.1.4", "issue": f"Min password length: {val} (should be >= 14)", "severity": "HIGH"})
        if "Maximum password age" in line:
            val = line.split(":")[-1].strip()
            if val == "Unlimited":
                findings.append({"check": "1.1.2", "issue": "No max password age", "severity": "MEDIUM"})
        if "Lockout threshold" in line:
            val = line.split(":")[-1].strip()
            if val == "Never" or (val.isdigit() and int(val) > 10):
                findings.append({"check": "1.2.1", "issue": f"Account lockout threshold: {val}", "severity": "MEDIUM"})
    return findings


def check_audit_policy():
    """CIS 17 — Advanced Audit Policy."""
    findings = []
    result = run_ps("auditpol /get /category:*")
    required_audits = {
        "Credential Validation": "Success and Failure",
        "Logon": "Success and Failure",
        "Security Group Management": "Success",
        "User Account Management": "Success and Failure",
        "Process Creation": "Success",
    }
    for subcategory, expected in required_audits.items():
        if subcategory in result:
            for line in result.splitlines():
                if subcategory in line:
                    if "No Auditing" in line:
                        findings.append({
                            "check": "17.x", "issue": f"Audit not configured: {subcategory}",
                            "severity": "HIGH",
                        })
    return findings


def check_windows_firewall():
    """CIS 9 — Windows Firewall."""
    findings = []
    profiles = ["Domain", "Private", "Public"]
    for profile in profiles:
        result = run_ps(f"Get-NetFirewallProfile -Name {profile} | Select-Object Enabled | ConvertTo-Json")
        try:
            data = json.loads(result) if result else {}
            if not data.get("Enabled"):
                findings.append({"check": "9.1", "issue": f"Firewall {profile} profile disabled", "severity": "HIGH"})
        except json.JSONDecodeError:
            pass
    return findings


def check_security_options():
    """CIS 2.3 — Security Options."""
    findings = []
    checks = [
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "LmCompatibilityLevel", 5,
         "2.3.11.7", "LAN Manager auth level not NTLMv2 only"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", 1,
         "2.3.17.1", "UAC not enabled"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters", "SMB1", 0,
         "18.3.2", "SMBv1 not disabled"),
    ]
    for path, name, expected, cis_id, desc in checks:
        result = run_ps(
            f"(Get-ItemProperty -Path '{path}' -Name '{name}' -ErrorAction SilentlyContinue).{name}"
        )
        if result.strip().isdigit() and int(result.strip()) != expected:
            findings.append({"check": cis_id, "issue": desc, "current": result.strip(), "severity": "HIGH"})
    return findings


def check_windows_features():
    """CIS 18 — Windows Features."""
    findings = []
    risky_features = ["SMB1Protocol", "TelnetClient", "TFTP"]
    for feature in risky_features:
        result = run_ps(
            f"Get-WindowsOptionalFeature -Online -FeatureName {feature} 2>$null | "
            f"Select-Object State | ConvertTo-Json"
        )
        try:
            data = json.loads(result) if result else {}
            if data.get("State") == 1:  # Enabled
                findings.append({"check": "18.x", "issue": f"Risky feature enabled: {feature}", "severity": "MEDIUM"})
        except json.JSONDecodeError:
            pass
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Audit Windows endpoint against CIS Benchmark"
    )
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] Windows CIS Benchmark Hardening Audit Agent")
    if sys.platform != "win32":
        print("[!] This agent requires Windows")
        return

    all_findings = []
    all_findings.extend(check_password_policy())
    all_findings.extend(check_audit_policy())
    all_findings.extend(check_windows_firewall())
    all_findings.extend(check_security_options())
    all_findings.extend(check_windows_features())

    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": all_findings,
        "total": len(all_findings),
        "high_severity": high,
        "compliance_score": max(0, 100 - len(all_findings) * 5),
    }
    print(f"[*] Findings: {len(all_findings)} (HIGH: {high})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
