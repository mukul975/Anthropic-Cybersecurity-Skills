#!/usr/bin/env python3
"""Agent for implementing and auditing Privileged Access Workstation (PAW) configurations."""

import json
import argparse
import subprocess
import re
from datetime import datetime


def check_device_hardening():
    """Audit local device hardening controls for PAW compliance."""
    checks = {}
    hardening_cmds = {
        "credential_guard": ["powershell", "-Command",
            "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).SecurityServicesRunning"],
        "vbs_status": ["powershell", "-Command",
            "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).VirtualizationBasedSecurityStatus"],
        "secure_boot": ["powershell", "-Command", "Confirm-SecureBootUEFI"],
        "bitlocker": ["powershell", "-Command",
            "(Get-BitLockerVolume -MountPoint C:).ProtectionStatus"],
        "applocker_status": ["powershell", "-Command",
            "(Get-AppLockerPolicy -Effective -Xml | Select-String 'RuleCollection').Count"],
        "firewall_enabled": ["powershell", "-Command",
            "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}).Name -join ','"],
        "uac_level": ["reg", "query",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "/v", "ConsentPromptBehaviorAdmin"],
    }
    for name, cmd in hardening_cmds.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout.strip()
            checks[name] = {"value": output, "status": "PASS" if output and output not in ("0", "False", "") else "FAIL"}
        except Exception as e:
            checks[name] = {"value": str(e), "status": "ERROR"}
    passed = sum(1 for c in checks.values() if c["status"] == "PASS")
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
        "passed": passed,
        "total": len(checks),
        "compliance_pct": round(passed / len(checks) * 100, 1),
        "risk": "LOW" if passed >= 6 else "MEDIUM" if passed >= 4 else "HIGH",
    }


def check_local_admin_group():
    """Enumerate local Administrators group membership for JIT audit."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass,PrincipalSource | ConvertTo-Json"],
            capture_output=True, text=True, timeout=15)
        members = json.loads(result.stdout) if result.stdout.strip() else []
        if isinstance(members, dict):
            members = [members]
        expected_admins = ["Administrator", "Domain Admins"]
        unexpected = [m for m in members if not any(e in m.get("Name", "") for e in expected_admins)]
        return {
            "total_members": len(members),
            "members": members,
            "unexpected_admins": unexpected,
            "jit_finding": "UNEXPECTED_ADMINS" if unexpected else "CLEAN",
            "severity": "HIGH" if unexpected else "INFO",
        }
    except Exception as e:
        return {"error": str(e)}


def check_installed_software():
    """Audit installed software against PAW allowlist."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
             "Select-Object DisplayName,Publisher,InstallDate | Where-Object {$_.DisplayName -ne $null} | "
             "ConvertTo-Json -Depth 2"],
            capture_output=True, text=True, timeout=30)
        software = json.loads(result.stdout) if result.stdout.strip() else []
        if isinstance(software, dict):
            software = [software]
        blocked_patterns = [
            "chrome", "firefox", "spotify", "steam", "vlc", "zoom", "slack",
            "dropbox", "onedrive personal", "itunes", "whatsapp", "telegram",
        ]
        violations = []
        for sw in software:
            name = (sw.get("DisplayName") or "").lower()
            if any(p in name for p in blocked_patterns):
                violations.append({"name": sw.get("DisplayName"), "publisher": sw.get("Publisher")})
        return {
            "total_installed": len(software),
            "paw_violations": len(violations),
            "violations": violations[:20],
            "finding": "BLOCKED_SOFTWARE_FOUND" if violations else "COMPLIANT",
        }
    except Exception as e:
        return {"error": str(e)}


def check_network_restrictions():
    """Verify PAW network isolation and restrictions."""
    checks = {}
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block'} | "
             "Measure-Object | Select-Object -ExpandProperty Count"],
            capture_output=True, text=True, timeout=15)
        checks["outbound_block_rules"] = int(result.stdout.strip() or 0)
    except Exception:
        checks["outbound_block_rules"] = 0
    try:
        result = subprocess.run(["powershell", "-Command",
            "Test-NetConnection -ComputerName google.com -Port 80 -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded | ConvertTo-Json"],
            capture_output=True, text=True, timeout=15)
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        checks["internet_access"] = data.get("TcpTestSucceeded", True)
    except Exception:
        checks["internet_access"] = "unknown"
    paw_should_block_internet = checks.get("internet_access") is False
    return {
        "network_checks": checks,
        "internet_blocked": paw_should_block_internet,
        "finding": "INTERNET_BLOCKED" if paw_should_block_internet else "INTERNET_ALLOWED",
        "severity": "INFO" if paw_should_block_internet else "MEDIUM",
        "recommendation": "PAW Tier 0 should block general internet — restrict to management endpoints only",
    }


def full_paw_audit():
    """Run comprehensive PAW compliance audit."""
    return {
        "audit_type": "Privileged Access Workstation",
        "timestamp": datetime.utcnow().isoformat(),
        "device_hardening": check_device_hardening(),
        "admin_group": check_local_admin_group(),
        "software_compliance": check_installed_software(),
        "network_isolation": check_network_restrictions(),
    }


def main():
    parser = argparse.ArgumentParser(description="Privileged Access Workstation Audit Agent")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("harden", help="Check device hardening controls")
    sub.add_parser("admins", help="Audit local admin group membership")
    sub.add_parser("software", help="Check installed software against allowlist")
    sub.add_parser("network", help="Verify network isolation")
    sub.add_parser("full", help="Full PAW compliance audit")
    args = parser.parse_args()
    if args.command == "harden":
        result = check_device_hardening()
    elif args.command == "admins":
        result = check_local_admin_group()
    elif args.command == "software":
        result = check_installed_software()
    elif args.command == "network":
        result = check_network_restrictions()
    elif args.command == "full":
        result = full_paw_audit()
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
