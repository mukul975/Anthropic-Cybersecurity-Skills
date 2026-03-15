#!/usr/bin/env python3
"""Windows event logging configuration audit agent."""

import json
import sys
import argparse
import subprocess
from datetime import datetime


CRITICAL_AUDIT_POLICIES = {
    "Logon/Logoff": {"Logon": "Success,Failure", "Logoff": "Success"},
    "Account Logon": {"Credential Validation": "Success,Failure", "Kerberos Authentication Service": "Success,Failure"},
    "Object Access": {"File System": "Success,Failure", "Registry": "Success,Failure"},
    "Privilege Use": {"Sensitive Privilege Use": "Success,Failure"},
    "Process Tracking": {"Process Creation": "Success"},
    "DS Access": {"Directory Service Access": "Success,Failure"},
    "Policy Change": {"Audit Policy Change": "Success,Failure", "Authentication Policy Change": "Success"},
}


def get_audit_policy():
    """Get current advanced audit policy configuration."""
    cmd = ["auditpol", "/get", "/category:*"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        lines = result.stdout.strip().split("\n")
        policies = {}
        current_category = ""
        for line in lines:
            stripped = line.strip()
            if not stripped or "Machine Name" in stripped or "Category" in stripped:
                continue
            if not stripped.startswith("  "):
                current_category = stripped
                policies[current_category] = {}
            else:
                parts = stripped.rsplit("  ", 1)
                if len(parts) == 2:
                    policies[current_category][parts[0].strip()] = parts[1].strip()
        return policies
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}


def check_sysmon_installed():
    """Check if Sysmon is installed and running."""
    cmd = ["powershell", "-Command", "Get-Service Sysmon* | ConvertTo-Json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.stdout.strip():
            service = json.loads(result.stdout)
            if isinstance(service, list):
                service = service[0]
            return {"installed": True, "status": service.get("Status", ""),
                    "name": service.get("Name", "")}
        return {"installed": False, "severity": "HIGH",
                "recommendation": "Install Sysmon with SwiftOnSecurity config"}
    except (FileNotFoundError, json.JSONDecodeError):
        return {"installed": False}


def check_log_sizes():
    """Check event log maximum sizes."""
    logs = ["Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational"]
    results = []
    for log_name in logs:
        cmd = ["powershell", "-Command",
               f"(Get-WinEvent -ListLog '{log_name}' -ErrorAction SilentlyContinue).MaximumSizeInBytes"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            size_bytes = int(result.stdout.strip()) if result.stdout.strip() else 0
            size_mb = round(size_bytes / (1024 * 1024), 1)
            results.append({
                "log": log_name,
                "max_size_mb": size_mb,
                "severity": "MEDIUM" if size_mb < 100 else "INFO",
            })
        except (ValueError, subprocess.TimeoutExpired):
            results.append({"log": log_name, "error": "Cannot query"})
    return results


def check_powershell_logging():
    """Check PowerShell script block logging and transcription."""
    checks = {}
    for name, path in [
        ("ScriptBlockLogging", r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"),
        ("Transcription", r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"),
    ]:
        cmd = ["powershell", "-Command", f"Get-ItemProperty -Path '{path}' -ErrorAction SilentlyContinue | ConvertTo-Json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            checks[name] = json.loads(result.stdout) if result.stdout.strip() else {"enabled": False}
        except (json.JSONDecodeError, subprocess.TimeoutExpired):
            checks[name] = {"enabled": False}
    return checks


def run_audit():
    """Execute Windows event logging audit."""
    print(f"\n{'='*60}")
    print(f"  WINDOWS EVENT LOGGING AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    sysmon = check_sysmon_installed()
    print(f"--- SYSMON ---")
    print(f"  Installed: {sysmon.get('installed', False)}")
    print(f"  Status: {sysmon.get('status', 'N/A')}")

    logs = check_log_sizes()
    print(f"\n--- LOG SIZES ---")
    for l in logs:
        if "error" not in l:
            print(f"  {l['log']}: {l['max_size_mb']} MB [{l['severity']}]")

    ps_logging = check_powershell_logging()
    print(f"\n--- POWERSHELL LOGGING ---")
    for name, config in ps_logging.items():
        enabled = config.get("EnableScriptBlockLogging", config.get("EnableTranscripting", False))
        print(f"  {name}: {'Enabled' if enabled else 'Disabled'}")

    return {"sysmon": sysmon, "log_sizes": logs, "powershell": ps_logging}


def main():
    parser = argparse.ArgumentParser(description="Windows Event Logging Audit Agent")
    parser.add_argument("--audit", action="store_true", help="Run full audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.audit:
        report = run_audit()
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
