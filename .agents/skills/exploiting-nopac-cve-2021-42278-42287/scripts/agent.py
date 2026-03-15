#!/usr/bin/env python3
"""Agent for detecting noPac (CVE-2021-42278/42287) AD privilege escalation vulnerability."""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def check_nopac_impacket(domain, username, password, dc_ip):
    """Check for noPac vulnerability using Impacket noPac.py."""
    cmd = [
        "noPac.py", f"{domain}/{username}:{password}",
        "-dc-ip", dc_ip, "--scan",
    ]
    try:
        result = subprocess.check_output(
            cmd, text=True, errors="replace", timeout=30
        )
        return {
            "method": "noPac.py",
            "vulnerable": "VULNERABLE" in result.upper() or "success" in result.lower(),
            "output": result[:1000],
        }
    except (subprocess.SubprocessError, FileNotFoundError):
        return {"method": "noPac.py", "status": "tool not available"}


def check_machineaccountquota(domain, username, password, dc_ip):
    """Check the MachineAccountQuota via LDAP — needed for noPac."""
    ps_cmd = (
        "([ADSI]'LDAP://DC='+($env:USERDNSDOMAIN -replace '\\.',',DC=')).'ms-DS-MachineAccountQuota'"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=10
        )
        quota = int(result.strip()) if result.strip().isdigit() else -1
        return {
            "machine_account_quota": quota,
            "exploitable": quota > 0,
            "note": "Quota > 0 means any domain user can create machine accounts",
        }
    except (subprocess.SubprocessError, ValueError):
        return {"machine_account_quota": "unknown"}


def check_patch_status():
    """Check if KB5008380 (noPac patch) is installed."""
    if sys.platform != "win32":
        return {"status": "non-windows"}
    try:
        result = subprocess.check_output(
            ["wmic", "qfe", "list", "brief"],
            text=True, errors="replace", timeout=15
        )
        patched = any(kb in result for kb in ["KB5008380", "KB5008602", "KB5008207"])
        return {
            "patched": patched,
            "relevant_kbs": ["KB5008380", "KB5008602", "KB5008207"],
        }
    except subprocess.SubprocessError:
        return {"status": "check_failed"}


def enumerate_sam_name_impersonation():
    """Check for sAMAccountName impersonation conditions."""
    ps_cmd = (
        "Get-ADComputer -Filter * -Properties sAMAccountName | "
        "Where-Object {$_.sAMAccountName -notmatch '\\$$'} | "
        "Select-Object Name,sAMAccountName | ConvertTo-Json"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=15
        )
        data = json.loads(result) if result.strip() else []
        return data if isinstance(data, list) else [data]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Detect noPac CVE-2021-42278/42287 vulnerability (authorized testing only)"
    )
    parser.add_argument("--domain", help="AD domain")
    parser.add_argument("--username", help="Domain username")
    parser.add_argument("--password", help="Domain password")
    parser.add_argument("--dc-ip", help="Domain controller IP")
    parser.add_argument("--check-patch", action="store_true")
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] noPac (CVE-2021-42278/42287) Detection Agent")
    print("[!] For authorized security testing only")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    if args.domain and args.username:
        nopac = check_nopac_impacket(
            args.domain, args.username, args.password or "", args.dc_ip or ""
        )
        report["findings"]["nopac_scan"] = nopac
        print(f"[*] noPac scan: {nopac.get('vulnerable', 'unknown')}")

        quota = check_machineaccountquota(args.domain, args.username, args.password or "", args.dc_ip or "")
        report["findings"]["machine_quota"] = quota

    if args.check_patch:
        patch = check_patch_status()
        report["findings"]["patch_status"] = patch
        print(f"[*] Patched: {patch.get('patched', 'unknown')}")

    report["risk_level"] = "CRITICAL" if any(
        v.get("vulnerable") or v.get("exploitable") for v in report["findings"].values() if isinstance(v, dict)
    ) else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
