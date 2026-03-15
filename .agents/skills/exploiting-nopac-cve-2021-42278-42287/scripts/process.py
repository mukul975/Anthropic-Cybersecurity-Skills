#!/usr/bin/env python3
"""
noPac Vulnerability Scanner and Assessment Script

Checks Active Directory environments for CVE-2021-42278/42287 vulnerability
by verifying patch status and MachineAccountQuota settings.
For authorized red team engagements only.
"""

import subprocess
import sys
import json
import os
from datetime import datetime


def check_machine_account_quota(dc_ip: str, domain: str, username: str, password: str) -> dict:
    """Check MachineAccountQuota via LDAP query."""
    try:
        result = subprocess.run(
            [
                "python3", "-c",
                f"""
import ldap3
server = ldap3.Server('{dc_ip}')
conn = ldap3.Connection(server, '{domain}\\\\{username}', '{password}', auto_bind=True)
conn.search('{",".join(["DC=" + p for p in domain.split(".")])}', '(objectClass=domain)',
            attributes=['ms-DS-MachineAccountQuota'])
if conn.entries:
    print(conn.entries[0]['ms-DS-MachineAccountQuota'])
else:
    print('QUERY_FAILED')
"""
            ],
            capture_output=True, text=True, timeout=30
        )
        quota = result.stdout.strip()
        return {
            "status": "success",
            "quota": int(quota) if quota.isdigit() else -1,
            "exploitable": int(quota) > 0 if quota.isdigit() else False
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def run_nopac_scanner(dc_ip: str, domain: str, username: str, password: str) -> dict:
    """Run noPac scanner to check vulnerability status."""
    try:
        result = subprocess.run(
            ["python3", "scanner.py", f"{domain}/{username}:{password}", "-dc-ip", dc_ip],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        vulnerable = "VULNERABLE" in output.upper() or "vulnerable" in output.lower()
        return {
            "status": "success",
            "vulnerable": vulnerable,
            "output": output.strip()[:1000]
        }
    except FileNotFoundError:
        return {"status": "error", "error": "noPac scanner not found. Clone from https://github.com/cube0x0/noPac"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def generate_assessment_report(dc_ip: str, domain: str, quota_result: dict, scan_result: dict) -> str:
    """Generate noPac vulnerability assessment report."""
    report = [
        "=" * 60,
        "noPac (CVE-2021-42278/42287) Vulnerability Assessment",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 60,
        "",
        f"Target DC: {dc_ip}",
        f"Domain: {domain}",
        "",
        "[MachineAccountQuota Check]",
    ]

    if quota_result["status"] == "success":
        quota = quota_result["quota"]
        report.append(f"  MachineAccountQuota: {quota}")
        if quota > 0:
            report.append(f"  Status: EXPLOITABLE - Users can create up to {quota} machine accounts")
        elif quota == 0:
            report.append("  Status: MITIGATED - Machine account creation disabled")
        else:
            report.append("  Status: UNKNOWN - Could not determine quota")
    else:
        report.append(f"  Error: {quota_result.get('error', 'Unknown error')}")

    report.append("")
    report.append("[noPac Scanner Result]")
    if scan_result["status"] == "success":
        status = "VULNERABLE" if scan_result["vulnerable"] else "NOT VULNERABLE"
        report.append(f"  Status: {status}")
        report.append(f"  Details: {scan_result['output'][:500]}")
    else:
        report.append(f"  Error: {scan_result.get('error', 'Unknown error')}")

    report.extend([
        "",
        "[Remediation]",
        "  1. Apply KB5008380 (CVE-2021-42287 Kerberos PAC fix)",
        "  2. Apply KB5008602 (CVE-2021-42278 sAMAccountName fix)",
        "  3. Set MachineAccountQuota to 0:",
        "     Set-ADDomain -Identity domain.local -Replace @{'ms-DS-MachineAccountQuota'='0'}",
        "  4. Monitor Event 4741 (machine account creation) and 4742 (modification)",
        "",
        "=" * 60
    ])

    return "\n".join(report)


def main():
    """Main entry point."""
    if len(sys.argv) < 4:
        print("Usage: python process.py <dc_ip> <domain> <username> <password>")
        print("Example: python process.py 10.10.10.1 domain.local user Password123")
        return

    dc_ip = sys.argv[1]
    domain = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4] if len(sys.argv) > 4 else ""

    print(f"Checking noPac vulnerability for {domain} at {dc_ip}...")
    quota_result = check_machine_account_quota(dc_ip, domain, username, password)
    scan_result = run_nopac_scanner(dc_ip, domain, username, password)

    report = generate_assessment_report(dc_ip, domain, quota_result, scan_result)
    print(report)

    report_file = f"nopac_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
