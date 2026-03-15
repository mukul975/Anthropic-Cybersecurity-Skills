#!/usr/bin/env python3
"""
Azure Service Principal Abuse Detection Script

Queries Microsoft Graph API to detect suspicious service principal
activities including new credentials, privilege escalation, and
unauthorized ownership.
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta


def run_az_cli(args):
    """Execute Azure CLI command and return parsed JSON output."""
    cmd = ["az"] + args + ["--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, result.stderr
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}, None
    except json.JSONDecodeError:
        return result.stdout, None


def check_recent_credential_additions(days=7):
    """Check for service principals with recently added credentials."""
    print(f"[*] Checking for SP credentials added in last {days} days...")
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    sps, err = run_az_cli(["ad", "sp", "list", "--all"])
    if err:
        print(f"[!] Error listing service principals: {err}")
        return []

    suspicious = []
    for sp in sps or []:
        display_name = sp.get("displayName", "Unknown")
        app_id = sp.get("appId", "")
        object_id = sp.get("id", "")

        # Check password credentials
        for cred in sp.get("passwordCredentials", []):
            start_date = cred.get("startDateTime", "")
            if start_date and start_date > cutoff:
                suspicious.append({
                    "type": "password_credential",
                    "sp_name": display_name,
                    "app_id": app_id,
                    "object_id": object_id,
                    "credential_start": start_date,
                    "credential_end": cred.get("endDateTime", ""),
                    "key_id": cred.get("keyId", "")
                })

        # Check certificate credentials
        for cert in sp.get("keyCredentials", []):
            start_date = cert.get("startDateTime", "")
            if start_date and start_date > cutoff:
                suspicious.append({
                    "type": "certificate_credential",
                    "sp_name": display_name,
                    "app_id": app_id,
                    "object_id": object_id,
                    "credential_start": start_date,
                    "credential_end": cert.get("endDateTime", ""),
                    "key_id": cert.get("keyId", "")
                })

    if suspicious:
        print(f"[!] Found {len(suspicious)} recently added credentials:")
        for item in suspicious:
            print(f"  - [{item['type']}] {item['sp_name']} (AppId: {item['app_id']})")
            print(f"    Added: {item['credential_start']}")
    else:
        print("[+] No recently added credentials found")

    return suspicious


def check_privileged_sp_roles():
    """Check for service principals with privileged directory roles."""
    print("\n[*] Checking service principals with privileged roles...")

    privileged_roles = [
        "Global Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Privileged Role Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "User Administrator"
    ]

    findings = []
    roles, err = run_az_cli(["rest", "--method", "GET",
                              "--url", "https://graph.microsoft.com/v1.0/directoryRoles"])
    if err:
        print(f"[!] Error fetching roles: {err}")
        return []

    for role in (roles or {}).get("value", []):
        role_name = role.get("displayName", "")
        role_id = role.get("id", "")

        if role_name not in privileged_roles:
            continue

        members, err = run_az_cli(["rest", "--method", "GET",
                                    "--url", f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members"])
        if err:
            continue

        for member in (members or {}).get("value", []):
            odata_type = member.get("@odata.type", "")
            if "servicePrincipal" in odata_type:
                findings.append({
                    "role": role_name,
                    "sp_name": member.get("displayName", "Unknown"),
                    "sp_id": member.get("id", ""),
                    "app_id": member.get("appId", "")
                })

    if findings:
        print(f"[!] Found {len(findings)} service principals with privileged roles:")
        for f in findings:
            print(f"  - {f['sp_name']} has role: {f['role']}")
    else:
        print("[+] No service principals with privileged roles found")

    return findings


def check_sp_ownership():
    """Identify applications with non-admin owners (potential abuse vector)."""
    print("\n[*] Checking application ownership for potential abuse vectors...")

    apps, err = run_az_cli(["ad", "app", "list", "--all"])
    if err:
        print(f"[!] Error listing applications: {err}")
        return []

    risky_ownership = []
    for app in apps or []:
        app_name = app.get("displayName", "Unknown")
        app_id = app.get("appId", "")
        object_id = app.get("id", "")

        owners, err = run_az_cli(["rest", "--method", "GET",
                                   "--url", f"https://graph.microsoft.com/v1.0/applications/{object_id}/owners"])
        if err:
            continue

        owner_list = (owners or {}).get("value", [])
        if len(owner_list) > 3:  # Flag apps with many owners
            risky_ownership.append({
                "app_name": app_name,
                "app_id": app_id,
                "owner_count": len(owner_list),
                "owners": [o.get("userPrincipalName", o.get("displayName", "Unknown")) for o in owner_list]
            })

    if risky_ownership:
        print(f"[!] Found {len(risky_ownership)} applications with excessive owners:")
        for item in risky_ownership:
            print(f"  - {item['app_name']}: {item['owner_count']} owners")
    else:
        print("[+] No applications with excessive ownership found")

    return risky_ownership


def generate_detection_report(cred_findings, role_findings, ownership_findings):
    """Generate a consolidated detection report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""
{'='*60}
Azure Service Principal Abuse Detection Report
Generated: {timestamp}
{'='*60}

## Summary
- Recent Credential Additions: {len(cred_findings)}
- Privileged Role Assignments: {len(role_findings)}
- Risky Application Ownership: {len(ownership_findings)}
- Overall Risk: {'HIGH' if cred_findings or role_findings else 'LOW'}
"""

    if cred_findings:
        report += "\n## Recently Added Credentials\n"
        for f in cred_findings:
            report += f"  [{f['type']}] {f['sp_name']} - Added {f['credential_start']}\n"

    if role_findings:
        report += "\n## Privileged Service Principals\n"
        for f in role_findings:
            report += f"  {f['sp_name']} -> {f['role']}\n"

    if ownership_findings:
        report += "\n## Risky Application Ownership\n"
        for f in ownership_findings:
            report += f"  {f['app_name']} - {f['owner_count']} owners\n"

    print(report)
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Azure Service Principal Abuse Detection")
    parser.add_argument("--days", type=int, default=7, help="Lookback period in days")
    parser.add_argument("--credentials", action="store_true", help="Check recent credential additions")
    parser.add_argument("--roles", action="store_true", help="Check privileged role assignments")
    parser.add_argument("--ownership", action="store_true", help="Check application ownership")
    parser.add_argument("--full", action="store_true", help="Run all checks")
    parser.add_argument("--output", type=str, help="Save report to file")

    args = parser.parse_args()

    cred_findings = []
    role_findings = []
    ownership_findings = []

    if args.full or args.credentials:
        cred_findings = check_recent_credential_additions(args.days)
    if args.full or args.roles:
        role_findings = check_privileged_sp_roles()
    if args.full or args.ownership:
        ownership_findings = check_sp_ownership()

    if args.full or (args.credentials and args.roles):
        report = generate_detection_report(cred_findings, role_findings, ownership_findings)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            print(f"\n[+] Report saved to {args.output}")
