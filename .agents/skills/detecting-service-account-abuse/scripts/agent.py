#!/usr/bin/env python3
"""Agent for detecting service account abuse in Active Directory and cloud environments."""

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone


def query_ad_service_accounts():
    """Query Active Directory for service accounts via PowerShell."""
    ps_cmd = (
        "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} "
        "-Properties ServicePrincipalName,LastLogonDate,Enabled,PasswordLastSet,"
        "PasswordNeverExpires,AdminCount,MemberOf "
        "| Select-Object SamAccountName,Enabled,LastLogonDate,PasswordLastSet,"
        "PasswordNeverExpires,AdminCount,@{N='SPNCount';E={$_.ServicePrincipalName.Count}} "
        "| ConvertTo-Json"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=30
        )
        data = json.loads(result) if result.strip().startswith(("[", "{")) else []
        return data if isinstance(data, list) else [data]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def check_interactive_logons(days=7):
    """Find service accounts with interactive logon events (type 2/10)."""
    ps_cmd = (
        f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624;"
        f"StartTime=(Get-Date).AddDays(-{days})}} "
        "| Where-Object {($_.Properties[8].Value -eq 2 -or $_.Properties[8].Value -eq 10) "
        "-and $_.Properties[5].Value -match 'svc_|service'} "
        "| Select-Object TimeCreated,@{N='Account';E={$_.Properties[5].Value}},"
        "@{N='LogonType';E={$_.Properties[8].Value}},"
        "@{N='SourceIP';E={$_.Properties[18].Value}} "
        "| ConvertTo-Json"
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


def analyze_logon_patterns(events):
    """Detect anomalous logon patterns for service accounts."""
    anomalies = []
    account_sources = {}
    for evt in events:
        acct = evt.get("Account", "unknown")
        src = evt.get("SourceIP", "unknown")
        account_sources.setdefault(acct, []).append(src)

    for acct, sources in account_sources.items():
        unique = set(sources)
        if len(unique) > 3:
            anomalies.append({
                "account": acct,
                "issue": "Service account logged in from multiple sources",
                "source_count": len(unique),
                "sources": list(unique)[:10],
            })
    return anomalies


def check_account_risks(accounts):
    """Identify risky service account configurations."""
    risks = []
    for acct in accounts:
        name = acct.get("SamAccountName", "unknown")
        issues = []
        if acct.get("PasswordNeverExpires"):
            issues.append("Password never expires")
        if acct.get("AdminCount") == 1:
            issues.append("Has AdminCount=1 (privileged)")
        if acct.get("Enabled") is False:
            issues.append("Account disabled but has SPNs")
        pw_set = acct.get("PasswordLastSet")
        if pw_set and isinstance(pw_set, str):
            try:
                pw_date = datetime.fromisoformat(pw_set.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - pw_date).days
                if age > 365:
                    issues.append(f"Password {age} days old")
            except ValueError:
                pass
        if issues:
            risks.append({"account": name, "issues": issues, "risk_count": len(issues)})
    return risks


def main():
    parser = argparse.ArgumentParser(
        description="Detect service account abuse in AD environments"
    )
    parser.add_argument("--days", type=int, default=7, help="Lookback days for logon events")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] Service Account Abuse Detection Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    accounts = query_ad_service_accounts()
    report["findings"]["service_accounts"] = len(accounts)
    print(f"[*] Found {len(accounts)} service accounts with SPNs")

    risks = check_account_risks(accounts)
    report["findings"]["risky_accounts"] = risks
    print(f"[*] Risky accounts: {len(risks)}")

    logons = check_interactive_logons(args.days)
    report["findings"]["interactive_logons"] = len(logons)
    anomalies = analyze_logon_patterns(logons)
    report["findings"]["logon_anomalies"] = anomalies
    print(f"[*] Logon anomalies: {len(anomalies)}")

    total_issues = len(risks) + len(anomalies)
    report["risk_level"] = "CRITICAL" if total_issues >= 5 else "HIGH" if total_issues >= 3 else "MEDIUM" if total_issues > 0 else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
