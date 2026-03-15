#!/usr/bin/env python3
"""Agent for auditing CyberArk Zero Standing Privilege (ZSP) configuration via REST API."""

import requests
import json
import argparse
import sys
from datetime import datetime, timezone
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def authenticate(base_url, username, password, auth_method="CyberArk"):
    """Authenticate to CyberArk PVWA and obtain session token."""
    url = f"{base_url}/api/auth/{auth_method}/Logon"
    payload = {"username": username, "password": password}
    resp = requests.post(url, json=payload, verify=False, timeout=30)
    resp.raise_for_status()
    token = resp.json().strip('"')
    print(f"[*] Authenticated to CyberArk PVWA as {username}")
    return {"Authorization": token}


def list_safes(base_url, headers):
    """List all safes to audit access policies."""
    url = f"{base_url}/api/Safes"
    resp = requests.get(url, headers=headers, verify=False, timeout=30)
    resp.raise_for_status()
    safes = resp.json().get("value", [])
    print(f"[*] Found {len(safes)} safes")
    for s in safes[:20]:
        print(f"  {s['safeName']} (retention: {s.get('numberOfDaysRetention', 'N/A')} days)")
    return safes


def audit_safe_members(base_url, headers, safe_name):
    """Audit members and permissions of a specific safe."""
    url = f"{base_url}/api/Safes/{safe_name}/Members"
    resp = requests.get(url, headers=headers, verify=False, timeout=30)
    resp.raise_for_status()
    members = resp.json().get("value", [])
    findings = []
    for m in members:
        perms = m.get("permissions", {})
        if perms.get("useAccounts") and perms.get("retrieveAccounts"):
            if not m.get("memberType") == "Role":
                findings.append({
                    "safe": safe_name, "member": m.get("memberName"),
                    "issue": "Standing retrieve+use privileges (not JIT)",
                    "severity": "HIGH",
                })
                print(f"  [!] {m.get('memberName')} has standing access to {safe_name}")
    return findings


def list_platforms(base_url, headers):
    """List platforms to verify JIT/ZSP configuration."""
    url = f"{base_url}/api/Platforms"
    resp = requests.get(url, headers=headers, verify=False, timeout=30)
    resp.raise_for_status()
    platforms = resp.json().get("Platforms", [])
    print(f"[*] Found {len(platforms)} platforms")
    for p in platforms:
        print(f"  {p.get('general', {}).get('name', 'Unknown')} - "
              f"Active: {p.get('general', {}).get('active', False)}")
    return platforms


def check_jit_sessions(base_url, headers, days=7):
    """Check recent privileged sessions for JIT compliance."""
    url = f"{base_url}/api/LiveSessions"
    resp = requests.get(url, headers=headers, verify=False, timeout=30)
    resp.raise_for_status()
    sessions = resp.json().get("LiveSessions", [])
    print(f"[*] Active privileged sessions: {len(sessions)}")
    long_sessions = []
    for s in sessions:
        duration = s.get("Duration", 0)
        if duration > 3600:
            long_sessions.append({
                "user": s.get("User"), "target": s.get("AccountName"),
                "duration_sec": duration, "severity": "MEDIUM",
            })
            print(f"  [!] Long session: {s.get('User')} -> {s.get('AccountName')} "
                  f"({duration // 60} min)")
    return long_sessions


def audit_accounts_standing_access(base_url, headers):
    """Find privileged accounts with standing (non-JIT) access enabled."""
    url = f"{base_url}/api/Accounts"
    params = {"limit": 100, "offset": 0}
    resp = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
    resp.raise_for_status()
    accounts = resp.json().get("value", [])
    findings = []
    for a in accounts:
        props = a.get("platformAccountProperties", {})
        if not props.get("JITEnabled", False):
            findings.append({
                "account": a.get("name"), "safe": a.get("safeName"),
                "platform": a.get("platformId"), "issue": "JIT not enabled",
                "severity": "HIGH",
            })
    print(f"[*] Accounts without JIT: {len(findings)}/{len(accounts)}")
    return findings


def generate_report(safe_findings, session_findings, account_findings, output_path):
    """Generate ZSP compliance audit report."""
    report = {
        "audit_date": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "standing_access_findings": len(safe_findings),
            "long_session_findings": len(session_findings),
            "non_jit_accounts": len(account_findings),
        },
        "safe_findings": safe_findings,
        "session_findings": session_findings,
        "account_findings": account_findings,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="CyberArk Zero Standing Privilege Audit Agent")
    parser.add_argument("action", choices=["safes", "audit-safe", "platforms",
                                           "sessions", "accounts", "full-audit"])
    parser.add_argument("--url", required=True, help="CyberArk PVWA base URL")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--safe", help="Specific safe name to audit")
    parser.add_argument("-o", "--output", default="zsp_audit.json")
    args = parser.parse_args()

    headers = authenticate(args.url, args.username, args.password)
    if args.action == "safes":
        list_safes(args.url, headers)
    elif args.action == "audit-safe" and args.safe:
        audit_safe_members(args.url, headers, args.safe)
    elif args.action == "platforms":
        list_platforms(args.url, headers)
    elif args.action == "sessions":
        check_jit_sessions(args.url, headers)
    elif args.action == "accounts":
        audit_accounts_standing_access(args.url, headers)
    elif args.action == "full-audit":
        safes = list_safes(args.url, headers)
        sf = []
        for s in safes:
            sf.extend(audit_safe_members(args.url, headers, s["safeName"]))
        sess = check_jit_sessions(args.url, headers)
        acct = audit_accounts_standing_access(args.url, headers)
        generate_report(sf, sess, acct, args.output)


if __name__ == "__main__":
    main()
