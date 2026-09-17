#!/usr/bin/env python3
"""CyberArk PAM configuration audit agent.

Audits CyberArk Privileged Access Management via the REST API to
verify safe configurations, privileged account inventory, platform
assignments, and password rotation compliance.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' required: pip install requests", file=sys.stderr)
    sys.exit(1)


def get_cyberark_config():
    """Return CyberArk PVWA URL."""
    pvwa_url = os.environ.get("CYBERARK_PVWA_URL", "").rstrip("/")
    if not pvwa_url:
        print("[!] Set CYBERARK_PVWA_URL env var", file=sys.stderr)
        sys.exit(1)
    return pvwa_url


def authenticate(pvwa_url, username, password, auth_type="CyberArk"):
    """Authenticate and get session token."""
    url = f"{pvwa_url}/PasswordVault/API/Auth/{auth_type}/Logon"
    resp = requests.post(url, json={"username": username, "password": password},
                         verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=30)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    resp.raise_for_status()
    token = resp.json().strip('"')
    print(f"[+] Authenticated as {username}")
    return token


def api_call(pvwa_url, token, endpoint, method="GET", data=None, params=None):
    """Make authenticated API call."""
    url = f"{pvwa_url}/PasswordVault/API{endpoint}"
    headers = {"Authorization": token, "Content-Type": "application/json"}
    if method == "POST":
        resp = requests.post(url, headers=headers, json=data, params=params,
                             verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=30)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    else:
        resp = requests.get(url, headers=headers, params=params,
                            verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=30)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    resp.raise_for_status()
    return resp.json()


def audit_safes(pvwa_url, token):
    """Audit safe configurations."""
    findings = []
    print("[*] Auditing safes...")
    data = api_call(pvwa_url, token, "/Safes", params={"limit": 1000})
    safes = data.get("value", data.get("Safes", []))

    for safe in safes:
        name = safe.get("safeName", safe.get("SafeName", ""))
        member_count = safe.get("numberOfMembers", safe.get("NumberOfMembers", 0))
        days_retention = safe.get("numberOfDaysRetention", safe.get("NumberOfDaysRetention", 0))
        versions = safe.get("numberOfVersionsRetention", safe.get("NumberOfVersionsRetention", 0))

        if member_count == 0:
            findings.append({
                "safe": name, "check": "Empty safe (no members)",
                "severity": "MEDIUM", "detail": "Safe has no members assigned",
            })
        if days_retention == 0 and versions == 0:
            findings.append({
                "safe": name, "check": "No retention policy",
                "severity": "HIGH",
                "detail": "No password history retention configured",
            })

    print(f"[+] Audited {len(safes)} safes")
    return findings, safes


def audit_accounts(pvwa_url, token, safe_name=None):
    """Audit privileged accounts."""
    findings = []
    print("[*] Auditing privileged accounts...")
    params = {"limit": 1000}
    if safe_name:
        params["filter"] = f"safeName eq {safe_name}"
    data = api_call(pvwa_url, token, "/Accounts", params=params)
    accounts = data.get("value", [])

    now = datetime.now(timezone.utc)
    for acct in accounts:
        acct_name = acct.get("name", "")
        platform = acct.get("platformId", "")
        safe = acct.get("safeName", "")
        secret_mgmt = acct.get("secretManagement", {})
        last_modified = secret_mgmt.get("lastModifiedTime", 0)
        auto_mgmt = secret_mgmt.get("automaticManagementEnabled", False)
        status = secret_mgmt.get("status", "")

        if not auto_mgmt:
            findings.append({
                "account": acct_name, "safe": safe, "platform": platform,
                "check": "Automatic password management disabled",
                "severity": "HIGH",
                "detail": "Password not managed by CyberArk CPM",
            })

        if last_modified:
            last_mod_dt = datetime.fromtimestamp(last_modified, tz=timezone.utc)
            age_days = (now - last_mod_dt).days
            if age_days > 90:
                findings.append({
                    "account": acct_name, "safe": safe,
                    "check": "Password age exceeds 90 days",
                    "severity": "HIGH",
                    "detail": f"Last rotated {age_days} days ago",
                })

        if status and status != "success":
            findings.append({
                "account": acct_name, "safe": safe,
                "check": f"CPM status: {status}",
                "severity": "CRITICAL" if "fail" in status.lower() else "MEDIUM",
                "detail": f"Password management status: {status}",
            })

    print(f"[+] Audited {len(accounts)} accounts")
    return findings, accounts


def audit_platforms(pvwa_url, token):
    """Audit platform configurations."""
    findings = []
    print("[*] Auditing platforms...")
    data = api_call(pvwa_url, token, "/Platforms")
    platforms = data.get("Platforms", data.get("value", []))

    for plat in platforms:
        name = plat.get("Name", plat.get("PlatformID", ""))
        active = plat.get("Active", True)
        if not active:
            continue
        priv_session = plat.get("PrivilegedSessionManagement", {})
        if not priv_session.get("PSMServerId"):
            findings.append({
                "platform": name,
                "check": "No PSM configured",
                "severity": "MEDIUM",
                "detail": "Platform missing privileged session management",
            })

    print(f"[+] Audited {len(platforms)} platforms")
    return findings, platforms


def logoff(pvwa_url, token):
    """End the CyberArk session."""
    try:
        requests.post(f"{pvwa_url}/PasswordVault/API/Auth/Logoff",
                      headers={"Authorization": token},
                      verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=10)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
        print("[+] Session ended")
    except requests.RequestException:
        pass


def format_summary(safe_findings, acct_findings, plat_findings, safes, accounts):
    """Print audit summary."""
    all_findings = safe_findings + acct_findings + plat_findings
    print(f"\n{'='*60}")
    print("  CyberArk PAM Audit Report")
    print(f"{'='*60}")
    print(f"  Safes        : {len(safes)}")
    print(f"  Accounts     : {len(accounts)}")
    print(f"  Findings     : {len(all_findings)}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"    {sev:10s}: {count}")

    if all_findings:
        print("\n  Top Issues:")
        for f in all_findings[:15]:
            if f["severity"] in ("CRITICAL", "HIGH"):
                print(f"    [{f['severity']:8s}] {f['check']}: "
                      f"{f.get('account', f.get('safe', f.get('platform', '')))}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="CyberArk PAM configuration audit agent")
    parser.add_argument("--pvwa-url", help="PVWA URL (or CYBERARK_PVWA_URL env)")
    parser.add_argument("--username", required=True, help="CyberArk username")
    parser.add_argument("--password", required=True, help="CyberArk password")
    parser.add_argument("--auth-type", default="CyberArk",
                        choices=["CyberArk", "LDAP", "RADIUS", "Windows"])
    parser.add_argument("--safe", help="Audit specific safe only")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.pvwa_url:
        os.environ["CYBERARK_PVWA_URL"] = args.pvwa_url
    pvwa_url = get_cyberark_config()

    token = authenticate(pvwa_url, args.username, args.password, args.auth_type)
    try:
        safe_findings, safes = audit_safes(pvwa_url, token)
        acct_findings, accounts = audit_accounts(pvwa_url, token, args.safe)
        plat_findings, platforms = audit_platforms(pvwa_url, token)
    finally:
        logoff(pvwa_url, token)

    severity_counts = format_summary(safe_findings, acct_findings, plat_findings, safes, accounts)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "CyberArk PAM Audit",
        "safes_count": len(safes),
        "accounts_count": len(accounts),
        "findings": safe_findings + acct_findings + plat_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
