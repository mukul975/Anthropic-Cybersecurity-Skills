#!/usr/bin/env python3
"""Agent for auditing zero trust controls on SaaS applications via Microsoft Graph API."""

import requests
import json
import argparse
from datetime import datetime, timezone

GRAPH_API = "https://graph.microsoft.com/v1.0"


def get_token(tenant_id, client_id, client_secret):
    """Acquire OAuth2 token for Microsoft Graph API."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {"grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default"}
    resp = requests.post(url, data=data, timeout=30)
    resp.raise_for_status()
    token = resp.json()["access_token"]
    print("[*] Authenticated to Microsoft Graph API")
    return {"Authorization": f"Bearer {token}"}


def list_conditional_access_policies(headers):
    """List Entra ID conditional access policies for SaaS apps."""
    url = f"{GRAPH_API}/identity/conditionalAccess/policies"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    policies = resp.json().get("value", [])
    findings = []
    print(f"\n[*] Conditional Access Policies: {len(policies)}")
    for p in policies:
        state = p.get("state", "disabled")
        conditions = p.get("conditions", {})
        grant_controls = p.get("grantControls", {})
        mfa_required = "mfa" in str(grant_controls.get("builtInControls", [])).lower()
        print(f"  [{'+' if state == 'enabled' else '-'}] {p['displayName']} "
              f"(state={state}, MFA={'Yes' if mfa_required else 'No'})")
        if state == "enabled" and not mfa_required:
            findings.append({"policy": p["displayName"], "issue": "No MFA required",
                             "severity": "HIGH"})
    return policies, findings


def list_enterprise_apps(headers):
    """List enterprise applications (service principals) for shadow IT discovery."""
    url = f"{GRAPH_API}/servicePrincipals"
    params = {"$top": 100, "$select": "displayName,appId,accountEnabled,signInAudience"}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    apps = resp.json().get("value", [])
    print(f"\n[*] Enterprise Applications: {len(apps)}")
    third_party = [a for a in apps if a.get("signInAudience") != "AzureADMyOrg"]
    print(f"  Third-party apps: {len(third_party)}")
    for a in third_party[:10]:
        print(f"  {a['displayName']} (enabled={a.get('accountEnabled', '?')})")
    return apps


def check_oauth_app_consents(headers):
    """Audit OAuth2 permission grants for overprivileged consents."""
    url = f"{GRAPH_API}/oauth2PermissionGrants"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    grants = resp.json().get("value", [])
    findings = []
    for g in grants:
        scope = g.get("scope", "")
        if any(perm in scope for perm in ["Mail.ReadWrite", "Files.ReadWrite.All",
                                           "Directory.ReadWrite.All", "User.ReadWrite.All"]):
            findings.append({
                "clientId": g.get("clientId"), "scope": scope,
                "consentType": g.get("consentType"), "severity": "HIGH",
            })
    print(f"\n[*] OAuth grants: {len(grants)} total, {len(findings)} overprivileged")
    for f in findings[:5]:
        print(f"  [!] {f['clientId']}: {f['scope'][:80]}")
    return findings


def check_sign_in_risk(headers, days=7):
    """Check risky sign-ins to SaaS applications."""
    url = f"{GRAPH_API}/identityProtection/riskyUsers"
    params = {"$filter": "riskState eq 'atRisk'", "$top": 50}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 200:
        users = resp.json().get("value", [])
        print(f"\n[*] Risky users: {len(users)}")
        for u in users[:10]:
            print(f"  [!] {u.get('userDisplayName', 'N/A')} - risk: {u.get('riskLevel')}")
        return users
    return []


def generate_report(policies, ca_findings, oauth_findings, risky_users, output_path):
    """Generate SaaS zero trust audit report."""
    report = {
        "audit_date": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "conditional_access_policies": len(policies),
            "ca_findings": len(ca_findings),
            "overprivileged_oauth": len(oauth_findings),
            "risky_users": len(risky_users),
        },
        "ca_findings": ca_findings,
        "oauth_findings": oauth_findings[:20],
        "risky_users": risky_users[:20],
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="SaaS Zero Trust Audit Agent")
    parser.add_argument("action", choices=["ca-policies", "apps", "oauth", "risk", "full-audit"])
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", required=True)
    parser.add_argument("-o", "--output", default="saas_zt_audit.json")
    args = parser.parse_args()

    headers = get_token(args.tenant_id, args.client_id, args.client_secret)
    if args.action == "ca-policies":
        list_conditional_access_policies(headers)
    elif args.action == "apps":
        list_enterprise_apps(headers)
    elif args.action == "oauth":
        check_oauth_app_consents(headers)
    elif args.action == "risk":
        check_sign_in_risk(headers)
    elif args.action == "full-audit":
        policies, ca_f = list_conditional_access_policies(headers)
        list_enterprise_apps(headers)
        oauth_f = check_oauth_app_consents(headers)
        risky = check_sign_in_risk(headers)
        generate_report(policies, ca_f, oauth_f, risky, args.output)


if __name__ == "__main__":
    main()
