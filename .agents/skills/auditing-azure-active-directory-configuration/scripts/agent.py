#!/usr/bin/env python3
"""Agent for auditing Azure Active Directory (Entra ID) configuration."""

import os
import json
import argparse
from datetime import datetime, timedelta

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
import requests


def get_graph_token(credential):
    """Obtain a Microsoft Graph API access token."""
    token = credential.get_token("https://graph.microsoft.com/.default")
    return token.token


def graph_get(token, endpoint, params=None):
    """Make an authenticated GET request to Microsoft Graph API."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"https://graph.microsoft.com/v1.0{endpoint}"
    resp = requests.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()


def get_tenant_info(token):
    """Get tenant organization details."""
    data = graph_get(token, "/organization")
    orgs = data.get("value", [])
    if orgs:
        org = orgs[0]
        return {
            "display_name": org.get("displayName"),
            "tenant_id": org.get("id"),
            "verified_domains": [d["name"] for d in org.get("verifiedDomains", [])],
        }
    return {}


def list_global_admins(token):
    """List all Global Administrator role assignments."""
    roles = graph_get(token, "/directoryRoles")
    ga_role = None
    for role in roles.get("value", []):
        if role["displayName"] == "Global Administrator":
            ga_role = role["id"]
            break
    if not ga_role:
        return []
    members = graph_get(token, f"/directoryRoles/{ga_role}/members")
    return [
        {"displayName": m.get("displayName"), "upn": m.get("userPrincipalName"),
         "type": m.get("@odata.type", "").split(".")[-1]}
        for m in members.get("value", [])
    ]


def list_conditional_access_policies(token):
    """List all Conditional Access policies with their state and grant controls."""
    policies = graph_get(token, "/identity/conditionalAccess/policies")
    results = []
    for p in policies.get("value", []):
        results.append({
            "name": p.get("displayName"),
            "state": p.get("state"),
            "grant_controls": p.get("grantControls", {}).get("builtInControls", []),
            "excluded_groups": p.get("conditions", {}).get("users", {}).get("excludeGroups", []),
        })
    return results


def find_stale_users(token, days=90):
    """Find users who have not signed in for specified number of days."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z")
    users = graph_get(
        token, "/users",
        params={
            "$select": "displayName,userPrincipalName,signInActivity,accountEnabled",
            "$top": "999",
        }
    )
    stale = []
    for u in users.get("value", []):
        sign_in = u.get("signInActivity", {})
        last_sign_in = sign_in.get("lastSignInDateTime")
        if last_sign_in and last_sign_in < cutoff:
            stale.append({
                "upn": u.get("userPrincipalName"),
                "display_name": u.get("displayName"),
                "last_sign_in": last_sign_in,
                "enabled": u.get("accountEnabled"),
            })
    return stale


def list_guest_users(token):
    """List all guest users in the tenant."""
    users = graph_get(
        token, "/users",
        params={"$filter": "userType eq 'Guest'", "$select": "displayName,userPrincipalName,createdDateTime"}
    )
    return [
        {"upn": u.get("userPrincipalName"), "display_name": u.get("displayName"),
         "created": u.get("createdDateTime")}
        for u in users.get("value", [])
    ]


def check_mfa_registration(token):
    """Check users without MFA registered."""
    try:
        data = graph_get(token, "/reports/authenticationMethods/userRegistrationDetails")
        no_mfa = [
            {"upn": u.get("userPrincipalName"), "mfa_registered": u.get("isMfaRegistered")}
            for u in data.get("value", []) if not u.get("isMfaRegistered")
        ]
        return no_mfa
    except Exception:
        return []


def get_risky_signins(token, days=7):
    """Get risky sign-in events from the last N days."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z")
    try:
        data = graph_get(
            token, "/auditLogs/signIns",
            params={"$filter": f"riskLevelDuringSignIn ne 'none' and createdDateTime ge {since}"}
        )
        return [
            {"user": s.get("userPrincipalName"), "risk": s.get("riskLevelDuringSignIn"),
             "ip": s.get("ipAddress"), "app": s.get("appDisplayName")}
            for s in data.get("value", [])
        ]
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description="Azure AD Configuration Audit Agent")
    parser.add_argument("--tenant-id", default=os.getenv("AZURE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.getenv("AZURE_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("AZURE_CLIENT_SECRET"))
    parser.add_argument("--stale-days", type=int, default=90)
    parser.add_argument("--output", default="azure_ad_audit.json")
    args = parser.parse_args()

    if args.client_id and args.client_secret and args.tenant_id:
        credential = ClientSecretCredential(args.tenant_id, args.client_id, args.client_secret)
    else:
        credential = DefaultAzureCredential()

    token = get_graph_token(credential)
    report = {"audit_date": datetime.utcnow().isoformat(), "findings": {}}

    report["findings"]["tenant_info"] = get_tenant_info(token)
    print(f"[+] Tenant: {report['findings']['tenant_info'].get('display_name')}")

    admins = list_global_admins(token)
    report["findings"]["global_admins"] = admins
    print(f"[+] Global Admins: {len(admins)}")

    ca_policies = list_conditional_access_policies(token)
    report["findings"]["conditional_access"] = ca_policies
    print(f"[+] Conditional Access policies: {len(ca_policies)}")

    stale = find_stale_users(token, args.stale_days)
    report["findings"]["stale_users"] = stale
    print(f"[+] Stale users ({args.stale_days}+ days): {len(stale)}")

    guests = list_guest_users(token)
    report["findings"]["guest_users"] = guests
    print(f"[+] Guest users: {len(guests)}")

    no_mfa = check_mfa_registration(token)
    report["findings"]["users_without_mfa"] = no_mfa
    print(f"[+] Users without MFA: {len(no_mfa)}")

    risky = get_risky_signins(token)
    report["findings"]["risky_signins"] = risky
    print(f"[+] Risky sign-ins (7d): {len(risky)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
