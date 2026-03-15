#!/usr/bin/env python3
"""Agent for identity governance and lifecycle management operations."""

import os
import json
import argparse
from datetime import datetime, timedelta

import requests


def get_graph_token(tenant_id, client_id, client_secret):
    """Authenticate to Microsoft Graph API via client credentials."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = requests.post(url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    })
    resp.raise_for_status()
    return resp.json()["access_token"]


def list_users(token, filter_query=None):
    """List users from Microsoft Entra ID with optional filter."""
    headers = {"Authorization": f"Bearer {token}"}
    url = "https://graph.microsoft.com/v1.0/users"
    params = {"$select": "id,displayName,userPrincipalName,accountEnabled,employeeId,"
              "department,jobTitle,createdDateTime,signInActivity",
              "$top": "999"}
    if filter_query:
        params["$filter"] = filter_query
    users = []
    while url:
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        users.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        params = {}
    return users


def detect_orphaned_accounts(token, days_inactive=90):
    """Find accounts with no sign-in activity for N days."""
    users = list_users(token)
    cutoff = datetime.utcnow() - timedelta(days=days_inactive)
    orphaned = []
    for u in users:
        if not u.get("accountEnabled"):
            continue
        sign_in = u.get("signInActivity", {})
        last_sign_in = sign_in.get("lastSignInDateTime")
        if not last_sign_in:
            orphaned.append({
                "user": u["userPrincipalName"],
                "department": u.get("department", ""),
                "reason": "No sign-in recorded",
                "risk": "HIGH",
            })
        else:
            last_dt = datetime.fromisoformat(last_sign_in.rstrip("Z"))
            if last_dt < cutoff:
                orphaned.append({
                    "user": u["userPrincipalName"],
                    "department": u.get("department", ""),
                    "last_sign_in": last_sign_in,
                    "days_inactive": (datetime.utcnow() - last_dt).days,
                    "risk": "MEDIUM",
                })
    return orphaned


def detect_stale_guests(token, days_inactive=60):
    """Find guest accounts with no recent activity."""
    guests = list_users(token, "userType eq 'Guest'")
    cutoff = datetime.utcnow() - timedelta(days=days_inactive)
    stale = []
    for g in guests:
        sign_in = g.get("signInActivity", {})
        last = sign_in.get("lastSignInDateTime")
        if not last or datetime.fromisoformat(last.rstrip("Z")) < cutoff:
            stale.append({
                "user": g["userPrincipalName"],
                "created": g.get("createdDateTime", ""),
                "last_sign_in": last,
            })
    return stale


def get_access_reviews(token):
    """List active access reviews from Entra ID Governance."""
    headers = {"Authorization": f"Bearer {token}"}
    url = "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    reviews = []
    for r in resp.json().get("value", []):
        reviews.append({
            "name": r["displayName"],
            "status": r["status"],
            "scope": r.get("scope", {}).get("query", ""),
            "created": r.get("createdDateTime"),
        })
    return reviews


def check_users_without_mfa(token):
    """Identify users without registered MFA methods."""
    headers = {"Authorization": f"Bearer {token}"}
    url = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
    resp = requests.get(url, headers=headers, params={"$top": "999"})
    resp.raise_for_status()
    no_mfa = []
    for u in resp.json().get("value", []):
        if not u.get("isMfaRegistered"):
            no_mfa.append({
                "user": u["userPrincipalName"],
                "mfa_registered": False,
                "methods": u.get("methodsRegistered", []),
            })
    return no_mfa


def generate_lifecycle_report(token):
    """Generate comprehensive identity governance report."""
    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}
    users = list_users(token)
    enabled = [u for u in users if u.get("accountEnabled")]
    disabled = [u for u in users if not u.get("accountEnabled")]
    report["summary"] = {
        "total_users": len(users),
        "enabled": len(enabled),
        "disabled": len(disabled),
    }
    report["findings"]["orphaned_accounts"] = detect_orphaned_accounts(token)
    report["findings"]["stale_guests"] = detect_stale_guests(token)
    report["findings"]["no_mfa"] = check_users_without_mfa(token)
    report["findings"]["access_reviews"] = get_access_reviews(token)
    return report


def main():
    parser = argparse.ArgumentParser(description="Identity Governance Lifecycle Agent")
    parser.add_argument("--tenant-id", default=os.getenv("AZURE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.getenv("AZURE_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("AZURE_CLIENT_SECRET"))
    parser.add_argument("--output", default="iga_report.json")
    parser.add_argument("--action", choices=[
        "orphaned", "guests", "mfa", "reviews", "full_report"
    ], default="full_report")
    args = parser.parse_args()

    token = get_graph_token(args.tenant_id, args.client_id, args.client_secret)
    report = {"scan_date": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("orphaned", "full_report"):
        results = detect_orphaned_accounts(token)
        report["findings"]["orphaned_accounts"] = results
        print(f"[+] Orphaned accounts: {len(results)}")

    if args.action in ("guests", "full_report"):
        results = detect_stale_guests(token)
        report["findings"]["stale_guests"] = results
        print(f"[+] Stale guest accounts: {len(results)}")

    if args.action in ("mfa", "full_report"):
        results = check_users_without_mfa(token)
        report["findings"]["no_mfa"] = results
        print(f"[+] Users without MFA: {len(results)}")

    if args.action in ("reviews", "full_report"):
        results = get_access_reviews(token)
        report["findings"]["access_reviews"] = results
        print(f"[+] Active access reviews: {len(results)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
