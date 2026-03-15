#!/usr/bin/env python3
"""Google Workspace admin security hardening agent using Admin SDK."""

import json
import sys
import argparse
from datetime import datetime

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("Install: pip install google-api-python-client google-auth")
    sys.exit(1)


SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.domain",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit",
]


def get_admin_service(credentials_file, admin_email, api="admin", version="directory_v1"):
    """Build Google Admin SDK service with domain-wide delegation."""
    creds = service_account.Credentials.from_service_account_file(
        credentials_file, scopes=SCOPES, subject=admin_email)
    return build(api, version, credentials=creds)


def get_reports_service(credentials_file, admin_email):
    """Build Reports API service."""
    creds = service_account.Credentials.from_service_account_file(
        credentials_file, scopes=SCOPES, subject=admin_email)
    return build("admin", "reports_v1", credentials=creds)


def list_users_without_2fa(service, domain):
    """List users who have not enrolled in 2-Step Verification."""
    users_without_2fa = []
    request = service.users().list(domain=domain, maxResults=500,
                                    projection="full", orderBy="email")
    while request:
        response = request.execute()
        for user in response.get("users", []):
            is_enrolled = user.get("isEnrolledIn2Sv", False)
            is_enforced = user.get("isEnforcedIn2Sv", False)
            if not is_enrolled:
                users_without_2fa.append({
                    "email": user["primaryEmail"],
                    "name": user.get("name", {}).get("fullName", ""),
                    "is_admin": user.get("isAdmin", False),
                    "is_2sv_enrolled": is_enrolled,
                    "is_2sv_enforced": is_enforced,
                    "last_login": user.get("lastLoginTime", "never"),
                })
        request = service.users().list_next(request, response)
    return users_without_2fa


def list_admin_users(service, domain):
    """List all admin users and their admin roles."""
    admins = []
    request = service.users().list(domain=domain, maxResults=500,
                                    projection="full", query="isAdmin=true")
    response = request.execute()
    for user in response.get("users", []):
        admins.append({
            "email": user["primaryEmail"],
            "name": user.get("name", {}).get("fullName", ""),
            "is_super_admin": user.get("isAdmin", False),
            "is_delegated_admin": user.get("isDelegatedAdmin", False),
            "is_2sv_enrolled": user.get("isEnrolledIn2Sv", False),
            "last_login": user.get("lastLoginTime", "never"),
            "creation_time": user.get("creationTime", ""),
        })
    return admins


def get_login_audit_events(reports_service, user_email=None, days=7):
    """Get login audit events to detect suspicious activity."""
    events = []
    try:
        params = {"userKey": "all", "applicationName": "login", "maxResults": 200}
        if user_email:
            params["userKey"] = user_email
        request = reports_service.activities().list(**params)
        response = request.execute()
        for activity in response.get("items", []):
            for event in activity.get("events", []):
                event_data = {
                    "user": activity.get("actor", {}).get("email", ""),
                    "event_name": event.get("name", ""),
                    "time": activity.get("id", {}).get("time", ""),
                    "ip_address": activity.get("ipAddress", ""),
                }
                for param in event.get("parameters", []):
                    event_data[param["name"]] = param.get("value", param.get("boolValue", ""))
                events.append(event_data)
    except HttpError as e:
        events.append({"error": str(e)})
    return events


def check_suspended_users(service, domain):
    """List suspended users that may still have active sessions."""
    suspended = []
    request = service.users().list(domain=domain, maxResults=500,
                                    query="isSuspended=true")
    response = request.execute()
    for user in response.get("users", []):
        suspended.append({
            "email": user["primaryEmail"],
            "suspension_reason": user.get("suspensionReason", "manual"),
            "last_login": user.get("lastLoginTime", "never"),
        })
    return suspended


def check_recovery_settings(service, domain):
    """Audit users with recovery email/phone that could be used for account takeover."""
    findings = []
    request = service.users().list(domain=domain, maxResults=500, projection="full")
    response = request.execute()
    for user in response.get("users", []):
        recovery_email = user.get("recoveryEmail", "")
        recovery_phone = user.get("recoveryPhone", "")
        if user.get("isAdmin") and (recovery_email or recovery_phone):
            if recovery_email and not recovery_email.endswith(f"@{domain}"):
                findings.append({
                    "email": user["primaryEmail"],
                    "issue": "Admin has external recovery email",
                    "recovery_email": recovery_email,
                    "severity": "HIGH",
                })
    return findings


def run_workspace_audit(service, reports_service, domain):
    """Run comprehensive Google Workspace security audit."""
    print(f"\n{'='*60}")
    print(f"  GOOGLE WORKSPACE SECURITY AUDIT")
    print(f"  Domain: {domain}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    admins = list_admin_users(service, domain)
    print(f"--- ADMIN ACCOUNTS ({len(admins)}) ---")
    for a in admins:
        mfa_status = "2FA ON" if a["is_2sv_enrolled"] else "2FA OFF"
        print(f"  [{mfa_status}] {a['email']} (Super: {a['is_super_admin']})")

    no_2fa = list_users_without_2fa(service, domain)
    print(f"\n--- USERS WITHOUT 2FA ({len(no_2fa)}) ---")
    admin_no_2fa = [u for u in no_2fa if u["is_admin"]]
    if admin_no_2fa:
        print(f"  CRITICAL: {len(admin_no_2fa)} admin(s) without 2FA!")
        for u in admin_no_2fa:
            print(f"    {u['email']}")
    print(f"  Total users without 2FA: {len(no_2fa)}")

    recovery = check_recovery_settings(service, domain)
    print(f"\n--- RECOVERY SETTINGS ISSUES ({len(recovery)}) ---")
    for r in recovery:
        print(f"  [{r['severity']}] {r['email']}: {r['issue']}")

    suspended = check_suspended_users(service, domain)
    print(f"\n--- SUSPENDED USERS ({len(suspended)}) ---")
    for s in suspended[:5]:
        print(f"  {s['email']} (Reason: {s['suspension_reason']})")

    events = get_login_audit_events(reports_service)
    suspicious = [e for e in events if e.get("event_name") == "login_failure"]
    print(f"\n--- RECENT LOGIN EVENTS ---")
    print(f"  Total events: {len(events)}")
    print(f"  Failed logins: {len(suspicious)}")

    print(f"\n{'='*60}\n")
    return {"admins": len(admins), "no_2fa": len(no_2fa),
            "admin_no_2fa": len(admin_no_2fa), "suspended": len(suspended)}


def main():
    parser = argparse.ArgumentParser(description="Google Workspace Admin Security Agent")
    parser.add_argument("--credentials", required=True, help="Service account JSON key file")
    parser.add_argument("--admin-email", required=True, help="Admin email for delegation")
    parser.add_argument("--domain", required=True, help="Google Workspace domain")
    parser.add_argument("--audit", action="store_true", help="Run full security audit")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.audit:
        service = get_admin_service(args.credentials, args.admin_email)
        reports = get_reports_service(args.credentials, args.admin_email)
        report = run_workspace_audit(service, reports, args.domain)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
