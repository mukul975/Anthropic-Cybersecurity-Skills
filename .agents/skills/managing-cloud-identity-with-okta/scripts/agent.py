#!/usr/bin/env python3
"""
Okta Cloud Identity Management Agent
Audits Okta tenant configuration including SSO apps, MFA policies,
lifecycle rules, and user provisioning status using the Okta Python SDK.
"""

import json
import os
import sys
from datetime import datetime, timezone

from okta.client import Client as OktaClient


async def get_okta_client(org_url: str, api_token: str) -> OktaClient:
    """Initialize Okta SDK client."""
    config = {
        "orgUrl": org_url,
        "token": api_token,
    }
    return OktaClient(config)


async def audit_users(client: OktaClient) -> dict:
    """Audit user accounts for security issues."""
    users, _, _ = await client.list_users()
    total = len(users)
    active = 0
    suspended = 0
    deprovisioned = 0
    no_mfa = []
    stale_users = []

    for user in users:
        status = user.status
        if status == "ACTIVE":
            active += 1
        elif status == "SUSPENDED":
            suspended += 1
        elif status == "DEPROVISIONED":
            deprovisioned += 1

        factors, _, _ = await client.list_factors(user.id)  # okta.client.list_factors(userId)
        if not factors:
            no_mfa.append({
                "user_id": user.id,
                "login": user.profile.login,
                "status": status,
            })

        if user.last_login:
            last = datetime.fromisoformat(user.last_login.replace("Z", "+00:00"))
            days_inactive = (datetime.now(timezone.utc) - last).days
            if days_inactive > 90:
                stale_users.append({
                    "login": user.profile.login,
                    "days_inactive": days_inactive,
                    "status": status,
                })

    return {
        "total_users": total,
        "active": active,
        "suspended": suspended,
        "deprovisioned": deprovisioned,
        "users_without_mfa": no_mfa,
        "stale_users_90d": stale_users,
    }


async def audit_applications(client: OktaClient) -> dict:
    """Audit SSO application integrations."""
    apps, _, _ = await client.list_applications()
    app_details = []

    for app in apps:
        sign_on = getattr(app, "signOnMode", "unknown")
        app_details.append({
            "id": app.id,
            "label": app.label,
            "status": app.status,
            "sign_on_mode": sign_on,
            "created": str(getattr(app, "created", "")),
        })

    saml_apps = [a for a in app_details if "SAML" in a["sign_on_mode"].upper()]
    oidc_apps = [a for a in app_details if "OPENID" in a["sign_on_mode"].upper()]
    inactive_apps = [a for a in app_details if a["status"] != "ACTIVE"]

    return {
        "total_apps": len(app_details),
        "saml_apps": len(saml_apps),
        "oidc_apps": len(oidc_apps),
        "inactive_apps": len(inactive_apps),
        "applications": app_details,
    }


async def audit_policies(client: OktaClient) -> dict:
    """Audit authentication and sign-on policies."""
    policies, _, _ = await client.list_policies({"type": "OKTA_SIGN_ON"})
    policy_details = []

    for policy in policies:
        rules, _, _ = await client.list_policy_rules(policy.id)
        rule_details = []
        for rule in rules:
            rule_details.append({
                "name": rule.name,
                "status": rule.status,
                "type": getattr(rule, "type", "unknown"),
            })

        policy_details.append({
            "id": policy.id,
            "name": policy.name,
            "status": policy.status,
            "rules_count": len(rules),
            "rules": rule_details,
        })

    mfa_policies, _, _ = await client.list_policies({"type": "MFA_ENROLL"})
    mfa_details = []
    for policy in mfa_policies:
        mfa_details.append({
            "id": policy.id,
            "name": policy.name,
            "status": policy.status,
        })

    return {
        "sign_on_policies": policy_details,
        "mfa_enrollment_policies": mfa_details,
    }


async def audit_groups(client: OktaClient) -> dict:
    """Audit group membership and assignments."""
    groups, _, _ = await client.list_groups()
    group_details = []

    for group in groups:
        members, _, _ = await client.list_group_users(group.id)
        group_details.append({
            "id": group.id,
            "name": group.profile.name,
            "type": group.type,
            "member_count": len(members),
        })

    return {
        "total_groups": len(group_details),
        "groups": group_details,
    }


def generate_report(users: dict, apps: dict, policies: dict, groups: dict) -> str:
    """Generate Okta identity audit report."""
    lines = [
        "OKTA CLOUD IDENTITY AUDIT REPORT",
        "=" * 50,
        f"Report Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "USER INVENTORY:",
        f"  Total Users: {users['total_users']}",
        f"  Active: {users['active']}  Suspended: {users['suspended']}  Deprovisioned: {users['deprovisioned']}",
        f"  Users Without MFA: {len(users['users_without_mfa'])}",
        f"  Stale Users (90+ days): {len(users['stale_users_90d'])}",
        "",
        "APPLICATION INTEGRATIONS:",
        f"  Total Apps: {apps['total_apps']}",
        f"  SAML SSO: {apps['saml_apps']}  OIDC: {apps['oidc_apps']}",
        f"  Inactive Apps: {apps['inactive_apps']}",
        "",
        "POLICIES:",
        f"  Sign-On Policies: {len(policies['sign_on_policies'])}",
        f"  MFA Enrollment Policies: {len(policies['mfa_enrollment_policies'])}",
        "",
        "GROUPS:",
        f"  Total Groups: {groups['total_groups']}",
        "",
        "ISSUES:",
    ]

    issues = []
    if users["users_without_mfa"]:
        issues.append(f"[HIGH] {len(users['users_without_mfa'])} users have no MFA enrolled")
    if users["stale_users_90d"]:
        issues.append(f"[MEDIUM] {len(users['stale_users_90d'])} users inactive for 90+ days")
    if apps["inactive_apps"]:
        issues.append(f"[LOW] {apps['inactive_apps']} inactive application integrations")

    for issue in issues:
        lines.append(f"  {issue}")

    return "\n".join(lines)


async def main():
    org_url = os.getenv("OKTA_ORG_URL", "https://your-org.okta.com")
    api_token = os.getenv("OKTA_API_TOKEN", "")

    if not api_token:
        print("[!] Set OKTA_API_TOKEN environment variable")
        sys.exit(1)

    print(f"[*] Connecting to Okta: {org_url}")
    client = await get_okta_client(org_url, api_token)

    users = await audit_users(client)
    apps = await audit_applications(client)
    policies = await audit_policies(client)
    groups = await audit_groups(client)

    report = generate_report(users, apps, policies, groups)
    print(report)

    output = f"okta_audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"users": users, "apps": apps, "policies": policies, "groups": groups}, f, indent=2, default=str)
    print(f"\n[*] Results saved to {output}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
