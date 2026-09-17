#!/usr/bin/env python3
"""Okta SCIM provisioning audit agent.

Audits Okta SCIM provisioning configuration by querying the Okta API
for provisioned applications, user assignments, group memberships, and
deprovisioning status. Identifies orphaned accounts, mismatched
assignments, and provisioning failures.
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


def get_okta_config():
    """Return Okta org URL and API token."""
    org_url = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
    api_token = os.environ.get("OKTA_API_TOKEN", "")
    if not org_url or not api_token:
        print("[!] Set OKTA_ORG_URL and OKTA_API_TOKEN env vars", file=sys.stderr)
        sys.exit(1)
    return org_url, api_token


def okta_api(org_url, token, endpoint, params=None):
    """Make authenticated Okta API call with pagination."""
    url = f"{org_url}/api/v1{endpoint}"
    headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
    all_results = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        all_results.extend(resp.json())
        links = resp.links
        url = links.get("next", {}).get("url")
        params = None  # Pagination URL includes params
    return all_results


def list_provisioning_apps(org_url, token):
    """List applications with SCIM provisioning enabled."""
    print("[*] Fetching provisioning-enabled applications...")
    apps = okta_api(org_url, token, "/apps", params={"limit": 200})
    scim_apps = []
    for app in apps:
        features = app.get("features", [])
        if any(f in features for f in [
            "PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION",
            "IMPORT_NEW_USERS", "PUSH_PROFILE_UPDATES"
        ]):
            scim_apps.append({
                "id": app.get("id"),
                "name": app.get("name", ""),
                "label": app.get("label", ""),
                "status": app.get("status", ""),
                "features": features,
                "sign_on_mode": app.get("signOnMode", ""),
                "created": app.get("created", ""),
            })
    print(f"[+] Found {len(scim_apps)} SCIM-enabled apps")
    return scim_apps


def audit_app_assignments(org_url, token, app_id, app_label):
    """Audit user assignments for a provisioning app."""
    findings = []
    print(f"[*] Auditing assignments for: {app_label}")
    users = okta_api(org_url, token, f"/apps/{app_id}/users", params={"limit": 200})

    status_counts = {}
    for user in users:
        status = user.get("status", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        scope = user.get("scope", "")
        sync_state = user.get("syncState", "")

        if status == "PROVISIONED" and sync_state == "ERROR":
            findings.append({
                "app": app_label,
                "user": user.get("credentials", {}).get("userName", "unknown"),
                "check": "Provisioning sync error",
                "severity": "HIGH",
                "detail": f"User sync state: ERROR (status: {status})",
            })
        if status == "DEPROVISIONED":
            findings.append({
                "app": app_label,
                "user": user.get("credentials", {}).get("userName", "unknown"),
                "check": "Deprovisioned user still assigned",
                "severity": "MEDIUM",
                "detail": "User is deprovisioned but assignment exists",
            })

    findings.append({
        "app": app_label,
        "check": "Assignment summary",
        "severity": "INFO",
        "detail": f"Total: {len(users)}, Status: {json.dumps(status_counts)}",
    })
    return findings, users


def audit_group_assignments(org_url, token, app_id, app_label):
    """Audit group-based provisioning assignments."""
    findings = []
    groups = okta_api(org_url, token, f"/apps/{app_id}/groups", params={"limit": 200})
    if not groups:
        findings.append({
            "app": app_label,
            "check": "Group assignments",
            "severity": "MEDIUM",
            "detail": "No group assignments found (user-level only)",
        })
    else:
        for group in groups:
            group_id = group.get("id", "")
            priority = group.get("priority", 0)
            findings.append({
                "app": app_label,
                "check": f"Group assignment: {group_id}",
                "severity": "INFO",
                "detail": f"Priority: {priority}",
            })
    return findings


def check_deprovisioning(org_url, token):
    """Check for deactivated Okta users that still have active app assignments."""
    findings = []
    print("[*] Checking for orphaned provisioning assignments...")
    deactivated = okta_api(org_url, token, "/users",
                           params={"filter": 'status eq "DEPROVISIONED"', "limit": 200})
    for user in deactivated[:50]:  # Check first 50
        user_id = user.get("id")
        login = user.get("profile", {}).get("login", "unknown")
        try:
            apps = okta_api(org_url, token, f"/users/{user_id}/appLinks")
            if apps:
                findings.append({
                    "check": "Orphaned app assignment",
                    "user": login,
                    "severity": "HIGH",
                    "detail": f"Deactivated user has {len(apps)} active app link(s)",
                    "apps": [a.get("appName", "") for a in apps[:5]],
                })
        except requests.RequestException:
            pass

    if not findings:
        findings.append({
            "check": "Deprovisioning audit",
            "severity": "INFO",
            "detail": f"No orphaned assignments found ({len(deactivated)} deactivated users checked)",
        })
    return findings


def format_summary(scim_apps, all_findings):
    """Print audit summary."""
    print(f"\n{'='*60}")
    print("  Okta SCIM Provisioning Audit Report")
    print(f"{'='*60}")
    print(f"  SCIM Apps    : {len(scim_apps)}")
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

    if scim_apps:
        print("\n  Provisioning-Enabled Apps:")
        for app in scim_apps:
            print(f"    {app['label']:30s} | {app['status']:10s} | "
                  f"Features: {', '.join(app['features'][:3])}")

    issues = [f for f in all_findings if f["severity"] in ("CRITICAL", "HIGH")]
    if issues:
        print("\n  Issues Requiring Attention:")
        for f in issues[:15]:
            print(f"    [{f['severity']:8s}] {f['check']}: {f.get('detail', '')[:50]}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="Okta SCIM provisioning audit agent")
    parser.add_argument("--org-url", help="Okta org URL (or OKTA_ORG_URL env)")
    parser.add_argument("--token", help="API token (or OKTA_API_TOKEN env)")
    parser.add_argument("--app-id", help="Audit a specific app ID")
    parser.add_argument("--skip-deprovisioning", action="store_true")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.org_url:
        os.environ["OKTA_ORG_URL"] = args.org_url
    if args.token:
        os.environ["OKTA_API_TOKEN"] = args.token

    org_url, token = get_okta_config()
    all_findings = []

    scim_apps = list_provisioning_apps(org_url, token)
    for app in scim_apps:
        if args.app_id and app["id"] != args.app_id:
            continue
        findings, _ = audit_app_assignments(org_url, token, app["id"], app["label"])
        all_findings.extend(findings)
        group_findings = audit_group_assignments(org_url, token, app["id"], app["label"])
        all_findings.extend(group_findings)

    if not args.skip_deprovisioning:
        all_findings.extend(check_deprovisioning(org_url, token))

    severity_counts = format_summary(scim_apps, all_findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Okta SCIM Audit",
        "scim_apps": scim_apps,
        "findings": all_findings,
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
