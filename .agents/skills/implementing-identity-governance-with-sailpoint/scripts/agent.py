#!/usr/bin/env python3
"""Agent for auditing SailPoint IdentityNow/IIQ identity governance."""

import json
import argparse
from datetime import datetime, timedelta
from collections import Counter

try:
    import requests
except ImportError:
    requests = None


def sailpoint_api(base_url, token, endpoint, method="GET", params=None):
    """Call SailPoint IdentityNow API."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.request(method, f"{base_url}{endpoint}",
                            headers=headers, params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()


def list_identities(base_url, token, limit=250):
    """List identities from SailPoint."""
    return sailpoint_api(base_url, token, "/v3/search/identities",
                         params={"limit": limit})


def list_access_profiles(base_url, token):
    """List access profiles."""
    return sailpoint_api(base_url, token, "/v3/access-profiles", params={"limit": 250})


def list_certifications(base_url, token):
    """List active certification campaigns."""
    return sailpoint_api(base_url, token, "/v3/campaigns", params={"limit": 50})


def audit_certification_campaigns(campaigns_data):
    """Audit certification campaign completion and compliance."""
    campaigns = campaigns_data if isinstance(campaigns_data, list) else \
        campaigns_data.get("campaigns", campaigns_data.get("items", []))
    findings = []
    for campaign in campaigns:
        status = campaign.get("status", "").lower()
        completion = campaign.get("completionPercentage", campaign.get("completion", 0))
        deadline = campaign.get("deadline", campaign.get("due_date", ""))
        if status == "active" and completion < 50:
            findings.append({
                "campaign": campaign.get("name", ""),
                "issue": f"Low completion: {completion}%",
                "severity": "HIGH",
                "deadline": deadline,
            })
        if status == "overdue":
            findings.append({
                "campaign": campaign.get("name", ""),
                "issue": "Campaign overdue",
                "severity": "CRITICAL",
            })
    return findings


def audit_sod_violations(sod_data):
    """Audit Separation of Duties policy violations."""
    violations = sod_data if isinstance(sod_data, list) else \
        sod_data.get("violations", [])
    by_policy = Counter(v.get("policy_name", "unknown") for v in violations)
    by_identity = Counter(v.get("identity", "unknown") for v in violations)
    critical = [v for v in violations if v.get("severity", "").lower() == "critical"]
    return {
        "total_violations": len(violations),
        "by_policy": dict(by_policy),
        "top_violators": dict(by_identity.most_common(10)),
        "critical_violations": len(critical),
        "details": critical[:20],
    }


def audit_orphan_accounts(accounts_data):
    """Find orphan accounts (no identity correlation)."""
    accounts = accounts_data if isinstance(accounts_data, list) else \
        accounts_data.get("accounts", [])
    orphans = []
    for acct in accounts:
        if not acct.get("identityId") and not acct.get("identity"):
            orphans.append({
                "account": acct.get("name", acct.get("nativeIdentity", "")),
                "source": acct.get("sourceName", acct.get("source", "")),
                "created": acct.get("created", ""),
                "last_login": acct.get("lastLogin", acct.get("last_login", "")),
                "severity": "HIGH",
            })
    return {
        "total_accounts": len(accounts),
        "orphan_count": len(orphans),
        "orphans": orphans[:50],
    }


def audit_access_reviews(reviews_path):
    """Audit access review data for over-provisioned users."""
    with open(reviews_path) as f:
        reviews = json.load(f)
    items = reviews if isinstance(reviews, list) else reviews.get("reviews", [])
    over_provisioned = []
    for review in items:
        entitlements = review.get("entitlements", review.get("access", []))
        unused = [e for e in entitlements if not e.get("used_last_90_days",
                  e.get("last_used", "") != "")]
        if len(unused) > 3:
            over_provisioned.append({
                "identity": review.get("identity", review.get("user", "")),
                "total_entitlements": len(entitlements),
                "unused_entitlements": len(unused),
                "severity": "HIGH" if len(unused) > 10 else "MEDIUM",
            })
    return {
        "total_reviewed": len(items),
        "over_provisioned": len(over_provisioned),
        "details": over_provisioned[:20],
    }


def generate_lifecycle_policy():
    """Generate identity lifecycle policy recommendations."""
    return {
        "joiner": {
            "trigger": "HR system new hire event",
            "actions": ["Create identity", "Provision birthright access",
                        "Assign department role", "Send welcome notification"],
            "sla": "Within 24 hours of start date",
        },
        "mover": {
            "trigger": "Department or role change in HR system",
            "actions": ["Recalculate role entitlements", "Revoke old department access",
                        "Provision new role access", "Trigger manager certification"],
            "sla": "Within 48 hours of change",
        },
        "leaver": {
            "trigger": "Termination event from HR system",
            "actions": ["Disable all accounts immediately", "Revoke all access",
                        "Transfer ownership of shared resources",
                        "Archive mailbox", "Remove from all groups"],
            "sla": "Within 1 hour of termination (immediate for involuntary)",
        },
    }


def main():
    parser = argparse.ArgumentParser(description="SailPoint Identity Governance Agent")
    parser.add_argument("--campaigns", help="Certification campaigns JSON")
    parser.add_argument("--sod", help="SOD violations JSON")
    parser.add_argument("--accounts", help="Accounts data JSON for orphan detection")
    parser.add_argument("--reviews", help="Access reviews JSON")
    parser.add_argument("--action", choices=["campaigns", "sod", "orphans", "reviews",
                                              "lifecycle", "full"], default="full")
    parser.add_argument("--output", default="sailpoint_governance_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("campaigns", "full") and args.campaigns:
        with open(args.campaigns) as f:
            data = json.load(f)
        findings = audit_certification_campaigns(data)
        report["results"]["campaigns"] = findings
        print(f"[+] Campaign issues: {len(findings)}")

    if args.action in ("sod", "full") and args.sod:
        with open(args.sod) as f:
            data = json.load(f)
        result = audit_sod_violations(data)
        report["results"]["sod"] = result
        print(f"[+] SOD violations: {result['total_violations']}")

    if args.action in ("orphans", "full") and args.accounts:
        with open(args.accounts) as f:
            data = json.load(f)
        result = audit_orphan_accounts(data)
        report["results"]["orphans"] = result
        print(f"[+] Orphan accounts: {result['orphan_count']}")

    if args.action in ("reviews", "full") and args.reviews:
        result = audit_access_reviews(args.reviews)
        report["results"]["reviews"] = result
        print(f"[+] Over-provisioned: {result['over_provisioned']}")

    if args.action in ("lifecycle", "full"):
        policy = generate_lifecycle_policy()
        report["results"]["lifecycle"] = policy
        print("[+] Lifecycle policy generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
