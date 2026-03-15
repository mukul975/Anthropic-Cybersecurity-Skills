#!/usr/bin/env python3
"""Agent for configuring and auditing NextDNS zero trust DNS filtering via API."""

import requests
import json
import argparse
import sys
from datetime import datetime, timezone

NEXTDNS_API = "https://api.nextdns.io"


def get_profile(api_key, profile_id):
    """Retrieve NextDNS profile configuration."""
    headers = {"X-Api-Key": api_key}
    resp = requests.get(f"{NEXTDNS_API}/profiles/{profile_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    profile = resp.json()
    print(f"[*] Profile: {profile.get('name', profile_id)}")
    print(f"  Security: {json.dumps(profile.get('security', {}), indent=2)[:200]}")
    return profile


def audit_security_settings(api_key, profile_id):
    """Audit security features enabled on a NextDNS profile."""
    headers = {"X-Api-Key": api_key}
    resp = requests.get(f"{NEXTDNS_API}/profiles/{profile_id}/security", headers=headers, timeout=15)
    resp.raise_for_status()
    security = resp.json()
    findings = []
    checks = {
        "threatIntelligenceFeeds": "Threat intelligence feeds",
        "aiDetection": "AI-driven threat detection",
        "googleSafeBrowsing": "Google Safe Browsing",
        "cryptojacking": "Cryptojacking protection",
        "dnsRebinding": "DNS rebinding protection",
        "idnHomographs": "IDN homograph protection",
        "typosquatting": "Typosquatting protection",
        "dga": "DGA domain protection",
        "nrd": "Newly registered domains blocking",
        "ddns": "Dynamic DNS blocking",
        "csam": "CSAM blocking",
    }
    for key, label in checks.items():
        enabled = security.get(key, False)
        status = "ENABLED" if enabled else "DISABLED"
        if not enabled:
            findings.append({"feature": label, "key": key, "severity": "MEDIUM"})
        print(f"  [{'+' if enabled else '!'}] {label}: {status}")
    print(f"\n[*] {len(findings)} security features disabled")
    return findings


def get_query_logs(api_key, profile_id, limit=100):
    """Retrieve recent DNS query logs for analysis."""
    headers = {"X-Api-Key": api_key}
    params = {"limit": limit}
    resp = requests.get(f"{NEXTDNS_API}/profiles/{profile_id}/logs",
                        headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    logs = resp.json().get("data", [])
    blocked = [l for l in logs if l.get("status") == "blocked"]
    print(f"[*] Query logs: {len(logs)} total, {len(blocked)} blocked")
    for entry in blocked[:10]:
        print(f"  [BLOCKED] {entry.get('domain')} - reason: {entry.get('reasons', ['?'])[0]}")
    return logs


def get_analytics(api_key, profile_id, period="last30d"):
    """Retrieve DNS analytics and threat statistics."""
    headers = {"X-Api-Key": api_key}
    endpoints = {
        "queries": f"/profiles/{profile_id}/analytics/status",
        "domains": f"/profiles/{profile_id}/analytics/domains",
        "blocked_reasons": f"/profiles/{profile_id}/analytics/blockedReasons",
    }
    analytics = {}
    for name, path in endpoints.items():
        resp = requests.get(f"{NEXTDNS_API}{path}", headers=headers,
                            params={"from": f"-{period}"}, timeout=15)
        if resp.status_code == 200:
            analytics[name] = resp.json()
    if "queries" in analytics:
        data = analytics["queries"].get("data", [])
        total = sum(d.get("queries", 0) for d in data)
        blocked = sum(d.get("blockedQueries", 0) for d in data)
        print(f"[*] Analytics ({period}): {total} queries, {blocked} blocked "
              f"({blocked/total*100:.1f}%)" if total else "[*] No query data")
    return analytics


def check_denylist(api_key, profile_id):
    """Check configured denylists and custom blocked domains."""
    headers = {"X-Api-Key": api_key}
    resp = requests.get(f"{NEXTDNS_API}/profiles/{profile_id}/denylist",
                        headers=headers, timeout=15)
    resp.raise_for_status()
    denylist = resp.json()
    entries = denylist.get("data", [])
    print(f"[*] Denylist entries: {len(entries)}")
    for e in entries[:20]:
        print(f"  {e.get('id', 'unknown')}: active={e.get('active', True)}")
    return entries


def generate_report(profile, findings, logs, analytics, output_path):
    """Generate NextDNS audit report."""
    report = {
        "audit_date": datetime.now(timezone.utc).isoformat(),
        "profile": profile.get("name", "unknown"),
        "security_findings": findings,
        "blocked_queries_sample": [l for l in logs if l.get("status") == "blocked"][:20],
        "analytics_summary": analytics,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="NextDNS Zero Trust DNS Audit Agent")
    parser.add_argument("action", choices=["audit", "logs", "analytics", "denylist", "full-audit"])
    parser.add_argument("--api-key", required=True, help="NextDNS API key")
    parser.add_argument("--profile", required=True, help="NextDNS profile ID")
    parser.add_argument("-o", "--output", default="nextdns_audit.json")
    args = parser.parse_args()

    if args.action == "audit":
        get_profile(args.api_key, args.profile)
        audit_security_settings(args.api_key, args.profile)
    elif args.action == "logs":
        get_query_logs(args.api_key, args.profile)
    elif args.action == "analytics":
        get_analytics(args.api_key, args.profile)
    elif args.action == "denylist":
        check_denylist(args.api_key, args.profile)
    elif args.action == "full-audit":
        prof = get_profile(args.api_key, args.profile)
        findings = audit_security_settings(args.api_key, args.profile)
        logs = get_query_logs(args.api_key, args.profile)
        analytics = get_analytics(args.api_key, args.profile)
        generate_report(prof, findings, logs, analytics, args.output)


if __name__ == "__main__":
    main()
