#!/usr/bin/env python3
"""Cortex XSOAR playbook management agent.

Interfaces with the Cortex XSOAR (Demisto) API to manage and audit
security playbooks, automation scripts, incidents, and integrations.
Supports listing playbooks, checking incident statistics, and
verifying integration health.
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


def get_xsoar_config():
    """Return XSOAR server URL and API key."""
    server = os.environ.get("XSOAR_URL", "").rstrip("/")
    api_key = os.environ.get("XSOAR_API_KEY", "")
    if not server or not api_key:
        print("[!] Set XSOAR_URL and XSOAR_API_KEY env vars", file=sys.stderr)
        sys.exit(1)
    return server, api_key


def xsoar_api(server, api_key, endpoint, method="POST", data=None):
    """Make authenticated XSOAR API call."""
    url = f"{server}{endpoint}"
    headers = {"Authorization": api_key, "Content-Type": "application/json",
               "Accept": "application/json"}
    if method == "GET":
        resp = requests.get(url, headers=headers,
                            verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=30)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    else:
        resp = requests.post(url, headers=headers, json=data or {},
                             verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=30)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    resp.raise_for_status()
    return resp.json()


def list_playbooks(server, api_key, query=""):
    """List all playbooks."""
    print("[*] Fetching playbooks...")
    data = {"query": query, "page": 0, "size": 500}
    result = xsoar_api(server, api_key, "/playbook/search", data=data)
    playbooks = result.get("playbooks", [])
    print(f"[+] Found {len(playbooks)} playbooks")
    return [{
        "id": pb.get("id", ""),
        "name": pb.get("name", ""),
        "version": pb.get("version", 0),
        "deprecated": pb.get("deprecated", False),
        "hidden": pb.get("hidden", False),
        "system": pb.get("system", False),
        "modified": pb.get("modified", ""),
    } for pb in playbooks]


def get_incident_stats(server, api_key, days=30):
    """Get incident statistics."""
    print(f"[*] Fetching incident statistics (last {days}d)...")
    data = {"size": 0, "filter": {"period": {"by": "day", "fromValue": days}}}
    result = xsoar_api(server, api_key, "/incidents/search", data=data)
    total = result.get("total", 0)
    print(f"[+] {total} incidents in last {days} days")

    # Get status breakdown
    statuses = {}
    data_with_agg = {"size": 0, "filter": {"period": {"by": "day", "fromValue": days}},
                     "aggregations": [{"field": "status", "type": "terms"}]}
    try:
        agg_result = xsoar_api(server, api_key, "/incidents/search", data=data_with_agg)
        for bucket in agg_result.get("aggregations", {}).get("status", {}).get("buckets", []):
            statuses[bucket.get("key", "unknown")] = bucket.get("doc_count", 0)
    except (requests.RequestException, KeyError):
        pass

    return {"total": total, "period_days": days, "by_status": statuses}


def list_integrations(server, api_key):
    """List configured integrations and their health."""
    print("[*] Fetching integrations...")
    result = xsoar_api(server, api_key, "/settings/integration/search",
                       data={"size": 500})
    instances = result.get("instances", [])
    integrations = []
    for inst in instances:
        integrations.append({
            "name": inst.get("name", ""),
            "brand": inst.get("brand", ""),
            "enabled": inst.get("enabled", ""),
            "is_long_running": inst.get("isLongRunning", False),
            "configured": inst.get("configurationStatus", ""),
        })
    print(f"[+] Found {len(integrations)} integration instances")
    return integrations


def audit_playbook_health(playbooks, integrations):
    """Audit playbooks for common issues."""
    findings = []
    deprecated = [pb for pb in playbooks if pb.get("deprecated")]
    if deprecated:
        findings.append({
            "check": "Deprecated playbooks in use",
            "severity": "MEDIUM",
            "count": len(deprecated),
            "detail": ", ".join(pb["name"] for pb in deprecated[:5]),
        })

    disabled_integrations = [i for i in integrations if i.get("enabled") == "false"]
    if disabled_integrations:
        findings.append({
            "check": "Disabled integrations",
            "severity": "HIGH",
            "count": len(disabled_integrations),
            "detail": ", ".join(i["name"] for i in disabled_integrations[:5]),
        })

    return findings


def format_summary(playbooks, incident_stats, integrations, findings):
    """Print XSOAR audit summary."""
    print(f"\n{'='*60}")
    print("  Cortex XSOAR Playbook Audit Report")
    print(f"{'='*60}")
    print(f"  Playbooks    : {len(playbooks)}")
    print(f"  Integrations : {len(integrations)}")
    print(f"  Incidents    : {incident_stats.get('total', 0)} (last {incident_stats.get('period_days', 30)}d)")
    print(f"  Findings     : {len(findings)}")

    if incident_stats.get("by_status"):
        print("\n  Incidents by Status:")
        for status, count in incident_stats["by_status"].items():
            print(f"    {status:15s}: {count}")

    enabled_count = sum(1 for i in integrations if i.get("enabled") != "false")
    print(f"\n  Integrations: {enabled_count} enabled, {len(integrations) - enabled_count} disabled")

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="Cortex XSOAR playbook audit agent")
    parser.add_argument("--url", help="XSOAR URL (or XSOAR_URL env)")
    parser.add_argument("--api-key", help="API key (or XSOAR_API_KEY env)")
    parser.add_argument("--days", type=int, default=30, help="Incident stats period")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.url:
        os.environ["XSOAR_URL"] = args.url
    if args.api_key:
        os.environ["XSOAR_API_KEY"] = args.api_key

    server, api_key = get_xsoar_config()

    playbooks = list_playbooks(server, api_key)
    incident_stats = get_incident_stats(server, api_key, args.days)
    integrations = list_integrations(server, api_key)
    findings = audit_playbook_health(playbooks, integrations)

    severity_counts = format_summary(playbooks, incident_stats, integrations, findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Cortex XSOAR Audit",
        "playbooks": playbooks,
        "incident_stats": incident_stats,
        "integrations": integrations,
        "findings": findings,
        "severity_counts": severity_counts,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
