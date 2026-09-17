#!/usr/bin/env python3
"""Rapid7 InsightVM vulnerability scanning agent.

Interfaces with the InsightVM (Nexpose) REST API to manage scan
configurations, launch scans, retrieve vulnerability results, and
generate remediation reports. Supports site management, asset
discovery, and vulnerability prioritization.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("[!] 'requests' required: pip install requests", file=sys.stderr)
    sys.exit(1)


def get_insightvm_config():
    """Return InsightVM API connection config."""
    host = os.environ.get("INSIGHTVM_HOST", "localhost")
    port = os.environ.get("INSIGHTVM_PORT", "3780")
    user = os.environ.get("INSIGHTVM_USER", "")
    password = os.environ.get("INSIGHTVM_PASSWORD", "")
    return f"https://{host}:{port}", user, password


def api_call(base_url, endpoint, user, password, method="GET",
             data=None, params=None):
    """Make authenticated API call to InsightVM."""
    url = f"{base_url}/api/3{endpoint}"
    auth = HTTPBasicAuth(user, password)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if method == "POST":
        resp = requests.post(url, auth=auth, headers=headers, json=data,
                             params=params,
                             verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=60)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    elif method == "PUT":
        resp = requests.put(url, auth=auth, headers=headers, json=data,
                            verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=60)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    else:
        resp = requests.get(url, auth=auth, headers=headers, params=params,
                            verify=not os.environ.get("SKIP_TLS_VERIFY", "").lower() == "true", timeout=60)  # Set SKIP_TLS_VERIFY=true for self-signed certs in lab environments
    resp.raise_for_status()
    return resp.json()


def list_sites(base_url, user, password):
    """List all scan sites."""
    print("[*] Listing sites...")
    data = api_call(base_url, "/sites", user, password, params={"size": 500})
    sites = []
    for site in data.get("resources", []):
        sites.append({
            "id": site.get("id"),
            "name": site.get("name", ""),
            "description": site.get("description", ""),
            "type": site.get("type", ""),
            "assets": site.get("assets", 0),
            "last_scan_time": site.get("lastScanTime", ""),
            "risk_score": site.get("riskScore", 0),
        })
    print(f"[+] Found {len(sites)} sites")
    return sites


def get_site_vulnerabilities(base_url, user, password, site_id):
    """Get vulnerabilities for a specific site."""
    print(f"[*] Fetching vulnerabilities for site {site_id}...")
    vulns = []
    page = 0
    while True:
        data = api_call(base_url, f"/sites/{site_id}/vulnerabilities",
                        user, password, params={"page": page, "size": 100})
        resources = data.get("resources", [])
        if not resources:
            break
        for v in resources:
            vulns.append({
                "id": v.get("id", ""),
                "title": v.get("title", ""),
                "severity": v.get("severity", ""),
                "cvss_v3_score": v.get("cvss", {}).get("v3", {}).get("score", 0),
                "risk_score": v.get("riskScore", 0),
                "instances": v.get("instances", 0),
                "status": v.get("status", ""),
            })
        page += 1
        total_pages = data.get("page", {}).get("totalPages", 1)
        if page >= total_pages:
            break

    print(f"[+] Retrieved {len(vulns)} vulnerabilities")
    return vulns


def launch_scan(base_url, user, password, site_id, scan_name=None):
    """Launch a scan on a site."""
    if not scan_name:
        scan_name = f"agent-scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    print(f"[*] Launching scan '{scan_name}' on site {site_id}...")
    data = api_call(base_url, f"/sites/{site_id}/scans", user, password,
                    method="POST", data={"name": scan_name})
    scan_id = data.get("id")
    print(f"[+] Scan started, ID: {scan_id}")
    return scan_id


def poll_scan_status(base_url, user, password, scan_id, max_wait=1800):
    """Poll scan status until completion."""
    print(f"[*] Waiting for scan {scan_id} to complete...")
    elapsed = 0
    interval = 30
    while elapsed < max_wait:
        data = api_call(base_url, f"/scans/{scan_id}", user, password)
        status = data.get("status", "unknown")
        if status in ("finished", "stopped", "error"):
            print(f"[+] Scan {status}")
            return status, data
        print(f"    Status: {status} ({elapsed}s)")
        time.sleep(interval)
        elapsed += interval
    print("[!] Scan timed out")
    return "timeout", {}


def get_scan_report(base_url, user, password, scan_id):
    """Get scan results summary."""
    data = api_call(base_url, f"/scans/{scan_id}", user, password)
    return {
        "scan_id": scan_id,
        "status": data.get("status", ""),
        "start_time": data.get("startTime", ""),
        "end_time": data.get("endTime", ""),
        "duration": data.get("duration", ""),
        "assets_discovered": data.get("assets", 0),
        "vulnerabilities": data.get("vulnerabilities", {}),
    }


def format_summary(sites, vulns=None, scan_report=None):
    """Print summary."""
    print(f"\n{'='*60}")
    print("  Rapid7 InsightVM Report")
    print(f"{'='*60}")

    if sites:
        print(f"\n  Sites ({len(sites)}):")
        for s in sites:
            print(f"    {s['name']:30s} | Assets: {s['assets']:5d} | "
                  f"Risk: {s['risk_score']:8.1f}")

    if vulns:
        severity_counts = {}
        for v in vulns:
            sev = v.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        print(f"\n  Vulnerabilities ({len(vulns)}):")
        for sev in sorted(severity_counts.keys()):
            print(f"    {sev:15s}: {severity_counts[sev]}")

    if scan_report:
        print("\n  Scan Report:")
        print(f"    Status    : {scan_report.get('status', 'N/A')}")
        print(f"    Assets    : {scan_report.get('assets_discovered', 0)}")


def main():
    parser = argparse.ArgumentParser(description="Rapid7 InsightVM scanning agent")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list-sites", help="List scan sites")

    p_vulns = sub.add_parser("get-vulns", help="Get site vulnerabilities")
    p_vulns.add_argument("--site-id", required=True, type=int)

    p_scan = sub.add_parser("scan", help="Launch a scan")
    p_scan.add_argument("--site-id", required=True, type=int)
    p_scan.add_argument("--wait", action="store_true", help="Wait for completion")
    p_scan.add_argument("--max-wait", type=int, default=1800)

    parser.add_argument("--host", help="InsightVM host (or INSIGHTVM_HOST env)")
    parser.add_argument("--user", help="Username (or INSIGHTVM_USER env)")
    parser.add_argument("--password", help="Password (or INSIGHTVM_PASSWORD env)")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.host:
        os.environ["INSIGHTVM_HOST"] = args.host
    if args.user:
        os.environ["INSIGHTVM_USER"] = args.user
    if args.password:
        os.environ["INSIGHTVM_PASSWORD"] = args.password

    base_url, user, password = get_insightvm_config()
    if not user or not password:
        print("[!] Set INSIGHTVM_USER and INSIGHTVM_PASSWORD", file=sys.stderr)
        sys.exit(1)

    result = {}
    if args.command == "list-sites":
        sites = list_sites(base_url, user, password)
        format_summary(sites)
        result = {"sites": sites}
    elif args.command == "get-vulns":
        vulns = get_site_vulnerabilities(base_url, user, password, args.site_id)
        format_summary([], vulns)
        result = {"site_id": args.site_id, "vulnerabilities": vulns}
    elif args.command == "scan":
        scan_id = launch_scan(base_url, user, password, args.site_id)
        if args.wait:
            status, data = poll_scan_status(base_url, user, password, scan_id, args.max_wait)
            scan_report = get_scan_report(base_url, user, password, scan_id)
            format_summary([], scan_report=scan_report)
            result = {"scan_id": scan_id, "report": scan_report}
        else:
            result = {"scan_id": scan_id, "status": "launched"}

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Rapid7 InsightVM",
        "command": args.command,
        "result": result,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
