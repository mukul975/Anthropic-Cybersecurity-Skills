#!/usr/bin/env python3
"""osquery endpoint monitoring agent for security auditing."""

import json
import sys
import argparse
import subprocess
from datetime import datetime


SECURITY_QUERIES = {
    "listening_ports": "SELECT p.pid, p.name, l.port, l.protocol, l.address FROM listening_ports l JOIN processes p ON l.pid = p.pid WHERE l.port != 0",
    "suid_binaries": "SELECT path, username, permissions FROM suid_bin",
    "crontab_entries": "SELECT command, path, event FROM crontab",
    "authorized_keys": "SELECT uid, username, key_file FROM authorized_keys",
    "logged_in_users": "SELECT user, host, type, time FROM logged_in_users",
    "kernel_modules": "SELECT name, size, used_by, status FROM kernel_modules WHERE status = 'Live'",
    "processes_high_cpu": "SELECT pid, name, uid, resident_size, percent_processor_time FROM processes WHERE percent_processor_time > 50",
    "docker_containers": "SELECT id, name, image, status, started_at FROM docker_containers",
    "browser_extensions": "SELECT name, identifier, version, path, browser_type FROM chrome_extensions UNION ALL SELECT name, identifier, version, path, browser_type FROM firefox_addons",
    "startup_items": "SELECT name, path, source FROM startup_items",
}


def run_osquery(query, output_format="json"):
    """Execute osquery and return results."""
    cmd = ["osqueryi", f"--{output_format}", query]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if output_format == "json" and result.stdout.strip():
            return json.loads(result.stdout)
        return [{"raw": result.stdout[:1000]}]
    except FileNotFoundError:
        return [{"error": "osquery not installed. Install from https://osquery.io/downloads/"}]
    except (json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        return [{"error": str(e)}]


def check_fleet_status(fleet_url, api_token):
    """Check Fleet server host enrollment status."""
    import requests
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        resp = requests.get(f"{fleet_url}/api/v1/fleet/hosts", headers=headers, timeout=10)
        resp.raise_for_status()
        hosts = resp.json().get("hosts", [])
        return [{
            "hostname": h.get("hostname", ""),
            "platform": h.get("platform", ""),
            "osquery_version": h.get("osquery_version", ""),
            "status": h.get("status", ""),
            "last_seen": h.get("seen_time", ""),
        } for h in hosts]
    except Exception as e:
        return [{"error": str(e)}]


def run_audit(queries=None, fleet_url=None, api_token=None):
    """Execute osquery security audit."""
    print(f"\n{'='*60}")
    print(f"  OSQUERY ENDPOINT MONITORING AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    selected = queries or list(SECURITY_QUERIES.keys())
    results = {}
    for name in selected:
        if name in SECURITY_QUERIES:
            data = run_osquery(SECURITY_QUERIES[name])
            results[name] = data
            count = len(data) if isinstance(data, list) else 0
            print(f"--- {name.upper()} ({count} results) ---")
            for row in (data[:5] if isinstance(data, list) else []):
                if "error" not in row:
                    print(f"  {json.dumps(row)[:100]}")

    if fleet_url and api_token:
        fleet = check_fleet_status(fleet_url, api_token)
        results["fleet_hosts"] = fleet
        print(f"\n--- FLEET HOSTS ({len(fleet)}) ---")
        for h in fleet[:10]:
            if "error" not in h:
                print(f"  {h['hostname']}: {h['platform']} ({h['status']})")

    return results


def main():
    parser = argparse.ArgumentParser(description="osquery Monitoring Agent")
    parser.add_argument("--queries", nargs="+", choices=list(SECURITY_QUERIES.keys()),
                        help="Specific queries to run")
    parser.add_argument("--fleet-url", help="Fleet server URL")
    parser.add_argument("--api-token", help="Fleet API token")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.queries, args.fleet_url, args.api_token)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
