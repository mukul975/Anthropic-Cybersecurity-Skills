#!/usr/bin/env python3
"""
CrowdStrike Falcon Deployment Verification Tool

Queries the CrowdStrike Falcon API to verify sensor deployment coverage,
identify unmanaged endpoints, and generate deployment status reports.
"""

import json
import sys
import os
import time
import csv
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError


FALCON_BASE_URL = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
FALCON_CLIENT_ID = os.environ.get("FALCON_CLIENT_ID", "")
FALCON_CLIENT_SECRET = os.environ.get("FALCON_CLIENT_SECRET", "")


def get_oauth_token() -> str:
    """Obtain OAuth2 bearer token from CrowdStrike API."""
    url = f"{FALCON_BASE_URL}/oauth2/token"
    data = urlencode({
        "client_id": FALCON_CLIENT_ID,
        "client_secret": FALCON_CLIENT_SECRET,
    }).encode()

    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urlopen(req) as resp:
        body = json.loads(resp.read())
        return body["access_token"]


def api_get(token: str, endpoint: str, params: dict = None) -> dict:
    """Make authenticated GET request to Falcon API."""
    url = f"{FALCON_BASE_URL}{endpoint}"
    if params:
        url += "?" + urlencode(params)

    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")

    with urlopen(req) as resp:
        return json.loads(resp.read())


def get_all_host_ids(token: str) -> list:
    """Retrieve all host device IDs from Falcon."""
    all_ids = []
    offset = 0
    limit = 5000

    while True:
        result = api_get(token, "/devices/queries/devices-scroll/v1", {
            "limit": limit,
            "offset": offset,
        })
        resources = result.get("resources", [])
        if not resources:
            break
        all_ids.extend(resources)
        offset += limit
        if len(resources) < limit:
            break

    return all_ids


def get_host_details(token: str, host_ids: list) -> list:
    """Retrieve detailed host information for given IDs (batches of 100)."""
    all_details = []

    for i in range(0, len(host_ids), 100):
        batch = host_ids[i:i + 100]
        url = f"{FALCON_BASE_URL}/devices/entities/devices/v2"
        data = json.dumps({"ids": batch}).encode()

        req = Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")

        with urlopen(req) as resp:
            body = json.loads(resp.read())
            all_details.extend(body.get("resources", []))

    return all_details


def analyze_deployment(hosts: list) -> dict:
    """Analyze deployment coverage and sensor health."""
    now = datetime.utcnow()
    stale_threshold = now - timedelta(days=7)

    analysis = {
        "total_hosts": len(hosts),
        "os_breakdown": {},
        "status_breakdown": {"online": 0, "offline": 0, "stale": 0},
        "sensor_versions": {},
        "rfm_hosts": [],
        "stale_hosts": [],
        "unprotected_hosts": [],
    }

    for host in hosts:
        platform = host.get("platform_name", "Unknown")
        analysis["os_breakdown"][platform] = analysis["os_breakdown"].get(platform, 0) + 1

        version = host.get("agent_version", "Unknown")
        analysis["sensor_versions"][version] = analysis["sensor_versions"].get(version, 0) + 1

        status = host.get("status", "unknown")
        last_seen = host.get("last_seen", "")

        if last_seen:
            try:
                last_seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00")).replace(tzinfo=None)
                if last_seen_dt < stale_threshold:
                    analysis["status_breakdown"]["stale"] += 1
                    analysis["stale_hosts"].append({
                        "hostname": host.get("hostname", ""),
                        "last_seen": last_seen,
                        "platform": platform,
                    })
                elif status == "normal":
                    analysis["status_breakdown"]["online"] += 1
                else:
                    analysis["status_breakdown"]["offline"] += 1
            except (ValueError, TypeError):
                analysis["status_breakdown"]["offline"] += 1

        reduced_functionality = host.get("reduced_functionality_mode", "no")
        if reduced_functionality == "yes":
            analysis["rfm_hosts"].append({
                "hostname": host.get("hostname", ""),
                "reason": host.get("device_policies", {}).get("prevention", {}).get("policy_type", "unknown"),
            })

        prevention_policy = host.get("device_policies", {}).get("prevention", {})
        if not prevention_policy.get("applied", False):
            analysis["unprotected_hosts"].append({
                "hostname": host.get("hostname", ""),
                "platform": platform,
                "reason": "Prevention policy not applied",
            })

    return analysis


def generate_deployment_report(analysis: dict, output_path: str) -> None:
    """Generate deployment status report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "deployment_summary": {
            "total_managed_hosts": analysis["total_hosts"],
            "online": analysis["status_breakdown"]["online"],
            "offline": analysis["status_breakdown"]["offline"],
            "stale_7_days": analysis["status_breakdown"]["stale"],
            "in_rfm": len(analysis["rfm_hosts"]),
            "unprotected": len(analysis["unprotected_hosts"]),
        },
        "os_distribution": analysis["os_breakdown"],
        "sensor_version_distribution": analysis["sensor_versions"],
        "hosts_requiring_attention": {
            "stale_hosts": analysis["stale_hosts"][:50],
            "rfm_hosts": analysis["rfm_hosts"][:50],
            "unprotected_hosts": analysis["unprotected_hosts"][:50],
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def export_stale_hosts_csv(stale_hosts: list, output_path: str) -> None:
    """Export stale hosts to CSV for remediation tracking."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Hostname", "Platform", "Last Seen", "Action Required"])
        for host in stale_hosts:
            writer.writerow([
                host["hostname"],
                host.get("platform", ""),
                host["last_seen"],
                "Investigate connectivity / reinstall sensor",
            ])


if __name__ == "__main__":
    if not FALCON_CLIENT_ID or not FALCON_CLIENT_SECRET:
        print("Error: Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables")
        print()
        print("Required environment variables:")
        print("  FALCON_CLIENT_ID     - API client ID from Falcon Console")
        print("  FALCON_CLIENT_SECRET - API client secret")
        print("  FALCON_BASE_URL      - (Optional) API base URL (default: https://api.crowdstrike.com)")
        sys.exit(1)

    print("Authenticating with CrowdStrike Falcon API...")
    token = get_oauth_token()

    print("Retrieving host inventory...")
    host_ids = get_all_host_ids(token)
    print(f"Found {len(host_ids)} managed hosts")

    print("Fetching host details...")
    hosts = get_host_details(token, host_ids)

    print("Analyzing deployment coverage...")
    analysis = analyze_deployment(hosts)

    report_path = "falcon_deployment_report.json"
    generate_deployment_report(analysis, report_path)
    print(f"\nDeployment report: {report_path}")

    if analysis["stale_hosts"]:
        csv_path = "falcon_stale_hosts.csv"
        export_stale_hosts_csv(analysis["stale_hosts"], csv_path)
        print(f"Stale hosts CSV: {csv_path}")

    print(f"\n--- Deployment Summary ---")
    print(f"Total hosts: {analysis['total_hosts']}")
    print(f"Online: {analysis['status_breakdown']['online']}")
    print(f"Offline: {analysis['status_breakdown']['offline']}")
    print(f"Stale (>7 days): {analysis['status_breakdown']['stale']}")
    print(f"In RFM: {len(analysis['rfm_hosts'])}")
    print(f"Unprotected: {len(analysis['unprotected_hosts'])}")
    print(f"\nOS Distribution: {json.dumps(analysis['os_breakdown'], indent=2)}")
    print(f"Sensor Versions: {json.dumps(analysis['sensor_versions'], indent=2)}")
