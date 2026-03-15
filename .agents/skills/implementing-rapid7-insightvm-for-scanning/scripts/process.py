#!/usr/bin/env python3
"""
Rapid7 InsightVM Scan Automation and Reporting Tool

Automates scan operations, asset queries, and vulnerability reporting
via the InsightVM API v3.

Requirements:
    pip install requests pandas tabulate

Usage:
    python process.py sites                          # List all sites
    python process.py scan --site-id 1               # Start scan for site
    python process.py status --scan-id 12345         # Check scan status
    python process.py vulns --asset-id 42            # Get asset vulnerabilities
    python process.py report --site-id 1 --output report.csv  # Export report
"""

import argparse
import json
import sys
import time
import urllib3
from datetime import datetime

import pandas as pd
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class InsightVMAPI:
    """Rapid7 InsightVM API v3 client."""

    def __init__(self, console_url, username=None, password=None, api_key=None):
        self.base_url = f"{console_url.rstrip('/')}/api/3"
        self.session = requests.Session()
        self.session.verify = False

        if api_key:
            self.session.headers.update({
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            })
        elif username and password:
            self.session.auth = (username, password)
            self.session.headers.update({"Content-Type": "application/json"})
        else:
            raise ValueError("Provide either api_key or username/password")

    def _get_paginated(self, endpoint, params=None):
        """Fetch all pages from a paginated endpoint."""
        all_resources = []
        page = 0
        while True:
            p = params.copy() if params else {}
            p["page"] = page
            p["size"] = 100
            response = self.session.get(
                f"{self.base_url}/{endpoint}", params=p, timeout=60
            )
            response.raise_for_status()
            data = response.json()
            resources = data.get("resources", [])
            all_resources.extend(resources)
            total_pages = data.get("page", {}).get("totalPages", 1)
            page += 1
            if page >= total_pages:
                break
        return all_resources

    def list_sites(self):
        """List all scan sites."""
        return self._get_paginated("sites")

    def get_site(self, site_id):
        """Get details for a specific site."""
        response = self.session.get(
            f"{self.base_url}/sites/{site_id}", timeout=30
        )
        response.raise_for_status()
        return response.json()

    def start_scan(self, site_id, engine_id=None, template_id=None, hosts=None):
        """Start a scan for a site."""
        payload = {}
        if engine_id:
            payload["engineId"] = engine_id
        if template_id:
            payload["templateId"] = template_id
        if hosts:
            payload["hosts"] = hosts

        response = self.session.post(
            f"{self.base_url}/sites/{site_id}/scans",
            json=payload, timeout=30
        )
        response.raise_for_status()
        return response.json()

    def get_scan_status(self, scan_id):
        """Get the status of a scan."""
        response = self.session.get(
            f"{self.base_url}/scans/{scan_id}", timeout=30
        )
        response.raise_for_status()
        return response.json()

    def wait_for_scan(self, scan_id, poll_interval=30, timeout=3600):
        """Wait for a scan to complete."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_scan_status(scan_id)
            state = status.get("status", "unknown")
            print(f"  Scan {scan_id}: {state} "
                  f"({status.get('assets', 0)} assets, "
                  f"{status.get('vulnerabilities', {}).get('total', 0)} vulns)")
            if state in ("finished", "stopped", "error", "aborted"):
                return status
            time.sleep(poll_interval)
        print(f"  [!] Scan timeout after {timeout}s")
        return None

    def get_site_assets(self, site_id):
        """Get all assets for a site."""
        return self._get_paginated(f"sites/{site_id}/assets")

    def get_asset_vulnerabilities(self, asset_id):
        """Get vulnerabilities for a specific asset."""
        return self._get_paginated(f"assets/{asset_id}/vulnerabilities")

    def get_vulnerability_details(self, vuln_id):
        """Get details for a specific vulnerability."""
        response = self.session.get(
            f"{self.base_url}/vulnerabilities/{vuln_id}", timeout=30
        )
        response.raise_for_status()
        return response.json()

    def list_scan_engines(self):
        """List all scan engines."""
        return self._get_paginated("scan_engines")

    def list_scan_templates(self):
        """List available scan templates."""
        return self._get_paginated("scan_templates")


def cmd_list_sites(api):
    """List all configured sites."""
    sites = api.list_sites()
    if not sites:
        print("No sites configured.")
        return

    print(f"\n{'ID':<6} {'Name':<35} {'Assets':<10} {'Last Scan':<20}")
    print("-" * 75)
    for site in sites:
        last_scan = site.get("lastScanTime", "Never")
        if last_scan != "Never":
            last_scan = last_scan[:19]
        print(f"{site['id']:<6} {site['name'][:34]:<35} "
              f"{site.get('assets', 0):<10} {last_scan:<20}")


def cmd_start_scan(api, site_id, engine_id=None, template_id=None, wait=False):
    """Start a scan for a site."""
    print(f"[*] Starting scan for site {site_id}...")
    result = api.start_scan(site_id, engine_id, template_id)
    scan_id = result.get("id")
    print(f"[+] Scan started: ID={scan_id}")

    if wait and scan_id:
        print("[*] Waiting for scan to complete...")
        final_status = api.wait_for_scan(scan_id)
        if final_status:
            print(f"\n[+] Scan completed: {final_status.get('status')}")
            vulns = final_status.get("vulnerabilities", {})
            print(f"    Total vulnerabilities: {vulns.get('total', 0)}")
            print(f"    Critical: {vulns.get('critical', 0)}")
            print(f"    Severe: {vulns.get('severe', 0)}")
            print(f"    Moderate: {vulns.get('moderate', 0)}")


def cmd_scan_status(api, scan_id):
    """Check scan status."""
    status = api.get_scan_status(scan_id)
    print(f"\nScan ID:     {status.get('id')}")
    print(f"Status:      {status.get('status')}")
    print(f"Start Time:  {status.get('startTime', 'N/A')}")
    print(f"End Time:    {status.get('endTime', 'N/A')}")
    print(f"Assets:      {status.get('assets', 0)}")
    vulns = status.get("vulnerabilities", {})
    print(f"Vulns Total: {vulns.get('total', 0)}")
    print(f"  Critical:  {vulns.get('critical', 0)}")
    print(f"  Severe:    {vulns.get('severe', 0)}")
    print(f"  Moderate:  {vulns.get('moderate', 0)}")


def cmd_asset_vulns(api, asset_id):
    """List vulnerabilities for an asset."""
    vulns = api.get_asset_vulnerabilities(asset_id)
    if not vulns:
        print(f"No vulnerabilities found for asset {asset_id}.")
        return

    print(f"\nVulnerabilities for asset {asset_id}: {len(vulns)} total\n")
    print(f"{'Vuln ID':<40} {'Severity':<10} {'CVSS':<8} {'Status':<12}")
    print("-" * 72)
    for v in sorted(vulns, key=lambda x: x.get("severity", ""), reverse=True):
        print(f"{v.get('id', 'N/A')[:39]:<40} "
              f"{v.get('severity', 'N/A'):<10} "
              f"{v.get('cvssV3Score', 'N/A'):<8} "
              f"{v.get('status', 'N/A'):<12}")


def cmd_export_report(api, site_id, output_file):
    """Export vulnerability report for a site to CSV."""
    print(f"[*] Fetching assets for site {site_id}...")
    assets = api.get_site_assets(site_id)
    print(f"[+] Found {len(assets)} assets")

    all_findings = []
    for asset in assets:
        asset_id = asset.get("id")
        hostname = asset.get("hostName", asset.get("ip", "unknown"))
        ip = asset.get("ip", "N/A")
        os_name = asset.get("os", {}).get("description", "Unknown")

        vulns = api.get_asset_vulnerabilities(asset_id)
        for v in vulns:
            all_findings.append({
                "asset_id": asset_id,
                "hostname": hostname,
                "ip_address": ip,
                "os": os_name,
                "vulnerability_id": v.get("id", ""),
                "severity": v.get("severity", ""),
                "cvss_v3_score": v.get("cvssV3Score", ""),
                "status": v.get("status", ""),
                "first_found": v.get("since", ""),
            })

        print(f"  Processed {hostname}: {len(vulns)} vulnerabilities")

    if all_findings:
        df = pd.DataFrame(all_findings)
        df = df.sort_values(["cvss_v3_score", "severity"], ascending=[False, False])
        df.to_csv(output_file, index=False)
        print(f"\n[+] Report exported to {output_file}")
        print(f"    Total findings: {len(all_findings)}")
        print(f"\n    Severity Distribution:")
        print(df["severity"].value_counts().to_string())
    else:
        print("[!] No findings to export.")


def main():
    parser = argparse.ArgumentParser(
        description="Rapid7 InsightVM Scan Automation Tool"
    )
    parser.add_argument("--console", default="https://localhost:3780",
                        help="InsightVM console URL")
    parser.add_argument("--username", help="Console username")
    parser.add_argument("--password", help="Console password")
    parser.add_argument("--api-key", help="API key (alternative to user/pass)")

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("sites", help="List all scan sites")

    scan_p = subparsers.add_parser("scan", help="Start a scan")
    scan_p.add_argument("--site-id", type=int, required=True)
    scan_p.add_argument("--engine-id", type=int)
    scan_p.add_argument("--template-id", type=str)
    scan_p.add_argument("--wait", action="store_true")

    status_p = subparsers.add_parser("status", help="Check scan status")
    status_p.add_argument("--scan-id", type=int, required=True)

    vuln_p = subparsers.add_parser("vulns", help="List asset vulnerabilities")
    vuln_p.add_argument("--asset-id", type=int, required=True)

    report_p = subparsers.add_parser("report", help="Export vulnerability report")
    report_p.add_argument("--site-id", type=int, required=True)
    report_p.add_argument("--output", default="insightvm_report.csv")

    subparsers.add_parser("engines", help="List scan engines")
    subparsers.add_parser("templates", help="List scan templates")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    api = InsightVMAPI(
        args.console,
        username=args.username,
        password=args.password,
        api_key=args.api_key
    )

    if args.command == "sites":
        cmd_list_sites(api)
    elif args.command == "scan":
        cmd_start_scan(api, args.site_id, args.engine_id,
                       args.template_id, args.wait)
    elif args.command == "status":
        cmd_scan_status(api, args.scan_id)
    elif args.command == "vulns":
        cmd_asset_vulns(api, args.asset_id)
    elif args.command == "report":
        cmd_export_report(api, args.site_id, args.output)
    elif args.command == "engines":
        engines = api.list_scan_engines()
        for e in engines:
            print(f"  Engine {e['id']}: {e['name']} - {e.get('address', 'N/A')}")
    elif args.command == "templates":
        templates = api.list_scan_templates()
        for t in templates:
            print(f"  {t['id']}: {t['name']}")


if __name__ == "__main__":
    main()
