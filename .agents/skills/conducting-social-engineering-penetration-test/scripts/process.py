#!/usr/bin/env python3
"""
Social Engineering Penetration Test — Campaign Metrics Processor

Processes GoPhish campaign results and generates analysis reports.
Requires: requests library for GoPhish API interaction.

Usage:
    python process.py --gophish-url https://localhost:3333 --api-key <key> --output ./results
"""

import json
import csv
import argparse
import datetime
from pathlib import Path
from typing import Optional

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("Install requests: pip install requests")
    raise


class GoPhishClient:
    """Client for GoPhish REST API."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_key}"}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False

    def get_campaigns(self) -> list[dict]:
        resp = self.session.get(f"{self.base_url}/api/campaigns/")
        resp.raise_for_status()
        return resp.json()

    def get_campaign(self, campaign_id: int) -> dict:
        resp = self.session.get(f"{self.base_url}/api/campaigns/{campaign_id}")
        resp.raise_for_status()
        return resp.json()

    def get_campaign_results(self, campaign_id: int) -> dict:
        resp = self.session.get(f"{self.base_url}/api/campaigns/{campaign_id}/results")
        resp.raise_for_status()
        return resp.json()


def analyze_campaign(campaign: dict) -> dict:
    """Analyze a single campaign's results."""
    results = campaign.get("results", [])
    timeline = campaign.get("timeline", [])

    stats = {
        "campaign_name": campaign.get("name", "Unknown"),
        "total_targets": len(results),
        "emails_sent": 0,
        "emails_opened": 0,
        "links_clicked": 0,
        "credentials_submitted": 0,
        "emails_reported": 0,
        "errors": 0,
    }

    for entry in results:
        status = entry.get("status", "")
        if status == "Email Sent" or status in ("Email Opened", "Clicked Link",
                                                  "Submitted Data", "Email Reported"):
            stats["emails_sent"] += 1
        if status in ("Email Opened", "Clicked Link", "Submitted Data"):
            stats["emails_opened"] += 1
        if status in ("Clicked Link", "Submitted Data"):
            stats["links_clicked"] += 1
        if status == "Submitted Data":
            stats["credentials_submitted"] += 1
        if status == "Email Reported":
            stats["emails_reported"] += 1
        if status == "Error":
            stats["errors"] += 1

    # Calculate rates
    total = stats["total_targets"]
    if total > 0:
        stats["open_rate"] = round(stats["emails_opened"] / total * 100, 1)
        stats["click_rate"] = round(stats["links_clicked"] / total * 100, 1)
        stats["submit_rate"] = round(stats["credentials_submitted"] / total * 100, 1)
        stats["report_rate"] = round(stats["emails_reported"] / total * 100, 1)
    else:
        stats["open_rate"] = stats["click_rate"] = stats["submit_rate"] = stats["report_rate"] = 0

    return stats


def analyze_by_department(results: list[dict]) -> dict[str, dict]:
    """Break down results by department/position."""
    departments = {}
    for entry in results:
        dept = entry.get("position", "Unknown")
        if dept not in departments:
            departments[dept] = {
                "total": 0, "clicked": 0, "submitted": 0, "reported": 0
            }
        departments[dept]["total"] += 1
        status = entry.get("status", "")
        if status in ("Clicked Link", "Submitted Data"):
            departments[dept]["clicked"] += 1
        if status == "Submitted Data":
            departments[dept]["submitted"] += 1
        if status == "Email Reported":
            departments[dept]["reported"] += 1

    return departments


def generate_report(stats: dict, dept_analysis: dict, output_dir: Path) -> str:
    """Generate campaign analysis report."""
    report_file = output_dir / "se_campaign_report.md"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(report_file, "w") as f:
        f.write("# Social Engineering Campaign Analysis Report\n\n")
        f.write(f"**Campaign:** {stats['campaign_name']}\n")
        f.write(f"**Generated:** {timestamp}\n\n---\n\n")

        f.write("## Campaign Metrics\n\n")
        f.write("| Metric | Count | Rate |\n")
        f.write("|--------|-------|------|\n")
        f.write(f"| Targets | {stats['total_targets']} | 100% |\n")
        f.write(f"| Emails Sent | {stats['emails_sent']} | — |\n")
        f.write(f"| Emails Opened | {stats['emails_opened']} | {stats['open_rate']}% |\n")
        f.write(f"| Links Clicked | {stats['links_clicked']} | {stats['click_rate']}% |\n")
        f.write(f"| Credentials Submitted | {stats['credentials_submitted']} | {stats['submit_rate']}% |\n")
        f.write(f"| Reported to Security | {stats['emails_reported']} | {stats['report_rate']}% |\n\n")

        f.write("## Department Breakdown\n\n")
        f.write("| Department | Total | Clicked | Submitted | Reported |\n")
        f.write("|-----------|-------|---------|-----------|----------|\n")
        for dept, data in sorted(dept_analysis.items()):
            f.write(f"| {dept} | {data['total']} | {data['clicked']} | {data['submitted']} | {data['reported']} |\n")
        f.write("\n")

        f.write("## Risk Assessment\n\n")
        if stats["submit_rate"] > 20:
            risk = "CRITICAL"
        elif stats["submit_rate"] > 10:
            risk = "HIGH"
        elif stats["submit_rate"] > 5:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        f.write(f"**Overall Risk Level: {risk}**\n\n")

        f.write("## Recommendations\n\n")
        f.write("1. Deploy phishing-resistant MFA (FIDO2/WebAuthn)\n")
        f.write("2. Implement targeted training for high-risk departments\n")
        f.write("3. Deploy email security gateway with URL sandboxing\n")
        f.write("4. Establish phishing report button and reward program\n")
        f.write("5. Conduct quarterly phishing simulations\n")

    print(f"[+] Report: {report_file}")
    return str(report_file)


def main():
    parser = argparse.ArgumentParser(description="SE Campaign Analysis")
    parser.add_argument("--gophish-url", default="https://localhost:3333")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--campaign-id", type=int, help="Specific campaign ID")
    parser.add_argument("--output", default="./results")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    client = GoPhishClient(args.gophish_url, args.api_key)

    if args.campaign_id:
        campaign = client.get_campaign(args.campaign_id)
        stats = analyze_campaign(campaign)
        dept_analysis = analyze_by_department(campaign.get("results", []))
        generate_report(stats, dept_analysis, output_dir)
    else:
        campaigns = client.get_campaigns()
        for campaign in campaigns:
            stats = analyze_campaign(campaign)
            dept_analysis = analyze_by_department(campaign.get("results", []))
            generate_report(stats, dept_analysis, output_dir)
            print(f"[+] Processed campaign: {campaign.get('name')}")


if __name__ == "__main__":
    main()
