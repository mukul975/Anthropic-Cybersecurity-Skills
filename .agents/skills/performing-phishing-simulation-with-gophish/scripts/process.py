#!/usr/bin/env python3
"""
GoPhish Campaign Automation and Analytics

Automates phishing simulation campaigns via the GoPhish REST API.
Creates campaigns, monitors progress, and generates detailed analytics reports.

Usage:
    python process.py create --config campaign.json
    python process.py status --campaign-id 1
    python process.py report --campaign-id 1 --output report.html
    python process.py list
"""

import argparse
import json
import sys
import csv
import os
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


GOPHISH_API_URL = os.environ.get("GOPHISH_API_URL", "https://localhost:3333")
GOPHISH_API_KEY = os.environ.get("GOPHISH_API_KEY", "")


class GoPhishClient:
    """Client for interacting with the GoPhish REST API."""

    def __init__(self, api_url: str, api_key: str, verify_ssl: bool = False):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        })
        self.session.verify = verify_ssl

    def _get(self, endpoint: str) -> dict:
        resp = self.session.get(f"{self.api_url}{endpoint}")
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data: dict) -> dict:
        resp = self.session.post(f"{self.api_url}{endpoint}", json=data)
        resp.raise_for_status()
        return resp.json()

    def _delete(self, endpoint: str) -> bool:
        resp = self.session.delete(f"{self.api_url}{endpoint}")
        resp.raise_for_status()
        return resp.status_code == 200

    # Sending Profiles
    def create_sending_profile(self, name: str, host: str, from_address: str,
                                username: str = "", password: str = "",
                                ignore_cert: bool = False) -> dict:
        data = {
            "name": name,
            "host": host,
            "from_address": from_address,
            "username": username,
            "password": password,
            "ignore_cert_errors": ignore_cert
        }
        return self._post("/api/smtp/", data)

    def list_sending_profiles(self) -> list:
        return self._get("/api/smtp/")

    # Email Templates
    def create_template(self, name: str, subject: str, html: str,
                        text: str = "", attachments: list = None) -> dict:
        data = {
            "name": name,
            "subject": subject,
            "html": html,
            "text": text,
            "attachments": attachments or []
        }
        return self._post("/api/templates/", data)

    def import_email(self, raw_email: str, convert_links: bool = True) -> dict:
        data = {
            "content": raw_email,
            "convert_links": convert_links
        }
        return self._post("/api/import/email", data)

    def list_templates(self) -> list:
        return self._get("/api/templates/")

    # Landing Pages
    def create_page(self, name: str, html: str, capture_credentials: bool = True,
                    capture_passwords: bool = False, redirect_url: str = "") -> dict:
        data = {
            "name": name,
            "html": html,
            "capture_credentials": capture_credentials,
            "capture_passwords": capture_passwords,
            "redirect_url": redirect_url
        }
        return self._post("/api/pages/", data)

    def import_site(self, url: str) -> dict:
        data = {"url": url, "include_resources": False}
        return self._post("/api/import/site", data)

    def list_pages(self) -> list:
        return self._get("/api/pages/")

    # User Groups
    def create_group(self, name: str, targets: list) -> dict:
        data = {
            "name": name,
            "targets": targets
        }
        return self._post("/api/groups/", data)

    def import_group_csv(self, name: str, csv_path: str) -> dict:
        targets = []
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                target = {
                    "first_name": row.get("First Name", row.get("first_name", "")),
                    "last_name": row.get("Last Name", row.get("last_name", "")),
                    "email": row.get("Email", row.get("email", "")),
                    "position": row.get("Position", row.get("position", ""))
                }
                if target["email"]:
                    targets.append(target)
        return self.create_group(name, targets)

    def list_groups(self) -> list:
        return self._get("/api/groups/")

    # Campaigns
    def create_campaign(self, name: str, template_name: str, page_name: str,
                        smtp_name: str, group_names: list, url: str,
                        launch_date: str = "", send_by_date: str = "") -> dict:
        templates = self.list_templates()
        template = next((t for t in templates if t["name"] == template_name), None)

        pages = self.list_pages()
        page = next((p for p in pages if p["name"] == page_name), None)

        smtps = self.list_sending_profiles()
        smtp = next((s for s in smtps if s["name"] == smtp_name), None)

        groups_list = self.list_groups()
        groups = [g for g in groups_list if g["name"] in group_names]

        if not all([template, page, smtp, groups]):
            missing = []
            if not template:
                missing.append(f"template '{template_name}'")
            if not page:
                missing.append(f"page '{page_name}'")
            if not smtp:
                missing.append(f"smtp '{smtp_name}'")
            if not groups:
                missing.append(f"groups {group_names}")
            raise ValueError(f"Missing components: {', '.join(missing)}")

        data = {
            "name": name,
            "template": {"name": template_name},
            "page": {"name": page_name},
            "smtp": {"name": smtp_name},
            "groups": [{"name": g["name"]} for g in groups],
            "url": url
        }
        if launch_date:
            data["launch_date"] = launch_date
        if send_by_date:
            data["send_by_date"] = send_by_date

        return self._post("/api/campaigns/", data)

    def get_campaign(self, campaign_id: int) -> dict:
        return self._get(f"/api/campaigns/{campaign_id}")

    def get_campaign_summary(self, campaign_id: int) -> dict:
        return self._get(f"/api/campaigns/{campaign_id}/summary")

    def get_campaign_results(self, campaign_id: int) -> dict:
        return self._get(f"/api/campaigns/{campaign_id}/results")

    def list_campaigns(self) -> list:
        return self._get("/api/campaigns/")

    def complete_campaign(self, campaign_id: int) -> dict:
        return self._get(f"/api/campaigns/{campaign_id}/complete")


def calculate_campaign_metrics(results: dict) -> dict:
    """Calculate detailed campaign metrics from GoPhish results."""
    timeline = results.get("timeline", [])
    total_targets = len(results.get("results", []))

    events = defaultdict(set)
    for event in timeline:
        email = event.get("email", "")
        message = event.get("message", "")

        if "Email Sent" in message:
            events["sent"].add(email)
        elif "Email Opened" in message:
            events["opened"].add(email)
        elif "Clicked Link" in message:
            events["clicked"].add(email)
        elif "Submitted Data" in message:
            events["submitted"].add(email)
        elif "Email Reported" in message:
            events["reported"].add(email)

    sent = len(events["sent"])
    opened = len(events["opened"])
    clicked = len(events["clicked"])
    submitted = len(events["submitted"])
    reported = len(events["reported"])

    metrics = {
        "total_targets": total_targets,
        "emails_sent": sent,
        "emails_opened": opened,
        "links_clicked": clicked,
        "data_submitted": submitted,
        "emails_reported": reported,
        "open_rate": round(opened / max(sent, 1) * 100, 1),
        "click_rate": round(clicked / max(sent, 1) * 100, 1),
        "submit_rate": round(submitted / max(sent, 1) * 100, 1),
        "report_rate": round(reported / max(sent, 1) * 100, 1),
        "click_to_submit_rate": round(submitted / max(clicked, 1) * 100, 1),
        "resilience_score": round((1 - submitted / max(sent, 1)) * 100, 1),
    }

    # Department breakdown
    dept_stats = defaultdict(lambda: {"sent": 0, "opened": 0, "clicked": 0, "submitted": 0})
    for result in results.get("results", []):
        dept = result.get("position", "Unknown")
        email = result.get("email", "")
        dept_stats[dept]["sent"] += 1
        if email in events["opened"]:
            dept_stats[dept]["opened"] += 1
        if email in events["clicked"]:
            dept_stats[dept]["clicked"] += 1
        if email in events["submitted"]:
            dept_stats[dept]["submitted"] += 1

    metrics["department_breakdown"] = dict(dept_stats)

    return metrics


def generate_html_report(campaign: dict, metrics: dict) -> str:
    """Generate an HTML campaign report."""
    name = campaign.get("name", "Unknown Campaign")
    created = campaign.get("created_date", "")
    status = campaign.get("status", "")

    html = f"""<!DOCTYPE html>
<html>
<head>
<title>Phishing Simulation Report: {name}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
.container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: #34495e; margin-top: 30px; }}
.metric-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
.metric-card {{ background: #f8f9fa; padding: 20px; border-radius: 6px; text-align: center; border-left: 4px solid #3498db; }}
.metric-value {{ font-size: 32px; font-weight: bold; color: #2c3e50; }}
.metric-label {{ font-size: 14px; color: #7f8c8d; margin-top: 5px; }}
.risk-high {{ border-left-color: #e74c3c; }}
.risk-medium {{ border-left-color: #f39c12; }}
.risk-low {{ border-left-color: #27ae60; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
td {{ padding: 10px; border-bottom: 1px solid #ecf0f1; }}
tr:hover {{ background: #f8f9fa; }}
.bar {{ height: 20px; background: #3498db; border-radius: 3px; }}
.bar-container {{ background: #ecf0f1; border-radius: 3px; overflow: hidden; }}
.footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #ecf0f1; color: #95a5a6; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>Phishing Simulation Report</h1>
<p><strong>Campaign:</strong> {name}<br>
<strong>Date:</strong> {created}<br>
<strong>Status:</strong> {status}<br>
<strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>

<h2>Campaign Metrics</h2>
<div class="metric-grid">
<div class="metric-card">
    <div class="metric-value">{metrics['emails_sent']}</div>
    <div class="metric-label">Emails Sent</div>
</div>
<div class="metric-card {'risk-medium' if metrics['open_rate'] > 50 else 'risk-low'}">
    <div class="metric-value">{metrics['open_rate']}%</div>
    <div class="metric-label">Open Rate</div>
</div>
<div class="metric-card {'risk-high' if metrics['click_rate'] > 20 else 'risk-medium' if metrics['click_rate'] > 10 else 'risk-low'}">
    <div class="metric-value">{metrics['click_rate']}%</div>
    <div class="metric-label">Click Rate</div>
</div>
<div class="metric-card {'risk-high' if metrics['submit_rate'] > 10 else 'risk-medium' if metrics['submit_rate'] > 5 else 'risk-low'}">
    <div class="metric-value">{metrics['submit_rate']}%</div>
    <div class="metric-label">Submit Rate</div>
</div>
<div class="metric-card risk-low">
    <div class="metric-value">{metrics['report_rate']}%</div>
    <div class="metric-label">Report Rate</div>
</div>
<div class="metric-card">
    <div class="metric-value">{metrics['resilience_score']}%</div>
    <div class="metric-label">Resilience Score</div>
</div>
</div>

<h2>Funnel Analysis</h2>
<table>
<tr><th>Stage</th><th>Count</th><th>Rate</th><th>Visual</th></tr>
<tr><td>Emails Sent</td><td>{metrics['emails_sent']}</td><td>100%</td>
    <td><div class="bar-container"><div class="bar" style="width:100%"></div></div></td></tr>
<tr><td>Emails Opened</td><td>{metrics['emails_opened']}</td><td>{metrics['open_rate']}%</td>
    <td><div class="bar-container"><div class="bar" style="width:{metrics['open_rate']}%"></div></div></td></tr>
<tr><td>Links Clicked</td><td>{metrics['links_clicked']}</td><td>{metrics['click_rate']}%</td>
    <td><div class="bar-container"><div class="bar" style="width:{metrics['click_rate']}%"></div></div></td></tr>
<tr><td>Data Submitted</td><td>{metrics['data_submitted']}</td><td>{metrics['submit_rate']}%</td>
    <td><div class="bar-container"><div class="bar" style="width:{metrics['submit_rate']}%"></div></div></td></tr>
<tr><td>Emails Reported</td><td>{metrics['emails_reported']}</td><td>{metrics['report_rate']}%</td>
    <td><div class="bar-container"><div class="bar" style="width:{metrics['report_rate']}%"></div></div></td></tr>
</table>

<h2>Department Breakdown</h2>
<table>
<tr><th>Department</th><th>Sent</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th>Click Rate</th></tr>"""

    for dept, stats in sorted(metrics.get("department_breakdown", {}).items()):
        dept_click_rate = round(stats["clicked"] / max(stats["sent"], 1) * 100, 1)
        html += f"""
<tr><td>{dept}</td><td>{stats['sent']}</td><td>{stats['opened']}</td>
<td>{stats['clicked']}</td><td>{stats['submitted']}</td><td>{dept_click_rate}%</td></tr>"""

    html += f"""
</table>

<h2>Industry Benchmarks</h2>
<table>
<tr><th>Metric</th><th>Your Result</th><th>Industry Average</th><th>Target</th></tr>
<tr><td>Click Rate</td><td>{metrics['click_rate']}%</td><td>11-15%</td><td>&lt;5%</td></tr>
<tr><td>Submit Rate</td><td>{metrics['submit_rate']}%</td><td>3-5%</td><td>&lt;2%</td></tr>
<tr><td>Report Rate</td><td>{metrics['report_rate']}%</td><td>10-15%</td><td>&gt;70%</td></tr>
</table>

<h2>Recommendations</h2>
<ul>"""

    if metrics['click_rate'] > 20:
        html += "<li><strong>High Priority:</strong> Click rate exceeds 20%. Implement mandatory phishing awareness training for all employees.</li>"
    if metrics['submit_rate'] > 10:
        html += "<li><strong>Critical:</strong> Submit rate exceeds 10%. Deploy MFA across all applications to mitigate credential harvesting risk.</li>"
    if metrics['report_rate'] < 20:
        html += "<li><strong>Improve Reporting:</strong> Report rate is low. Deploy phishing report button in email client and incentivize reporting.</li>"

    html += """
</ul>

<div class="footer">
<p>This report was generated by the GoPhish Campaign Analytics tool.
Campaign data is confidential and should be handled according to organizational data protection policies.</p>
</div>
</div>
</body>
</html>"""

    return html


def generate_text_report(campaign: dict, metrics: dict) -> str:
    """Generate a text-based campaign report."""
    name = campaign.get("name", "Unknown")
    lines = []
    lines.append("=" * 60)
    lines.append("  PHISHING SIMULATION CAMPAIGN REPORT")
    lines.append("=" * 60)
    lines.append(f"  Campaign: {name}")
    lines.append(f"  Status: {campaign.get('status', '')}")
    lines.append(f"  Created: {campaign.get('created_date', '')}")
    lines.append("")
    lines.append("[METRICS]")
    lines.append(f"  Emails Sent:     {metrics['emails_sent']}")
    lines.append(f"  Emails Opened:   {metrics['emails_opened']} ({metrics['open_rate']}%)")
    lines.append(f"  Links Clicked:   {metrics['links_clicked']} ({metrics['click_rate']}%)")
    lines.append(f"  Data Submitted:  {metrics['data_submitted']} ({metrics['submit_rate']}%)")
    lines.append(f"  Emails Reported: {metrics['emails_reported']} ({metrics['report_rate']}%)")
    lines.append(f"  Resilience:      {metrics['resilience_score']}%")
    lines.append("")
    lines.append("[DEPARTMENT BREAKDOWN]")
    for dept, stats in sorted(metrics.get("department_breakdown", {}).items()):
        rate = round(stats["clicked"] / max(stats["sent"], 1) * 100, 1)
        lines.append(f"  {dept}: {stats['sent']} sent, {stats['clicked']} clicked ({rate}%)")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="GoPhish Campaign Automation")
    subparsers = parser.add_subparsers(dest="command")

    # Create campaign from config
    create_parser = subparsers.add_parser("create", help="Create campaign from config")
    create_parser.add_argument("--config", required=True, help="Campaign config JSON file")

    # Campaign status
    status_parser = subparsers.add_parser("status", help="Get campaign status")
    status_parser.add_argument("--campaign-id", type=int, required=True)

    # Generate report
    report_parser = subparsers.add_parser("report", help="Generate campaign report")
    report_parser.add_argument("--campaign-id", type=int, required=True)
    report_parser.add_argument("--output", "-o", help="Output file path")
    report_parser.add_argument("--format", choices=["html", "text", "json"], default="text")

    # List campaigns
    subparsers.add_parser("list", help="List all campaigns")

    # Import users
    import_parser = subparsers.add_parser("import-users", help="Import user group from CSV")
    import_parser.add_argument("--csv", required=True, help="CSV file path")
    import_parser.add_argument("--group-name", required=True, help="Group name")

    parser.add_argument("--api-url", default=GOPHISH_API_URL)
    parser.add_argument("--api-key", default=GOPHISH_API_KEY)
    parser.add_argument("--no-verify-ssl", action="store_true")

    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("Error: 'requests' library required. Install with: pip install requests",
              file=sys.stderr)
        sys.exit(1)

    api_url = args.api_url
    api_key = args.api_key

    if not api_key:
        print("Error: GoPhish API key required. Set GOPHISH_API_KEY env var or use --api-key",
              file=sys.stderr)
        sys.exit(1)

    client = GoPhishClient(api_url, api_key, verify_ssl=not args.no_verify_ssl)

    if args.command == "create":
        with open(args.config, "r") as f:
            config = json.load(f)
        result = client.create_campaign(**config)
        print(f"Campaign created: ID={result.get('id')}, Name={result.get('name')}")

    elif args.command == "status":
        summary = client.get_campaign_summary(args.campaign_id)
        print(json.dumps(summary, indent=2))

    elif args.command == "report":
        campaign = client.get_campaign(args.campaign_id)
        results = client.get_campaign_results(args.campaign_id)
        metrics = calculate_campaign_metrics(results)

        if args.format == "html":
            output = generate_html_report(campaign, metrics)
        elif args.format == "json":
            output = json.dumps({"campaign": campaign, "metrics": metrics}, indent=2, default=str)
        else:
            output = generate_text_report(campaign, metrics)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Report written to {args.output}")
        else:
            print(output)

    elif args.command == "list":
        campaigns = client.list_campaigns()
        for c in campaigns:
            print(f"  ID: {c['id']} | Name: {c['name']} | Status: {c['status']} | "
                  f"Created: {c.get('created_date', '')}")

    elif args.command == "import-users":
        result = client.import_group_csv(args.group_name, args.csv)
        targets = result.get("targets", [])
        print(f"Group '{args.group_name}' created with {len(targets)} targets")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
