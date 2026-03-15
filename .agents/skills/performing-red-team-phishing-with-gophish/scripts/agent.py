#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""GoPhish Campaign Agent - Automates phishing simulation setup, launch, and analysis."""

import json
import csv
import logging
import argparse
from datetime import datetime

from gophish import Gophish
from gophish.models import Campaign, Template, Group, SMTP, Page, User

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def connect_gophish(api_key, host):
    """Connect to GoPhish server via API."""
    api = Gophish(api_key, host=host, verify=False)
    logger.info("Connected to GoPhish at %s", host)
    return api


def create_email_template(api, name, subject, html_body, text_body=""):
    """Create an email template in GoPhish."""
    template = Template(name=name, subject=subject, html=html_body, text=text_body)
    result = api.templates.post(template)
    logger.info("Created template: %s (ID: %d)", result.name, result.id)
    return result


def create_landing_page(api, name, html_content, capture_credentials=True, redirect_url=""):
    """Create a landing page for credential capture."""
    page = Page(
        name=name,
        html=html_content,
        capture_credentials=capture_credentials,
        redirect_url=redirect_url,
    )
    result = api.pages.post(page)
    logger.info("Created landing page: %s (ID: %d)", result.name, result.id)
    return result


def create_smtp_profile(api, name, smtp_from, host, port=587, username="", password="", ignore_cert=False):
    """Create an SMTP sending profile."""
    smtp = SMTP(
        name=name,
        from_address=smtp_from,
        host=f"{host}:{port}",
        username=username,
        password=password,
        ignore_cert_errors=ignore_cert,
    )
    result = api.smtp.post(smtp)
    logger.info("Created SMTP profile: %s (ID: %d)", result.name, result.id)
    return result


def import_targets_from_csv(api, group_name, csv_path):
    """Import target users from a CSV file into a GoPhish group."""
    targets = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            targets.append(User(
                first_name=row.get("first_name", ""),
                last_name=row.get("last_name", ""),
                email=row.get("email", ""),
                position=row.get("position", ""),
            ))
    group = Group(name=group_name, targets=targets)
    result = api.groups.post(group)
    logger.info("Created group '%s' with %d targets", group_name, len(targets))
    return result


def launch_campaign(api, name, template_name, page_name, smtp_name, group_name, url):
    """Launch a phishing simulation campaign."""
    campaign = Campaign(
        name=name,
        template=Template(name=template_name),
        page=Page(name=page_name),
        smtp=SMTP(name=smtp_name),
        groups=[Group(name=group_name)],
        url=url,
    )
    result = api.campaigns.post(campaign)
    logger.info("Launched campaign: %s (ID: %d)", result.name, result.id)
    return result


def get_campaign_results(api, campaign_id):
    """Retrieve detailed results for a campaign."""
    campaign = api.campaigns.get(campaign_id=campaign_id)
    results = {
        "name": campaign.name,
        "status": campaign.status,
        "created_date": str(campaign.created_date),
        "launch_date": str(campaign.launch_date),
        "results": [],
    }
    for result in campaign.results:
        results["results"].append({
            "email": result.email,
            "first_name": result.first_name,
            "last_name": result.last_name,
            "status": result.status,
            "reported": result.reported,
        })
    return results


def analyze_campaign_metrics(campaign_results):
    """Calculate campaign performance metrics."""
    results = campaign_results.get("results", [])
    total = len(results)
    if total == 0:
        return {"total": 0}
    statuses = {"Email Sent": 0, "Email Opened": 0, "Clicked Link": 0, "Submitted Data": 0, "Reported": 0}
    for r in results:
        status = r.get("status", "")
        if status in statuses:
            statuses[status] += 1
        if r.get("reported"):
            statuses["Reported"] += 1
    metrics = {
        "total_targets": total,
        "emails_sent": statuses["Email Sent"],
        "opened": statuses["Email Opened"],
        "clicked": statuses["Clicked Link"],
        "submitted_credentials": statuses["Submitted Data"],
        "reported": statuses["Reported"],
        "open_rate": round(statuses["Email Opened"] / total * 100, 1),
        "click_rate": round(statuses["Clicked Link"] / total * 100, 1),
        "submission_rate": round(statuses["Submitted Data"] / total * 100, 1),
        "report_rate": round(statuses["Reported"] / total * 100, 1),
    }
    logger.info("Campaign metrics: %d targets, %.1f%% clicked, %.1f%% submitted",
                total, metrics["click_rate"], metrics["submission_rate"])
    return metrics


def list_campaigns(api):
    """List all campaigns and their statuses."""
    campaigns = api.campaigns.get()
    return [{"id": c.id, "name": c.name, "status": c.status} for c in campaigns]


def generate_report(campaign_results, metrics):
    """Generate phishing simulation report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "campaign": campaign_results.get("name"),
        "status": campaign_results.get("status"),
        "metrics": metrics,
        "detailed_results": campaign_results.get("results", [])[:50],
    }
    print(f"PHISHING REPORT: {metrics.get('total_targets', 0)} targets, "
          f"{metrics.get('click_rate', 0)}% click rate, "
          f"{metrics.get('submission_rate', 0)}% credential submission")
    return report


def main():
    parser = argparse.ArgumentParser(description="GoPhish Campaign Agent")
    parser.add_argument("--gophish-url", required=True, help="GoPhish server URL")
    parser.add_argument("--api-key", required=True, help="GoPhish API key")
    parser.add_argument("--campaign-id", type=int, help="Existing campaign ID to analyze")
    parser.add_argument("--campaign-name", help="Name for new campaign")
    parser.add_argument("--template-name", help="Email template name")
    parser.add_argument("--group-name", help="Target group name")
    parser.add_argument("--targets-csv", help="CSV file with targets")
    parser.add_argument("--output", default="phishing_report.json")
    args = parser.parse_args()

    api = connect_gophish(args.api_key, args.gophish_url)

    if args.targets_csv and args.group_name:
        import_targets_from_csv(api, args.group_name, args.targets_csv)

    if args.campaign_id:
        results = get_campaign_results(api, args.campaign_id)
        metrics = analyze_campaign_metrics(results)
        report = generate_report(results, metrics)
    else:
        campaigns = list_campaigns(api)
        report = {"campaigns": campaigns, "timestamp": datetime.utcnow().isoformat()}
        logger.info("Listed %d campaigns", len(campaigns))

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
