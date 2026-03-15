#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""Phishing simulation campaign agent using requests to interact with GoPhish API."""

import argparse
import json
import logging
import sys
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class GoPhishClient:
    """Client for the GoPhish REST API."""

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}"})
        self.session.verify = verify_ssl

    def _get(self, endpoint: str) -> dict:
        resp = self.session.get(f"{self.base_url}/api/{endpoint}")
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data: dict) -> dict:
        resp = self.session.post(f"{self.base_url}/api/{endpoint}", json=data)
        resp.raise_for_status()
        return resp.json()

    def create_sending_profile(self, name: str, smtp_from: str, host: str,
                                username: str, password: str) -> dict:
        """Create an SMTP sending profile."""
        payload = {
            "name": name,
            "from_address": smtp_from,
            "host": host,
            "username": username,
            "password": password,
            "ignore_cert_errors": True,
        }
        result = self._post("smtp/", payload)
        logger.info("Created sending profile: %s (id=%s)", name, result.get("id"))
        return result

    def create_email_template(self, name: str, subject: str, html_body: str,
                               text_body: str = "") -> dict:
        """Create a phishing email template with tracking."""
        payload = {
            "name": name,
            "subject": subject,
            "html": html_body,
            "text": text_body,
            "capture_credentials": True,
            "capture_passwords": True,
        }
        result = self._post("templates/", payload)
        logger.info("Created email template: %s (id=%s)", name, result.get("id"))
        return result

    def create_landing_page(self, name: str, html: str, capture_creds: bool = True,
                             redirect_url: str = "") -> dict:
        """Create a credential harvesting landing page."""
        payload = {
            "name": name,
            "html": html,
            "capture_credentials": capture_creds,
            "capture_passwords": True,
            "redirect_url": redirect_url,
        }
        result = self._post("pages/", payload)
        logger.info("Created landing page: %s (id=%s)", name, result.get("id"))
        return result

    def import_targets(self, group_name: str, targets: list) -> dict:
        """Import target email list as a user group."""
        payload = {
            "name": group_name,
            "targets": [{"email": t["email"], "first_name": t.get("first_name", ""),
                         "last_name": t.get("last_name", ""), "position": t.get("position", "")}
                        for t in targets],
        }
        result = self._post("groups/", payload)
        logger.info("Created target group '%s' with %d targets", group_name, len(targets))
        return result

    def launch_campaign(self, name: str, template_id: int, page_id: int,
                         smtp_id: int, group_ids: list, url: str) -> dict:
        """Launch the phishing campaign."""
        payload = {
            "name": name,
            "template": {"id": template_id},
            "page": {"id": page_id},
            "smtp": {"id": smtp_id},
            "groups": [{"id": gid} for gid in group_ids],
            "url": url,
            "launch_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        }
        result = self._post("campaigns/", payload)
        logger.info("Launched campaign '%s' (id=%s)", name, result.get("id"))
        return result

    def get_campaign_results(self, campaign_id: int) -> dict:
        """Retrieve campaign results and metrics."""
        return self._get(f"campaigns/{campaign_id}/results")

    def get_campaign_summary(self, campaign_id: int) -> dict:
        """Get summary statistics for a campaign."""
        result = self._get(f"campaigns/{campaign_id}/summary")
        return result

    def list_campaigns(self) -> list:
        """List all campaigns."""
        return self._get("campaigns/")


def compute_metrics(results: dict) -> dict:
    """Compute phishing simulation success metrics from campaign results."""
    timeline = results.get("timeline", [])
    total = results.get("stats", {}).get("total", 0)
    sent = sum(1 for e in timeline if e.get("message") == "Email Sent")
    opened = sum(1 for e in timeline if e.get("message") == "Email Opened")
    clicked = sum(1 for e in timeline if e.get("message") == "Clicked Link")
    submitted = sum(1 for e in timeline if e.get("message") == "Submitted Data")
    reported = sum(1 for e in timeline if e.get("message") == "Email Reported")

    return {
        "total_targets": total,
        "emails_sent": sent,
        "emails_opened": opened,
        "links_clicked": clicked,
        "credentials_submitted": submitted,
        "reported_to_it": reported,
        "click_rate": f"{(clicked / total * 100):.1f}%" if total else "0%",
        "submission_rate": f"{(submitted / total * 100):.1f}%" if total else "0%",
        "report_rate": f"{(reported / total * 100):.1f}%" if total else "0%",
    }


def main():
    parser = argparse.ArgumentParser(description="Phishing Simulation Campaign Agent")
    parser.add_argument("--gophish-url", required=True, help="GoPhish server URL")
    parser.add_argument("--api-key", required=True, help="GoPhish API key")
    parser.add_argument("--action", choices=["launch", "results", "list"], default="list")
    parser.add_argument("--campaign-id", type=int, help="Campaign ID for results")
    parser.add_argument("--output", default="phishing_report.json")
    args = parser.parse_args()

    client = GoPhishClient(args.gophish_url, args.api_key)

    if args.action == "list":
        campaigns = client.list_campaigns()
        print(json.dumps(campaigns, indent=2, default=str))
    elif args.action == "results" and args.campaign_id:
        results = client.get_campaign_results(args.campaign_id)
        metrics = compute_metrics(results)
        with open(args.output, "w") as f:
            json.dump(metrics, f, indent=2)
        logger.info("Metrics saved to %s", args.output)
        print(json.dumps(metrics, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
