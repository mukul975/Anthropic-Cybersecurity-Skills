#!/usr/bin/env python3
"""Spearphishing simulation campaign agent using GoPhish API."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class GoPhishCampaign:
    """GoPhish campaign manager for spearphishing simulations."""

    def __init__(self, base_url, api_key):
        self.url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_key}"}

    def _req(self, method, endpoint, data=None):
        resp = requests.request(method, f"{self.url}/api/{endpoint}",
                                headers=self.headers, json=data, verify=False)
        resp.raise_for_status()
        return resp.json()

    def create_campaign(self, name, template_id, page_id, smtp_id, group_id, launch_date=None):
        return self._req("POST", "campaigns/", {
            "name": name, "template": {"id": template_id},
            "page": {"id": page_id}, "smtp": {"id": smtp_id},
            "groups": [{"id": group_id}],
            "launch_date": launch_date or datetime.utcnow().isoformat() + "Z",
        })

    def get_summary(self, campaign_id):
        return self._req("GET", f"campaigns/{campaign_id}/summary")

    def list_campaigns(self):
        return self._req("GET", "campaigns/")

    def complete_campaign(self, campaign_id):
        return self._req("DELETE", f"campaigns/{campaign_id}")


def generate_spearphish_templates():
    """Generate targeted spearphishing email templates."""
    return [
        {
            "name": "Shared Document Notification",
            "subject": "{{.FirstName}}, {{.From}} shared a document with you",
            "category": "credential_harvest",
            "difficulty": "easy",
        },
        {
            "name": "IT Security Alert",
            "subject": "Action Required: Unusual sign-in activity on your account",
            "category": "credential_harvest",
            "difficulty": "medium",
        },
        {
            "name": "Payroll Update Request",
            "subject": "Important: Verify your direct deposit information",
            "category": "credential_harvest",
            "difficulty": "medium",
        },
        {
            "name": "Conference Registration",
            "subject": "Your registration for {{.Position}} Summit is confirmed",
            "category": "link_click",
            "difficulty": "hard",
        },
    ]


def analyze_campaign_metrics(summary):
    """Analyze campaign summary for executive reporting."""
    stats = summary.get("stats", {})
    total = stats.get("total", 1)
    return {
        "total_targets": total,
        "emails_sent": stats.get("sent", 0),
        "emails_opened": stats.get("opened", 0),
        "links_clicked": stats.get("clicked", 0),
        "data_submitted": stats.get("submitted_data", 0),
        "reported": stats.get("email_reported", 0),
        "open_rate_pct": round(stats.get("opened", 0) / max(total, 1) * 100, 1),
        "click_rate_pct": round(stats.get("clicked", 0) / max(total, 1) * 100, 1),
        "submit_rate_pct": round(stats.get("submitted_data", 0) / max(total, 1) * 100, 1),
    }


def run_simulation(base_url=None, api_key=None, campaign_id=None):
    """Execute spearphishing simulation analysis."""
    print(f"\n{'='*60}")
    print(f"  SPEARPHISHING SIMULATION CAMPAIGN")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    templates = generate_spearphish_templates()
    print(f"--- SPEARPHISH TEMPLATES ({len(templates)}) ---")
    for t in templates:
        print(f"  [{t['difficulty'].upper()}] {t['name']}: {t['subject'][:60]}")

    if base_url and api_key:
        client = GoPhishCampaign(base_url, api_key)
        if campaign_id:
            summary = client.get_summary(campaign_id)
            metrics = analyze_campaign_metrics(summary)
            print(f"\n--- CAMPAIGN METRICS ---")
            for k, v in metrics.items():
                print(f"  {k}: {v}")
            return {"templates": templates, "metrics": metrics}

    return {"templates": templates}


def main():
    parser = argparse.ArgumentParser(description="Spearphishing Simulation Agent")
    parser.add_argument("--gophish-url", help="GoPhish server URL")
    parser.add_argument("--api-key", help="GoPhish API key")
    parser.add_argument("--campaign-id", type=int, help="Campaign ID for metrics")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_simulation(args.gophish_url, args.api_key, args.campaign_id)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
