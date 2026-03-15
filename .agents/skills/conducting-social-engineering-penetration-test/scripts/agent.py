#!/usr/bin/env python3
"""Social engineering penetration test management agent using GoPhish API."""

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


class GoPhishClient:
    """GoPhish API client for phishing campaign management."""

    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _get(self, endpoint):
        resp = requests.get(f"{self.base_url}/api/{endpoint}", headers=self.headers, verify=False)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint, data):
        resp = requests.post(f"{self.base_url}/api/{endpoint}", headers=self.headers,
                             json=data, verify=False)
        resp.raise_for_status()
        return resp.json()

    def list_campaigns(self):
        return self._get("campaigns/")

    def get_campaign_results(self, campaign_id):
        return self._get(f"campaigns/{campaign_id}/results")

    def create_sending_profile(self, name, host, from_addr, username, password):
        return self._post("smtp/", {
            "name": name, "host": host, "from_address": from_addr,
            "username": username, "password": password, "ignore_cert_errors": True,
        })

    def create_template(self, name, subject, html, text=""):
        return self._post("templates/", {
            "name": name, "subject": subject, "html": html, "text": text,
        })

    def create_group(self, name, targets):
        return self._post("groups/", {
            "name": name,
            "targets": [{"email": t["email"], "first_name": t.get("first_name", ""),
                         "last_name": t.get("last_name", "")} for t in targets],
        })


def analyze_campaign_results(results):
    """Analyze phishing campaign results for metrics."""
    stats = {"total": 0, "sent": 0, "opened": 0, "clicked": 0, "submitted": 0, "reported": 0}
    for r in results:
        stats["total"] += 1
        status = r.get("status", "").lower()
        if status == "email sent":
            stats["sent"] += 1
        elif status == "email opened":
            stats["opened"] += 1
        elif status == "clicked link":
            stats["clicked"] += 1
        elif status == "submitted data":
            stats["submitted"] += 1
    if stats["sent"] > 0:
        stats["open_rate"] = round(stats["opened"] / stats["sent"] * 100, 1)
        stats["click_rate"] = round(stats["clicked"] / stats["sent"] * 100, 1)
        stats["submit_rate"] = round(stats["submitted"] / stats["sent"] * 100, 1)
    return stats


def generate_pretext_scenarios():
    """Generate social engineering pretext scenarios for testing."""
    return [
        {
            "scenario": "IT Password Reset",
            "pretext": "IT department requires immediate password reset due to security incident",
            "vector": "email",
            "urgency": "high",
            "success_indicator": "User clicks link and enters credentials",
        },
        {
            "scenario": "CEO Wire Transfer",
            "pretext": "CEO requests urgent wire transfer for confidential acquisition",
            "vector": "email",
            "urgency": "high",
            "success_indicator": "User initiates transfer or reveals banking info",
        },
        {
            "scenario": "Vendor Invoice",
            "pretext": "Known vendor sends updated invoice with changed payment details",
            "vector": "email",
            "urgency": "medium",
            "success_indicator": "User opens attachment or clicks payment link",
        },
        {
            "scenario": "Physical Tailgating",
            "pretext": "Contractor with clipboard requests building access",
            "vector": "physical",
            "urgency": "low",
            "success_indicator": "Employee holds door without badge verification",
        },
    ]


def run_assessment(base_url=None, api_key=None, campaign_id=None):
    """Execute social engineering assessment analysis."""
    print(f"\n{'='*60}")
    print(f"  SOCIAL ENGINEERING PENETRATION TEST")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    if base_url and api_key:
        client = GoPhishClient(base_url, api_key)
        campaigns = client.list_campaigns()
        print(f"--- CAMPAIGNS ({len(campaigns)}) ---")
        for c in campaigns[:5]:
            print(f"  {c['name']}: {c['status']}")

        if campaign_id:
            results = client.get_campaign_results(campaign_id)
            stats = analyze_campaign_results(results)
            print(f"\n--- CAMPAIGN METRICS ---")
            for k, v in stats.items():
                print(f"  {k}: {v}")

    scenarios = generate_pretext_scenarios()
    print(f"\n--- PRETEXT SCENARIOS ({len(scenarios)}) ---")
    for s in scenarios:
        print(f"  [{s['urgency'].upper()}] {s['scenario']}: {s['vector']}")

    return {"scenarios": scenarios}


def main():
    parser = argparse.ArgumentParser(description="Social Engineering Pentest Agent")
    parser.add_argument("--gophish-url", help="GoPhish server URL")
    parser.add_argument("--api-key", help="GoPhish API key")
    parser.add_argument("--campaign-id", type=int, help="Campaign ID for results")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_assessment(args.gophish_url, args.api_key, args.campaign_id)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
