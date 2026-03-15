#!/usr/bin/env python3
"""Agent for performing phishing simulation campaigns with GoPhish API."""

import json
import argparse
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None


class GoPhishClient:
    """Client for GoPhish REST API."""

    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _get(self, path):
        resp = requests.get(f"{self.base_url}{path}", headers=self.headers, verify=False, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path, data):
        resp = requests.post(f"{self.base_url}{path}", headers=self.headers, json=data, verify=False, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_campaigns(self):
        return self._get("/api/campaigns/")

    def get_campaign(self, campaign_id):
        return self._get(f"/api/campaigns/{campaign_id}")

    def get_campaign_results(self, campaign_id):
        return self._get(f"/api/campaigns/{campaign_id}/results")

    def create_campaign(self, name, template_id, page_id, smtp_id, group_ids, url, launch_date=None):
        data = {"name": name, "template": {"id": template_id}, "page": {"id": page_id},
                "smtp": {"id": smtp_id}, "groups": [{"id": gid} for gid in group_ids], "url": url}
        if launch_date:
            data["launch_date"] = launch_date
        return self._post("/api/campaigns/", data)

    def get_groups(self):
        return self._get("/api/groups/")

    def get_templates(self):
        return self._get("/api/templates/")

    def get_sending_profiles(self):
        return self._get("/api/smtp/")


def list_campaigns(base_url, api_key):
    """List all phishing simulation campaigns."""
    client = GoPhishClient(base_url, api_key)
    campaigns = client.get_campaigns()
    return {
        "total_campaigns": len(campaigns),
        "campaigns": [{"id": c["id"], "name": c["name"], "status": c["status"],
                        "created_date": c.get("created_date"), "launch_date": c.get("launch_date")}
                       for c in campaigns],
    }


def get_campaign_metrics(base_url, api_key, campaign_id):
    """Get detailed metrics for a phishing campaign."""
    client = GoPhishClient(base_url, api_key)
    campaign = client.get_campaign(campaign_id)
    results = campaign.get("results", [])
    stats = {"total": len(results), "sent": 0, "opened": 0, "clicked": 0, "submitted": 0, "reported": 0}
    for r in results:
        status = r.get("status", "").lower()
        if "sent" in status or "email sent" in status:
            stats["sent"] += 1
        if "opened" in status or "email opened" in status:
            stats["opened"] += 1
        if "clicked" in status:
            stats["clicked"] += 1
        if "submitted" in status:
            stats["submitted"] += 1
        if "reported" in status:
            stats["reported"] += 1
    total = max(stats["sent"], 1)
    return {
        "campaign_id": campaign_id, "name": campaign.get("name"),
        "status": campaign.get("status"),
        "stats": stats,
        "rates": {
            "open_rate": round(stats["opened"] / total * 100, 1),
            "click_rate": round(stats["clicked"] / total * 100, 1),
            "submit_rate": round(stats["submitted"] / total * 100, 1),
            "report_rate": round(stats["reported"] / total * 100, 1),
        },
    }


def launch_campaign(base_url, api_key, name, template_id, page_id, smtp_id, group_ids, url):
    """Launch a new phishing simulation campaign."""
    client = GoPhishClient(base_url, api_key)
    result = client.create_campaign(name, template_id, page_id, smtp_id, group_ids, url)
    return {"campaign_created": True, "campaign": result}


def list_resources(base_url, api_key):
    """List available templates, groups, and sending profiles."""
    client = GoPhishClient(base_url, api_key)
    return {
        "groups": [{"id": g["id"], "name": g["name"], "targets": len(g.get("targets", []))}
                   for g in client.get_groups()],
        "templates": [{"id": t["id"], "name": t["name"]} for t in client.get_templates()],
        "sending_profiles": [{"id": s["id"], "name": s["name"], "host": s.get("host")}
                             for s in client.get_sending_profiles()],
    }


def generate_report(base_url, api_key, campaign_id):
    """Generate phishing simulation report with recommendations."""
    metrics = get_campaign_metrics(base_url, api_key, campaign_id)
    recommendations = []
    if metrics["rates"]["click_rate"] > 20:
        recommendations.append("HIGH click rate — mandatory security awareness training needed")
    if metrics["rates"]["submit_rate"] > 10:
        recommendations.append("CRITICAL — over 10% submitted credentials, implement MFA immediately")
    if metrics["rates"]["report_rate"] < 5:
        recommendations.append("Low report rate — train users on how to report phishing")
    return {
        "generated": datetime.utcnow().isoformat(),
        **metrics,
        "risk_level": "CRITICAL" if metrics["rates"]["submit_rate"] > 10 else "HIGH" if metrics["rates"]["click_rate"] > 20 else "MEDIUM",
        "recommendations": recommendations,
    }


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed"}))
        return
    parser = argparse.ArgumentParser(description="GoPhish Phishing Simulation Agent")
    parser.add_argument("--url", required=True, help="GoPhish server URL")
    parser.add_argument("--api-key", required=True, help="GoPhish API key")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("campaigns", help="List campaigns")
    m = sub.add_parser("metrics", help="Campaign metrics")
    m.add_argument("--id", type=int, required=True)
    sub.add_parser("resources", help="List templates, groups, profiles")
    r = sub.add_parser("report", help="Generate campaign report")
    r.add_argument("--id", type=int, required=True)
    l = sub.add_parser("launch", help="Launch new campaign")
    l.add_argument("--name", required=True)
    l.add_argument("--template-id", type=int, required=True)
    l.add_argument("--page-id", type=int, required=True)
    l.add_argument("--smtp-id", type=int, required=True)
    l.add_argument("--group-ids", nargs="+", type=int, required=True)
    l.add_argument("--phish-url", required=True)
    args = parser.parse_args()
    if args.command == "campaigns":
        result = list_campaigns(args.url, args.api_key)
    elif args.command == "metrics":
        result = get_campaign_metrics(args.url, args.api_key, args.id)
    elif args.command == "resources":
        result = list_resources(args.url, args.api_key)
    elif args.command == "report":
        result = generate_report(args.url, args.api_key, args.id)
    elif args.command == "launch":
        result = launch_campaign(args.url, args.api_key, args.name, args.template_id,
                                 args.page_id, args.smtp_id, args.group_ids, args.phish_url)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
