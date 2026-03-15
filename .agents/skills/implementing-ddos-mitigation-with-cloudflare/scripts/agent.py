#!/usr/bin/env python3
"""DDoS mitigation agent using Cloudflare API for traffic analysis and rule management."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CF_API = "https://api.cloudflare.com/client/v4"


class CloudflareClient:
    """Client for Cloudflare API v4."""

    def __init__(self, api_token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        })

    def list_zones(self) -> List[dict]:
        resp = self.session.get(f"{CF_API}/zones", timeout=15)
        resp.raise_for_status()
        return resp.json().get("result", [])

    def get_zone_analytics(self, zone_id: str, since: str = "-1440") -> dict:
        resp = self.session.get(
            f"{CF_API}/zones/{zone_id}/analytics/dashboard",
            params={"since": since}, timeout=15)
        return resp.json().get("result", {}) if resp.status_code == 200 else {}

    def get_firewall_events(self, zone_id: str, limit: int = 100) -> List[dict]:
        resp = self.session.get(
            f"{CF_API}/zones/{zone_id}/security/events",
            params={"per_page": limit}, timeout=15)
        return resp.json().get("result", []) if resp.status_code == 200 else []

    def get_ddos_settings(self, zone_id: str) -> dict:
        resp = self.session.get(
            f"{CF_API}/zones/{zone_id}/firewall/ddos_protection", timeout=15)
        return resp.json().get("result", {}) if resp.status_code == 200 else {}

    def create_rate_limit_rule(self, zone_id: str, url_pattern: str,
                                threshold: int, period: int) -> dict:
        payload = {
            "match": {"request": {"url_pattern": url_pattern}},
            "threshold": threshold,
            "period": period,
            "action": {"mode": "challenge"},
        }
        resp = self.session.post(
            f"{CF_API}/zones/{zone_id}/rate_limits", json=payload, timeout=15)
        return resp.json().get("result", {})

    def set_security_level(self, zone_id: str, level: str = "high") -> dict:
        resp = self.session.patch(
            f"{CF_API}/zones/{zone_id}/settings/security_level",
            json={"value": level}, timeout=15)
        return resp.json().get("result", {})


def analyze_traffic(analytics: dict) -> dict:
    """Analyze traffic patterns for DDoS indicators."""
    totals = analytics.get("totals", {})
    requests_data = totals.get("requests", {})
    threats = totals.get("threats", {})
    return {
        "total_requests": requests_data.get("all", 0),
        "cached_requests": requests_data.get("cached", 0),
        "threats_blocked": threats.get("all", 0),
        "bandwidth_bytes": totals.get("bandwidth", {}).get("all", 0),
    }


def generate_report(client: CloudflareClient) -> dict:
    """Generate DDoS mitigation posture report."""
    zones = client.list_zones()
    report = {"analysis_date": datetime.utcnow().isoformat(), "zones": []}
    for zone in zones[:10]:
        zid = zone["id"]
        analytics = client.get_zone_analytics(zid)
        traffic = analyze_traffic(analytics)
        events = client.get_firewall_events(zid, 50)
        ddos_settings = client.get_ddos_settings(zid)
        report["zones"].append({
            "name": zone["name"], "id": zid,
            "traffic": traffic,
            "security_events": len(events),
            "ddos_protection": ddos_settings,
        })
    report["summary"] = {
        "zones_assessed": len(report["zones"]),
        "total_threats": sum(z["traffic"]["threats_blocked"] for z in report["zones"]),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Cloudflare DDoS Mitigation Agent")
    parser.add_argument("--api-token", required=True, help="Cloudflare API token")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="cloudflare_ddos_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    client = CloudflareClient(args.api_token)
    report = generate_report(client)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
