#!/usr/bin/env python3
"""
Proofpoint TAP API Integration and Analysis

Pulls threat data from Proofpoint TAP SIEM API, analyzes sandbox results,
identifies Very Attacked People, and generates threat reports.

Usage:
    python process.py threats --hours 24
    python process.py vap
    python process.py campaign --id <campaign-id>
    python process.py report --hours 168 --output report.html
"""

import argparse
import json
import sys
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from dataclasses import dataclass, field, asdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

PP_SERVICE_PRINCIPAL = os.environ.get("PP_SERVICE_PRINCIPAL", "")
PP_SECRET = os.environ.get("PP_SECRET", "")
PP_BASE_URL = "https://tap-api-v2.proofpoint.com"


class ProofpointTAPClient:
    """Client for Proofpoint TAP SIEM API."""

    def __init__(self, principal: str, secret: str):
        self.auth = (principal, secret)
        self.base = PP_BASE_URL

    def _get(self, endpoint: str, params: dict = None) -> dict:
        resp = requests.get(f"{self.base}{endpoint}",
                            auth=self.auth, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_all_threats(self, since_seconds: int = 3600) -> dict:
        params = {"sinceSeconds": since_seconds, "format": "json"}
        return self._get("/v2/siem/all", params)

    def get_blocked_messages(self, since_seconds: int = 3600) -> dict:
        params = {"sinceSeconds": since_seconds, "format": "json"}
        return self._get("/v2/siem/messages/blocked", params)

    def get_delivered_threats(self, since_seconds: int = 3600) -> dict:
        params = {"sinceSeconds": since_seconds, "format": "json"}
        return self._get("/v2/siem/messages/delivered", params)

    def get_blocked_clicks(self, since_seconds: int = 3600) -> dict:
        params = {"sinceSeconds": since_seconds, "format": "json"}
        return self._get("/v2/siem/clicks/blocked", params)

    def get_permitted_clicks(self, since_seconds: int = 3600) -> dict:
        params = {"sinceSeconds": since_seconds, "format": "json"}
        return self._get("/v2/siem/clicks/permitted", params)

    def get_vap(self, window: int = 14) -> dict:
        params = {"window": window}
        return self._get("/v2/people/vap", params)

    def get_campaign(self, campaign_id: str) -> dict:
        return self._get(f"/v2/campaign/{campaign_id}")


def analyze_threats(threat_data: dict) -> dict:
    """Analyze threat data and produce summary statistics."""
    messages_blocked = threat_data.get("messagesBlocked", [])
    messages_delivered = threat_data.get("messagesDelivered", [])
    clicks_blocked = threat_data.get("clicksBlocked", [])
    clicks_permitted = threat_data.get("clicksPermitted", [])

    # Threat classification counts
    threat_types = defaultdict(int)
    threat_families = defaultdict(int)
    targeted_users = defaultdict(int)
    sender_domains = defaultdict(int)

    all_messages = messages_blocked + messages_delivered
    for msg in all_messages:
        for threat in msg.get("threatsInfoMap", []):
            threat_types[threat.get("classification", "unknown")] += 1
            if threat.get("threatType") == "attachment":
                threat_families[threat.get("threat", "unknown")] += 1

        for recipient in msg.get("recipient", []) if isinstance(msg.get("recipient"), list) else [msg.get("recipient", "")]:
            if recipient:
                targeted_users[recipient] += 1

        sender = msg.get("senderDomain", msg.get("fromAddress", ""))
        if sender:
            sender_domains[sender] += 1

    summary = {
        "total_messages_blocked": len(messages_blocked),
        "total_messages_delivered_with_threats": len(messages_delivered),
        "total_clicks_blocked": len(clicks_blocked),
        "total_clicks_permitted": len(clicks_permitted),
        "threat_type_breakdown": dict(threat_types),
        "top_threat_families": dict(sorted(threat_families.items(),
                                           key=lambda x: x[1], reverse=True)[:10]),
        "top_targeted_users": dict(sorted(targeted_users.items(),
                                          key=lambda x: x[1], reverse=True)[:10]),
        "top_sender_domains": dict(sorted(sender_domains.items(),
                                          key=lambda x: x[1], reverse=True)[:10]),
    }
    return summary


def format_threat_report(summary: dict, hours: int) -> str:
    """Format threat summary as text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  PROOFPOINT TAP THREAT REPORT")
    lines.append("=" * 60)
    lines.append(f"  Period: Last {hours} hours")
    lines.append(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    lines.append("[OVERVIEW]")
    lines.append(f"  Messages Blocked:           {summary['total_messages_blocked']}")
    lines.append(f"  Delivered with Threats:      {summary['total_messages_delivered_with_threats']}")
    lines.append(f"  Clicks Blocked:              {summary['total_clicks_blocked']}")
    lines.append(f"  Clicks Permitted:            {summary['total_clicks_permitted']}")
    lines.append("")

    if summary["threat_type_breakdown"]:
        lines.append("[THREAT TYPES]")
        for t, count in sorted(summary["threat_type_breakdown"].items(),
                                key=lambda x: x[1], reverse=True):
            lines.append(f"  {t}: {count}")
        lines.append("")

    if summary["top_targeted_users"]:
        lines.append("[MOST TARGETED USERS]")
        for user, count in list(summary["top_targeted_users"].items())[:10]:
            lines.append(f"  {user}: {count} threats")
        lines.append("")

    if summary["top_sender_domains"]:
        lines.append("[TOP THREAT SENDER DOMAINS]")
        for domain, count in list(summary["top_sender_domains"].items())[:10]:
            lines.append(f"  {domain}: {count}")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Proofpoint TAP Analysis")
    subparsers = parser.add_subparsers(dest="command")

    threats_parser = subparsers.add_parser("threats", help="Get recent threats")
    threats_parser.add_argument("--hours", type=int, default=24)

    vap_parser = subparsers.add_parser("vap", help="Get Very Attacked People")
    vap_parser.add_argument("--window", type=int, default=14, help="Days to look back")

    campaign_parser = subparsers.add_parser("campaign", help="Get campaign details")
    campaign_parser.add_argument("--id", required=True)

    report_parser = subparsers.add_parser("report", help="Generate threat report")
    report_parser.add_argument("--hours", type=int, default=168)
    report_parser.add_argument("--output", "-o")

    parser.add_argument("--json", action="store_true")
    parser.add_argument("--principal", default=PP_SERVICE_PRINCIPAL)
    parser.add_argument("--secret", default=PP_SECRET)

    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("Error: requests library required", file=sys.stderr)
        sys.exit(1)

    principal = args.principal
    secret = args.secret

    if not principal or not secret:
        print("Error: Proofpoint TAP credentials required.", file=sys.stderr)
        print("Set PP_SERVICE_PRINCIPAL and PP_SECRET environment variables.", file=sys.stderr)
        sys.exit(1)

    client = ProofpointTAPClient(principal, secret)

    if args.command == "threats":
        seconds = args.hours * 3600
        data = client.get_all_threats(seconds)
        summary = analyze_threats(data)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(format_threat_report(summary, args.hours))

    elif args.command == "vap":
        data = client.get_vap(args.window)
        users = data.get("users", [])
        print(f"Very Attacked People (last {args.window} days):")
        for user in users:
            identity = user.get("identity", {})
            print(f"  {identity.get('emails', [''])[0]} - "
                  f"Attacks: {user.get('threatStatistics', {}).get('attackIndex', 0)}")

    elif args.command == "campaign":
        data = client.get_campaign(args.id)
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Campaign: {data.get('name', 'Unknown')}")
            print(f"Description: {data.get('description', '')}")
            actors = data.get("actors", [])
            for actor in actors:
                print(f"  Actor: {actor.get('name', 'Unknown')}")

    elif args.command == "report":
        seconds = args.hours * 3600
        data = client.get_all_threats(seconds)
        summary = analyze_threats(data)
        report = format_threat_report(summary, args.hours)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            print(f"Report written to {args.output}")
        else:
            print(report)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
