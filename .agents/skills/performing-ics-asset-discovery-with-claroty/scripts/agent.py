#!/usr/bin/env python3
"""Agent for performing ICS asset discovery with Claroty xDome/CTD API."""

import json
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


class ClarotyClient:
    """Client for Claroty xDome / Continuous Threat Detection API."""

    def __init__(self, base_url, api_token):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        })

    def get_assets(self, asset_type=None, limit=100):
        """Retrieve discovered OT/IoT assets."""
        params = {"limit": limit}
        if asset_type:
            params["type"] = asset_type
        resp = self.session.get(f"{self.base_url}/api/v1/assets", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_asset_detail(self, asset_id):
        """Get detailed info for a specific asset."""
        resp = self.session.get(f"{self.base_url}/api/v1/assets/{asset_id}", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_vulnerabilities(self, severity=None, limit=100):
        """Retrieve vulnerabilities found on OT assets."""
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_alerts(self, status="active", limit=50):
        """Retrieve active security alerts."""
        params = {"status": status, "limit": limit}
        resp = self.session.get(f"{self.base_url}/api/v1/alerts", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_network_segments(self):
        """Retrieve network segmentation topology."""
        resp = self.session.get(f"{self.base_url}/api/v1/network/segments", timeout=30)
        resp.raise_for_status()
        return resp.json()


def discover_assets(base_url, token, asset_type=None, limit=100):
    """Run asset discovery and categorize results."""
    client = ClarotyClient(base_url, token)
    data = client.get_assets(asset_type, limit)
    assets = data.get("assets", data.get("results", []))
    categories = {}
    vendors = {}
    for asset in assets:
        cat = asset.get("type", asset.get("category", "unknown"))
        categories[cat] = categories.get(cat, 0) + 1
        vendor = asset.get("vendor", asset.get("manufacturer", "unknown"))
        vendors[vendor] = vendors.get(vendor, 0) + 1
    critical = [a for a in assets if a.get("criticality", "").lower() in ("critical", "high")]
    return {
        "total_assets": len(assets),
        "by_category": categories,
        "by_vendor": dict(sorted(vendors.items(), key=lambda x: -x[1])[:20]),
        "critical_assets": len(critical),
        "assets": [{"id": a.get("id"), "name": a.get("name"), "type": a.get("type"),
                     "ip": a.get("ip_address", a.get("ip")), "vendor": a.get("vendor"),
                     "firmware": a.get("firmware_version", ""), "criticality": a.get("criticality")}
                    for a in assets[:50]],
        "timestamp": datetime.utcnow().isoformat(),
    }


def assess_vulnerabilities(base_url, token, severity=None, limit=100):
    """Retrieve and prioritize OT vulnerabilities."""
    client = ClarotyClient(base_url, token)
    data = client.get_vulnerabilities(severity, limit)
    vulns = data.get("vulnerabilities", data.get("results", []))
    by_severity = {}
    for v in vulns:
        s = v.get("severity", "unknown")
        by_severity[s] = by_severity.get(s, 0) + 1
    return {
        "total_vulnerabilities": len(vulns),
        "by_severity": by_severity,
        "vulnerabilities": [{"cve": v.get("cve_id"), "severity": v.get("severity"),
                             "asset": v.get("asset_name", v.get("asset_id")),
                             "description": v.get("description", "")[:200]}
                            for v in vulns[:30]],
    }


def get_alerts_summary(base_url, token, status="active"):
    """Get security alert summary."""
    client = ClarotyClient(base_url, token)
    data = client.get_alerts(status)
    alerts = data.get("alerts", data.get("results", []))
    by_type = {}
    for a in alerts:
        t = a.get("alert_type", a.get("type", "unknown"))
        by_type[t] = by_type.get(t, 0) + 1
    return {
        "total_alerts": len(alerts),
        "status": status,
        "by_type": by_type,
        "alerts": [{"id": a.get("id"), "type": a.get("alert_type"),
                     "severity": a.get("severity"), "description": a.get("description", "")[:150],
                     "asset": a.get("asset_name")} for a in alerts[:20]],
    }


def network_topology(base_url, token):
    """Map OT network segments."""
    client = ClarotyClient(base_url, token)
    data = client.get_network_segments()
    segments = data.get("segments", data.get("results", []))
    return {
        "total_segments": len(segments),
        "segments": [{"name": s.get("name"), "subnet": s.get("subnet"),
                       "asset_count": s.get("asset_count", 0),
                       "zone": s.get("zone", s.get("purdue_level", ""))}
                      for s in segments],
    }


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed"}))
        return
    parser = argparse.ArgumentParser(description="ICS Asset Discovery with Claroty Agent")
    parser.add_argument("--url", required=True, help="Claroty xDome/CTD base URL")
    parser.add_argument("--token", required=True, help="API token")
    sub = parser.add_subparsers(dest="command")
    a = sub.add_parser("assets", help="Discover OT/IoT assets")
    a.add_argument("--type", help="Filter by asset type (PLC, HMI, RTU, etc.)")
    a.add_argument("--limit", type=int, default=100)
    v = sub.add_parser("vulns", help="List vulnerabilities")
    v.add_argument("--severity", help="Filter by severity")
    v.add_argument("--limit", type=int, default=100)
    sub.add_parser("alerts", help="Get active alerts")
    sub.add_parser("topology", help="Map network segments")
    args = parser.parse_args()
    if args.command == "assets":
        result = discover_assets(args.url, args.token, args.type, args.limit)
    elif args.command == "vulns":
        result = assess_vulnerabilities(args.url, args.token, args.severity, args.limit)
    elif args.command == "alerts":
        result = get_alerts_summary(args.url, args.token)
    elif args.command == "topology":
        result = network_topology(args.url, args.token)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
