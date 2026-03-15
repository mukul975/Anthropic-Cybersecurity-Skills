#!/usr/bin/env python3
"""
Threat Intelligence Platform Management Script

Manages a multi-component TIP deployment:
- Checks platform component health
- Configures feed ingestion across MISP and OpenCTI
- Runs enrichment pipelines via Cortex analyzers
- Generates platform metrics and dashboards

Requirements:
    pip install pymisp pycti requests

Usage:
    python process.py --check-health --misp-url URL --misp-key KEY --opencti-url URL --opencti-token TOKEN
    python process.py --configure-feeds --misp-url URL --misp-key KEY
    python process.py --platform-stats --misp-url URL --misp-key KEY --opencti-url URL --opencti-token TOKEN
"""

import argparse
import json
import sys
from datetime import datetime

import requests

try:
    from pymisp import PyMISP
except ImportError:
    PyMISP = None

try:
    from pycti import OpenCTIApiClient
except ImportError:
    OpenCTIApiClient = None


class TIPManager:
    """Manage Threat Intelligence Platform operations."""

    def __init__(self, misp_url="", misp_key="", opencti_url="", opencti_token="",
                 thehive_url="", thehive_key="", cortex_url="", cortex_key=""):
        self.misp = PyMISP(misp_url, misp_key, ssl=False) if PyMISP and misp_url else None
        self.opencti = (
            OpenCTIApiClient(opencti_url, opencti_token)
            if OpenCTIApiClient and opencti_url else None
        )
        self.thehive_url = thehive_url
        self.thehive_key = thehive_key
        self.cortex_url = cortex_url
        self.cortex_key = cortex_key

    def check_health(self) -> dict:
        """Check health of all platform components."""
        health = {}

        if self.misp:
            try:
                version = self.misp.misp_instance_version
                health["misp"] = {"status": "healthy", "version": str(version)}
            except Exception as e:
                health["misp"] = {"status": "unhealthy", "error": str(e)}

        if self.opencti:
            try:
                about = self.opencti.health.check()
                health["opencti"] = {"status": "healthy"}
            except Exception as e:
                health["opencti"] = {"status": "unhealthy", "error": str(e)}

        if self.thehive_url:
            try:
                resp = requests.get(
                    f"{self.thehive_url}/api/status",
                    headers={"Authorization": f"Bearer {self.thehive_key}"},
                    timeout=10,
                )
                health["thehive"] = {
                    "status": "healthy" if resp.status_code == 200 else "unhealthy"
                }
            except Exception as e:
                health["thehive"] = {"status": "unreachable", "error": str(e)}

        if self.cortex_url:
            try:
                resp = requests.get(
                    f"{self.cortex_url}/api/status",
                    headers={"Authorization": f"Bearer {self.cortex_key}"},
                    timeout=10,
                )
                health["cortex"] = {
                    "status": "healthy" if resp.status_code == 200 else "unhealthy"
                }
            except Exception as e:
                health["cortex"] = {"status": "unreachable", "error": str(e)}

        return health

    def configure_feeds(self) -> dict:
        """Configure default OSINT feeds in MISP."""
        if not self.misp:
            return {"error": "MISP not configured"}

        feeds = self.misp.feeds()
        enabled = []
        for feed in feeds:
            feed_info = feed.get("Feed", {})
            if not feed_info.get("enabled"):
                try:
                    self.misp.enable_feed(feed_info["id"])
                    enabled.append(feed_info["name"])
                except Exception:
                    pass

        return {"enabled_feeds": enabled, "total_feeds": len(feeds)}

    def get_platform_stats(self) -> dict:
        """Collect statistics from all platform components."""
        stats = {"timestamp": datetime.utcnow().isoformat()}

        if self.misp:
            try:
                server_stats = self.misp.get_server_statistics()
                feeds = self.misp.feeds()
                stats["misp"] = {
                    "events": server_stats.get("event_count", 0),
                    "attributes": server_stats.get("attribute_count", 0),
                    "active_feeds": len([
                        f for f in feeds if f.get("Feed", {}).get("enabled")
                    ]),
                    "organizations": server_stats.get("org_count", 0),
                }
            except Exception as e:
                stats["misp"] = {"error": str(e)}

        if self.opencti:
            try:
                connectors = self.opencti.connector.list()
                stats["opencti"] = {
                    "active_connectors": len([
                        c for c in connectors if c.get("active")
                    ]),
                    "total_connectors": len(connectors),
                }
            except Exception as e:
                stats["opencti"] = {"error": str(e)}

        return stats


def main():
    parser = argparse.ArgumentParser(description="TIP Management Tool")
    parser.add_argument("--misp-url", default="", help="MISP URL")
    parser.add_argument("--misp-key", default="", help="MISP API key")
    parser.add_argument("--opencti-url", default="", help="OpenCTI URL")
    parser.add_argument("--opencti-token", default="", help="OpenCTI token")
    parser.add_argument("--check-health", action="store_true")
    parser.add_argument("--configure-feeds", action="store_true")
    parser.add_argument("--platform-stats", action="store_true")
    parser.add_argument("--output", default="tip_report.json", help="Output file")

    args = parser.parse_args()
    manager = TIPManager(args.misp_url, args.misp_key, args.opencti_url, args.opencti_token)

    result = {}
    if args.check_health:
        result = manager.check_health()
    elif args.configure_feeds:
        result = manager.configure_feeds()
    elif args.platform_stats:
        result = manager.get_platform_stats()

    print(json.dumps(result, indent=2, default=str))
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
