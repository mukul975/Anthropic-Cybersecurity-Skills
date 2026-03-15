#!/usr/bin/env python3
"""
MISP Threat Intelligence Collection Script

Automates IOC collection from MISP instance including:
- Feed management and scheduled fetching
- Event search and attribute extraction
- IOC export in multiple formats (STIX, CSV, Suricata)
- Warninglist filtering to reduce false positives
- Correlation summary generation

Requirements:
    pip install pymisp requests stix2

Usage:
    python process.py --url https://misp.local --key YOUR_API_KEY --action collect
    python process.py --url https://misp.local --key YOUR_API_KEY --action export --format stix2
    python process.py --url https://misp.local --key YOUR_API_KEY --action feeds --enable-defaults
"""

import argparse
import json
import csv
import sys
import os
from datetime import datetime, timedelta
from typing import Optional

try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
except ImportError:
    print("ERROR: pymisp not installed. Run: pip install pymisp")
    sys.exit(1)


class MISPCollector:
    """Automated threat intelligence collector for MISP."""

    def __init__(self, url: str, api_key: str, ssl_verify: bool = True):
        self.misp = PyMISP(url, api_key, ssl=ssl_verify)
        self.url = url
        self.stats = {
            "events_processed": 0,
            "attributes_collected": 0,
            "iocs_exported": 0,
            "feeds_enabled": 0,
            "warninglist_filtered": 0,
        }

    def enable_default_feeds(self) -> dict:
        """Enable and fetch default MISP community feeds."""
        default_feeds = [
            "CIRCL OSINT Feed",
            "Botvrij.eu",
            "abuse.ch URLhaus",
            "The Botnet Channel",
            "Phishtank online valid phishing",
        ]

        feeds = self.misp.feeds()
        enabled = []

        for feed in feeds:
            feed_name = feed.get("Feed", {}).get("name", "")
            feed_id = feed.get("Feed", {}).get("id")

            if any(default in feed_name for default in default_feeds):
                try:
                    self.misp.enable_feed(feed_id)
                    self.misp.fetch_feed(feed_id)
                    enabled.append(feed_name)
                    self.stats["feeds_enabled"] += 1
                    print(f"[+] Enabled feed: {feed_name}")
                except Exception as e:
                    print(f"[-] Failed to enable {feed_name}: {e}")

        return {"enabled_feeds": enabled, "count": len(enabled)}

    def add_custom_feed(self, name: str, url: str, provider: str,
                        source_format: str = "csv") -> dict:
        """Add a custom threat intelligence feed."""
        feed_config = {
            "name": name,
            "provider": provider,
            "url": url,
            "source_format": source_format,
            "input_source": "network",
            "publish": False,
            "enabled": True,
            "distribution": 0,
            "default": False,
            "lookup_visible": True,
        }

        result = self.misp.add_feed(feed_config)
        print(f"[+] Added custom feed: {name} from {provider}")
        return result

    def collect_recent_iocs(self, days: int = 7,
                            ioc_types: Optional[list] = None) -> list:
        """Collect IOCs from recent events."""
        if ioc_types is None:
            ioc_types = [
                "ip-dst", "ip-src", "domain", "hostname",
                "url", "md5", "sha1", "sha256", "email-src",
            ]

        date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        all_iocs = []

        for ioc_type in ioc_types:
            try:
                results = self.misp.search(
                    controller="attributes",
                    type_attribute=ioc_type,
                    date_from=date_from,
                    to_ids=True,
                    pythonify=True,
                )

                for attr in results:
                    ioc_entry = {
                        "type": attr.type,
                        "value": attr.value,
                        "category": attr.category,
                        "event_id": attr.event_id,
                        "timestamp": str(attr.timestamp),
                        "to_ids": attr.to_ids,
                        "comment": attr.comment or "",
                    }
                    all_iocs.append(ioc_entry)
                    self.stats["attributes_collected"] += 1

                print(f"[+] Collected {len(results)} {ioc_type} IOCs")

            except Exception as e:
                print(f"[-] Error collecting {ioc_type}: {e}")

        return all_iocs

    def collect_events_by_tag(self, tags: list, limit: int = 100) -> list:
        """Collect events matching specific tags."""
        events = self.misp.search(
            controller="events",
            tags=tags,
            limit=limit,
            pythonify=True,
        )

        collected = []
        for event in events:
            event_data = {
                "id": event.id,
                "info": event.info,
                "date": str(event.date),
                "threat_level": event.threat_level_id,
                "analysis": event.analysis,
                "attribute_count": len(event.attributes),
                "tags": [tag.name for tag in event.tags] if event.tags else [],
                "attributes": [],
            }

            for attr in event.attributes:
                event_data["attributes"].append({
                    "type": attr.type,
                    "value": attr.value,
                    "category": attr.category,
                    "to_ids": attr.to_ids,
                })

            collected.append(event_data)
            self.stats["events_processed"] += 1

        print(f"[+] Collected {len(collected)} events with tags: {tags}")
        return collected

    def filter_warninglists(self, iocs: list) -> list:
        """Filter IOCs against MISP warninglists to remove known-good indicators."""
        filtered = []

        for ioc in iocs:
            result = self.misp.values_in_warninglist([ioc["value"]])

            if not result or not result.get(ioc["value"]):
                filtered.append(ioc)
            else:
                self.stats["warninglist_filtered"] += 1
                print(f"[!] Filtered (warninglist): {ioc['value']}")

        print(f"[+] Filtered {self.stats['warninglist_filtered']} IOCs via warninglists")
        return filtered

    def export_stix2(self, event_ids: Optional[list] = None,
                     tags: Optional[list] = None) -> dict:
        """Export events as STIX 2.1 bundles."""
        search_params = {
            "controller": "events",
            "return_format": "stix2",
        }

        if event_ids:
            search_params["eventid"] = event_ids
        if tags:
            search_params["tags"] = tags

        stix_bundle = self.misp.search(**search_params)
        self.stats["iocs_exported"] += len(
            stix_bundle.get("objects", []) if isinstance(stix_bundle, dict) else []
        )

        print(f"[+] Exported STIX 2.1 bundle")
        return stix_bundle

    def export_csv(self, iocs: list, output_path: str) -> str:
        """Export IOCs to CSV file."""
        if not iocs:
            print("[-] No IOCs to export")
            return ""

        fieldnames = ["type", "value", "category", "event_id", "timestamp",
                      "to_ids", "comment"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ioc in iocs:
                writer.writerow({k: ioc.get(k, "") for k in fieldnames})

        self.stats["iocs_exported"] = len(iocs)
        print(f"[+] Exported {len(iocs)} IOCs to {output_path}")
        return output_path

    def export_suricata(self, days: int = 7) -> str:
        """Export network IOCs as Suricata rules."""
        rules = self.misp.search(
            controller="attributes",
            return_format="suricata",
            to_ids=True,
            type_attribute=["ip-dst", "ip-src", "domain", "url"],
            date_from=(datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d"),
        )

        print(f"[+] Generated Suricata rules")
        return rules

    def get_correlation_summary(self, event_id: int) -> dict:
        """Get correlation summary for a specific event."""
        event = self.misp.get_event(event_id, pythonify=True)
        correlations = {}

        for attr in event.attributes:
            if hasattr(attr, "RelatedAttribute") and attr.RelatedAttribute:
                correlations[attr.value] = {
                    "type": attr.type,
                    "related_events": [
                        rel["Event"]["id"] for rel in attr.RelatedAttribute
                    ],
                }

        return {
            "event_id": event_id,
            "event_info": event.info,
            "total_attributes": len(event.attributes),
            "correlated_attributes": len(correlations),
            "correlations": correlations,
        }

    def print_stats(self):
        """Print collection statistics."""
        print("\n=== MISP Collection Statistics ===")
        for key, value in self.stats.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        print("=================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="MISP Threat Intelligence Collection Tool"
    )
    parser.add_argument("--url", required=True, help="MISP instance URL")
    parser.add_argument("--key", required=True, help="MISP API key")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument(
        "--action",
        choices=["collect", "export", "feeds", "correlate"],
        required=True,
        help="Action to perform",
    )
    parser.add_argument("--days", type=int, default=7, help="Lookback period in days")
    parser.add_argument(
        "--format",
        choices=["csv", "stix2", "suricata"],
        default="csv",
        help="Export format",
    )
    parser.add_argument("--output", default="misp_iocs_export.csv", help="Output file path")
    parser.add_argument("--tags", nargs="+", help="Filter by tags")
    parser.add_argument(
        "--enable-defaults",
        action="store_true",
        help="Enable default community feeds",
    )
    parser.add_argument("--event-id", type=int, help="Event ID for correlation")

    args = parser.parse_args()

    collector = MISPCollector(args.url, args.key, ssl_verify=not args.no_ssl)

    if args.action == "feeds":
        if args.enable_defaults:
            result = collector.enable_default_feeds()
            print(json.dumps(result, indent=2))

    elif args.action == "collect":
        iocs = collector.collect_recent_iocs(days=args.days)
        if args.tags:
            events = collector.collect_events_by_tag(args.tags)
            print(json.dumps(events[:5], indent=2, default=str))
        filtered = collector.filter_warninglists(iocs)
        collector.export_csv(filtered, args.output)

    elif args.action == "export":
        if args.format == "stix2":
            bundle = collector.export_stix2(tags=args.tags)
            with open(args.output.replace(".csv", ".json"), "w") as f:
                json.dump(bundle, f, indent=2, default=str)
        elif args.format == "suricata":
            rules = collector.export_suricata(days=args.days)
            with open(args.output.replace(".csv", ".rules"), "w") as f:
                f.write(str(rules))
        else:
            iocs = collector.collect_recent_iocs(days=args.days)
            collector.export_csv(iocs, args.output)

    elif args.action == "correlate":
        if args.event_id:
            summary = collector.get_correlation_summary(args.event_id)
            print(json.dumps(summary, indent=2, default=str))
        else:
            print("[-] --event-id required for correlation action")

    collector.print_stats()


if __name__ == "__main__":
    main()
