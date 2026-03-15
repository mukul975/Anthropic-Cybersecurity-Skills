#!/usr/bin/env python3
"""
STIX/TAXII 2.1 Feed Integration Script

Implements a TAXII 2.1 feed consumer that:
- Discovers TAXII server API roots and collections
- Polls collections for new STIX objects
- Parses and categorizes STIX 2.1 objects
- Extracts actionable IOCs from indicators
- Exports to multiple formats (JSON, CSV, STIX bundle)

Requirements:
    pip install taxii2-client stix2 requests

Usage:
    python process.py --server https://cti-taxii.mitre.org/taxii2/ --discover
    python process.py --server https://cti-taxii.mitre.org/taxii2/ --collection COLLECTION_ID --poll
    python process.py --server https://cti-taxii.mitre.org/taxii2/ --collection COLLECTION_ID --extract-iocs
"""

import argparse
import json
import csv
import sys
import re
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional

try:
    from taxii2client.v21 import Server, Collection, as_pages
except ImportError:
    print("ERROR: taxii2-client not installed. Run: pip install taxii2-client")
    sys.exit(1)

try:
    from stix2 import parse, MemoryStore, Filter
except ImportError:
    print("ERROR: stix2 not installed. Run: pip install stix2")
    sys.exit(1)


class STIXTAXIIIntegrator:
    """STIX/TAXII 2.1 feed consumer and IOC extractor."""

    def __init__(self, server_url: str, user: str = "", password: str = ""):
        self.server_url = server_url
        self.user = user
        self.password = password
        self.server = None
        self.stats = defaultdict(int)

    def discover(self) -> dict:
        """Discover TAXII server API roots and collections."""
        self.server = Server(self.server_url, user=self.user, password=self.password)

        discovery = {
            "title": self.server.title,
            "description": getattr(self.server, "description", ""),
            "api_roots": [],
        }

        for api_root in self.server.api_roots:
            root_info = {
                "title": api_root.title,
                "url": api_root.url,
                "collections": [],
            }

            for collection in api_root.collections:
                root_info["collections"].append({
                    "id": collection.id,
                    "title": collection.title,
                    "description": getattr(collection, "description", ""),
                    "can_read": collection.can_read,
                    "can_write": collection.can_write,
                })
                self.stats["collections"] += 1

            discovery["api_roots"].append(root_info)

        self.stats["api_roots"] = len(discovery["api_roots"])
        return discovery

    def poll_collection(self, collection_url: str,
                        added_after: Optional[str] = None,
                        max_objects: int = 1000) -> list:
        """Poll a TAXII collection for STIX objects."""
        collection = Collection(
            collection_url, user=self.user, password=self.password
        )

        all_objects = []
        kwargs = {}
        if added_after:
            kwargs["added_after"] = added_after

        try:
            for envelope in as_pages(
                collection.get_objects, per_request=100, **kwargs
            ):
                objects = envelope.get("objects", [])
                all_objects.extend(objects)
                self.stats["objects_fetched"] += len(objects)

                if len(all_objects) >= max_objects:
                    all_objects = all_objects[:max_objects]
                    break

        except Exception as e:
            print(f"[-] Polling error: {e}")

        # Categorize by type
        for obj in all_objects:
            self.stats[f"type_{obj.get('type', 'unknown')}"] += 1

        return all_objects

    def extract_indicators(self, objects: list) -> list:
        """Extract indicator patterns from STIX objects."""
        indicators = []

        for obj in objects:
            if obj.get("type") != "indicator":
                continue

            pattern = obj.get("pattern", "")
            indicator = {
                "id": obj.get("id", ""),
                "name": obj.get("name", ""),
                "pattern": pattern,
                "pattern_type": obj.get("pattern_type", ""),
                "valid_from": obj.get("valid_from", ""),
                "valid_until": obj.get("valid_until", ""),
                "confidence": obj.get("confidence", 0),
                "indicator_types": obj.get("indicator_types", []),
                "labels": obj.get("labels", []),
                "created": obj.get("created", ""),
                "modified": obj.get("modified", ""),
            }

            # Parse pattern to extract observable values
            parsed = self._parse_stix_pattern(pattern)
            indicator["parsed_observables"] = parsed

            indicators.append(indicator)
            self.stats["indicators_extracted"] += 1

        return indicators

    def _parse_stix_pattern(self, pattern: str) -> list:
        """Parse STIX pattern to extract observable values."""
        observables = []

        # Match common STIX patterns
        ip_pattern = re.compile(
            r"ipv[46]-addr:value\s*=\s*'([^']+)'"
        )
        domain_pattern = re.compile(
            r"domain-name:value\s*=\s*'([^']+)'"
        )
        url_pattern = re.compile(
            r"url:value\s*=\s*'([^']+)'"
        )
        hash_pattern = re.compile(
            r"file:hashes\.'([^']+)'\s*=\s*'([^']+)'"
        )
        email_pattern = re.compile(
            r"email-addr:value\s*=\s*'([^']+)'"
        )

        for match in ip_pattern.finditer(pattern):
            observables.append({"type": "ip", "value": match.group(1)})

        for match in domain_pattern.finditer(pattern):
            observables.append({"type": "domain", "value": match.group(1)})

        for match in url_pattern.finditer(pattern):
            observables.append({"type": "url", "value": match.group(1)})

        for match in hash_pattern.finditer(pattern):
            observables.append({
                "type": f"hash-{match.group(1).lower()}",
                "value": match.group(2),
            })

        for match in email_pattern.finditer(pattern):
            observables.append({"type": "email", "value": match.group(1)})

        return observables

    def build_relationship_graph(self, objects: list) -> dict:
        """Build a relationship graph from STIX objects."""
        store = MemoryStore(stix_data=objects)
        relationships = store.query([Filter("type", "=", "relationship")])

        graph = {"nodes": {}, "edges": []}

        for obj in objects:
            if obj.get("type") not in ("relationship", "marking-definition"):
                graph["nodes"][obj.get("id")] = {
                    "type": obj.get("type"),
                    "name": obj.get("name", obj.get("value", obj.get("id"))),
                }

        for rel in relationships:
            graph["edges"].append({
                "source": rel.get("source_ref"),
                "target": rel.get("target_ref"),
                "type": rel.get("relationship_type"),
            })
            self.stats["relationships"] += 1

        return graph

    def export_iocs_csv(self, indicators: list, output_path: str):
        """Export parsed IOCs to CSV."""
        rows = []
        for ind in indicators:
            for obs in ind.get("parsed_observables", []):
                rows.append({
                    "indicator_id": ind["id"],
                    "indicator_name": ind["name"],
                    "observable_type": obs["type"],
                    "observable_value": obs["value"],
                    "confidence": ind["confidence"],
                    "valid_from": ind["valid_from"],
                    "valid_until": ind["valid_until"],
                })

        if rows:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            print(f"[+] Exported {len(rows)} IOCs to {output_path}")
        else:
            print("[-] No IOCs to export")

    def print_stats(self):
        """Print integration statistics."""
        print("\n=== STIX/TAXII Integration Statistics ===")
        for key, value in sorted(self.stats.items()):
            print(f"  {key.replace('_', ' ').title()}: {value}")
        print("=========================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="STIX/TAXII 2.1 Feed Integration Tool"
    )
    parser.add_argument("--server", required=True, help="TAXII server URL")
    parser.add_argument("--user", default="", help="TAXII username")
    parser.add_argument("--password", default="", help="TAXII password")
    parser.add_argument("--discover", action="store_true", help="Discover server")
    parser.add_argument("--collection", help="Collection ID or URL to poll")
    parser.add_argument("--poll", action="store_true", help="Poll for objects")
    parser.add_argument("--extract-iocs", action="store_true", help="Extract IOCs")
    parser.add_argument("--added-after", help="Filter: added after timestamp")
    parser.add_argument("--max-objects", type=int, default=1000, help="Max objects")
    parser.add_argument("--output", default="stix_output.json", help="Output file")
    parser.add_argument("--csv-output", help="CSV output for IOCs")

    args = parser.parse_args()
    integrator = STIXTAXIIIntegrator(args.server, args.user, args.password)

    if args.discover:
        discovery = integrator.discover()
        print(json.dumps(discovery, indent=2))
        with open(args.output, "w") as f:
            json.dump(discovery, f, indent=2)

    elif args.collection and (args.poll or args.extract_iocs):
        # Build collection URL
        if args.collection.startswith("http"):
            collection_url = args.collection
        else:
            collection_url = (
                f"{args.server.rstrip('/')}/stix/collections/{args.collection}/"
            )

        objects = integrator.poll_collection(
            collection_url,
            added_after=args.added_after,
            max_objects=args.max_objects,
        )
        print(f"[+] Fetched {len(objects)} objects")

        if args.extract_iocs:
            indicators = integrator.extract_indicators(objects)
            print(f"[+] Extracted {len(indicators)} indicators")

            if args.csv_output:
                integrator.export_iocs_csv(indicators, args.csv_output)

            with open(args.output, "w") as f:
                json.dump(indicators, f, indent=2, default=str)
        else:
            with open(args.output, "w") as f:
                json.dump(objects, f, indent=2, default=str)

    integrator.print_stats()


if __name__ == "__main__":
    main()
