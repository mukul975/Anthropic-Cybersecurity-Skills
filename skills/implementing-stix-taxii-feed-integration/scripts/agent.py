#!/usr/bin/env python3
"""STIX/TAXII threat intelligence feed integration agent.

Connects to TAXII 2.0/2.1 servers to discover and consume threat intelligence
feeds in STIX format. Extracts indicators of compromise (IOCs), threat actors,
malware families, and attack patterns from STIX bundles.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

try:
    from taxii2client.v20 import Server as Server20, Collection as Collection20
    from taxii2client.v21 import Server as Server21, Collection as Collection21
    HAS_TAXII_CLIENT = True
except ImportError:
    HAS_TAXII_CLIENT = False

try:
    from stix2 import parse as stix_parse
    HAS_STIX2 = True
except ImportError:
    HAS_STIX2 = False

try:
    import requests
except ImportError:
    requests = None


def connect_taxii_server(url, username=None, password=None, version="2.1"):
    """Connect to a TAXII server and return Server object."""
    if not HAS_TAXII_CLIENT:
        print("[!] taxii2-client required: pip install taxii2-client", file=sys.stderr)
        sys.exit(1)

    kwargs = {}
    if username and password:
        kwargs["user"] = username
        kwargs["password"] = password

    print(f"[*] Connecting to TAXII {version} server: {url}")
    if version == "2.0":
        server = Server20(url, **kwargs)
    else:
        server = Server21(url, **kwargs)

    print(f"[+] Connected: {server.title or 'Untitled'}")
    return server


def discover_collections(server, version="2.1"):
    """Discover available collections on the TAXII server."""
    collections = []
    for api_root in server.api_roots:
        print(f"[*] API Root: {api_root.title or api_root.url}")
        for col in api_root.collections:
            col_info = {
                "id": col.id,
                "title": col.title or "Untitled",
                "description": getattr(col, "description", ""),
                "can_read": getattr(col, "can_read", True),
                "can_write": getattr(col, "can_write", False),
                "media_types": getattr(col, "media_types", []),
                "api_root": api_root.title or str(api_root.url),
            }
            collections.append(col_info)
            print(f"    Collection: {col_info['title']} ({col.id})")
    return collections


def fetch_collection_objects(collection, added_after=None, limit=100, obj_type=None):
    """Fetch STIX objects from a TAXII collection."""
    kwargs = {}
    if added_after:
        kwargs["added_after"] = added_after

    print(f"[*] Fetching objects from collection: {collection.title or collection.id}")
    try:
        envelope = collection.get_objects(**kwargs)
    except Exception as e:
        print(f"[!] Error fetching objects: {e}", file=sys.stderr)
        return []

    if isinstance(envelope, dict):
        objects = envelope.get("objects", [])
    elif hasattr(envelope, "objects"):
        objects = envelope.objects or []
    else:
        objects = []

    if obj_type:
        objects = [o for o in objects if o.get("type") == obj_type]

    if limit and len(objects) > limit:
        objects = objects[:limit]

    print(f"[+] Retrieved {len(objects)} object(s)")
    return objects


def extract_indicators(stix_objects):
    """Extract indicators of compromise from STIX objects."""
    indicators = []
    for obj in stix_objects:
        obj_type = obj.get("type", "")
        if obj_type == "indicator":
            indicators.append({
                "type": "indicator",
                "id": obj.get("id", ""),
                "name": obj.get("name", ""),
                "description": obj.get("description", "")[:200],
                "pattern": obj.get("pattern", ""),
                "pattern_type": obj.get("pattern_type", "stix"),
                "valid_from": obj.get("valid_from", ""),
                "valid_until": obj.get("valid_until", ""),
                "labels": obj.get("labels", []),
                "confidence": obj.get("confidence", 0),
                "created": obj.get("created", ""),
            })
    return indicators


def extract_threat_actors(stix_objects):
    """Extract threat actor information from STIX objects."""
    actors = []
    for obj in stix_objects:
        if obj.get("type") == "threat-actor":
            actors.append({
                "type": "threat-actor",
                "id": obj.get("id", ""),
                "name": obj.get("name", ""),
                "description": obj.get("description", "")[:200],
                "aliases": obj.get("aliases", []),
                "roles": obj.get("roles", []),
                "goals": obj.get("goals", []),
                "sophistication": obj.get("sophistication", ""),
                "resource_level": obj.get("resource_level", ""),
                "primary_motivation": obj.get("primary_motivation", ""),
            })
    return actors


def extract_malware(stix_objects):
    """Extract malware family info from STIX objects."""
    malware = []
    for obj in stix_objects:
        if obj.get("type") == "malware":
            malware.append({
                "type": "malware",
                "id": obj.get("id", ""),
                "name": obj.get("name", ""),
                "description": obj.get("description", "")[:200],
                "malware_types": obj.get("malware_types", []),
                "is_family": obj.get("is_family", False),
                "aliases": obj.get("aliases", []),
                "capabilities": obj.get("capabilities", []),
            })
    return malware


def extract_attack_patterns(stix_objects):
    """Extract MITRE ATT&CK patterns from STIX objects."""
    patterns = []
    for obj in stix_objects:
        if obj.get("type") == "attack-pattern":
            external_refs = obj.get("external_references", [])
            mitre_id = ""
            for ref in external_refs:
                if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack"):
                    mitre_id = ref.get("external_id", "")
                    break
            patterns.append({
                "type": "attack-pattern",
                "id": obj.get("id", ""),
                "name": obj.get("name", ""),
                "mitre_id": mitre_id,
                "description": obj.get("description", "")[:200],
                "kill_chain_phases": obj.get("kill_chain_phases", []),
            })
    return patterns


def summarize_stix_objects(stix_objects):
    """Group and count STIX objects by type."""
    type_counts = {}
    for obj in stix_objects:
        t = obj.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    return type_counts


def format_summary(type_counts, indicators, actors, malware, attack_patterns):
    """Print human-readable summary."""
    print(f"\n{'='*60}")
    print("  STIX/TAXII Feed Intelligence Report")
    print(f"{'='*60}")

    print("\n  Object Type Distribution:")
    for obj_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {obj_type:30s}: {count}")

    if indicators:
        print(f"\n  Indicators ({len(indicators)}):")
        for ind in indicators[:10]:
            print(f"    {ind['name'][:40]:40s} | {ind['pattern_type']:8s} | "
                  f"{ind['pattern'][:50]}")

    if actors:
        print(f"\n  Threat Actors ({len(actors)}):")
        for actor in actors[:10]:
            aliases = ", ".join(actor["aliases"][:3]) if actor["aliases"] else ""
            print(f"    {actor['name']:30s} | {actor['sophistication']:12s} | {aliases}")

    if malware:
        print(f"\n  Malware Families ({len(malware)}):")
        for m in malware[:10]:
            types = ", ".join(m["malware_types"][:3]) if m["malware_types"] else ""
            print(f"    {m['name']:30s} | {types}")

    if attack_patterns:
        print(f"\n  ATT&CK Patterns ({len(attack_patterns)}):")
        for ap in attack_patterns[:10]:
            print(f"    {ap.get('mitre_id', 'N/A'):12s} | {ap['name']}")


def main():
    parser = argparse.ArgumentParser(
        description="STIX/TAXII threat intelligence feed integration agent"
    )
    parser.add_argument("--server", required=True, help="TAXII server discovery URL")
    parser.add_argument("--username", help="TAXII authentication username")
    parser.add_argument("--password", help="TAXII authentication password")
    parser.add_argument("--version", choices=["2.0", "2.1"], default="2.1",
                        help="TAXII version (default: 2.1)")
    parser.add_argument("--collection-id", help="Specific collection ID to fetch")
    parser.add_argument("--added-after", help="Only fetch objects added after date (ISO format)")
    parser.add_argument("--type", dest="obj_type",
                        help="Filter by STIX object type (e.g., indicator, malware)")
    parser.add_argument("--limit", type=int, default=500,
                        help="Max objects to retrieve (default: 500)")
    parser.add_argument("--discover-only", action="store_true",
                        help="Only discover collections, don't fetch objects")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    server = connect_taxii_server(args.server, args.username, args.password, args.version)
    collections = discover_collections(server, args.version)

    if args.discover_only:
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "STIX/TAXII Client",
            "server": args.server,
            "collections": collections,
        }
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Report saved to {args.output}")
        else:
            print(json.dumps(report, indent=2))
        return

    # Fetch objects from specified or all readable collections
    all_objects = []
    for col_info in collections:
        if args.collection_id and col_info["id"] != args.collection_id:
            continue
        if not col_info.get("can_read", True):
            continue
        try:
            if args.version == "2.0":
                col = Collection20(
                    f"{args.server.rstrip('/')}/collections/{col_info['id']}/",
                    user=args.username, password=args.password
                )
            else:
                col = Collection21(
                    f"{args.server.rstrip('/')}/collections/{col_info['id']}/",
                    user=args.username, password=args.password
                )
            objects = fetch_collection_objects(col, args.added_after, args.limit, args.obj_type)
            all_objects.extend(objects)
        except Exception as e:
            print(f"[!] Error fetching {col_info['title']}: {e}")

    type_counts = summarize_stix_objects(all_objects)
    indicators = extract_indicators(all_objects)
    actors = extract_threat_actors(all_objects)
    malware_items = extract_malware(all_objects)
    attack_patterns = extract_attack_patterns(all_objects)

    format_summary(type_counts, indicators, actors, malware_items, attack_patterns)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "STIX/TAXII Client",
        "server": args.server,
        "taxii_version": args.version,
        "collections_discovered": len(collections),
        "total_objects": len(all_objects),
        "type_distribution": type_counts,
        "indicators": indicators,
        "threat_actors": actors,
        "malware": malware_items,
        "attack_patterns": attack_patterns,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
