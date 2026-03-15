#!/usr/bin/env python3
"""STIX/TAXII threat intelligence feed processor using taxii2-client and stix2."""

import json
import sys
from datetime import datetime, timedelta

try:
    from taxii2client.v21 import Server, Collection, as_pages
    from stix2 import parse as stix_parse, Bundle, Indicator, Malware, ThreatActor
    from stix2 import AttackPattern, Relationship, Identity, Campaign
    from stix2.exceptions import InvalidValueError
except ImportError:
    print("Install: pip install taxii2-client stix2")
    sys.exit(1)


def discover_server(taxii_url, user=None, password=None):
    """Discover TAXII server API roots and collections."""
    kwargs = {}
    if user and password:
        kwargs["user"] = user
        kwargs["password"] = password
    server = Server(taxii_url, **kwargs)
    roots = []
    for api_root in server.api_roots:
        collections = []
        for coll in api_root.collections:
            collections.append({
                "id": coll.id,
                "title": coll.title,
                "can_read": coll.can_read,
                "can_write": coll.can_write,
                "media_types": getattr(coll, "media_types", []),
            })
        roots.append({
            "title": api_root.title,
            "url": api_root.url,
            "collections": collections,
        })
    return {"server": taxii_url, "api_roots": roots}


def fetch_collection(taxii_url, collection_id, user=None, password=None,
                     added_after=None, limit=100):
    """Fetch STIX objects from a TAXII collection with pagination."""
    kwargs = {}
    if user and password:
        kwargs["user"] = user
        kwargs["password"] = password
    server = Server(taxii_url, **kwargs)
    collection = None
    for api_root in server.api_roots:
        for coll in api_root.collections:
            if coll.id == collection_id:
                collection = coll
                break
    if not collection:
        return {"error": f"Collection {collection_id} not found"}
    fetch_kwargs = {}
    if added_after:
        fetch_kwargs["added_after"] = added_after
    objects = []
    for bundle in as_pages(collection.get_objects, per_request=limit, **fetch_kwargs):
        if "objects" in bundle:
            objects.extend(bundle["objects"])
    return {
        "collection_id": collection_id,
        "total_objects": len(objects),
        "objects": objects,
    }


def parse_stix_bundle(bundle_data):
    """Parse and validate a STIX 2.1 bundle, categorizing objects by type."""
    if isinstance(bundle_data, str):
        bundle_data = json.loads(bundle_data)
    categories = {
        "indicators": [], "malware": [], "threat_actors": [],
        "attack_patterns": [], "campaigns": [], "relationships": [],
        "identities": [], "other": [],
    }
    errors = []
    for obj in bundle_data.get("objects", []):
        obj_type = obj.get("type", "unknown")
        try:
            parsed = stix_parse(obj, allow_custom=True)
            if obj_type == "indicator":
                categories["indicators"].append({
                    "id": parsed.id,
                    "name": getattr(parsed, "name", ""),
                    "pattern": parsed.pattern,
                    "pattern_type": parsed.pattern_type,
                    "valid_from": str(parsed.valid_from),
                    "labels": getattr(parsed, "labels", []),
                })
            elif obj_type == "malware":
                categories["malware"].append({
                    "id": parsed.id,
                    "name": parsed.name,
                    "is_family": parsed.is_family,
                    "malware_types": getattr(parsed, "malware_types", []),
                })
            elif obj_type == "threat-actor":
                categories["threat_actors"].append({
                    "id": parsed.id,
                    "name": parsed.name,
                    "threat_actor_types": getattr(parsed, "threat_actor_types", []),
                    "aliases": getattr(parsed, "aliases", []),
                })
            elif obj_type == "attack-pattern":
                categories["attack_patterns"].append({
                    "id": parsed.id,
                    "name": parsed.name,
                    "external_references": [
                        {"source": r.get("source_name"), "id": r.get("external_id")}
                        for r in getattr(parsed, "external_references", [])
                        if isinstance(r, dict)
                    ],
                })
            elif obj_type == "campaign":
                categories["campaigns"].append({
                    "id": parsed.id,
                    "name": parsed.name,
                    "first_seen": str(getattr(parsed, "first_seen", "")),
                })
            elif obj_type == "relationship":
                categories["relationships"].append({
                    "id": parsed.id,
                    "type": parsed.relationship_type,
                    "source": parsed.source_ref,
                    "target": parsed.target_ref,
                })
            elif obj_type == "identity":
                categories["identities"].append({
                    "id": parsed.id,
                    "name": parsed.name,
                })
            else:
                categories["other"].append({"id": obj.get("id"), "type": obj_type})
        except (InvalidValueError, Exception) as e:
            errors.append({"object_id": obj.get("id"), "error": str(e)})
    return {"categories": categories, "parse_errors": errors}


def extract_iocs(parsed_bundle):
    """Extract actionable IOCs from parsed STIX indicators."""
    iocs = {"ipv4": [], "ipv6": [], "domain": [], "url": [], "hash_md5": [],
            "hash_sha1": [], "hash_sha256": [], "email": []}
    for indicator in parsed_bundle["categories"]["indicators"]:
        pattern = indicator.get("pattern", "")
        import re
        ipv4 = re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        iocs["ipv4"].extend(ipv4)
        domains = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        iocs["domain"].extend(domains)
        urls = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)
        iocs["url"].extend(urls)
        md5 = re.findall(r"MD5\s*=\s*'([a-fA-F0-9]{32})'", pattern)
        iocs["hash_md5"].extend(md5)
        sha256 = re.findall(r"SHA-256\s*=\s*'([a-fA-F0-9]{64})'", pattern)
        iocs["hash_sha256"].extend(sha256)
    for key in iocs:
        iocs[key] = list(set(iocs[key]))
    return iocs


def build_relationship_graph(parsed_bundle):
    """Map relationships between STIX objects."""
    graph = {}
    all_objects = {}
    for cat_name, objects in parsed_bundle["categories"].items():
        for obj in objects:
            if "id" in obj:
                all_objects[obj["id"]] = {"type": cat_name, "name": obj.get("name", obj["id"])}
    for rel in parsed_bundle["categories"]["relationships"]:
        src = rel["source"]
        tgt = rel["target"]
        src_name = all_objects.get(src, {}).get("name", src)
        tgt_name = all_objects.get(tgt, {}).get("name", tgt)
        graph.setdefault(src_name, []).append({
            "relationship": rel["type"], "target": tgt_name,
        })
    return graph


def print_report(parsed, iocs):
    print("STIX/TAXII Feed Processing Report")
    print("=" * 50)
    cats = parsed["categories"]
    print(f"Indicators:      {len(cats['indicators'])}")
    print(f"Malware:         {len(cats['malware'])}")
    print(f"Threat Actors:   {len(cats['threat_actors'])}")
    print(f"Attack Patterns: {len(cats['attack_patterns'])}")
    print(f"Campaigns:       {len(cats['campaigns'])}")
    print(f"Relationships:   {len(cats['relationships'])}")
    print(f"Parse Errors:    {len(parsed['parse_errors'])}")
    print(f"\nExtracted IOCs:")
    for ioc_type, values in iocs.items():
        if values:
            print(f"  {ioc_type}: {len(values)}")
            for v in values[:5]:
                print(f"    - {v}")


if __name__ == "__main__":
    taxii_url = sys.argv[1] if len(sys.argv) > 1 else "https://cti.example.com/taxii/"
    user = os.environ.get("TAXII_USER") if "os" in dir() else None
    import os
    user = os.environ.get("TAXII_USER")
    password = os.environ.get("TAXII_PASSWORD")
    print(f"Discovering TAXII server: {taxii_url}")
    discovery = discover_server(taxii_url, user, password)
    print(json.dumps(discovery, indent=2, default=str))
