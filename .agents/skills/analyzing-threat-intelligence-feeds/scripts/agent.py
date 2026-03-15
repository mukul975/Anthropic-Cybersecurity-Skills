#!/usr/bin/env python3
"""Agent for analyzing threat intelligence feeds via TAXII 2.1 and STIX 2.1."""

import os
import json
import argparse
from datetime import datetime, timedelta

from taxii2client.v21 import Server, Collection, as_pages
from stix2 import Filter, MemoryStore, Indicator, Relationship, Bundle
from stix2 import ThreatActor, Malware


def discover_taxii_server(url, user=None, password=None):
    """Discover TAXII 2.1 server and list available API roots and collections."""
    server = Server(url, user=user, password=password)
    info = {"title": server.title, "api_roots": []}
    for api_root in server.api_roots:
        root_info = {"title": api_root.title, "collections": []}
        for collection in api_root.collections:
            root_info["collections"].append({
                "id": collection.id,
                "title": collection.title,
                "can_read": collection.can_read,
                "can_write": collection.can_write,
            })
        info["api_roots"].append(root_info)
    return info


def fetch_indicators(collection_url, user=None, password=None, added_after=None):
    """Fetch STIX indicators from a TAXII 2.1 collection."""
    collection = Collection(collection_url, user=user, password=password)
    kwargs = {}
    if added_after:
        kwargs["added_after"] = added_after
    indicators = []
    for bundle_resource in as_pages(collection.get_objects, per_request=50, **kwargs):
        if "objects" in bundle_resource:
            for obj in bundle_resource["objects"]:
                if obj.get("type") == "indicator":
                    indicators.append(obj)
    return indicators


def normalize_to_stix(ioc_value, ioc_type, source_name, confidence=50):
    """Convert a raw IOC into a STIX 2.1 Indicator object."""
    pattern_map = {
        "ipv4": f"[ipv4-addr:value = '{ioc_value}']",
        "domain": f"[domain-name:value = '{ioc_value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{ioc_value}']",
        "url": f"[url:value = '{ioc_value}']",
        "email": f"[email-addr:value = '{ioc_value}']",
    }
    pattern = pattern_map.get(ioc_type)
    if not pattern:
        raise ValueError(f"Unsupported IOC type: {ioc_type}")
    indicator = Indicator(
        name=f"{ioc_type.upper()} indicator: {ioc_value}",
        pattern=pattern,
        pattern_type="stix",
        valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        confidence=confidence,
        created_by_ref="identity--f165a29e-a997-5f8a-a63b-4b72b9f2f963",
        labels=["malicious-activity"],
        external_references=[{
            "source_name": source_name,
            "description": f"IOC from {source_name}",
        }],
    )
    return indicator


def deduplicate_indicators(indicators):
    """Deduplicate indicators by pattern value."""
    seen = set()
    unique = []
    for ind in indicators:
        pattern = ind.get("pattern") if isinstance(ind, dict) else ind.pattern
        if pattern not in seen:
            seen.add(pattern)
            unique.append(ind)
    return unique


def score_feed_quality(indicators, known_good_iocs=None):
    """Score feed quality based on indicator attributes."""
    total = len(indicators)
    if total == 0:
        return {"total": 0, "score": 0}
    with_confidence = sum(1 for i in indicators if i.get("confidence", 0) > 0)
    with_labels = sum(1 for i in indicators if i.get("labels"))
    with_refs = sum(1 for i in indicators if i.get("external_references"))
    freshness = sum(
        1 for i in indicators
        if i.get("valid_from") and
        datetime.fromisoformat(i["valid_from"].replace("Z", "+00:00"))
        > datetime.now(tz=__import__("datetime").timezone.utc) - timedelta(days=90)
    )
    score = int(
        (with_confidence / total * 25) +
        (with_labels / total * 25) +
        (with_refs / total * 25) +
        (freshness / total * 25)
    )
    return {
        "total": total,
        "with_confidence": with_confidence,
        "with_labels": with_labels,
        "with_external_refs": with_refs,
        "fresh_last_90d": freshness,
        "quality_score": score,
    }


def export_stix_bundle(indicators, output_path):
    """Export indicators as a STIX 2.1 bundle JSON file."""
    bundle = Bundle(objects=indicators, allow_custom=True)
    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty=True))
    return output_path


def classify_ioc_type(value):
    """Auto-detect IOC type from value."""
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ipv4"
    elif re.match(r"^[a-fA-F0-9]{64}$", value):
        return "sha256"
    elif re.match(r"^https?://", value):
        return "url"
    elif re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return "email"
    else:
        return "domain"


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Feed Analysis Agent")
    parser.add_argument("--taxii-url", help="TAXII 2.1 server discovery URL")
    parser.add_argument("--collection-url", help="TAXII collection URL to fetch from")
    parser.add_argument("--user", default=os.getenv("TAXII_USER"))
    parser.add_argument("--password", default=os.getenv("TAXII_PASSWORD"))
    parser.add_argument("--added-after", help="Fetch indicators added after (ISO date)")
    parser.add_argument("--ioc-file", help="File with raw IOCs (one per line) to normalize")
    parser.add_argument("--source", default="custom-feed", help="Source name for IOCs")
    parser.add_argument("--output", default="stix_bundle.json", help="Output STIX bundle path")
    parser.add_argument("--action", choices=[
        "discover", "fetch", "normalize", "score", "full_pipeline"
    ], default="full_pipeline")
    args = parser.parse_args()

    if args.action == "discover" and args.taxii_url:
        info = discover_taxii_server(args.taxii_url, args.user, args.password)
        print(json.dumps(info, indent=2))
        return

    if args.action in ("fetch", "full_pipeline") and args.collection_url:
        indicators = fetch_indicators(args.collection_url, args.user, args.password, args.added_after)
        indicators = deduplicate_indicators(indicators)
        quality = score_feed_quality(indicators)
        print(f"[+] Fetched {len(indicators)} unique indicators")
        print(f"[+] Feed quality score: {quality['quality_score']}/100")

    if args.action in ("normalize", "full_pipeline") and args.ioc_file:
        stix_objects = []
        with open(args.ioc_file) as f:
            for line in f:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                ioc_type = classify_ioc_type(value)
                indicator = normalize_to_stix(value, ioc_type, args.source)
                stix_objects.append(indicator)
        path = export_stix_bundle(stix_objects, args.output)
        print(f"[+] Normalized {len(stix_objects)} IOCs -> {path}")


if __name__ == "__main__":
    main()
