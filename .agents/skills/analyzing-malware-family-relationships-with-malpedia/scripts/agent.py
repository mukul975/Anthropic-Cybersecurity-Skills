#!/usr/bin/env python3
"""Malpedia Malware Family Relationship Agent - Queries Malpedia API for malware family intelligence."""

import json
import logging
import argparse
from datetime import datetime
from collections import defaultdict

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MALPEDIA_API = "https://malpedia.caad.fkie.fraunhofer.de/api"


def malpedia_get(endpoint, api_key):
    """Make authenticated GET request to Malpedia API."""
    headers = {"Authorization": f"apitoken {api_key}"}
    resp = requests.get(f"{MALPEDIA_API}{endpoint}", headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def list_families(api_key):
    """List all malware families from Malpedia."""
    data = malpedia_get("/list/families", api_key)
    logger.info("Retrieved %d malware families", len(data))
    return data


def get_family_info(family_name, api_key):
    """Get detailed info for a malware family."""
    return malpedia_get(f"/get/family/{family_name}", api_key)


def get_family_yara(family_name, api_key):
    """Get YARA rules for a malware family."""
    return malpedia_get(f"/get/yara/{family_name}", api_key)


def list_actors(api_key):
    """List all threat actors from Malpedia."""
    data = malpedia_get("/list/actors", api_key)
    logger.info("Retrieved %d threat actors", len(data))
    return data


def get_actor_info(actor_name, api_key):
    """Get detailed info for a threat actor."""
    return malpedia_get(f"/get/actor/{actor_name}", api_key)


def build_family_graph(families_data):
    """Build relationship graph between malware families."""
    relationships = []
    family_actors = defaultdict(list)

    for family_name, info in families_data.items():
        if not isinstance(info, dict):
            continue
        alt_names = info.get("alt_names", [])
        actors = info.get("attribution", [])
        urls = info.get("urls", [])

        for actor in actors:
            family_actors[actor].append(family_name)

        for alt in alt_names:
            relationships.append({
                "source": family_name,
                "target": alt,
                "relation": "also_known_as",
            })

    for actor, actor_families in family_actors.items():
        if len(actor_families) > 1:
            for i in range(len(actor_families)):
                for j in range(i + 1, len(actor_families)):
                    relationships.append({
                        "source": actor_families[i],
                        "target": actor_families[j],
                        "relation": "shared_actor",
                        "actor": actor,
                    })
    return relationships, dict(family_actors)


def analyze_family(family_name, api_key):
    """Analyze a specific malware family and its relationships."""
    info = get_family_info(family_name, api_key)
    result = {
        "family": family_name,
        "description": info.get("description", ""),
        "alt_names": info.get("alt_names", []),
        "attribution": info.get("attribution", []),
        "urls": info.get("urls", [])[:10],
        "common_name": info.get("common_name", ""),
    }
    try:
        yara_data = get_family_yara(family_name, api_key)
        result["yara_rule_count"] = len(yara_data) if isinstance(yara_data, dict) else 0
    except requests.RequestException:
        result["yara_rule_count"] = 0
    return result


def generate_report(families_analyzed, relationships, actor_map):
    """Generate malware family relationship report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "families_analyzed": len(families_analyzed),
        "relationships_found": len(relationships),
        "actors_mapped": len(actor_map),
        "family_details": families_analyzed,
        "relationships": relationships[:200],
        "actor_family_map": {a: f for a, f in list(actor_map.items())[:50]},
    }
    print(f"MALPEDIA REPORT: {len(families_analyzed)} families, {len(relationships)} relationships, {len(actor_map)} actors")
    return report


def main():
    parser = argparse.ArgumentParser(description="Malpedia Malware Family Analysis Agent")
    parser.add_argument("--api-key", required=True, help="Malpedia API key")
    parser.add_argument("--family", help="Specific family to analyze")
    parser.add_argument("--list-families", action="store_true")
    parser.add_argument("--build-graph", action="store_true", help="Build full relationship graph")
    parser.add_argument("--output", default="malpedia_report.json")
    args = parser.parse_args()

    families_analyzed = []
    relationships = []
    actor_map = {}

    if args.family:
        result = analyze_family(args.family, args.api_key)
        families_analyzed.append(result)
    elif args.build_graph:
        all_families = list_families(args.api_key)
        relationships, actor_map = build_family_graph(all_families)
    elif args.list_families:
        all_families = list_families(args.api_key)
        families_analyzed = [{"family": k, "alt_names": v.get("alt_names", []) if isinstance(v, dict) else []} for k, v in list(all_families.items())[:100]]

    report = generate_report(families_analyzed, relationships, actor_map)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
