#!/usr/bin/env python3
"""MISP Threat Landscape Analysis Agent - Generates threat landscape reports from MISP event data."""

import json
import logging
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from pymisp import PyMISP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

THREAT_LEVELS = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
ANALYSIS_LEVELS = {0: "Initial", 1: "Ongoing", 2: "Completed"}

MITRE_TAG_PREFIX = "misp-galaxy:mitre-attack-pattern="
THREAT_ACTOR_PREFIX = "misp-galaxy:threat-actor="
MALWARE_PREFIX = "misp-galaxy:malpedia="


def connect_misp(url, api_key, ssl=True):
    """Connect to MISP instance."""
    misp = PyMISP(url, api_key, ssl=ssl)
    logger.info("Connected to MISP: %s", url)
    return misp


def fetch_events(misp, days=90):
    """Fetch events from the last N days."""
    date_from = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    events = misp.search(date_from=date_from, pythonify=True)
    logger.info("Fetched %d events from last %d days", len(events), days)
    return events


def analyze_threat_levels(events):
    """Break down events by threat level."""
    counter = Counter()
    for event in events:
        level = getattr(event, "threat_level_id", 4)
        counter[THREAT_LEVELS.get(int(level), "Undefined")] += 1
    total = sum(counter.values()) or 1
    return {level: {"count": count, "percent": round(count / total * 100, 1)} for level, count in counter.most_common()}


def analyze_attribute_types(events):
    """Analyze distribution of attribute types across events."""
    counter = Counter()
    for event in events:
        for attr in getattr(event, "Attribute", []):
            counter[attr.type] += 1
    total = sum(counter.values()) or 1
    return {
        atype: {"count": count, "percent": round(count / total * 100, 1)}
        for atype, count in counter.most_common(20)
    }


def extract_tags(events):
    """Extract and categorize tags from events."""
    mitre_techniques = Counter()
    threat_actors = Counter()
    malware_families = Counter()
    all_tags = Counter()

    for event in events:
        for tag in getattr(event, "Tag", []):
            tag_name = tag.name
            all_tags[tag_name] += 1
            if tag_name.startswith(MITRE_TAG_PREFIX):
                technique = tag_name[len(MITRE_TAG_PREFIX):].strip('"').strip("'")
                mitre_techniques[technique] += 1
            elif tag_name.startswith(THREAT_ACTOR_PREFIX):
                actor = tag_name[len(THREAT_ACTOR_PREFIX):].strip('"').strip("'")
                threat_actors[actor] += 1
            elif tag_name.startswith(MALWARE_PREFIX):
                malware = tag_name[len(MALWARE_PREFIX):].strip('"').strip("'")
                malware_families[malware] += 1

    return {
        "mitre_techniques": dict(mitre_techniques.most_common(20)),
        "threat_actors": dict(threat_actors.most_common(20)),
        "malware_families": dict(malware_families.most_common(20)),
        "top_tags": dict(all_tags.most_common(30)),
    }


def analyze_temporal_trends(events, days=90):
    """Analyze event creation trends over time (weekly buckets)."""
    buckets = defaultdict(int)
    for event in events:
        event_date = getattr(event, "date", None)
        if event_date:
            if isinstance(event_date, str):
                event_date = datetime.strptime(event_date, "%Y-%m-%d")
            week_start = event_date - timedelta(days=event_date.weekday())
            buckets[week_start.strftime("%Y-%m-%d")] += 1
    return dict(sorted(buckets.items()))


def analyze_organizations(events):
    """Analyze contributing organizations."""
    org_counter = Counter()
    for event in events:
        org = getattr(event, "Orgc", None)
        if org:
            org_name = getattr(org, "name", "Unknown")
            org_counter[org_name] += 1
    return dict(org_counter.most_common(20))


def compute_ioc_stats(events):
    """Compute IOC statistics: total count, unique values, categories."""
    ioc_values = set()
    category_counter = Counter()
    for event in events:
        for attr in getattr(event, "Attribute", []):
            ioc_values.add(attr.value)
            category_counter[attr.category] += 1
    return {
        "total_attributes": sum(category_counter.values()),
        "unique_values": len(ioc_values),
        "categories": dict(category_counter.most_common(15)),
    }


def generate_report(events, threat_levels, attr_types, tags, trends, orgs, ioc_stats, days):
    """Generate threat landscape report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "period_days": days,
        "total_events": len(events),
        "threat_level_distribution": threat_levels,
        "attribute_type_distribution": attr_types,
        "ioc_statistics": ioc_stats,
        "mitre_attack_techniques": tags["mitre_techniques"],
        "top_threat_actors": tags["threat_actors"],
        "top_malware_families": tags["malware_families"],
        "temporal_trends": trends,
        "contributing_organizations": orgs,
    }
    high_pct = threat_levels.get("High", {}).get("percent", 0)
    top_technique = next(iter(tags["mitre_techniques"]), "N/A")
    top_actor = next(iter(tags["threat_actors"]), "N/A")
    print(f"THREAT LANDSCAPE: {len(events)} events, {high_pct}% high severity, top technique: {top_technique}, top actor: {top_actor}")
    return report


def main():
    parser = argparse.ArgumentParser(description="MISP Threat Landscape Analysis Agent")
    parser.add_argument("--misp-url", required=True, help="MISP instance URL")
    parser.add_argument("--api-key", required=True, help="MISP API key")
    parser.add_argument("--days", type=int, default=90, help="Analysis period in days")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--output", default="landscape_report.json")
    args = parser.parse_args()

    misp = connect_misp(args.misp_url, args.api_key, ssl=not args.no_ssl)
    events = fetch_events(misp, args.days)

    threat_levels = analyze_threat_levels(events)
    attr_types = analyze_attribute_types(events)
    tags = extract_tags(events)
    trends = analyze_temporal_trends(events, args.days)
    orgs = analyze_organizations(events)
    ioc_stats = compute_ioc_stats(events)

    report = generate_report(events, threat_levels, attr_types, tags, trends, orgs, ioc_stats, args.days)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
