#!/usr/bin/env python3
"""Threat Feed Aggregation Agent - Aggregates and correlates threat intelligence feeds using MISP."""

import json
import logging
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def misp_request(url, key, endpoint, method="GET", data=None):
    """Make authenticated MISP API request."""
    headers = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}
    full_url = f"{url}/{endpoint}"
    try:
        if method == "GET":
            resp = requests.get(full_url, headers=headers, timeout=30, verify=False)
        else:
            resp = requests.post(full_url, headers=headers, json=data or {}, timeout=30, verify=False)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.error("MISP request failed: %s", e)
        return {"error": str(e)}


def list_feeds(url, key):
    """List configured MISP feeds."""
    data = misp_request(url, key, "feeds/index", method="POST")
    feeds = data if isinstance(data, list) else data.get("Feed", [])
    result = []
    for feed in feeds:
        f = feed.get("Feed", feed) if isinstance(feed, dict) and "Feed" in feed else feed
        result.append({"id": f.get("id"), "name": f.get("name"), "provider": f.get("provider"),
                       "url": f.get("url"), "enabled": f.get("enabled"), "source_format": f.get("source_format"),
                       "caching_enabled": f.get("caching_enabled")})
    logger.info("Found %d configured feeds", len(result))
    return result


def fetch_feed_data(url, key, feed_id):
    """Fetch and cache data from a specific feed."""
    result = misp_request(url, key, f"feeds/cacheFeeds/{feed_id}", method="POST")
    logger.info("Cached feed %s", feed_id)
    return result


def search_attributes(url, key, attr_type=None, value=None, last_days=30):
    """Search MISP attributes across all events."""
    search_body = {"returnFormat": "json", "limit": 1000, "last": f"{last_days}d"}
    if attr_type:
        search_body["type"] = attr_type
    if value:
        search_body["value"] = value
    data = misp_request(url, key, "attributes/restSearch", method="POST", data=search_body)
    attributes = data.get("response", {}).get("Attribute", [])
    logger.info("Found %d attributes (type=%s, last %dd)", len(attributes), attr_type, last_days)
    return attributes


def aggregate_feed_statistics(url, key, last_days=30):
    """Aggregate statistics across all feeds."""
    events_data = misp_request(url, key, "events/restSearch", method="POST",
                                data={"returnFormat": "json", "limit": 500, "last": f"{last_days}d"})
    events = events_data.get("response", [])
    stats = {"total_events": len(events), "by_threat_level": defaultdict(int),
             "by_org": defaultdict(int), "by_tag": defaultdict(int), "attribute_types": defaultdict(int)}
    threat_levels = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}
    for event_wrap in events:
        event = event_wrap.get("Event", event_wrap)
        tl = threat_levels.get(str(event.get("threat_level_id", 4)), "Undefined")
        stats["by_threat_level"][tl] += 1
        org = event.get("Orgc", {}).get("name", "Unknown")
        stats["by_org"][org] += 1
        for tag in event.get("Tag", []):
            stats["by_tag"][tag.get("name", "")] += 1
        for attr in event.get("Attribute", []):
            stats["attribute_types"][attr.get("type", "unknown")] += 1
    return {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}


def correlate_across_feeds(url, key, ioc_value):
    """Correlate an IOC across all feed events."""
    data = misp_request(url, key, "attributes/restSearch", method="POST",
                        data={"returnFormat": "json", "value": ioc_value, "limit": 100})
    attributes = data.get("response", {}).get("Attribute", [])
    correlations = []
    seen_events = set()
    for attr in attributes:
        event_id = attr.get("event_id")
        if event_id not in seen_events:
            seen_events.add(event_id)
            correlations.append({"event_id": event_id, "type": attr.get("type"), "category": attr.get("category"),
                                 "comment": attr.get("comment", "")[:100]})
    logger.info("IOC '%s' found in %d events", ioc_value, len(correlations))
    return correlations


def assess_feed_health(feeds):
    """Assess health and coverage of configured feeds."""
    total = len(feeds)
    enabled = sum(1 for f in feeds if f.get("enabled"))
    cached = sum(1 for f in feeds if f.get("caching_enabled"))
    return {"total_feeds": total, "enabled": enabled, "disabled": total - enabled,
            "caching_enabled": cached, "health_score": round(enabled / total * 100, 1) if total else 0}


def generate_report(feeds, stats, feed_health):
    """Generate threat feed aggregation report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "feed_inventory": feeds,
        "feed_health": feed_health,
        "aggregated_statistics": stats,
    }
    print(f"FEED REPORT: {feed_health['total_feeds']} feeds, {feed_health['enabled']} enabled, "
          f"{stats.get('total_events', 0)} events")
    return report


def main():
    parser = argparse.ArgumentParser(description="Threat Feed Aggregation with MISP")
    parser.add_argument("--url", required=True, help="MISP instance URL")
    parser.add_argument("--key", required=True, help="MISP API key")
    parser.add_argument("--days", type=int, default=30, help="Look-back period in days")
    parser.add_argument("--correlate", help="IOC value to correlate across feeds")
    parser.add_argument("--output", default="feed_aggregation_report.json")
    args = parser.parse_args()

    feeds = list_feeds(args.url, args.key)
    stats = aggregate_feed_statistics(args.url, args.key, args.days)
    feed_health = assess_feed_health(feeds)
    report = generate_report(feeds, stats, feed_health)
    if args.correlate:
        report["correlation_results"] = correlate_across_feeds(args.url, args.key, args.correlate)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
