#!/usr/bin/env python3
"""Threat intelligence collection agent using MISP/PyMISP.

Connects to MISP instances to collect, filter, and export threat intelligence
including events, attributes, and feeds via the PyMISP REST API client.
"""

import sys
import json
import os
import datetime

try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
    HAS_PYMISP = True
except ImportError:
    HAS_PYMISP = False


def init_misp(url=None, key=None):
    """Initialize PyMISP client."""
    url = url or os.environ.get("MISP_URL", "https://misp.example.org")
    key = key or os.environ.get("MISP_API_KEY", "")
    if not HAS_PYMISP:
        return None
    return PyMISP(url, key, ssl=True)


def search_events(misp, tags=None, date_from=None, published=True, limit=50):
    """Search MISP events by tags and date."""
    if not misp:
        return {"error": "PyMISP not available"}
    kwargs = {"limit": limit, "published": published, "pythonify": True}
    if tags:
        kwargs["tags"] = tags
    if date_from:
        kwargs["date_from"] = date_from
    try:
        events = misp.search("events", **kwargs)
        return [
            {
                "id": e.id,
                "uuid": e.uuid,
                "info": e.info,
                "date": str(e.date),
                "threat_level": {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}.get(e.threat_level_id, "?"),
                "analysis": {0: "Initial", 1: "Ongoing", 2: "Complete"}.get(e.analysis, "?"),
                "attribute_count": e.attribute_count,
                "org": e.Orgc.name if hasattr(e, "Orgc") and e.Orgc else "",
                "tags": [t.name for t in (e.tags or [])],
            }
            for e in events
        ]
    except Exception as e:
        return {"error": str(e)}


def extract_attributes(misp, event_id, attr_type=None):
    """Extract attributes from a MISP event."""
    if not misp:
        return {"error": "PyMISP not available"}
    try:
        kwargs = {"eventid": event_id, "pythonify": True}
        if attr_type:
            kwargs["type_attribute"] = attr_type
        attrs = misp.search("attributes", **kwargs)
        return [
            {
                "type": a.type,
                "value": a.value,
                "category": a.category,
                "to_ids": a.to_ids,
                "comment": a.comment or "",
                "timestamp": str(datetime.datetime.fromtimestamp(int(a.timestamp))),
            }
            for a in attrs
        ]
    except Exception as e:
        return {"error": str(e)}


def collect_iocs_by_type(misp, ioc_types, date_from=None, limit=500):
    """Collect IOCs filtered by attribute type."""
    if not misp:
        return {"error": "PyMISP not available"}
    results = {}
    for ioc_type in ioc_types:
        try:
            kwargs = {"type_attribute": ioc_type, "to_ids": True, "pythonify": True, "limit": limit}
            if date_from:
                kwargs["date_from"] = date_from
            attrs = misp.search("attributes", **kwargs)
            results[ioc_type] = [
                {"value": a.value, "event_id": a.event_id, "comment": a.comment or ""}
                for a in attrs
            ]
        except Exception as e:
            results[ioc_type] = {"error": str(e)}
    return results


def list_feeds(misp):
    """List configured MISP feeds."""
    if not misp:
        return {"error": "PyMISP not available"}
    try:
        feeds = misp.feeds()
        return [
            {
                "id": f["Feed"]["id"],
                "name": f["Feed"]["name"],
                "provider": f["Feed"]["provider"],
                "url": f["Feed"]["url"],
                "enabled": f["Feed"]["enabled"],
                "source_format": f["Feed"]["source_format"],
            }
            for f in feeds
        ]
    except Exception as e:
        return {"error": str(e)}


def export_stix2(misp, event_id):
    """Export MISP event as STIX 2.1 bundle."""
    if not misp:
        return {"error": "PyMISP not available"}
    try:
        stix_data = misp.get_stix_event(event_id)
        return stix_data
    except Exception as e:
        return {"error": str(e)}


COMMON_IOC_TYPES = [
    "ip-dst", "ip-src", "domain", "hostname", "url",
    "md5", "sha1", "sha256", "email-src", "filename",
]


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Intelligence Collection with MISP")
    print("PyMISP REST client, event search, attribute extraction, feeds")
    print("=" * 60)
    print("  PyMISP available: {}".format(HAS_PYMISP))

    misp = init_misp() if HAS_PYMISP else None

    if not misp:
        print("\n[DEMO] No MISP connection. Showing IOC types and feed structure.")
        print("\n--- Common IOC Types ---")
        for t in COMMON_IOC_TYPES:
            print("  - {}".format(t))
        print("\n--- Usage ---")
        print("  Set MISP_URL and MISP_API_KEY environment variables")
        print("  python agent.py")
    else:
        print("\n[*] Searching recent events...")
        events = search_events(misp, date_from="7d")
        if isinstance(events, list):
            print("  Found {} events".format(len(events)))
            for e in events[:5]:
                print("    [{}] {} ({} attrs)".format(e["id"], e["info"][:60], e["attribute_count"]))
        else:
            print("  Error: {}".format(events))

        feeds = list_feeds(misp)
        if isinstance(feeds, list):
            print("\n--- Feeds ({}) ---".format(len(feeds)))
            for f in feeds[:10]:
                status = "enabled" if f["enabled"] else "disabled"
                print("  [{}] {} ({})".format(f["id"], f["name"], status))

    print("\n" + json.dumps({"pymisp_available": HAS_PYMISP}, indent=2))
