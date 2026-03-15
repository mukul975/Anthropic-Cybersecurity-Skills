#!/usr/bin/env python3
"""Threat campaign correlation agent using MISP and STIX."""

import json
import sys
import urllib.request
import urllib.parse
import ssl
from collections import Counter
from datetime import datetime
from math import radians, sin, cos, sqrt, atan2


class MISPClient:
    """Client for MISP REST API for campaign correlation."""

    def __init__(self, url, api_key, verify_ssl=False):
        self.base_url = url.rstrip("/")
        self.headers = {
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.ctx = ssl.create_default_context()
        if not verify_ssl:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method, path, data=None):
        url = f"{self.base_url}{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def search_attributes(self, attr_type, value):
        """Search MISP for attributes matching type and value."""
        data = {"type": attr_type, "value": value, "searchall": 1}
        return self._request("POST", "/attributes/restSearch", data)

    def search_events(self, tags=None, date_from=None, date_to=None):
        """Search MISP events with filters."""
        data = {}
        if tags:
            data["tags"] = tags
        if date_from:
            data["from"] = date_from
        if date_to:
            data["to"] = date_to
        return self._request("POST", "/events/restSearch", data)

    def get_event(self, event_id):
        """Get full event details by ID."""
        return self._request("GET", f"/events/view/{event_id}")

    def get_correlations(self, event_id):
        """Retrieve correlation data for a MISP event."""
        event = self.get_event(event_id)
        if "error" in event:
            return event
        correlations = []
        ev = event.get("Event", event)
        for attr in ev.get("Attribute", []):
            if attr.get("RelatedAttribute"):
                for rel in attr["RelatedAttribute"]:
                    correlations.append({
                        "source_event": event_id,
                        "source_attr": attr.get("value"),
                        "source_type": attr.get("type"),
                        "related_event": rel.get("event_id"),
                        "related_value": rel.get("value"),
                    })
        return correlations


def calculate_campaign_confidence(events):
    """Calculate campaign attribution confidence from correlated events."""
    if not events or len(events) < 2:
        return {"confidence": "LOW", "score": 0, "reason": "Insufficient events"}

    all_ips = []
    all_domains = []
    all_hashes = []
    all_tags = []

    for event in events:
        ev = event.get("Event", event)
        for attr in ev.get("Attribute", []):
            atype = attr.get("type", "")
            val = attr.get("value", "")
            if atype in ("ip-src", "ip-dst"):
                all_ips.append(val)
            elif atype in ("domain", "hostname"):
                all_domains.append(val)
            elif "hash" in atype or "md5" in atype or "sha" in atype:
                all_hashes.append(val)
        for tag in ev.get("Tag", []):
            all_tags.append(tag.get("name", ""))

    ip_counts = Counter(all_ips)
    domain_counts = Counter(all_domains)
    hash_counts = Counter(all_hashes)

    shared_ips = sum(1 for c in ip_counts.values() if c > 1)
    shared_domains = sum(1 for c in domain_counts.values() if c > 1)
    shared_hashes = sum(1 for c in hash_counts.values() if c > 1)

    num_events = len(events)
    infra_score = min(40, (shared_ips + shared_domains) / max(num_events, 1) * 40)
    capability_score = min(35, shared_hashes / max(num_events, 1) * 35)
    tag_overlap = len(set(all_tags)) / max(len(all_tags), 1)
    ttp_score = min(15, tag_overlap * 15)

    total = infra_score + capability_score + ttp_score
    if total >= 70:
        confidence = "HIGH"
    elif total >= 45:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "confidence": confidence,
        "score": round(total, 1),
        "shared_infrastructure": {"ips": shared_ips, "domains": shared_domains},
        "shared_capabilities": {"hashes": shared_hashes},
        "events_analyzed": num_events,
    }


def extract_campaign_iocs(events):
    """Extract shared IOCs across correlated events for blocking."""
    ioc_events = {}
    for event in events:
        ev = event.get("Event", event)
        eid = ev.get("id", "unknown")
        for attr in ev.get("Attribute", []):
            val = attr.get("value", "")
            atype = attr.get("type", "")
            key = f"{atype}:{val}"
            if key not in ioc_events:
                ioc_events[key] = []
            ioc_events[key].append(eid)

    shared = {k: v for k, v in ioc_events.items() if len(v) > 1}
    return {
        "total_unique_iocs": len(ioc_events),
        "shared_iocs": len(shared),
        "shared_indicators": [
            {"type": k.split(":")[0], "value": ":".join(k.split(":")[1:]), "event_count": len(v)}
            for k, v in sorted(shared.items(), key=lambda x: len(x[1]), reverse=True)
        ][:50],
    }


def build_campaign_report(campaign_name, events, attribution=None):
    """Build a structured campaign intelligence report."""
    confidence = calculate_campaign_confidence(events)
    iocs = extract_campaign_iocs(events)

    dates = []
    targets = []
    for event in events:
        ev = event.get("Event", event)
        if ev.get("date"):
            dates.append(ev["date"])
        info = ev.get("info", "")
        if info:
            targets.append(info)

    return {
        "campaign_name": campaign_name,
        "report_date": datetime.utcnow().isoformat() + "Z",
        "timeline": {"first_seen": min(dates) if dates else None, "last_seen": max(dates) if dates else None},
        "attribution": attribution or "Unattributed",
        "confidence": confidence,
        "shared_indicators": iocs,
        "events_correlated": len(events),
        "target_summary": targets[:10],
    }


if __name__ == "__main__":
    import os
    misp_url = os.environ.get("MISP_URL", "https://misp.example.com")
    misp_key = os.environ.get("MISP_KEY", "")

    action = sys.argv[1] if len(sys.argv) > 1 else "help"
    if action == "search" and len(sys.argv) > 3:
        client = MISPClient(misp_url, misp_key)
        result = client.search_attributes(sys.argv[2], sys.argv[3])
        print(json.dumps(result, indent=2, default=str))
    elif action == "correlations" and len(sys.argv) > 2:
        client = MISPClient(misp_url, misp_key)
        result = client.get_correlations(sys.argv[2])
        print(json.dumps(result, indent=2, default=str))
    elif action == "events":
        client = MISPClient(misp_url, misp_key)
        tags = sys.argv[2] if len(sys.argv) > 2 else None
        result = client.search_events(tags=tags)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: agent.py [search <type> <value>|correlations <event_id>|events [tag]]")
        print("Env: MISP_URL, MISP_KEY")
