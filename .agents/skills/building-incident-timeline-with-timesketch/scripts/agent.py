#!/usr/bin/env python3
"""Incident Timeline Builder Agent - Creates forensic timelines using Timesketch API."""

import json
import logging
import argparse
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_session(host, username, password):
    """Authenticate to Timesketch and return session."""
    session = requests.Session()
    resp = session.post(
        f"{host}/login/",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    logger.info("Authenticated to Timesketch as %s", username)
    return session


def list_sketches(session, host):
    """List all sketches."""
    resp = session.get(f"{host}/api/v1/sketches/", timeout=15)
    resp.raise_for_status()
    sketches = resp.json().get("objects", [])
    return [{"id": s["id"], "name": s["name"], "status": s.get("status", [{}])[0].get("status", "unknown"),
             "timelines": len(s.get("timelines", []))} for s in sketches]


def create_sketch(session, host, name, description=""):
    """Create a new sketch."""
    resp = session.post(
        f"{host}/api/v1/sketches/",
        json={"name": name, "description": description},
        timeout=15,
    )
    resp.raise_for_status()
    sketch = resp.json().get("objects", [{}])[0]
    logger.info("Created sketch %s (id=%s)", name, sketch.get("id"))
    return sketch


def upload_timeline(session, host, sketch_id, file_path, timeline_name):
    """Upload a Plaso/CSV/JSONL timeline to a sketch."""
    with open(file_path, "rb") as f:
        resp = session.post(
            f"{host}/api/v1/upload/",
            data={"name": timeline_name, "sketch_id": sketch_id},
            files={"file": (file_path, f)},
            timeout=120,
        )
    resp.raise_for_status()
    logger.info("Uploaded timeline %s to sketch %s", timeline_name, sketch_id)
    return resp.json()


def search_events(session, host, sketch_id, query, time_start=None, time_end=None, max_entries=500):
    """Search events in a sketch using OpenSearch query string."""
    body = {"query": query, "limit": max_entries, "fields": ["datetime", "timestamp_desc", "message", "source_short"]}
    chips = []
    if time_start and time_end:
        chips.append({"type": "datetime_range", "value": f"{time_start},{time_end}", "active": True})
        body["filter"] = {"chips": chips}
    resp = session.post(f"{host}/api/v1/sketches/{sketch_id}/explore/", json=body, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    events = data.get("objects", [])
    meta = data.get("meta", {})
    logger.info("Search returned %d events (total: %s)", len(events), meta.get("total_count", "?"))
    return events, meta


def build_timeline_summary(events):
    """Analyze events to build timeline summary with key milestones."""
    if not events:
        return {"total_events": 0, "sources": {}, "milestones": []}
    sources = {}
    earliest = None
    latest = None
    for evt in events:
        src = evt.get("source_short", "unknown")
        sources[src] = sources.get(src, 0) + 1
        dt = evt.get("datetime", "")
        if dt:
            if earliest is None or dt < earliest:
                earliest = dt
            if latest is None or dt > latest:
                latest = dt
    sorted_events = sorted(events, key=lambda e: e.get("datetime", ""))
    milestones = []
    if sorted_events:
        milestones.append({"type": "first_event", "datetime": sorted_events[0].get("datetime"),
                           "message": sorted_events[0].get("message", "")[:200]})
        milestones.append({"type": "last_event", "datetime": sorted_events[-1].get("datetime"),
                           "message": sorted_events[-1].get("message", "")[:200]})
    return {"total_events": len(events), "time_range": {"start": earliest, "end": latest},
            "sources": sources, "milestones": milestones}


def tag_events(session, host, sketch_id, event_ids, tags):
    """Tag events for annotation."""
    results = []
    for eid in event_ids:
        resp = session.post(
            f"{host}/api/v1/sketches/{sketch_id}/event/annotate/",
            json={"annotation": ",".join(tags), "annotation_type": "tag", "events": {"event_id": eid}},
            timeout=15,
        )
        results.append({"event_id": eid, "status": resp.status_code})
    logger.info("Tagged %d events with %s", len(event_ids), tags)
    return results


def generate_report(sketches, search_results, summary):
    """Generate incident timeline report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "sketches": sketches,
        "search_summary": summary,
        "event_count": summary.get("total_events", 0),
        "source_breakdown": summary.get("sources", {}),
        "milestones": summary.get("milestones", []),
    }
    status = "EVENTS_FOUND" if summary.get("total_events", 0) > 0 else "NO_EVENTS"
    print(f"TIMELINE REPORT: {status}, {summary.get('total_events', 0)} events across {len(summary.get('sources', {}))} sources")
    return report


def main():
    parser = argparse.ArgumentParser(description="Incident Timeline Builder with Timesketch")
    parser.add_argument("--host", required=True, help="Timesketch server URL")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--sketch-id", type=int, help="Existing sketch ID to query")
    parser.add_argument("--query", default="*", help="OpenSearch query string")
    parser.add_argument("--time-start", help="Start time filter (ISO 8601)")
    parser.add_argument("--time-end", help="End time filter (ISO 8601)")
    parser.add_argument("--output", default="timeline_report.json")
    args = parser.parse_args()

    session = get_session(args.host, args.username, args.password)
    sketches = list_sketches(session, args.host)

    search_results = []
    summary = {"total_events": 0, "sources": {}, "milestones": []}
    if args.sketch_id:
        events, meta = search_events(session, args.host, args.sketch_id, args.query, args.time_start, args.time_end)
        search_results = events
        summary = build_timeline_summary(events)

    report = generate_report(sketches, search_results, summary)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
