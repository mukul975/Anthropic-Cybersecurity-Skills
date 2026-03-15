#!/usr/bin/env python3
"""Diamond Model intrusion analysis agent for structuring adversary activity."""

import argparse
import json
import hashlib
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class Vertex:
    vertex_type: str
    values: List[str] = field(default_factory=list)
    confidence: str = "medium"
    notes: str = ""


@dataclass
class DiamondEvent:
    event_id: str
    timestamp: str
    adversary: Vertex
    capability: Vertex
    infrastructure: Vertex
    victim: Vertex
    phase: str = ""
    direction: str = "external-to-internal"
    result: str = "success"
    meta_notes: str = ""


def create_event(event_data: dict) -> DiamondEvent:
    """Build a DiamondEvent from a raw dict of incident data."""
    return DiamondEvent(
        event_id=event_data.get("event_id", hashlib.md5(
            json.dumps(event_data, sort_keys=True).encode()
        ).hexdigest()[:8]),
        timestamp=event_data.get("timestamp", datetime.utcnow().isoformat()),
        adversary=Vertex(
            vertex_type="adversary",
            values=event_data.get("adversary", []),
            confidence=event_data.get("adversary_confidence", "medium"),
        ),
        capability=Vertex(
            vertex_type="capability",
            values=event_data.get("capabilities", []),
        ),
        infrastructure=Vertex(
            vertex_type="infrastructure",
            values=event_data.get("infrastructure", []),
        ),
        victim=Vertex(
            vertex_type="victim",
            values=event_data.get("victims", []),
        ),
        phase=event_data.get("phase", ""),
        direction=event_data.get("direction", "external-to-internal"),
        result=event_data.get("result", "success"),
    )


def pivot_on_vertex(events: List[DiamondEvent], vertex_type: str, value: str) -> List[DiamondEvent]:
    """Pivot across events sharing a common vertex value."""
    matches = []
    for event in events:
        vertex = getattr(event, vertex_type, None)
        if vertex and value in vertex.values:
            matches.append(event)
    logger.info("Pivot on %s='%s' returned %d events", vertex_type, value, len(matches))
    return matches


def cluster_events(events: List[DiamondEvent]) -> dict:
    """Cluster events by shared infrastructure and capability vertices."""
    infra_map = {}
    cap_map = {}
    for event in events:
        for val in event.infrastructure.values:
            infra_map.setdefault(val, []).append(event.event_id)
        for val in event.capability.values:
            cap_map.setdefault(val, []).append(event.event_id)

    clusters = []
    for key, eids in infra_map.items():
        if len(eids) > 1:
            clusters.append({"pivot": "infrastructure", "value": key, "event_ids": eids})
    for key, eids in cap_map.items():
        if len(eids) > 1:
            clusters.append({"pivot": "capability", "value": key, "event_ids": eids})
    return {"clusters": clusters, "total_events": len(events)}


def build_activity_thread(events: List[DiamondEvent]) -> List[dict]:
    """Order events into a time-sorted activity thread."""
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    thread = []
    for idx, event in enumerate(sorted_events):
        thread.append({
            "sequence": idx + 1,
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "phase": event.phase,
            "adversary": event.adversary.values,
            "capability": event.capability.values,
            "infrastructure": event.infrastructure.values,
            "victim": event.victim.values,
            "result": event.result,
        })
    return thread


def generate_report(events: List[DiamondEvent]) -> dict:
    """Generate a complete Diamond Model analysis report."""
    clusters = cluster_events(events)
    thread = build_activity_thread(events)

    all_adversaries = set()
    all_infra = set()
    all_caps = set()
    for e in events:
        all_adversaries.update(e.adversary.values)
        all_infra.update(e.infrastructure.values)
        all_caps.update(e.capability.values)

    return {
        "report_date": datetime.utcnow().isoformat(),
        "total_events": len(events),
        "unique_adversaries": sorted(all_adversaries),
        "unique_infrastructure": sorted(all_infra),
        "unique_capabilities": sorted(all_caps),
        "activity_thread": thread,
        "clusters": clusters,
    }


def load_events_from_file(filepath: str) -> List[DiamondEvent]:
    """Load raw event data from a JSON file."""
    with open(filepath) as f:
        raw = json.load(f)
    events_data = raw if isinstance(raw, list) else raw.get("events", [])
    return [create_event(e) for e in events_data]


def main():
    parser = argparse.ArgumentParser(description="Diamond Model Analysis Agent")
    parser.add_argument("--input", required=True, help="JSON file with raw event data")
    parser.add_argument("--output", default="diamond_report.json", help="Output report path")
    parser.add_argument("--pivot-type", choices=["adversary", "capability", "infrastructure", "victim"])
    parser.add_argument("--pivot-value", help="Value to pivot on")
    args = parser.parse_args()

    events = load_events_from_file(args.input)
    logger.info("Loaded %d Diamond events", len(events))

    if args.pivot_type and args.pivot_value:
        events = pivot_on_vertex(events, args.pivot_type, args.pivot_value)

    report = generate_report(events)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Diamond Model report saved to %s", args.output)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
