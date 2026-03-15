#!/usr/bin/env python3
"""Diamond Model intrusion analysis agent for structuring threat intelligence events."""

import argparse
import json
import logging
import os
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class DiamondEvent:
    """A Diamond Model event with four core vertices."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = ""
    adversary: str = ""
    capability: str = ""
    infrastructure: str = ""
    victim: str = ""
    phase: str = ""
    result: str = ""
    direction: str = ""
    methodology: str = ""
    confidence: str = "medium"
    notes: str = ""


def create_event(adversary: str, capability: str, infrastructure: str,
                 victim: str, **kwargs) -> DiamondEvent:
    """Create a Diamond Model event from the four vertices."""
    return DiamondEvent(
        adversary=adversary, capability=capability,
        infrastructure=infrastructure, victim=victim,
        timestamp=datetime.utcnow().isoformat(), **kwargs)


def load_events(data_path: str) -> List[DiamondEvent]:
    """Load Diamond Model events from JSON file."""
    with open(data_path) as f:
        data = json.load(f)
    events = []
    for item in data.get("events", []):
        events.append(DiamondEvent(**{k: v for k, v in item.items()
                                      if k in DiamondEvent.__dataclass_fields__}))
    return events


def pivot_on_vertex(events: List[DiamondEvent], vertex: str, value: str) -> List[DiamondEvent]:
    """Pivot analysis: find all events sharing a vertex value."""
    return [e for e in events if getattr(e, vertex, "") == value]


def build_activity_thread(events: List[DiamondEvent], adversary: str) -> dict:
    """Build an activity thread for an adversary across events."""
    thread_events = [e for e in events if e.adversary == adversary]
    thread_events.sort(key=lambda e: e.timestamp)
    return {
        "adversary": adversary,
        "event_count": len(thread_events),
        "first_seen": thread_events[0].timestamp if thread_events else "",
        "last_seen": thread_events[-1].timestamp if thread_events else "",
        "capabilities_used": list({e.capability for e in thread_events if e.capability}),
        "infrastructure_used": list({e.infrastructure for e in thread_events if e.infrastructure}),
        "victims_targeted": list({e.victim for e in thread_events if e.victim}),
        "phases": [e.phase for e in thread_events if e.phase],
    }


def cluster_by_infrastructure(events: List[DiamondEvent]) -> Dict[str, List[str]]:
    """Cluster events by shared infrastructure to identify campaigns."""
    clusters = {}
    for e in events:
        if e.infrastructure:
            clusters.setdefault(e.infrastructure, []).append(e.event_id)
    return clusters


def compute_vertex_statistics(events: List[DiamondEvent]) -> dict:
    """Compute statistics across all Diamond Model vertices."""
    return {
        "total_events": len(events),
        "unique_adversaries": len({e.adversary for e in events if e.adversary}),
        "unique_capabilities": len({e.capability for e in events if e.capability}),
        "unique_infrastructure": len({e.infrastructure for e in events if e.infrastructure}),
        "unique_victims": len({e.victim for e in events if e.victim}),
        "confidence_distribution": {
            "high": sum(1 for e in events if e.confidence == "high"),
            "medium": sum(1 for e in events if e.confidence == "medium"),
            "low": sum(1 for e in events if e.confidence == "low"),
        },
    }


def generate_report(data_path: str) -> dict:
    """Generate Diamond Model analysis report."""
    events = load_events(data_path)
    stats = compute_vertex_statistics(events)
    adversaries = {e.adversary for e in events if e.adversary}
    threads = [build_activity_thread(events, adv) for adv in adversaries]
    clusters = cluster_by_infrastructure(events)
    return {
        "analysis_date": datetime.utcnow().isoformat(),
        "statistics": stats,
        "activity_threads": threads,
        "infrastructure_clusters": clusters,
        "events": [asdict(e) for e in events],
    }


def main():
    parser = argparse.ArgumentParser(description="Diamond Model Intrusion Analysis Agent")
    parser.add_argument("--data", required=True, help="Path to events JSON")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="diamond_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report(args.data)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["statistics"], indent=2))


if __name__ == "__main__":
    main()
