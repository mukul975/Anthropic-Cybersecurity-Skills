#!/usr/bin/env python3
"""
Diamond Model of Intrusion Analysis Implementation

Creates Diamond Model events, builds activity threads, and performs pivot analysis.

Requirements: pip install networkx stix2

Usage:
    python process.py --events events.json --output analysis.json
    python process.py --demo --output demo_analysis.json
"""

import argparse
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DiamondEvent:
    adversary: str = ""
    capability: str = ""
    infrastructure: str = ""
    victim: str = ""
    timestamp: str = ""
    phase: str = ""
    result: str = "success"
    confidence: int = 0
    mitre_techniques: list = field(default_factory=list)
    iocs: list = field(default_factory=list)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self):
        return vars(self)


class DiamondModelAnalyzer:
    def __init__(self):
        self.events = []

    def add_event(self, event: DiamondEvent):
        self.events.append(event)

    def load_events(self, filepath):
        with open(filepath) as f:
            data = json.load(f)
        for e in data:
            self.events.append(DiamondEvent(**e))

    def find_pivots(self):
        pivots = {"infrastructure": defaultdict(list), "capability": defaultdict(list),
                  "adversary": defaultdict(list), "victim": defaultdict(list)}
        for e in self.events:
            for feature in pivots:
                val = getattr(e, feature, "")
                if val:
                    pivots[feature][val].append(e.event_id)
        return {k: {pk: pv for pk, pv in v.items() if len(pv) > 1} for k, v in pivots.items()}

    def build_activity_threads(self):
        threads = defaultdict(list)
        for e in sorted(self.events, key=lambda x: x.timestamp):
            key = e.adversary or "unknown"
            threads[key].append(e.to_dict())
        return dict(threads)

    def generate_report(self):
        return {
            "total_events": len(self.events),
            "unique_adversaries": len(set(e.adversary for e in self.events if e.adversary)),
            "unique_victims": len(set(e.victim for e in self.events if e.victim)),
            "unique_infrastructure": len(set(e.infrastructure for e in self.events if e.infrastructure)),
            "pivots": self.find_pivots(),
            "activity_threads": self.build_activity_threads(),
            "events": [e.to_dict() for e in self.events],
        }


def run_demo():
    analyzer = DiamondModelAnalyzer()
    analyzer.add_event(DiamondEvent(
        adversary="APT29", capability="Cobalt Strike", infrastructure="198.51.100.1",
        victim="Gov Agency A", timestamp="2025-06-01T10:00:00Z", phase="initial-access",
        mitre_techniques=["T1566.001"], confidence=80,
    ))
    analyzer.add_event(DiamondEvent(
        adversary="APT29", capability="Custom Backdoor", infrastructure="198.51.100.1",
        victim="Gov Agency A", timestamp="2025-06-01T12:00:00Z", phase="persistence",
        mitre_techniques=["T1547.001"], confidence=85,
    ))
    analyzer.add_event(DiamondEvent(
        adversary="APT29", capability="Mimikatz", infrastructure="198.51.100.2",
        victim="Gov Agency A", timestamp="2025-06-02T09:00:00Z", phase="credential-access",
        mitre_techniques=["T1003.001"], confidence=90,
    ))
    return analyzer.generate_report()


def main():
    parser = argparse.ArgumentParser(description="Diamond Model Analyzer")
    parser.add_argument("--events", help="Events JSON file")
    parser.add_argument("--demo", action="store_true", help="Run demo analysis")
    parser.add_argument("--output", default="diamond_analysis.json")
    args = parser.parse_args()

    if args.demo:
        report = run_demo()
    elif args.events:
        analyzer = DiamondModelAnalyzer()
        analyzer.load_events(args.events)
        report = analyzer.generate_report()
    else:
        parser.print_help()
        return

    print(json.dumps(report, indent=2))
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
