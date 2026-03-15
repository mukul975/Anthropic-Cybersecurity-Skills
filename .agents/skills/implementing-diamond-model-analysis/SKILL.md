---
name: implementing-diamond-model-analysis
description: >-
  Apply the Diamond Model of Intrusion Analysis to map adversary, capability,
  infrastructure, and victim relationships so analysts can correlate events,
  build activity threads, and produce pivot-ready threat intelligence.
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, diamond-model, intrusion-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Diamond Model Analysis

## Overview

The Diamond Model of Intrusion Analysis provides a structured framework for analyzing cyber intrusions by examining four core features: Adversary, Capability, Infrastructure, and Victim. This skill covers implementing the Diamond Model programmatically to classify and correlate intrusion events, build activity threads linking related events, create activity-attack graphs, and generate pivot-ready intelligence from intrusion data.

## Prerequisites

- Python 3.9+ with `networkx`, `stix2`, `graphviz` libraries
- Understanding of the Diamond Model core and meta-features
- Access to threat intelligence data (MISP/OpenCTI events)
- Familiarity with MITRE ATT&CK for capability mapping

## Key Concepts

### Diamond Model Core Features
- **Adversary**: The threat actor or operator conducting the intrusion
- **Capability**: The tools, techniques, and malware used (maps to ATT&CK)
- **Infrastructure**: C2 servers, domains, email addresses, hosting providers
- **Victim**: Target organization, system, person, or data asset

### Meta-Features
- **Timestamp**: When the event occurred
- **Phase**: Kill chain stage (recon, delivery, exploitation, etc.)
- **Result**: Success, failure, or unknown
- **Direction**: Adversary-to-infrastructure, infrastructure-to-victim, etc.
- **Methodology**: Social engineering, technical exploit, insider threat
- **Resources**: Financial, human, technical resources required

### Activity Threads and Groups
- **Activity Thread**: Sequence of Diamond events from a single adversary operation
- **Activity Group**: Cluster of threads attributed to the same adversary

## Practical Steps

### Step 1: Define Diamond Event Data Structure

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json
import uuid

@dataclass
class DiamondEvent:
    adversary: str = ""
    capability: str = ""
    infrastructure: str = ""
    victim: str = ""
    timestamp: str = ""
    phase: str = ""
    result: str = ""
    direction: str = ""
    methodology: str = ""
    confidence: int = 0
    notes: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    mitre_techniques: list = field(default_factory=list)
    iocs: list = field(default_factory=list)

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "adversary": self.adversary,
            "capability": self.capability,
            "infrastructure": self.infrastructure,
            "victim": self.victim,
            "timestamp": self.timestamp,
            "phase": self.phase,
            "result": self.result,
            "direction": self.direction,
            "methodology": self.methodology,
            "confidence": self.confidence,
            "mitre_techniques": self.mitre_techniques,
            "iocs": self.iocs,
            "notes": self.notes,
        }
```

### Step 2: Build Activity Thread from Events

```python
import networkx as nx

class DiamondAnalysis:
    def __init__(self):
        self.events = []
        self.graph = nx.DiGraph()

    def add_event(self, event: DiamondEvent):
        self.events.append(event)
        self.graph.add_node(event.event_id, **event.to_dict())

    def build_activity_thread(self):
        """Link events chronologically into activity threads."""
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        for i in range(len(sorted_events) - 1):
            self.graph.add_edge(
                sorted_events[i].event_id,
                sorted_events[i + 1].event_id,
                relationship="followed_by",
            )

    def find_pivots(self):
        """Find pivot points where events share infrastructure or capabilities."""
        pivots = {"infrastructure": {}, "capability": {}, "adversary": {}}

        for event in self.events:
            if event.infrastructure:
                pivots["infrastructure"].setdefault(event.infrastructure, []).append(event.event_id)
            if event.capability:
                pivots["capability"].setdefault(event.capability, []).append(event.event_id)
            if event.adversary:
                pivots["adversary"].setdefault(event.adversary, []).append(event.event_id)

        return {
            k: {pk: pv for pk, pv in v.items() if len(pv) > 1}
            for k, v in pivots.items()
        }

    def generate_report(self):
        return {
            "total_events": len(self.events),
            "unique_adversaries": len(set(e.adversary for e in self.events if e.adversary)),
            "unique_victims": len(set(e.victim for e in self.events if e.victim)),
            "unique_infrastructure": len(set(e.infrastructure for e in self.events if e.infrastructure)),
            "pivots": self.find_pivots(),
            "events": [e.to_dict() for e in self.events],
        }
```

## Validation Criteria

- Diamond events capture all four core features with meta-features
- Activity threads link related events chronologically
- Pivot analysis identifies shared infrastructure and capabilities across events
- Graph visualization renders the activity-attack graph correctly
- Events map to MITRE ATT&CK techniques for capability classification

## References

- [Diamond Model Paper](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX 2.1 Campaign Object](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
