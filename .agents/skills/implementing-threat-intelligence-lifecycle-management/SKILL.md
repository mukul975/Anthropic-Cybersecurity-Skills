---
name: implementing-threat-intelligence-lifecycle-management
description: Implement a structured threat intelligence lifecycle encompassing planning, collection, processing, analysis, dissemination, and feedback stages to produce actionable intelligence for organizational decision-making.
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, lifecycle, intelligence-cycle, collection, analysis, dissemination, strategic-intelligence, cti-program]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Threat Intelligence Lifecycle Management

## Overview

The threat intelligence lifecycle is a structured, iterative process for transforming raw data into actionable intelligence. Based on the intelligence cycle used by military and government agencies, it comprises six phases: Direction (requirements gathering), Collection (data acquisition), Processing (normalization and deduplication), Analysis (contextualization and assessment), Dissemination (distribution to stakeholders), and Feedback (evaluation and refinement). This skill covers building each phase with tooling, metrics, and integration points for a mature CTI program.

## Prerequisites

- Python 3.9+ with `pymisp`, `stix2`, `requests`, `pandas` libraries
- MISP or OpenCTI as threat intelligence platform
- Ticketing system (Jira, ServiceNow) for requirements management
- SIEM integration (Splunk, Elastic) for indicator operationalization
- Understanding of intelligence analysis techniques (ACH, Diamond Model)

## Key Concepts

### Intelligence Requirements (IR)

Priority Intelligence Requirements (PIRs) define what the organization needs to know. Examples: Which threat actors target our sector? What vulnerabilities are being actively exploited? Are our brand or credentials being traded on dark web? PIRs drive collection planning and ensure intelligence production is relevant.

### Collection Management Framework

A collection management framework maps intelligence requirements to collection sources, tracks collection gaps, and ensures coverage across the threat landscape. Sources include OSINT, commercial feeds, ISAC sharing, internal telemetry, and human intelligence from industry contacts.

### Intelligence Levels

Strategic intelligence informs executive decision-making (threat landscape, risk trends, geopolitical context). Operational intelligence supports security operations (campaign tracking, actor TTPs, attack timing). Tactical intelligence enables immediate defense (IOCs, detection rules, blocklists).

## Practical Steps

### Step 1: Define Intelligence Requirements

```python
import json
from datetime import datetime
from enum import Enum

class Priority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

class IntelligenceRequirement:
    def __init__(self, requirement_id, question, priority, stakeholder,
                 intelligence_level, collection_sources=None):
        self.id = requirement_id
        self.question = question
        self.priority = priority
        self.stakeholder = stakeholder
        self.level = intelligence_level
        self.sources = collection_sources or []
        self.created = datetime.now().isoformat()
        self.status = "active"
        self.last_answered = None

    def to_dict(self):
        return {
            "id": self.id,
            "question": self.question,
            "priority": self.priority.name,
            "stakeholder": self.stakeholder,
            "intelligence_level": self.level,
            "collection_sources": self.sources,
            "created": self.created,
            "status": self.status,
            "last_answered": self.last_answered,
        }

class RequirementsManager:
    def __init__(self):
        self.requirements = []

    def add_requirement(self, requirement):
        self.requirements.append(requirement)
        print(f"[+] Added IR-{requirement.id}: {requirement.question[:60]}...")

    def get_active_requirements(self, priority=None, level=None):
        filtered = [r for r in self.requirements if r.status == "active"]
        if priority:
            filtered = [r for r in filtered if r.priority == priority]
        if level:
            filtered = [r for r in filtered if r.level == level]
        return filtered

    def export_requirements(self, output_file="intelligence_requirements.json"):
        data = [r.to_dict() for r in self.requirements]
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Exported {len(data)} requirements to {output_file}")

# Define organizational PIRs
mgr = RequirementsManager()
mgr.add_requirement(IntelligenceRequirement(
    "PIR-001", "Which threat actors are actively targeting our sector?",
    Priority.CRITICAL, "CISO", "strategic",
    ["MITRE ATT&CK", "ISAC feeds", "Vendor reports"],
))
mgr.add_requirement(IntelligenceRequirement(
    "PIR-002", "What vulnerabilities are being actively exploited in the wild?",
    Priority.CRITICAL, "Vulnerability Management", "operational",
    ["CISA KEV", "Exploit-DB", "VulnCheck", "Shodan"],
))
mgr.add_requirement(IntelligenceRequirement(
    "PIR-003", "Are any organization credentials or data exposed on dark web?",
    Priority.HIGH, "SOC Manager", "tactical",
    ["Dark web monitoring", "Paste site monitoring", "Breach databases"],
))
mgr.add_requirement(IntelligenceRequirement(
    "PIR-004", "What are the emerging attack techniques against cloud infrastructure?",
    Priority.HIGH, "Cloud Security", "operational",
    ["ATT&CK Cloud matrix", "Vendor advisories", "ISAC bulletins"],
))
mgr.export_requirements()
```

### Step 2: Build Collection Pipeline

```python
import requests
from datetime import datetime, timedelta

class CollectionPipeline:
    def __init__(self, config):
        self.config = config
        self.collected_data = []

    def collect_cisa_kev(self):
        """Collect CISA Known Exploited Vulnerabilities catalog."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            self.collected_data.append({
                "source": "CISA KEV",
                "type": "vulnerability",
                "count": len(vulns),
                "collected_at": datetime.now().isoformat(),
                "data": vulns,
            })
            print(f"[+] CISA KEV: {len(vulns)} known exploited vulnerabilities")
            return vulns
        return []

    def collect_otx_pulses(self, api_key, days=7):
        """Collect recent OTX pulses."""
        headers = {"X-OTX-API-KEY": api_key}
        since = (datetime.now() - timedelta(days=days)).isoformat()
        url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            pulses = resp.json().get("results", [])
            self.collected_data.append({
                "source": "AlienVault OTX",
                "type": "threat_intelligence",
                "count": len(pulses),
                "collected_at": datetime.now().isoformat(),
            })
            print(f"[+] OTX: {len(pulses)} pulses in last {days} days")
            return pulses
        return []

    def collect_abuse_ch(self):
        """Collect recent malware samples from MalwareBazaar."""
        url = "https://mb-api.abuse.ch/api/v1/"
        resp = requests.post(url, data={"query": "get_recent", "selector": "time"}, timeout=30)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            self.collected_data.append({
                "source": "MalwareBazaar",
                "type": "malware_samples",
                "count": len(data),
                "collected_at": datetime.now().isoformat(),
            })
            print(f"[+] MalwareBazaar: {len(data)} recent samples")
            return data
        return []

    def get_collection_summary(self):
        summary = {
            "total_sources": len(self.collected_data),
            "total_items": sum(d.get("count", 0) for d in self.collected_data),
            "sources": [
                {"name": d["source"], "type": d["type"], "count": d["count"]}
                for d in self.collected_data
            ],
        }
        return summary

pipeline = CollectionPipeline({})
pipeline.collect_cisa_kev()
pipeline.collect_abuse_ch()
print(json.dumps(pipeline.get_collection_summary(), indent=2))
```

### Step 3: Process and Normalize Data

```python
class IntelligenceProcessor:
    def __init__(self):
        self.processed_items = []
        self.dedup_hashes = set()

    def process_collection(self, raw_data, source_name):
        """Normalize and deduplicate collected intelligence."""
        processed = []
        duplicates = 0

        for item in raw_data:
            normalized = self._normalize(item, source_name)
            if normalized:
                item_hash = self._compute_hash(normalized)
                if item_hash not in self.dedup_hashes:
                    self.dedup_hashes.add(item_hash)
                    normalized["processed_at"] = datetime.now().isoformat()
                    processed.append(normalized)
                else:
                    duplicates += 1

        self.processed_items.extend(processed)
        print(f"[+] Processed {len(processed)} items from {source_name} "
              f"({duplicates} duplicates removed)")
        return processed

    def _normalize(self, item, source):
        """Normalize item to standard format."""
        return {
            "source": source,
            "type": item.get("type", "unknown"),
            "value": item.get("value", item.get("indicator", "")),
            "confidence": item.get("confidence", 50),
            "tlp": item.get("tlp", "green"),
            "tags": item.get("tags", []),
            "first_seen": item.get("first_seen", item.get("date_added", "")),
            "raw": item,
        }

    def _compute_hash(self, item):
        import hashlib
        key = f"{item['type']}:{item['value']}:{item['source']}"
        return hashlib.sha256(key.encode()).hexdigest()

processor = IntelligenceProcessor()
```

### Step 4: Analyze and Produce Intelligence

```python
class IntelligenceAnalyzer:
    def __init__(self, requirements, processed_data):
        self.requirements = requirements
        self.data = processed_data

    def answer_requirement(self, requirement_id):
        """Produce intelligence answering a specific requirement."""
        req = next((r for r in self.requirements if r.id == requirement_id), None)
        if not req:
            return None

        # Filter relevant data based on requirement type
        relevant = self.data  # In practice, filter by requirement topic
        analysis = {
            "requirement_id": requirement_id,
            "question": req.question,
            "intelligence_level": req.level,
            "data_points_analyzed": len(relevant),
            "produced_at": datetime.now().isoformat(),
            "key_findings": [],
            "confidence": "medium",
            "recommendations": [],
        }
        return analysis

    def produce_daily_brief(self):
        """Produce daily threat intelligence brief."""
        brief = {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "total_items_processed": len(self.data),
            "highlights": [],
            "active_requirements_status": [
                {"id": r.id, "question": r.question[:80], "status": r.status}
                for r in self.requirements if r.status == "active"
            ],
        }
        return brief
```

### Step 5: Disseminate and Track Feedback

```python
class IntelligenceDisseminator:
    def __init__(self):
        self.distribution_log = []

    def distribute_report(self, report, channels, classification="TLP:GREEN"):
        """Distribute intelligence report to appropriate channels."""
        for channel in channels:
            entry = {
                "report_id": report.get("requirement_id", "daily"),
                "channel": channel,
                "classification": classification,
                "distributed_at": datetime.now().isoformat(),
                "status": "sent",
            }
            self.distribution_log.append(entry)
            print(f"  [+] Distributed to {channel}")

    def collect_feedback(self, report_id, stakeholder, rating, comments=""):
        """Collect stakeholder feedback on intelligence product."""
        feedback = {
            "report_id": report_id,
            "stakeholder": stakeholder,
            "rating": rating,  # 1-5
            "comments": comments,
            "received_at": datetime.now().isoformat(),
        }
        print(f"[+] Feedback received from {stakeholder}: {rating}/5")
        return feedback

    def calculate_metrics(self):
        """Calculate CTI program performance metrics."""
        metrics = {
            "total_products_distributed": len(self.distribution_log),
            "distribution_by_channel": {},
        }
        for entry in self.distribution_log:
            channel = entry["channel"]
            if channel not in metrics["distribution_by_channel"]:
                metrics["distribution_by_channel"][channel] = 0
            metrics["distribution_by_channel"][channel] += 1
        return metrics

disseminator = IntelligenceDisseminator()
```

## Validation Criteria

- Intelligence requirements defined with priorities and stakeholders
- Collection pipeline gathering from multiple sources
- Processing deduplicates and normalizes data correctly
- Analysis produces intelligence answering specific requirements
- Dissemination reaches appropriate stakeholders through right channels
- Feedback mechanism captures and incorporates stakeholder input

## References

- [SANS: Cyber Threat Intelligence Lifecycle](https://www.sans.org/white-papers/36297/)
- [CISA: Cybersecurity Automation Best Practices](https://www.cisa.gov/sites/default/files/publications/Operational%20Value%20of%20IOCs_508c.pdf)
- [CyCognito: Threat Intelligence Lifecycle](https://www.cycognito.com/learn/threat-intelligence/)
- [MISP Project](https://www.misp-project.org/)
- [STIX/TAXII Documentation](https://oasis-open.github.io/cti-documentation/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
