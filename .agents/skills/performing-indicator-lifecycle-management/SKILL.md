---
name: performing-indicator-lifecycle-management
description: Indicator lifecycle management tracks IOCs from initial discovery through validation, enrichment, deployment, monitoring, and eventual retirement. This skill covers implementing systematic processes f
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, indicator-lifecycle, ioc-management]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Indicator Lifecycle Management

## Overview

Indicator lifecycle management tracks IOCs from initial discovery through validation, enrichment, deployment, monitoring, and eventual retirement. This skill covers implementing systematic processes for IOC quality assessment, aging policies, confidence scoring decay, false positive tracking, hit-rate monitoring, and automated expiration to maintain a high-quality, actionable indicator database that minimizes analyst fatigue and maximizes detection efficacy.

## Prerequisites

- Python 3.9+ with `pymisp`, `requests`, `stix2` libraries
- MISP or OpenCTI instance for indicator storage
- SIEM with IOC watchlist capabilities (Splunk, Elastic)
- Understanding of IOC types, confidence scoring, and TLP classifications

## Key Concepts

### Indicator Lifecycle Phases
1. **Discovery**: IOC first identified from threat intelligence, malware analysis, or incident response
2. **Validation**: IOC verified against enrichment sources (VirusTotal, Shodan)
3. **Enrichment**: Additional context added (WHOIS, passive DNS, threat actor attribution)
4. **Deployment**: IOC pushed to detection systems (SIEM, IDS, firewall)
5. **Monitoring**: Track hit rates, false positive rates, detection efficacy
6. **Review**: Periodic assessment of IOC relevance and accuracy
7. **Retirement**: IOC expired or removed based on aging policy

### Confidence Decay
Indicator confidence decreases over time as adversaries rotate infrastructure. A time-based decay function reduces confidence scores automatically, ensuring old indicators do not generate excessive alerts. Typical half-life: IP addresses (30 days), domains (90 days), file hashes (365 days).

### Quality Metrics
- **Hit Rate**: Percentage of deployed IOCs generating true positive alerts
- **False Positive Rate**: Percentage of IOC alerts that are benign
- **Coverage**: Percentage of known threat techniques with IOC coverage
- **Freshness**: Average age of active indicators in the database

## Practical Steps

### Step 1: Implement IOC Lifecycle State Machine

```python
from datetime import datetime, timedelta
from enum import Enum

class IOCState(Enum):
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    ENRICHED = "enriched"
    DEPLOYED = "deployed"
    MONITORING = "monitoring"
    UNDER_REVIEW = "under_review"
    RETIRED = "retired"

class IOCLifecycle:
    def __init__(self, ioc_type, value, source, initial_confidence=50):
        self.ioc_type = ioc_type
        self.value = value
        self.source = source
        self.confidence = initial_confidence
        self.state = IOCState.DISCOVERED
        self.created = datetime.utcnow()
        self.last_updated = datetime.utcnow()
        self.last_seen = None
        self.hit_count = 0
        self.false_positive_count = 0
        self.history = [{"state": "discovered", "timestamp": self.created.isoformat()}]

    def transition(self, new_state: IOCState, reason=""):
        self.state = new_state
        self.last_updated = datetime.utcnow()
        self.history.append({
            "state": new_state.value,
            "timestamp": self.last_updated.isoformat(),
            "reason": reason,
        })

    def apply_decay(self):
        """Apply confidence decay based on IOC type half-life."""
        half_lives = {"ip": 30, "domain": 90, "hash": 365, "url": 60}
        half_life = half_lives.get(self.ioc_type, 90)
        age_days = (datetime.utcnow() - self.created).days
        decay_factor = 0.5 ** (age_days / half_life)
        self.confidence = max(0, int(self.confidence * decay_factor))

    def record_hit(self, is_true_positive=True):
        self.hit_count += 1
        self.last_seen = datetime.utcnow()
        if not is_true_positive:
            self.false_positive_count += 1
            if self.false_positive_count > 3:
                self.transition(IOCState.UNDER_REVIEW, "Excessive false positives")

    def should_retire(self):
        max_ages = {"ip": 90, "domain": 180, "hash": 730, "url": 120}
        max_age = max_ages.get(self.ioc_type, 180)
        age_days = (datetime.utcnow() - self.created).days
        return age_days > max_age and self.hit_count == 0
```

## Validation Criteria

- IOC lifecycle state machine transitions correctly between phases
- Confidence decay reduces scores based on IOC type half-life
- Hit rate and false positive tracking functional
- Aging policy automatically flags indicators for review/retirement
- Quality metrics dashboard shows IOC database health

## References

- [MISP Indicator Lifecycle](https://www.misp-project.org/)
- [STIX Indicator Valid From/Until](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [IOC Quality Framework](https://www.first.org/)
