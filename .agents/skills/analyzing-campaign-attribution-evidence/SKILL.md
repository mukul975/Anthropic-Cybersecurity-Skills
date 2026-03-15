---
name: analyzing-campaign-attribution-evidence
description: Campaign attribution analysis involves systematically evaluating evidence to determine which threat actor or group is responsible for a cyber operation. This skill covers collecting and weighting attr
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, attribution, campaign-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Campaign Attribution Evidence

## Overview

Campaign attribution analysis involves systematically evaluating evidence to determine which threat actor or group is responsible for a cyber operation. This skill covers collecting and weighting attribution indicators using the Diamond Model and ACH (Analysis of Competing Hypotheses), analyzing infrastructure overlaps, TTP consistency, malware code similarities, operational timing patterns, and language artifacts to build confidence-weighted attribution assessments.

## Prerequisites

- Python 3.9+ with `attackcti`, `stix2`, `networkx` libraries
- Access to threat intelligence platforms (MISP, OpenCTI)
- Understanding of Diamond Model of Intrusion Analysis
- Familiarity with MITRE ATT&CK threat group profiles
- Knowledge of malware analysis and infrastructure tracking techniques

## Key Concepts

### Attribution Evidence Categories
1. **Infrastructure Overlap**: Shared C2 servers, domains, IP ranges, hosting providers
2. **TTP Consistency**: Matching ATT&CK techniques and sub-techniques across campaigns
3. **Malware Code Similarity**: Shared code bases, compilers, PDB paths, encryption routines
4. **Operational Patterns**: Timing (working hours, time zones), targeting patterns, operational tempo
5. **Language Artifacts**: Embedded strings, variable names, error messages in specific languages
6. **Victimology**: Target sector, geography, and organizational profile consistency

### Confidence Levels
- **High Confidence**: Multiple independent evidence categories converge on same actor
- **Moderate Confidence**: Several evidence categories match, some ambiguity remains
- **Low Confidence**: Limited evidence, possible false flags or shared tooling

### Analysis of Competing Hypotheses (ACH)
Structured analytical method that evaluates evidence against multiple competing hypotheses. Each piece of evidence is scored as consistent, inconsistent, or neutral with respect to each hypothesis. The hypothesis with the least inconsistent evidence is favored.

## Practical Steps

### Step 1: Collect Attribution Evidence

```python
from stix2 import MemoryStore, Filter
from collections import defaultdict

class AttributionAnalyzer:
    def __init__(self):
        self.evidence = []
        self.hypotheses = {}

    def add_evidence(self, category, description, value, confidence):
        self.evidence.append({
            "category": category,
            "description": description,
            "value": value,
            "confidence": confidence,
            "timestamp": None,
        })

    def add_hypothesis(self, actor_name, actor_id=""):
        self.hypotheses[actor_name] = {
            "actor_id": actor_id,
            "consistent_evidence": [],
            "inconsistent_evidence": [],
            "neutral_evidence": [],
            "score": 0,
        }

    def evaluate_evidence(self, evidence_idx, actor_name, assessment):
        """Assess evidence against a hypothesis: consistent/inconsistent/neutral."""
        if assessment == "consistent":
            self.hypotheses[actor_name]["consistent_evidence"].append(evidence_idx)
            self.hypotheses[actor_name]["score"] += self.evidence[evidence_idx]["confidence"]
        elif assessment == "inconsistent":
            self.hypotheses[actor_name]["inconsistent_evidence"].append(evidence_idx)
            self.hypotheses[actor_name]["score"] -= self.evidence[evidence_idx]["confidence"] * 2
        else:
            self.hypotheses[actor_name]["neutral_evidence"].append(evidence_idx)

    def rank_hypotheses(self):
        """Rank hypotheses by attribution score."""
        ranked = sorted(
            self.hypotheses.items(),
            key=lambda x: x[1]["score"],
            reverse=True,
        )
        return [
            {
                "actor": name,
                "score": data["score"],
                "consistent": len(data["consistent_evidence"]),
                "inconsistent": len(data["inconsistent_evidence"]),
                "confidence": self._score_to_confidence(data["score"]),
            }
            for name, data in ranked
        ]

    def _score_to_confidence(self, score):
        if score >= 80:
            return "HIGH"
        elif score >= 40:
            return "MODERATE"
        else:
            return "LOW"
```

### Step 2: Infrastructure Overlap Analysis

```python
def analyze_infrastructure_overlap(campaign_a_infra, campaign_b_infra):
    """Compare infrastructure between two campaigns for attribution."""
    overlap = {
        "shared_ips": set(campaign_a_infra.get("ips", [])).intersection(
            campaign_b_infra.get("ips", [])
        ),
        "shared_domains": set(campaign_a_infra.get("domains", [])).intersection(
            campaign_b_infra.get("domains", [])
        ),
        "shared_asns": set(campaign_a_infra.get("asns", [])).intersection(
            campaign_b_infra.get("asns", [])
        ),
        "shared_registrars": set(campaign_a_infra.get("registrars", [])).intersection(
            campaign_b_infra.get("registrars", [])
        ),
    }

    overlap_score = 0
    if overlap["shared_ips"]:
        overlap_score += 30
    if overlap["shared_domains"]:
        overlap_score += 25
    if overlap["shared_asns"]:
        overlap_score += 15
    if overlap["shared_registrars"]:
        overlap_score += 10

    return {
        "overlap": {k: list(v) for k, v in overlap.items()},
        "overlap_score": overlap_score,
        "assessment": "STRONG" if overlap_score >= 40 else "MODERATE" if overlap_score >= 20 else "WEAK",
    }
```

### Step 3: TTP Comparison Across Campaigns

```python
from attackcti import attack_client

def compare_campaign_ttps(campaign_techniques, known_actor_techniques):
    """Compare campaign TTPs against known threat actor profiles."""
    campaign_set = set(campaign_techniques)
    actor_set = set(known_actor_techniques)

    common = campaign_set.intersection(actor_set)
    unique_campaign = campaign_set - actor_set
    unique_actor = actor_set - campaign_set

    jaccard = len(common) / len(campaign_set.union(actor_set)) if campaign_set.union(actor_set) else 0

    return {
        "common_techniques": sorted(common),
        "common_count": len(common),
        "unique_to_campaign": sorted(unique_campaign),
        "unique_to_actor": sorted(unique_actor),
        "jaccard_similarity": round(jaccard, 3),
        "overlap_percentage": round(len(common) / len(campaign_set) * 100, 1) if campaign_set else 0,
    }
```

### Step 4: Generate Attribution Report

```python
def generate_attribution_report(analyzer):
    """Generate structured attribution assessment report."""
    rankings = analyzer.rank_hypotheses()

    report = {
        "assessment_date": "2026-02-23",
        "total_evidence_items": len(analyzer.evidence),
        "hypotheses_evaluated": len(analyzer.hypotheses),
        "rankings": rankings,
        "primary_attribution": rankings[0] if rankings else None,
        "evidence_summary": [
            {
                "index": i,
                "category": e["category"],
                "description": e["description"],
                "confidence": e["confidence"],
            }
            for i, e in enumerate(analyzer.evidence)
        ],
    }

    return report
```

## Validation Criteria

- Evidence collection covers all six attribution categories
- ACH matrix properly evaluates evidence against competing hypotheses
- Infrastructure overlap analysis identifies shared indicators
- TTP comparison uses ATT&CK technique IDs for precision
- Attribution confidence levels are properly justified
- Report includes alternative hypotheses and false flag considerations

## References

- [Diamond Model of Intrusion Analysis](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [Analysis of Competing Hypotheses](https://www.cia.gov/static/9a5f1162fd0932c29e985f0159f56c07/Tradecraft-Primer-apr09.pdf)
- [Threat Attribution Framework](https://www.mandiant.com/resources/reports)
