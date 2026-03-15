---
name: analyzing-apt-group-with-mitre-navigator
description: Analyze advanced persistent threat (APT) group techniques using MITRE ATT&CK Navigator to create layered heatmaps of adversary TTPs for detection gap analysis and threat-informed defense.
domain: cybersecurity
subdomain: threat-intelligence
tags: [mitre-attack, navigator, apt, threat-actor, ttp-analysis, heatmap, detection-gap, threat-intelligence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing APT Group with MITRE ATT&CK Navigator

## Overview

MITRE ATT&CK Navigator is a web-based tool for annotating and exploring ATT&CK matrices, enabling analysts to visualize threat actor technique coverage, compare multiple APT groups, identify detection gaps, and build threat-informed defense strategies. This skill covers querying ATT&CK data programmatically, mapping APT group TTPs to Navigator layers, creating multi-layer overlays for gap analysis, and generating actionable intelligence reports for detection engineering teams.

## Prerequisites

- Python 3.9+ with `attackcti`, `mitreattack-python`, `stix2`, `requests` libraries
- ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) or local deployment
- Understanding of ATT&CK Enterprise matrix: 14 Tactics, 200+ Techniques, Sub-techniques
- Access to threat intelligence reports or MISP/OpenCTI for threat actor data
- Familiarity with STIX 2.1 Intrusion Set and Attack Pattern objects

## Key Concepts

### ATT&CK Navigator Layers

Navigator layers are JSON files that annotate ATT&CK techniques with scores, colors, comments, and metadata. Each layer can represent a single APT group's technique usage, a detection capability map, or a combined overlay. Layer version 4.5 supports enterprise-attack, mobile-attack, and ics-attack domains with filtering by platform (Windows, Linux, macOS, Cloud, Azure AD, Office 365, SaaS).

### APT Group Profiles in ATT&CK

ATT&CK catalogs over 140 threat groups with documented technique usage. Each group profile includes aliases, targeted sectors, associated campaigns, software used, and technique mappings with procedure-level detail. Groups are identified by G-codes (e.g., G0016 for APT29, G0007 for APT28, G0032 for Lazarus Group).

### Multi-Layer Analysis

The Navigator supports loading multiple layers simultaneously, allowing analysts to overlay threat actor TTPs against detection coverage to identify gaps, compare multiple APT groups to find common techniques worth prioritizing, and track technique coverage changes over time.

## Practical Steps

### Step 1: Query ATT&CK Data for APT Group

```python
from attackcti import attack_client
import json

lift = attack_client()

# Get all threat groups
groups = lift.get_groups()
print(f"Total ATT&CK groups: {len(groups)}")

# Find APT29 (Cozy Bear / Midnight Blizzard)
apt29 = next((g for g in groups if g.get('name') == 'APT29'), None)
if apt29:
    print(f"Group: {apt29['name']}")
    print(f"Aliases: {apt29.get('aliases', [])}")
    print(f"Description: {apt29.get('description', '')[:300]}")

# Get techniques used by APT29 (G0016)
techniques = lift.get_techniques_used_by_group("G0016")
print(f"APT29 uses {len(techniques)} techniques")

technique_map = {}
for tech in techniques:
    tech_id = ""
    for ref in tech.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            tech_id = ref.get("external_id", "")
            break
    if tech_id:
        tactics = [p.get("phase_name", "") for p in tech.get("kill_chain_phases", [])]
        technique_map[tech_id] = {
            "name": tech.get("name", ""),
            "tactics": tactics,
            "description": tech.get("description", "")[:500],
            "platforms": tech.get("x_mitre_platforms", []),
            "data_sources": tech.get("x_mitre_data_sources", []),
        }
```

### Step 2: Generate Navigator Layer JSON

```python
def create_navigator_layer(group_name, technique_map, color="#ff6666"):
    techniques_list = []
    for tech_id, info in technique_map.items():
        for tactic in info["tactics"]:
            techniques_list.append({
                "techniqueID": tech_id,
                "tactic": tactic,
                "color": color,
                "comment": info["name"],
                "enabled": True,
                "score": 100,
                "metadata": [
                    {"name": "group", "value": group_name},
                    {"name": "platforms", "value": ", ".join(info["platforms"])},
                ],
            })

    layer = {
        "name": f"{group_name} TTP Coverage",
        "versions": {"attack": "16.1", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques attributed to {group_name}",
        "filters": {
            "platforms": ["Linux", "macOS", "Windows", "Cloud",
                          "Azure AD", "Office 365", "SaaS", "Google Workspace"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side", "aggregateFunction": "average",
            "showID": True, "showName": True,
            "showAggregateScores": False, "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques_list,
        "gradient": {"colors": ["#ffffff", color], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": f"Used by {group_name}", "color": color},
            {"label": "Not observed", "color": "#ffffff"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    return layer

layer = create_navigator_layer("APT29", technique_map)
with open("apt29_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
print("[+] Layer saved: apt29_layer.json")
```

### Step 3: Compare Multiple APT Groups

```python
groups_to_compare = {"G0016": "APT29", "G0007": "APT28", "G0032": "Lazarus Group"}
group_techniques = {}

for gid, gname in groups_to_compare.items():
    techs = lift.get_techniques_used_by_group(gid)
    tech_ids = set()
    for t in techs:
        for ref in t.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_ids.add(ref.get("external_id", ""))
    group_techniques[gname] = tech_ids

common_to_all = set.intersection(*group_techniques.values())
print(f"Techniques common to all groups: {len(common_to_all)}")
for tid in sorted(common_to_all):
    print(f"  {tid}")

for gname, techs in group_techniques.items():
    others = set.union(*[t for n, t in group_techniques.items() if n != gname])
    unique = techs - others
    print(f"\nUnique to {gname}: {len(unique)} techniques")
```

### Step 4: Detection Gap Analysis with Layer Overlay

```python
# Define your current detection capabilities
detected_techniques = {
    "T1059", "T1059.001", "T1071", "T1071.001", "T1566", "T1566.001",
    "T1547", "T1547.001", "T1053", "T1053.005", "T1078", "T1027",
}

actor_techniques = set(technique_map.keys())
covered = actor_techniques.intersection(detected_techniques)
gaps = actor_techniques - detected_techniques

print(f"=== Detection Gap Analysis for APT29 ===")
print(f"Actor techniques: {len(actor_techniques)}")
print(f"Detected: {len(covered)} ({len(covered)/len(actor_techniques)*100:.0f}%)")
print(f"Gaps: {len(gaps)} ({len(gaps)/len(actor_techniques)*100:.0f}%)")

# Create gap layer (red = undetected, green = detected)
gap_techniques = []
for tech_id in actor_techniques:
    info = technique_map.get(tech_id, {})
    for tactic in info.get("tactics", [""]):
        color = "#66ff66" if tech_id in detected_techniques else "#ff3333"
        gap_techniques.append({
            "techniqueID": tech_id,
            "tactic": tactic,
            "color": color,
            "comment": f"{'DETECTED' if tech_id in detected_techniques else 'GAP'}: {info.get('name', '')}",
            "enabled": True,
            "score": 100 if tech_id in detected_techniques else 0,
        })

gap_layer = {
    "name": "APT29 Detection Gap Analysis",
    "versions": {"attack": "16.1", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Green = detected, Red = gap",
    "techniques": gap_techniques,
    "gradient": {"colors": ["#ff3333", "#66ff66"], "minValue": 0, "maxValue": 100},
    "legendItems": [
        {"label": "Detected", "color": "#66ff66"},
        {"label": "Detection Gap", "color": "#ff3333"},
    ],
}
with open("apt29_gap_layer.json", "w") as f:
    json.dump(gap_layer, f, indent=2)
```

### Step 5: Tactic Breakdown Analysis

```python
from collections import defaultdict

tactic_breakdown = defaultdict(list)
for tech_id, info in technique_map.items():
    for tactic in info["tactics"]:
        tactic_breakdown[tactic].append({"id": tech_id, "name": info["name"]})

tactic_order = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

print("\n=== APT29 Tactic Breakdown ===")
for tactic in tactic_order:
    techs = tactic_breakdown.get(tactic, [])
    if techs:
        print(f"\n{tactic.upper()} ({len(techs)} techniques):")
        for t in techs:
            print(f"  {t['id']}: {t['name']}")
```

## Validation Criteria

- ATT&CK data queried successfully via TAXII server
- APT group mapped to all documented techniques with procedure examples
- Navigator layer JSON validates and renders correctly in ATT&CK Navigator
- Multi-layer overlay shows threat actor vs. detection coverage
- Detection gap analysis identifies unmonitored techniques with data source recommendations
- Cross-group comparison reveals shared and unique TTPs
- Output is actionable for detection engineering prioritization

## References

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK Groups](https://attack.mitre.org/groups/)
- [attackcti Python Library](https://github.com/OTRF/ATTACK-Python-Client)
- [Navigator Layer Format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md)
- [CISA Best Practices for MITRE ATT&CK Mapping](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)
- [Picus: Leverage MITRE ATT&CK for Threat Intelligence](https://www.picussecurity.com/how-to-leverage-the-mitre-attack-framework-for-threat-intelligence)
