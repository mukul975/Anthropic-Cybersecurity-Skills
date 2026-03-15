---
name: mapping-mitre-attack-techniques
description: >
  Maps observed adversary behaviors, security alerts, and detection rules to MITRE ATT&CK
  techniques and sub-techniques to quantify detection coverage and guide control prioritization.
  Use when building an ATT&CK-based coverage heatmap, tagging SIEM alerts with technique IDs,
  aligning security controls to adversary playbooks, or reporting threat exposure to executives.
  Activates for requests involving ATT&CK Navigator, Sigma rules, MITRE D3FEND, or coverage gap analysis.
domain: cybersecurity
subdomain: threat-intelligence
tags: [MITRE-ATT&CK, ATT&CK-Navigator, Sigma, D3FEND, TTP, detection-engineering, NIST-CSF]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Mapping MITRE ATT&CK Techniques

## When to Use

Use this skill when:
- Generating an ATT&CK coverage heatmap to show which techniques your detection stack addresses
- Tagging existing SIEM use cases or Sigma rules with ATT&CK technique IDs for structured reporting
- Aligning your security program roadmap to specific adversary groups known to target your sector

**Do not use** this skill for real-time incident triage — ATT&CK mapping is an analytical activity best performed post-detection or during threat hunting planning.

## Prerequisites

- Access to MITRE ATT&CK knowledge base (https://attack.mitre.org) or local ATT&CK STIX data bundle
- ATT&CK Navigator web app or local installation (https://mitre-attack.github.io/attack-navigator/)
- Inventory of existing detection rules (Sigma, Splunk, Sentinel KQL) to assess current coverage
- ATT&CK Python library: `pip install mitreattack-python`

## Workflow

### Step 1: Obtain Current ATT&CK Data

Download the latest ATT&CK STIX bundle for the relevant matrix (Enterprise, Mobile, ICS):
```bash
curl -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

Use the mitreattack-python library to query techniques programmatically:
```python
from mitreattack.stix20 import MitreAttackData

mitre = MitreAttackData("enterprise-attack.json")
techniques = mitre.get_techniques(remove_revoked_deprecated=True)
for t in techniques[:5]:
    print(t["external_references"][0]["external_id"], t["name"])
```

### Step 2: Map Existing Detections to Techniques

For each SIEM rule or Sigma file, assign ATT&CK technique IDs. Sigma rules support native ATT&CK tagging:
```yaml
tags:
  - attack.execution
  - attack.t1059.001  # PowerShell
  - attack.t1059.003  # Windows Command Shell
```

Create a coverage matrix: list each technique ID and mark as: Detected (alert fires), Logged (data present but no alert), Blind (no data source).

### Step 3: Prioritize Coverage Gaps Using Threat Intelligence

Cross-reference coverage gaps with adversary groups targeting your sector. Use ATT&CK Groups data:
```python
groups = mitre.get_groups()
apt29 = mitre.get_object_by_attack_id("G0016", "groups")
apt29_techniques = mitre.get_techniques_used_by_group(apt29)
for t in apt29_techniques:
    print(t["object"]["external_references"][0]["external_id"])
```

Prioritize adding detection for techniques used by high-priority threat groups where your coverage is blind.

### Step 4: Build Navigator Heatmap

Export coverage scores as ATT&CK Navigator JSON layer:
```python
import json

layer = {
    "name": "SOC Detection Coverage Q1 2025",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": "T1059.001", "score": 100, "comment": "Splunk rule: PS_Encoded_Command"},
        {"techniqueID": "T1071.001", "score": 50, "comment": "Logged only, no alert"},
        {"techniqueID": "T1055", "score": 0, "comment": "No coverage — blind spot"}
    ],
    "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100}
}
with open("coverage_layer.json", "w") as f:
    json.dump(layer, f)
```

Import layer into ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) for visualization.

### Step 5: Generate Executive Coverage Report

Summarize coverage by tactic category (Initial Access, Execution, Persistence, etc.) with counts and percentages. Provide a risk-ranked list of top 10 blind-spot techniques based on adversary group usage frequency. Recommend data source additions (e.g., "Enable PowerShell Script Block Logging to address 12 Execution sub-technique gaps").

## Key Concepts

| Term | Definition |
|------|-----------|
| **ATT&CK Technique** | Specific adversary method identified by T-number (e.g., T1059 = Command and Scripting Interpreter) |
| **Sub-technique** | More granular variant of a technique (e.g., T1059.001 = PowerShell, T1059.003 = Windows Command Shell) |
| **Tactic** | Adversary goal category in ATT&CK: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C&C, Exfiltration, Impact |
| **Data Source** | ATT&CK v10+ component identifying telemetry required to detect a technique (e.g., Process Creation, Network Traffic) |
| **Coverage Score** | Numeric (0–100) representing detection completeness for a technique: 0=blind, 50=logged only, 100=alerted |
| **MITRE D3FEND** | Defensive countermeasure ontology complementing ATT&CK — maps defensive techniques to attack techniques they mitigate |

## Tools & Systems

- **ATT&CK Navigator**: Browser-based heatmap visualization tool for layering coverage scores and annotations on the ATT&CK matrix
- **mitreattack-python**: Official MITRE Python library for programmatic access to ATT&CK STIX data (techniques, groups, software, mitigations)
- **Atomic Red Team**: MITRE-aligned test library providing atomic test cases to validate detection for each technique
- **Sigma**: Detection rule format with ATT&CK tagging support; translatable to Splunk, Sentinel, QRadar, Elastic
- **ATT&CK Workbench**: Self-hosted ATT&CK knowledge base for organizations maintaining custom technique extensions

## Common Pitfalls

- **Over-claiming coverage**: Logging a data source (e.g., process creation events) does not mean the associated technique is detected — a rule must actually fire on malicious patterns.
- **Mapping at tactic level only**: Tagging a rule as "attack.execution" without a specific technique ID prevents granular gap analysis.
- **Ignoring sub-techniques**: Many adversaries use specific sub-techniques. Coverage of T1059 (parent) doesn't imply coverage of T1059.005 (Visual Basic).
- **Static mapping without updates**: ATT&CK releases major versions annually. Coverage maps go stale as techniques are added, revised, or deprecated.
- **Not mapping to adversary groups**: Generic coverage maps don't distinguish between techniques used by APTs targeting your sector vs. commodity malware.
