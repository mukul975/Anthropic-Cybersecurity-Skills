---
name: analyzing-threat-actor-ttps-with-mitre-navigator
description: >
  Map advanced persistent threat (APT) group tactics, techniques, and procedures (TTPs) to
  the MITRE ATT&CK framework using the ATT&CK Navigator and attackcti Python library. The
  analyst queries STIX/TAXII data for group-technique associations, generates Navigator layer
  files for visualization, and compares defensive coverage against adversary profiles.
  Activates for requests involving APT TTP mapping, ATT&CK Navigator layers, threat actor
  profiling, or MITRE technique coverage analysis.
domain: cybersecurity
subdomain: threat-intelligence
tags: [mitre-attack, navigator, threat-intelligence, apt, ttp-mapping, stix, attackcti]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Threat Actor TTPs with MITRE Navigator

## Overview

The MITRE ATT&CK Navigator is a web application for annotating and visualizing ATT&CK matrices.
Combined with the attackcti Python library (which queries ATT&CK STIX data via TAXII), analysts
can programmatically generate Navigator layer files mapping specific threat group TTPs, compare
multiple groups, and assess detection coverage gaps against known adversaries.

## Prerequisites

- Python 3.8+ with attackcti and stix2 libraries installed
- MITRE ATT&CK Navigator (web UI or local instance)
- Understanding of STIX 2.1 objects and relationships

## Steps

1. Query ATT&CK STIX data for target threat group using attackcti
2. Extract techniques associated with the group via STIX relationships
3. Generate ATT&CK Navigator layer JSON with technique annotations
4. Overlay detection coverage to identify gaps
5. Export layer for team review and defensive planning

## Expected Output

```json
{
  "name": "APT29 TTPs",
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1566.001", "score": 1, "comment": "Spearphishing Attachment"},
    {"techniqueID": "T1059.001", "score": 1, "comment": "PowerShell"}
  ]
}
```
