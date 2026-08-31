---
name: mapping-mitre-attack-techniques
description: "Maps observed adversary behaviors, security alerts, and detection rules to MITRE ATT&CK techniques and sub-techniques to quantify detection coverage and guide control prioritization. Use when building an ATT&CK-based coverage heatmap, tagging SIEM alerts with technique IDs, aligning security controls to adversary playbooks, or reporting threat exposure to executives. Activates for requests involving ATT&CK Navigator, Sigma rules, MITRE D3FEND, or coverage gap analysis. Do not use for mapping detection and control coverage across the ATT&CK matrix - use implementing-mitre-attack-coverage-mapping."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- MITRE-ATT&CK
- ATT&CK-Navigator
- Sigma
- D3FEND
- TTP
- detection-engineering
- NIST-CSF
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1591
- T1592
- T1593
- T1589
- T1685.002
---
