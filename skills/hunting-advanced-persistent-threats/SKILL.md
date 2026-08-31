---
name: hunting-advanced-persistent-threats
description: "Proactively hunts for Advanced Persistent Threat (APT) activity within enterprise environments using hypothesis-driven searches across endpoint telemetry, network logs, and memory artifacts. Use when conducting scheduled threat hunting cycles, investigating anomalous behavior flagged by UEBA, or validating that known APT TTPs are not present in the environment. Activates for requests involving MITRE ATT&CK, Velociraptor, osquery, Zeek, or threat hunting playbooks. Do not use for visualizing threat actor TTPs in the MITRE ATT&CK Navigator - use analyzing-threat-actor-ttps-with-mitre-navigator."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- MITRE-ATT&CK
- threat-hunting
- APT
- Velociraptor
- osquery
- Zeek
- TTP
- NIST-CSF
- EDR
version: 1.0.0
author: mahipal
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Application Protocol Command Analysis
- Identifier Analysis
- Content Format Conversion
- Message Analysis
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
- T1005
---
