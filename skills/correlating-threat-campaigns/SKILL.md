---
name: correlating-threat-campaigns
description: "Correlates disparate security incidents, IOCs, and adversary behaviors across time and organizations to identify unified threat campaigns, attribute them to common threat actors, and extract shared indicators for improved detection. Use when multiple incidents exhibit overlapping indicators, when sector-wide attack campaigns require cross-organizational analysis, or when building campaign-level intelligence products. Activates for requests involving campaign analysis, incident clustering, cross-organizational IOC correlation, or MISP correlation engine. Do not use for triaging individual indicators of compromise - use analyzing-indicators-of-compromise."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- campaign-analysis
- correlation
- MISP
- ATT&CK
- threat-actor
- intrusion-set
- clustering
- CTI
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1566
- T1071.001
- T1587.001
- T1583.001
- T1588.002
---
