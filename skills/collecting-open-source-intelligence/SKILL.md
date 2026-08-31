---
name: collecting-open-source-intelligence
description: "Collects and synthesizes open-source intelligence (OSINT) about threat actors, malicious infrastructure, and attack campaigns using publicly available data sources, passive reconnaissance tools, and dark web monitoring. Use when investigating external threat actor infrastructure, performing pre-engagement reconnaissance for authorized red team assessments, or enriching CTI reports with publicly available adversary context. Activates for requests involving Maltego, Shodan, OSINT framework, SpiderFoot, or infrastructure reconnaissance. Do not use for compiling collected OSINT into a structured threat actor profile - use building-threat-actor-profile-from-osint."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- OSINT
- Maltego
- Shodan
- Recon-ng
- SpiderFoot
- threat-intelligence
- ATT&CK-T1591
- NIST-CSF
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1593.001
- T1589.002
- T1596.002
- T1590
- T1596.001
---
