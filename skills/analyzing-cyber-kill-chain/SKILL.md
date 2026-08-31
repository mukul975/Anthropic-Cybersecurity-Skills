---
name: analyzing-cyber-kill-chain
description: "Analyzes intrusion activity against the Lockheed Martin Cyber Kill Chain framework to identify which phases an adversary has completed, where defenses succeeded or failed, and what controls would have interrupted the attack at earlier phases. Use when conducting post-incident analysis, building prevention-focused security controls, or mapping detection gaps to kill chain phases. Activates for requests involving kill chain analysis, intrusion kill chain, attack phase mapping, or Lockheed Martin kill chain framework. Do not use for mapping observed activity to granular MITRE ATT&CK tactics and techniques - use analyzing-threat-actor-ttps-with-mitre-attack."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- kill-chain
- Lockheed-Martin
- MITRE-ATT&CK
- intrusion-analysis
- defense-in-depth
- NIST-CSF
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1566.001
- T1190
- T1547.001
- T1071.001
- T1486
---
