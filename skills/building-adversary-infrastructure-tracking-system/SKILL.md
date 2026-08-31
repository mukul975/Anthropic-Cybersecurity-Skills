---
name: building-adversary-infrastructure-tracking-system
description: "Build an automated adversary infrastructure tracking system in Python (dnspython, python-whois, shodan, networkx) that pivots across passive DNS, certificate transparency logs, WHOIS records, and IP enrichment to map threat-actor C2 networks and flag newly registered domains matching known patterns. Use when pivoting from known indicators to discover related C2 infrastructure or maintaining a continuously updated map of a threat actor's network. Do not use for the hands-on pivoting and tracking of actor infrastructure rather than building the tracking system - use tracking-threat-actor-infrastructure."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- infrastructure-tracking
- passive-dns
- c2
- whois
- threat-actor
- pivoting
- threat-intelligence
- domain-analysis
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1583.001
- T1583.004
- T1596.001
- T1590.002
- T1071.001
---
