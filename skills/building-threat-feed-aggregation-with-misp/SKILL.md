---
name: building-threat-feed-aggregation-with-misp
description: "Deploy MISP via Docker and configure feeds from sources like abuse.ch, AlienVault OTX, and CIRCL to aggregate, correlate, and distribute threat intelligence, including automated feed synchronization and STIX/TAXII-based integration with Splunk, Elasticsearch, and SOAR platforms. Use when standing up centralized IOC management or wiring multi-source threat feeds into a SIEM. Do not use for evaluating and analyzing the content of threat feeds - use analyzing-threat-intelligence-feeds."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- misp
- threat-feed
- aggregation
- indicator
- sharing
- correlation
- siem-integration
- threat-intelligence
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1071
- T1105
- T1588.001
---
