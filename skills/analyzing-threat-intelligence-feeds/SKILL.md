---
name: analyzing-threat-intelligence-feeds
description: "Analyzes structured and unstructured threat intelligence feeds to extract actionable indicators, adversary tactics, and campaign context. Use when ingesting commercial or open-source CTI feeds, evaluating feed quality, normalizing data into STIX 2.1 format, or enriching existing IOCs with campaign attribution. Activates for requests involving ThreatConnect, Recorded Future, Mandiant Advantage, MISP, AlienVault OTX, or automated feed aggregation pipelines. Do not use for building the MISP feed-aggregation infrastructure - use building-threat-feed-aggregation-with-misp."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- STIX
- TAXII
- MITRE-ATT&CK
- IOC
- ThreatConnect
- Recorded-Future
- MISP
- CTI
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
- T1071.001
- T1566
- T1568
- T1583.001
- T1102
---
