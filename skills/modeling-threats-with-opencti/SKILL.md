---
name: modeling-threats-with-opencti
description: "Deploy OpenCTI (Filigran) via Docker Compose and use the pycti Python client to model threat actors, intrusion sets, campaigns, and indicators as a STIX 2.1 knowledge graph with relationships (uses, attributed-to, targets). Use when building a centralized threat-intel knowledge base, correlating IOCs from multiple feeds into one adversary graph, or producing STIX bundles for detection engineering. Do not use for building an IOC enrichment pipeline in OpenCTI - use building-ioc-enrichment-pipeline-with-opencti."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- opencti
- threat-intelligence
- stix2
- pycti
- knowledge-graph
- threat-modeling
- mitre-attack
- cti
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-03
mitre_attack:
- T1589
---
