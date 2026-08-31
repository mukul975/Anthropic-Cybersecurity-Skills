---
name: building-ioc-defanging-and-sharing-pipeline
description: "Build an automated pipeline that ingests raw IOCs (URLs, IPs, domains, emails), normalizes and deduplicates them, then produces defanged renderings for safe human reading alongside canonical STIX 2.1 bundles distributed via TAXII servers, MISP, or email reports. Use when preparing indicators of compromise for safe analyst sharing or automating threat intel distribution to TAXII/MISP feeds. Do not use for ingesting and parsing STIX/TAXII threat feeds - use processing-stix-taxii-feeds."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- ioc
- defanging
- threat-sharing
- stix
- pipeline
- indicator
- automation
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
- T1071.001
- T1583.001
- T1105
- T1566.002
---
