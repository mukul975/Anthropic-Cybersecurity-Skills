---
name: building-ioc-enrichment-pipeline-with-opencti
description: "Build an automated IOC enrichment pipeline on OpenCTI (STIX 2.1 native threat intel platform) using its internal enrichment connectors to pull context from VirusTotal, Shodan, AbuseIPDB, and GreyNoise, correlate indicators with known actors/campaigns, and score them for analyst prioritization. Use when deploying OpenCTI or automating enrichment and confidence scoring of newly ingested indicators. Do not use for tool-agnostic IOC enrichment automation outside OpenCTI - use performing-ioc-enrichment-automation."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- threat-intelligence
- cti
- ioc
- mitre-attack
- stix
- opencti
- enrichment
- virustotal
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
- T1590.005
- T1588.001
---
