---
name: analyzing-threat-landscape-with-misp
description: "Query a MISP (Malware Information Sharing Platform) instance via PyMISP to compute event statistics, IOC type breakdowns, threat actor galaxy clusters, and tag trends, and generate threat landscape reports with temporal trends. Use when asked to analyze threat intelligence data, summarize top threat actors or malware families, or produce a CTI landscape report from MISP events. Do not use for sharing and publishing intelligence to MISP communities - use performing-threat-intelligence-sharing-with-misp."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- threat-intelligence
- misp
- threat-landscape
- ioc-analysis
- cti
- threat-sharing
version: '1.0'
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
- T1566
- T1071.001
- T1568
- T1583.001
- T1102
---
