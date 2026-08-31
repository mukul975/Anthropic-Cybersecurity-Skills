---
name: operationalizing-misp-threat-feeds
description: "Stand up MISP, enable and cache curated threat feeds (CIRCL, abuse.ch, Feodo Tracker), apply warninglists to suppress false positives, query indicators with PyMISP, and export attributes as auto-generated Suricata/Sigma/Wazuh detection rules. Use when maturing a MISP instance to actively drive detection, curating threat feeds with quality controls, or automating IOC-to-detection pipelines for the SIEM/IDS. Do not use for sharing and publishing intelligence to MISP communities - use performing-threat-intelligence-sharing-with-misp."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- threat-intelligence
- misp
- pymisp
- threat-feeds
- ioc
- suricata
- sigma
- detection-engineering
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-02
mitre_attack:
- T1589
---
