---
name: analyzing-indicators-of-compromise
description: "Analyzes indicators of compromise (IOCs) including IP addresses, domains, file hashes, URLs, and email artifacts to determine maliciousness confidence, campaign attribution, and blocking priority. Use when triaging IOCs from phishing emails, security alerts, or external threat feeds; enriching raw IOCs with multi-source intelligence; or making block/monitor/whitelist decisions. Activates for requests involving VirusTotal, AbuseIPDB, MalwareBazaar, MISP, or IOC enrichment pipelines. Do not use for building the automated multi-source IOC enrichment pipeline itself - use performing-ioc-enrichment-automation."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- IOC
- VirusTotal
- AbuseIPDB
- MalwareBazaar
- MISP
- threat-intelligence
- STIX
- NIST-CSF
version: 1.0.0
author: mahipal
license: Apache-2.0
atlas_techniques:
- AML.T0052
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1071
- T1105
- T1041
- T1567
mitre_f3:
  version: '1.1'
  tactics:
  - reconnaissance
  - resource-development
  - initial-access
  techniques:
  - id: T1598
    name: Phishing for Information
    tactic: reconnaissance
    source: attack
  - id: T1660
    name: Phishing
    tactic: initial-access
    source: attack
  - id: T1583.001
    name: 'Acquire Infrastructure: Domains'
    tactic: resource-development
    source: attack
  - id: F1020.002
    name: 'Create Fake Materials: Fake Website'
    tactic: resource-development
    source: f3
---
