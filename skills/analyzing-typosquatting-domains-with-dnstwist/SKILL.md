---
name: analyzing-typosquatting-domains-with-dnstwist
description: "Generate domain permutations with dnstwist and check DNS resolution to detect typosquatting, homograph phishing, and brand impersonation domains registered against your organization. Use when asked to monitor for lookalike domains, investigate a phishing domain, or assess brand-impersonation risk. Do not use for broader brand-impersonation monitoring across web and social channels - use performing-brand-monitoring-for-impersonation."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- dnstwist
- typosquatting
- phishing
- domain-monitoring
- brand-protection
- homograph
- dns
- threat-intelligence
version: '1.0'
author: mahipal
license: Apache-2.0
atlas_techniques:
- AML.T0073
- AML.T0052
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1583.001
- T1566.002
- T1598.003
- T1583.006
mitre_f3:
  version: '1.1'
  tactics:
  - resource-development
  - reconnaissance
  - initial-access
  techniques:
  - id: T1583.001
    name: 'Acquire Infrastructure: Domains'
    tactic: resource-development
    source: attack
  - id: F1020.002
    name: 'Create Fake Materials: Fake Website'
    tactic: resource-development
    source: f3
  - id: T1598
    name: Phishing for Information
    tactic: reconnaissance
    source: attack
  - id: T1593
    name: Search Open Websites/Domains
    tactic: reconnaissance
    source: attack
  - id: T1660
    name: Phishing
    tactic: initial-access
    source: attack
---
