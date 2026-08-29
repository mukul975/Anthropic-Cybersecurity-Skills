---
name: analyzing-ransomware-leak-site-intelligence
description: "Safely monitor ransomware group Tor-hosted data leak sites (DLS) to collect and extract structured victim posting data, track group activity trends over time, and produce sector- and geography-specific ransomware risk assessments. Use when performing threat intelligence gathering on active ransomware groups or building proactive defense reporting from double-extortion leak-site activity. Do not use for broad dark web forum and marketplace monitoring - use performing-dark-web-monitoring-for-threats."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- ransomware
- leak-site
- data-leak
- extortion
- threat-intelligence
- leak-site-monitoring
- dls
- victim-tracking
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1657
- T1486
- T1567.002
- T1591
mitre_f3:
  version: '1.1'
  tactics:
  - monetization
  - reconnaissance
  techniques:
  - id: F1018
    name: Convert to Cryptocurrency
    tactic: monetization
    source: f3
  - id: F1029
    name: Gather Customer Information
    tactic: reconnaissance
    source: f3
  - id: T1593
    name: Search Open Websites/Domains
    tactic: reconnaissance
    source: attack
  - id: F1025.003
    name: 'Electronic Funds Transfer: Wire Transfer'
    tactic: monetization
    source: f3
---
