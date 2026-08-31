---
name: automating-ioc-enrichment
description: "Automates the enrichment of raw indicators of compromise with multi-source threat intelligence context using SOAR platforms, Python pipelines, or TIP playbooks to reduce analyst triage time and standardize enrichment outputs. Use when building automated enrichment workflows integrated with SIEM alerts, email submission pipelines, or bulk IOC processing from threat feeds. Activates for requests involving SOAR enrichment, Cortex XSOAR, Splunk SOAR, TheHive, Python enrichment pipelines, or automated IOC processing. Do not use for building general SOAR playbook automation in Splunk Phantom - use implementing-soar-automation-with-phantom."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- SOAR
- enrichment
- IOC
- Cortex-XSOAR
- Splunk-SOAR
- VirusTotal
- automation
- CTI
- NIST-CSF
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1071.001
- T1583.001
- T1588.001
- T1590.005
- T1596
---
