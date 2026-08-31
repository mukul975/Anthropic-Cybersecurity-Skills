---
name: building-attack-pattern-library-from-cti-reports
description: "Parse cyber threat intelligence reports (Mandiant, CrowdStrike, Talos, Microsoft) with stix2, mitreattack-python, and spaCy to extract adversary behaviors, map them to MITRE ATT&CK technique IDs, and build a searchable STIX 2.1 attack-pattern library with detection templates. Use when cataloging attack patterns from CTI reports for threat-informed detection engineering, or generating Sigma/YARA templates from documented behaviors. Do not use for mapping individual observed behaviors to MITRE ATT&CK technique IDs - use mapping-mitre-attack-techniques."
domain: cybersecurity
subdomain: threat-intelligence
tags:
- attack-pattern
- cti-reports
- mitre-attack
- stix
- detection-engineering
- threat-intelligence
- nlp
- extraction
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
- T1566.001
- T1059.001
- T1003.001
- T1558.003
- T1550.002
---
