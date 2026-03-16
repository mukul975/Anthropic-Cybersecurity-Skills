---
name: compliance-validation
description: >
  Validates documentation and controls against compliance frameworks. Use when checking ISO 27001, NIST CSF, SOC2,
  PCI DSS, or GDPR compliance. Identifies gaps and recommends remediation.
domain: cybersecurity
subdomain: compliance-governance
tags: [iso-27001, nist-csf, soc2, pci-dss, compliance-audit]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Compliance Validation Skill

Validate controls against regulatory frameworks.

## Primary Frameworks

### ISO 27001

Annex A controls (A.5-A.18) covering policies, access control, cryptography, operations, incident management.

### NIST CSF

Five functions: Identify, Protect, Detect, Respond, Recover.

## Secondary Frameworks

- **SOC 2**: Security, Availability, Processing Integrity, Confidentiality, Privacy
- **PCI DSS v4.0**: 12 requirements for payment card security
- **GDPR**: EU data protection

## Output Format

1. Framework and scope
2. Compliance score
3. Detailed findings per requirement
4. Gap analysis
5. Prioritized remediation plan
