---
name: configuring-active-directory-tiered-model
description: Implement Microsoft's Enhanced Security Admin Environment (ESAE) tiered
  administration model for Active Directory. Covers Tier 0/1/2 separation, privileged
  access workstations (PAWs), administrative f
domain: cybersecurity
subdomain: identity-access-management
tags:
- iam
- identity
- access-control
- active-directory
- tiered-model
- paw
- esae
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1078.002
- T1550.002
- T1550.003
- T1003.001
- T1021
---
# Configuring Active Directory Tiered Model

## Overview
Implement Microsoft's Enhanced Security Admin Environment (ESAE) tiered administration model for Active Directory. Covers Tier 0/1/2 separation, privileged access workstations (PAWs), administrative forest design, authentication policy silos, and credential theft mitigation.


## When to Use

- When deploying or configuring configuring active directory tiered model capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives
- Implement comprehensive configuring active directory tiered model capability
- Establish automated discovery and monitoring processes
- Integrate with enterprise IAM and security tools
- Generate compliance-ready documentation and reports
- Align with NIST 800-53 access control requirements

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Account Management | AC-2 | Lifecycle management |
| Access Enforcement | AC-3 | Policy-based access control |
| Least Privilege | AC-6 | Minimum necessary permissions |
| Audit Logging | AU-3 | Authentication and access events |
| Identification | IA-2 | User and service identification |

## Verification
- [ ] Implementation tested in non-production environment
- [ ] Security policies configured and enforced
- [ ] Audit logging enabled and forwarding to SIEM
- [ ] Documentation and runbooks complete
- [ ] Compliance evidence generated
