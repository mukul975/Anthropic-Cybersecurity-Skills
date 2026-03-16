---
name: zero-trust-architecture-review
description:
  Reviews architecture designs for Zero Trust compliance. Use when evaluating system designs, reviewing architecture
  documents, or assessing Zero Trust alignment. Validates against NIST 800-207 tenets and CISA ZTMM pillars.
domain: cybersecurity
subdomain: zero-trust-architecture
tags: [zero-trust, nist-800-207, cisa-ztmm, architecture-review]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Zero Trust Architecture Review Skill

## Overview

Validate architectural designs against Zero Trust principles from NIST SP 800-207, CISA ZTMM, and Forrester ZTX.
This skill provides a structured approach to evaluating system and network architecture for Zero Trust alignment,
identifying gaps, and recommending improvements.

## Prerequisites

- Familiarity with NIST SP 800-207 and CISA Zero Trust Maturity Model
- Access to architecture design documents under review
- Understanding of the organization's current security posture

## Key Concepts

### NIST SP 800-207 Seven Tenets

1. All data sources and computing services are resources
2. All communication is secured regardless of network location
3. Access to individual resources is granted on a per-session basis
4. Access is determined by dynamic policy
5. Enterprise monitors and measures security posture of all assets
6. Authentication and authorization are dynamic and strictly enforced
7. Enterprise collects information to improve security posture

### CISA ZTMM Five Pillars

Assess maturity (Traditional -> Initial -> Advanced -> Optimal):

- **Identity**: MFA, risk-based auth, JIT access, identity threat detection
- **Devices**: Inventory, posture assessment, EDR, device trust
- **Networks**: Microsegmentation, encryption, ZTNA, monitoring
- **Applications**: Secure SDLC, API security, workload protection
- **Data**: Classification, encryption, DLP, access logging

## Practical Steps

1. Gather architecture documentation and design artifacts
2. Map each component against the NIST SP 800-207 seven tenets
3. Assess maturity level for each CISA ZTMM pillar
4. Identify critical gaps where implicit trust exists
5. Develop prioritized recommendations for remediation

## Verification

### Review Output Format

1. Executive Summary
2. Zero Trust Alignment Score (1-10)
3. Pillar-by-Pillar Analysis
4. Critical Gaps
5. Prioritized Recommendations
6. Implementation Considerations
