---
name: prioritizing-vulnerabilities-with-cvss-scoring
description: The Common Vulnerability Scoring System (CVSS) is the industry standard framework maintained by FIRST (Forum of Incident Response and Security Teams) for assessing vulnerability severity. CVSS v4.0 (r
domain: cybersecurity
subdomain: vulnerability-management
tags: [vulnerability-management, cve, cvss, risk, prioritization, nist]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Prioritizing Vulnerabilities with CVSS Scoring

## Overview
The Common Vulnerability Scoring System (CVSS) is the industry standard framework maintained by FIRST (Forum of Incident Response and Security Teams) for assessing vulnerability severity. CVSS v4.0 (released November 2023) introduces refined metrics for more accurate scoring. This skill covers calculating CVSS scores, interpreting vector strings, and using CVSS alongside contextual factors like EPSS and CISA KEV for effective vulnerability prioritization.

## Prerequisites
- Understanding of common vulnerability types (buffer overflow, injection, XSS, etc.)
- Familiarity with networking concepts (attack vectors, protocols)
- Access to NVD (National Vulnerability Database) for CVE lookups
- Vulnerability scan results requiring prioritization

## Core Concepts

### CVSS v4.0 Metric Groups

#### 1. Base Metrics (Intrinsic Severity)
Represent the inherent characteristics of a vulnerability:

**Exploitability Metrics:**
- **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P)
- **Attack Complexity (AC)**: Low (L), High (H)
- **Attack Requirements (AT)**: None (N), Present (P) - NEW in v4.0
- **Privileges Required (PR)**: None (N), Low (L), High (H)
- **User Interaction (UI)**: None (N), Passive (P), Active (A) - Expanded in v4.0

**Impact Metrics (Vulnerable System):**
- **Confidentiality (VC)**: None (N), Low (L), High (H)
- **Integrity (VI)**: None (N), Low (L), High (H)
- **Availability (VA)**: None (N), Low (L), High (H)

**Impact Metrics (Subsequent System):**
- **Confidentiality (SC)**: None (N), Low (L), High (H)
- **Integrity (SI)**: None (N), Low (L), High (H)
- **Availability (SA)**: None (N), Low (L), High (H)

#### 2. Threat Metrics (Dynamic Context)
- **Exploit Maturity (E)**: Attacked (A), POC (P), Unreported (U)

#### 3. Environmental Metrics (Organization-Specific)
Modified versions of base metrics reflecting local deployment context, plus:
- **Confidentiality Requirement (CR)**: High (H), Medium (M), Low (L)
- **Integrity Requirement (IR)**: High (H), Medium (M), Low (L)
- **Availability Requirement (AR)**: High (H), Medium (M), Low (L)

#### 4. Supplemental Metrics (Advisory Information)
- **Safety (S)**: Present (P), Negligible (X)
- **Automatable (AU)**: Yes (Y), No (N)
- **Recovery (R)**: Automatic (A), User (U), Irrecoverable (I)
- **Value Density (V)**: Diffuse (D), Concentrated (C)
- **Vulnerability Response Effort (RE)**: Low (L), Moderate (M), High (H)
- **Provider Urgency (U)**: Red, Amber, Green, Clear

### CVSS v4.0 Severity Ratings
| Score Range | Severity |
|-------------|----------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

### CVSS v4.0 Vector String Format
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```
This example represents a network-exploitable vulnerability requiring no privileges, no user interaction, no attack requirements, with high impact on confidentiality, integrity, and availability of the vulnerable system.

## Implementation Steps

### Step 1: Assess Base Metrics
For each vulnerability, evaluate:

```
Example: CVE-2024-3094 (XZ Utils Backdoor)

Attack Vector:        Network (N)     - Exploitable over network
Attack Complexity:    High (H)        - Specific conditions required
Attack Requirements:  Present (P)     - Specific build/config needed
Privileges Required:  None (N)        - No authentication needed
User Interaction:     None (N)        - No victim action needed

Vulnerable System Impact:
  Confidentiality:    High (H)        - Complete access to SSH keys
  Integrity:          High (H)        - Arbitrary code execution
  Availability:       High (H)        - Full system compromise

Subsequent System Impact:
  Confidentiality:    High (H)        - Lateral movement possible
  Integrity:          High (H)        - Network-wide compromise
  Availability:       None (N)        - No downstream availability impact

Vector: CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N
```

### Step 2: Apply Threat Intelligence Context
Enrich CVSS with real-world threat data:

```
Exploit Maturity:     Attacked (A)    - Active exploitation in the wild
EPSS Score:           0.94            - 94% probability of exploitation in 30 days
CISA KEV:            Listed           - Mandatory remediation for federal agencies
```

### Step 3: Calculate Environmental Score
Adjust for organizational context:

```
Confidentiality Req:  High (H)        - Handles PII/financial data
Integrity Req:        High (H)        - Critical business process
Availability Req:     Medium (M)      - Has DR/failover capability

Modified Attack Vector: Network (N)   - Internet-facing deployment
```

### Step 4: Multi-Factor Prioritization Matrix

Combine CVSS with additional prioritization factors:

| Factor | Weight | Source |
|--------|--------|--------|
| CVSS Base Score | 25% | NVD/Scanner |
| EPSS Score | 25% | FIRST EPSS API |
| Asset Criticality | 20% | Asset inventory/CMDB |
| CISA KEV Listed | 15% | CISA catalog |
| Network Exposure | 15% | Network segmentation data |

### Step 5: Define Remediation SLAs

| Priority Level | CVSS Range | EPSS | Asset Tier | SLA |
|---------------|------------|------|------------|-----|
| P1 - Emergency | 9.0-10.0 | >0.5 | Tier 1 | 24-48 hours |
| P2 - Critical | 7.0-8.9 | >0.3 | Tier 1-2 | 7 days |
| P3 - High | 7.0-8.9 | <0.3 | Tier 2-3 | 14 days |
| P4 - Medium | 4.0-6.9 | Any | Any | 30 days |
| P5 - Low | 0.1-3.9 | Any | Any | 90 days |

## Best Practices
1. Never rely solely on CVSS base score for prioritization
2. Always incorporate threat intelligence (EPSS, KEV, exploit databases)
3. Maintain accurate asset criticality ratings in your CMDB
4. Adjust environmental metrics for your specific deployment context
5. Use CVSS v4.0 vector strings for precise communication between teams
6. Document scoring rationale for audit trail and consistency
7. Re-evaluate scores when new threat intelligence becomes available
8. Train remediation teams on interpreting CVSS metrics and vector strings

## Common Pitfalls
- Treating CVSS base score as the sole prioritization factor
- Ignoring environmental metrics that reflect organizational risk
- Not updating threat metrics when exploit maturity changes
- Confusing CVSS severity with actual organizational risk
- Using outdated CVSS v2.0 scores instead of v3.1/v4.0
- Over-relying on scanner-provided scores without validation

## Related Skills
- prioritizing-patches-with-exploit-prediction-scoring
- implementing-risk-based-vulnerability-management
- implementing-vulnerability-remediation-sla
