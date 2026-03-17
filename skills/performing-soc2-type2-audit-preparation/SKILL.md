---
name: performing-soc-2-type-ii-audit-preparation
description: SOC 2 Type II audit preparation involves designing, implementing, and demonstrating the operational effectiveness of controls aligned to the AICPA Trust Services Criteria (TSC) over a defined audit pe
domain: cybersecurity
subdomain: compliance-governance
tags: [compliance, governance, soc2, audit, trust-services-criteria, aicpa]
nist_csf: [GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, ID.RA, PR.AA, PR.DS, DE.CM, DE.AE, RS.MA]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing SOC 2 Type II Audit Preparation

## Overview
SOC 2 Type II audit preparation involves designing, implementing, and demonstrating the operational effectiveness of controls aligned to the AICPA Trust Services Criteria (TSC) over a defined audit period (typically 6-12 months). Unlike Type I which assesses control design at a point in time, Type II evaluates whether controls operated effectively throughout the entire examination period.

## Prerequisites
- Understanding of AICPA Trust Services Criteria (2017, updated 2022)
- Knowledge of internal control frameworks (COSO 2013)
- Familiarity with organizational IT infrastructure and data flows
- Access to GRC (Governance, Risk, Compliance) tooling

## Core Concepts

### Trust Services Criteria (TSC)
Five categories, with Security (Common Criteria) being mandatory:

| Criteria | Description | Required |
|----------|-------------|----------|
| **Security (CC)** | Protection against unauthorized access | Mandatory |
| **Availability (A)** | System availability for operation and use | Optional |
| **Processing Integrity (PI)** | System processing is complete, valid, accurate, timely, authorized | Optional |
| **Confidentiality (C)** | Information designated as confidential is protected | Optional |
| **Privacy (P)** | Personal information collected, used, retained, disclosed per notice | Optional |

### Common Criteria (CC Series)
Security is organized into 9 series based on COSO principles:

| Series | Focus Area | COSO Principle |
|--------|-----------|----------------|
| CC1 | Control Environment | Integrity and ethical values |
| CC2 | Communication and Information | Quality information for controls |
| CC3 | Risk Assessment | Identify and assess risks |
| CC4 | Monitoring Activities | Monitor and evaluate controls |
| CC5 | Control Activities | Select and develop controls |
| CC6 | Logical and Physical Access | Restrict access to authorized users |
| CC7 | System Operations | Detect and respond to system anomalies |
| CC8 | Change Management | Authorized, tested, approved changes |
| CC9 | Risk Mitigation | Risk mitigation through business processes |

### Type I vs Type II

| Aspect | Type I | Type II |
|--------|--------|---------|
| Scope | Control design at a point in time | Control effectiveness over a period |
| Audit Period | Single date | 6-12 months (typically 12) |
| Evidence | Design documentation | Operating evidence throughout period |
| Assurance | Lower | Higher |
| Market Value | Initial baseline | Industry standard expectation |

## Implementation Steps

### Phase 1: Scoping and Readiness (Weeks 1-4)
1. Determine which TSC categories to include (Security mandatory, others based on customer needs)
2. Define system boundaries and description components:
   - Infrastructure (servers, networks, cloud services)
   - Software (applications, operating systems)
   - People (roles, responsibilities)
   - Procedures (automated and manual)
   - Data (data flows, classification)
3. Select audit firm (CPA firm with SOC experience)
4. Define audit window (start and end dates)
5. Conduct readiness assessment against selected criteria

### Phase 2: Control Design and Implementation (Weeks 5-16)
1. Map organizational controls to TSC criteria
2. Design controls for each applicable criterion:
   - **CC6.1**: Logical access security (SSO, MFA, RBAC)
   - **CC6.2**: System credential management
   - **CC6.3**: Access removal upon termination
   - **CC7.1**: Intrusion detection and monitoring
   - **CC7.2**: Security incident response
   - **CC8.1**: Change management process
3. Implement technical controls:
   - Identity provider (Okta, Azure AD)
   - Endpoint detection and response
   - SIEM for log aggregation
   - Vulnerability scanning
   - Encryption at rest and in transit
4. Implement administrative controls:
   - Security policies and procedures
   - Background check process
   - Security awareness training
   - Vendor management programme
5. Document all controls with:
   - Control objective
   - Control activity description
   - Frequency (continuous, daily, weekly, quarterly, annual)
   - Control owner
   - Evidence type (screenshot, report, ticket, log)

### Phase 3: Evidence Collection Period (Audit Window)
1. Operate controls consistently throughout the audit period
2. Collect and organize evidence:
   - Access review completion records (quarterly)
   - Change management tickets and approvals
   - Incident response logs
   - Vulnerability scan reports
   - Penetration test results
   - Training completion records
   - Backup verification logs
   - System availability reports
3. Maintain evidence repository with clear naming conventions
4. Track control failures and exceptions
5. Implement remediation for any control gaps identified during the period

### Phase 4: Pre-Audit Preparation (Weeks before audit)
1. Perform internal control testing (walkthroughs)
2. Prepare system description document
3. Organize evidence by TSC criterion
4. Brief control owners on audit process
5. Prepare management assertion letter
6. Identify and remediate any last-minute gaps

### Phase 5: Audit Execution
1. Auditor performs inquiry, observation, inspection, and reperformance
2. Provide requested evidence and access
3. Respond to auditor questions and information requests
4. Address any exceptions identified during testing
5. Review draft report for factual accuracy

### Phase 6: Report and Remediation
1. Receive SOC 2 Type II report
2. Address any qualified opinions or control exceptions
3. Distribute report to customers (typically under NDA)
4. Plan remediation for identified exceptions
5. Begin preparing for next audit cycle

## Key Artifacts
- System Description Document
- Control Matrix (TSC mapping)
- Risk Assessment Documentation
- Evidence Repository
- Management Assertion Letter
- SOC 2 Type II Report (Sections I-V)
- Remediation Plan for Exceptions

## Common Pitfalls
- Starting evidence collection too late - need full audit period coverage
- Inconsistent control operation (e.g., missing quarterly access reviews)
- Insufficient system description detail
- Not including subservice organizations (IaaS providers)
- Failing to document complementary user entity controls (CUECs)
- Manual controls without documented evidence of execution

## References
- AICPA Trust Services Criteria 2017 (updated 2022): https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- AICPA SOC 2 Reporting Guide
- COSO Internal Control Framework 2013
- Secureframe SOC 2 Trust Services Criteria Guide: https://secureframe.com/hub/soc-2/trust-services-criteria
