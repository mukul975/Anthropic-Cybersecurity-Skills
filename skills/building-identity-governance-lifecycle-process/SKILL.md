---
name: building-identity-governance-lifecycle-process
description: Design identity governance and lifecycle (IGA) programs on platforms like SailPoint, Saviynt, or Entra ID Governance, covering joiner-mover-leaver (JML) automation, role mining, access requests, periodic recertification, and orphaned-account remediation sourced from an HR feed. Use when automating cross-system JML provisioning, remediating former-employee access, or building lifecycle processes for SOX, HIPAA, or GDPR compliance. Do not use for deploying and configuring the SailPoint IGA platform itself - use implementing-identity-governance-with-sailpoint.
domain: cybersecurity
subdomain: identity-access-management
tags:
- identity-governance
- lifecycle-management
- JML
- access-provisioning
- RBAC
- IGA
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- GOVERN-1.1
- GOVERN-1.7
- MAP-1.1
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1098
- T1136
- T1078
- T1531
- T1087
mitre_f3:
  version: '1.1'
  tactics:
  - positioning
  - defense-impairment
  - initial-access
  techniques:
  - id: F1005
    name: Account Manipulation
    tactic: positioning
    source: f3
  - id: F1005.002
    name: 'Account Manipulation: Add Authorized User'
    tactic: positioning
    source: f3
  - id: F1033
    name: Insider Access Abuse
    tactic: initial-access
    source: f3
  - id: F1042
    name: Reactivate Account
    tactic: positioning
    source: f3
  - id: F1006
    name: Account Takeover
    tactic: initial-access
    source: f3
---

# Building Identity Governance Lifecycle Process

## When to Use

- Organization lacks automated joiner-mover-leaver (JML) processes for identity management
- Access provisioning is manual and takes days, creating productivity loss and security gaps
- Former employees retain access to systems after termination (orphaned accounts)
- Role explosion has created thousands of roles with unclear ownership and overlapping entitlements
- Compliance requirements mandate documented identity lifecycle processes (SOX, HIPAA, GDPR)
- No centralized visibility into who has access to what across the enterprise

**Do not use** for single-application user management; identity governance addresses cross-system lifecycle management requiring correlation of authoritative HR sources with downstream application provisioning.

## Prerequisites

- Authoritative HR system (Workday, SAP SuccessFactors, BambooHR) as identity source of truth
- IGA platform (SailPoint, Saviynt, One Identity) or Microsoft Entra ID Governance
- Active Directory and/or Azure AD as primary directory services
- Application connectors for target systems requiring automated provisioning
- Defined organizational role structure and reporting hierarchy
- Stakeholder buy-in from HR, IT, security, and business unit managers

## Workflow

### Step 1: Define Identity Lifecycle States and Transitions

Map the identity lifecycle from hire to termination. The state machine defines seven states (PRE_HIRE, ACTIVE, ROLE_CHANGE, LEAVE_OF_ABSENCE, TERMINATED, REHIRE, DELETED), each with its automated actions and valid transitions, plus retention periods for the terminated-to-deleted window, mailbox, OneDrive, and audit logs.

See the full `IDENTITY_LIFECYCLE` state-machine definition in [references/implementation-code.md](references/implementation-code.md#step-1-identity-lifecycle-state-machine).

### Step 2: Implement Authoritative Source Integration

Connect the HR system as the single source of truth for identity data. The `WorkdayIdentityConnector` authenticates to the Workday REST API, polls for worker changes since the last sync, and maps each worker record to a JML lifecycle event (JOINER, MOVER, LEAVER, PRE_HIRE, LEAVE_OF_ABSENCE) based on status and hire date.

See the full connector implementation in [references/implementation-code.md](references/implementation-code.md#step-2-hr-source-integration-workday-connector).

### Step 3: Implement Role Mining and Birthright Access

Define roles based on job functions for automated provisioning. The `RoleMiningEngine` mines birthright roles (entitlements held by 80%+ of a job code become automatic), detects role explosion via entitlement overlap analysis, and finds orphaned access that no longer aligns with any role definition.

See the full role-mining implementation in [references/implementation-code.md](references/implementation-code.md#step-3-role-mining-engine).

### Step 4: Build Access Request and Approval Workflow

Implement self-service access requests with risk-based approvals. The `ACCESS_REQUEST_WORKFLOW` defines four risk levels (LOW, MEDIUM, HIGH, CRITICAL) with escalating approval chains, SLAs, justification, time-limit, and SOD-check requirements. The `AccessRequestEngine` classifies each request, auto-approves birthright access, runs SOD checks, and builds the approval chain.

See the full workflow engine and risk catalog in [references/implementation-code.md](references/implementation-code.md#step-4-access-request-and-approval-workflow).

### Step 5: Implement Orphaned Account Detection and Remediation

Identify and remediate accounts without active identity associations. The `OrphanedAccountDetector` compares application accounts against active HR employees, flags terminated-but-active and uncorrelated accounts, assesses risk (privileged/involuntary/active), and generates a prioritized remediation plan with SLAs.

See the full detection and remediation implementation in [references/implementation-code.md](references/implementation-code.md#step-5-orphaned-account-detection-and-remediation).

## Key Concepts

| Term | Definition |
|------|------------|
| **Joiner-Mover-Leaver (JML)** | Core identity lifecycle transitions covering employee onboarding (joiner), role/department changes (mover), and offboarding (leaver) |
| **Birthright Access** | Baseline entitlements automatically provisioned based on job code, department, or location without requiring an access request |
| **Role Mining** | Analysis of existing access patterns to derive role definitions by identifying common entitlement groupings across similar job functions |
| **Orphaned Account** | Application account that no longer has a corresponding active identity in the authoritative HR source, representing a security risk |
| **Authoritative Source** | System of record (typically HR) that serves as the single source of truth for identity attributes and employment status |
| **Access Request Workflow** | Self-service process enabling users to request additional entitlements with risk-based approval routing |

## Tools & Systems

- **SailPoint IdentityIQ/IdentityNow**: Enterprise IGA platform for lifecycle management, access certifications, and automated provisioning
- **Saviynt Enterprise Identity Cloud**: Cloud-native IGA with identity warehouse, access governance, and application access management
- **Microsoft Entra ID Governance**: Identity governance capabilities including lifecycle workflows, access reviews, and entitlement management
- **One Identity Manager**: IGA solution with business role management, attestation, and IT shop for access requests

## Common Scenarios

### Scenario: Building JML Process for 10,000-Employee Organization

**Context**: Rapidly growing company has no automated identity lifecycle. IT manually creates accounts, taking 3-5 days for new hires. Terminated employees retain access for weeks. Audit found 2,300 orphaned accounts across 45 applications.

**Approach**:
1. Integrate Workday as authoritative source with daily delta sync to IGA platform
2. Mine existing access patterns to define birthright roles for the top 20 job codes (covering 80% of employees)
3. Implement pre-hire provisioning triggered 7 days before start date for AD, email, and birthright apps
4. Build termination workflow that disables all access within 1 hour of HR status change
5. Create mover workflow that recalculates roles when job code or department changes
6. Deploy self-service access request portal with risk-based approval chains
7. Run orphaned account detection to identify and remediate the 2,300 existing orphans
8. Schedule quarterly access certifications to prevent access accumulation

**Pitfalls**:
- Not defining a single authoritative source leads to conflicting identity data from multiple HR systems
- Mining roles without business validation creates technical roles that do not align with organizational structure
- Automating termination without grace period for knowledge transfer frustrates business managers
- Not handling contractor and vendor identities that exist outside the HR system

## Output Format

```
IDENTITY GOVERNANCE LIFECYCLE REPORT
=======================================
Authoritative Source:   Workday
IGA Platform:          SailPoint IdentityIQ
Total Identities:      10,247
Active Employees:      9,834
Contractors:           413

LIFECYCLE AUTOMATION
Joiner (Pre-Hire) SLA:     Target: 0 days | Actual: 0.2 days avg
Mover Processing SLA:      Target: 1 day  | Actual: 0.8 days avg
Leaver Disablement SLA:    Target: 1 hour | Actual: 0.5 hours avg

PROVISIONING METRICS (Last 30 Days)
New Hires Provisioned:     187
  Auto-Provisioned:        174 (93.0%)
  Manual Intervention:     13 (7.0%)
Role Changes Processed:    89
Terminations Processed:    43
  Within 1-Hour SLA:       41 (95.3%)

ROLE GOVERNANCE
Defined Roles:             127
Birthright Roles:          48
Average Entitlements/Role: 12.3
Role Overlap > 70%:        8 pairs (consolidation recommended)

ORPHANED ACCOUNTS
Detected:                  23
  Critical:                2 (privileged accounts)
  High:                    8
  Medium:                  13
Remediated (30 days):      19
Outstanding:               4

ACCESS REQUESTS
Submitted:                 342
Auto-Approved (Birthright):87 (25.4%)
Approved:                  231 (67.5%)
Denied:                    24 (7.0%)
Average Approval Time:     6.2 hours
SOD Violations Flagged:    12
```
