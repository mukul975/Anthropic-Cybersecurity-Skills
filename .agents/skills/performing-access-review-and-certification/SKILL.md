---
name: performing-access-review-and-certification
description: Conduct systematic access reviews and certifications to ensure users have appropriate access rights aligned with their roles. This skill covers review campaign design, reviewer selection, risk-based p
domain: cybersecurity
subdomain: identity-access-management
tags: [iam, identity, access-control, access-review, certification, compliance, governance]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Access Review and Certification

## Overview
Conduct systematic access reviews and certifications to ensure users have appropriate access rights aligned with their roles. This skill covers review campaign design, reviewer selection, risk-based prioritization, micro-certification strategies, and remediation tracking for compliance with SOX, HIPAA, and PCI DSS requirements.

## Objectives
- Design and execute access review campaigns across enterprise applications
- Implement risk-based prioritization for review scope
- Configure reviewer selection (manager, application owner, hybrid)
- Automate entitlement data collection and presentation
- Track remediation of inappropriate access findings
- Generate compliance evidence for auditors

## Key Concepts

### Access Review Types
1. **User Access Review**: Manager certifies all entitlements for their direct reports
2. **Entitlement Review**: Application owner certifies all users with specific entitlement
3. **Role Review**: Role owner certifies role membership and permissions
4. **Privileged Access Review**: Security team reviews high-risk/privileged access
5. **SOD Review**: Verify no users have conflicting separation-of-duty violations

### Risk-Based Prioritization
- **High Risk**: Privileged access, financial systems, PII/PHI systems, external-facing apps
- **Medium Risk**: Internal business applications, shared drives, collaboration tools
- **Low Risk**: Standard employee tools, read-only access, public information systems

### Review Campaign Lifecycle
1. **Planning**: Define scope, reviewers, timeline, escalation
2. **Data Collection**: Aggregate entitlements from all identity sources
3. **Distribution**: Assign review items to appropriate certifiers
4. **Certification**: Reviewers approve or revoke each entitlement
5. **Remediation**: Revoke inappropriate access, enforce timeline
6. **Reporting**: Generate compliance evidence and metrics
7. **Closure**: Archive campaign, feed findings into next cycle

## Implementation Steps

### Step 1: Define Review Scope and Schedule
- Identify in-scope applications and systems
- Determine review frequency: quarterly (SOX), semi-annual, annual
- Define campaign timeline: review period, escalation dates, hard close
- Establish escalation chain for non-responsive reviewers

### Step 2: Data Collection and Aggregation
- Extract user-entitlement mappings from each application
- Correlate with HR data (active employees, role, department, manager)
- Identify terminated/transferred users still holding access
- Flag high-risk entitlements (admin, DBA, system, privileged)
- Calculate risk scores based on entitlement sensitivity and user role

### Step 3: Reviewer Assignment
- **Manager Reviews**: Direct manager certifies subordinate access
- **Application Owner Reviews**: App owner certifies all users of their application
- **Hybrid Model**: Manager reviews standard access, app owner reviews privileged
- **Delegate Management**: Allow reviewers to delegate with audit trail

### Step 4: Execute Certification Campaign
- Send notifications to reviewers with clear instructions
- Present entitlements with context (last used date, risk level, role justification)
- Require reviewers to explicitly approve or revoke each item
- Track completion percentage and send reminders
- Escalate to management after deadline

### Step 5: Remediation and Tracking
- Automatically ticket revocations to IT operations
- Set SLA for revocation execution (24-48 hours for high-risk)
- Verify revocation completed (re-check entitlement)
- Exception management for business-justified deviations
- Document all exceptions with expiration dates

### Step 6: Reporting and Evidence
- Generate campaign completion metrics
- Produce per-application compliance reports
- Create audit-ready evidence packages
- Track trends across review cycles
- Feed findings into risk assessment process

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Access Review | AC-2(3) | Periodic review of account privileges |
| Account Management | AC-2 | Account lifecycle management |
| Least Privilege | AC-6 | Minimum necessary access enforcement |
| Separation of Duties | AC-5 | SOD conflict identification |
| Audit Logging | AU-6 | Review of access audit records |

## Common Pitfalls
- Rubber-stamping: reviewers approving all access without examination
- Incomplete scope: missing critical applications from review campaigns
- No remediation tracking: revoking access on paper but not in systems
- Inconsistent reviewer assignment causing gaps in coverage
- Not including service accounts and non-human identities

## Verification
- [ ] All in-scope applications included in campaign
- [ ] Reviewers assigned for 100% of entitlements
- [ ] Campaign completion rate exceeds 95%
- [ ] Revocations executed within SLA
- [ ] Audit evidence package complete and archived
- [ ] SOD violations identified and documented
- [ ] Exceptions documented with business justification and expiry
