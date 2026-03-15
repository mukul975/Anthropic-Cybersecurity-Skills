# Access Recertification with Saviynt - Workflows

## Campaign Execution Workflow

```
WEEK 1: PREPARATION
    ├── Review and update certifier assignments
    ├── Verify identity data freshness (HR sync)
    ├── Validate entitlement data accuracy
    ├── Configure campaign template
    └── Schedule campaign launch

WEEK 2: LAUNCH AND REVIEW
    ├── Launch campaign (auto-notifications sent)
    ├── Certifiers receive email with review link
    ├── Certifiers review each line item:
    │   ├── Check user's current role
    │   ├── Review risk score
    │   ├── Check last access date
    │   ├── Compare with peer group
    │   └── Make certify/revoke decision
    └── Day 7: First reminder sent

WEEK 3: FOLLOW-UP
    ├── Day 10: Second reminder sent
    ├── Day 13: Final reminder (escalation warning)
    ├── Security team contacts non-responsive certifiers
    └── Campaign manager reviews progress dashboard

WEEK 4: CLOSE AND REMEDIATE
    ├── Day 14: Campaign due date
    ├── Day 15: Auto-revoke for non-certified items (if configured)
    ├── Revocation tasks created automatically
    ├── Remediation tickets sent to provisioning team
    ├── Access removed from target systems
    └── Campaign report generated for compliance
```

## Certifier Decision Workflow

```
Certifier opens Saviynt certification inbox
    │
    ├── For each user-entitlement pair:
    │
    │   ├── Review Context:
    │   │   ├── User's name, title, department
    │   │   ├── Entitlement name and application
    │   │   ├── Risk score (1-10)
    │   │   ├── Last access: 3 days ago / 180 days ago / Never
    │   │   ├── Peer analysis: 85% of peers have this access
    │   │   └── SoD violation: None / Conflict detected
    │   │
    │   ├── Decision Logic:
    │   │   ├── Active user + Used recently + Peers have it → CERTIFY
    │   │   ├── Active user + Not used in 90+ days → INVESTIGATE
    │   │   ├── User changed department → LIKELY REVOKE
    │   │   ├── SoD violation detected → REVOKE or ESCALATE
    │   │   └── Cannot determine → DELEGATE to app owner
    │   │
    │   └── Record decision with justification
    │
    └── Submit all decisions
```

## Event-Based Certification Workflow

```
User attribute changes in HR system (e.g., department transfer)
    │
    ├── Saviynt detects change via HR connector sync
    │
    ├── User update rule triggers micro-certification:
    │   ├── Scope: All entitlements for this user
    │   ├── Certifier: New manager
    │   └── Due date: 7 days
    │
    ├── New manager reviews all access:
    │   ├── Certify access relevant to new role
    │   ├── Revoke access specific to old role
    │   └── Request new access if needed
    │
    └── Remediation executes for revoked items
```

## Remediation Tracking Workflow

```
Campaign completes with revoked items
    │
    ├── Saviynt creates provisioning tasks for each revocation
    │
    ├── For each revoked entitlement:
    │   ├── Create deprovisioning request
    │   ├── Route to target system connector
    │   ├── Execute removal (API/connector)
    │   ├── Verify removal succeeded
    │   └── Update audit log
    │
    ├── If automated removal fails:
    │   ├── Create manual remediation ticket (ServiceNow)
    │   ├── Assign to application admin
    │   ├── Track SLA compliance
    │   └── Escalate if overdue
    │
    └── Post-remediation verification:
        ├── Re-scan target systems
        ├── Confirm revoked access no longer present
        └── Archive compliance evidence
```
