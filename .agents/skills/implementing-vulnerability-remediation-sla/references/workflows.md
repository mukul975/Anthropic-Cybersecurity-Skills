# Workflows - Vulnerability Remediation SLA

## Workflow 1: SLA Assignment and Tracking

```
Vulnerability Discovered
    │
    ├──> Determine Severity (CVSS + EPSS + KEV)
    ├──> Determine Asset Tier (CMDB lookup)
    ├──> Calculate SLA Deadline
    │
    ├──> Create Remediation Ticket (Auto)
    │       ├──> Assign to responsible team
    │       ├──> Set SLA deadline
    │       └──> Include remediation instructions
    │
    ├──> Monitor Progress
    │       ├──> 50% elapsed: Status check
    │       ├──> 75% elapsed: Warning notification
    │       └──> 100% elapsed: Breach escalation
    │
    └──> Verify Remediation
            ├──> Re-scan target
            ├──> Confirm vulnerability resolved
            └──> Close ticket
```

## Workflow 2: SLA Breach Escalation

```
SLA Breached (100% elapsed)
    │
    ├──> Day 0: Auto-notify asset owner + manager
    ├──> Day 7: Escalate to department head
    ├──> Day 14: Escalate to CISO
    ├──> Day 30: Require formal risk acceptance
    └──> Day 90: Report to executive committee
```

## Workflow 3: Exception Management

```
Exception Request Submitted
    │
    ├──> Validate justification
    ├──> Verify compensating controls
    ├──> Risk assessment review
    │
    ├──> Approved → Set new deadline, document in system
    └──> Denied → Original SLA enforced, escalate
```
