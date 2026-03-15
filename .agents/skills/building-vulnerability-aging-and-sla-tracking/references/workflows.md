# Workflows - Vulnerability Aging and SLA Tracking

## Workflow 1: SLA Lifecycle

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Vulnerability    │────>│ Assign Severity  │────>│ Calculate SLA    │
│ Discovered       │     │ + Asset Context  │     │ Deadline         │
└──────────────────┘     └──────────────────┘     └──────────────────┘
        │                                                  │
        v                                                  v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Create Ticket    │────>│ Monitor Aging    │────>│ Trigger          │
│ (ITSM)           │     │ (Daily)          │     │ Escalations      │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

## Workflow 2: Escalation Ladder

```
SLA % Elapsed:
    50%  ──> Email reminder to asset owner
    75%  ──> Escalation to owner's manager
    100% ──> CISO notification, marked overdue
    120% ──> VP/CTO escalation, exception required
```

## Workflow 3: Monthly Reporting Cycle

```
Week 1: Collect scan data and aging metrics
Week 2: Generate KPI dashboard
Week 3: Present to security committee
Week 4: Action items assigned, SLA adjustments if needed
```
