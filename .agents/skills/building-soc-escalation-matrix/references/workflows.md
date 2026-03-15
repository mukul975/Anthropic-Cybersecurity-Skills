# Workflows - SOC Escalation Matrix

## Escalation Flow

```
Alert Generated
    |
    v
Tier 1 Triage (15 min)
    |
    +-- P4/P3: Handle to resolution
    |
    +-- P2: Escalate to Tier 2
    |       |
    |       +-- Resolved: Close
    |       +-- Unresolved (4h): Escalate to Tier 3
    |
    +-- P1: Immediate escalation
            |
            v
        Tier 3 + Management Notified
            |
            v
        War Room / Bridge Activated
            |
            v
        Containment within SLA
            |
            v
        Resolution + Post-Incident Review
```

## Notification Matrix

| Priority | Tier 1 | Tier 2 | Tier 3 | SOC Mgr | CISO | Legal |
|---|---|---|---|---|---|---|
| P1 | Aware | Aware | Lead | Notified | Notified | Standby |
| P2 | Aware | Lead | Consulted | Informed | - | - |
| P3 | Lead | Consulted | - | - | - | - |
| P4 | Lead | - | - | - | - | - |
