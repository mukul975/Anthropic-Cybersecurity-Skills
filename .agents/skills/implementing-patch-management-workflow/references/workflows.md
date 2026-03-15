# Workflows - Patch Management

## Workflow 1: End-to-End Patch Lifecycle

```
┌────────────┐   ┌──────────┐   ┌──────────────┐   ┌──────────┐
│  Discover  │──>│  Assess  │──>│  Prioritize  │──>│   Test   │
│  (Vendor   │   │  (CVE    │   │  (CVSS+EPSS  │   │  (Lab    │
│   Feeds)   │   │  Match)  │   │   Scoring)   │   │  Ring 0) │
└────────────┘   └──────────┘   └──────────────┘   └──────────┘
                                                         │
    ┌───────────────────────────────────────────────────┘
    v
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ Approve  │──>│  Deploy  │──>│  Verify  │──>│  Report  │
│ (CAB /   │   │ (Phased  │   │ (Re-scan │   │ (Metrics │
│  Change) │   │  Rings)  │   │  Confirm)│   │  + KPIs) │
└──────────┘   └──────────┘   └──────────┘   └──────────┘
```

## Workflow 2: Emergency Patch Process

For critical zero-day or actively exploited vulnerabilities:

1. **Alert** (T+0h): Vendor advisory or threat intel notification
2. **Triage** (T+1h): Assess applicability and impact
3. **Fast-track Test** (T+4h): Rapid testing on critical systems
4. **Emergency CAB** (T+6h): Expedited approval
5. **Deploy** (T+8h): Direct to production (skip pilot rings)
6. **Verify** (T+12h): Post-patch scan verification
7. **Post-mortem** (T+48h): Review process effectiveness

## Workflow 3: Rollback Procedure

```
Patch Deployment Fails
    │
    ├──> Application Not Starting
    │       └──> Restore from snapshot/backup
    │
    ├──> Performance Degradation
    │       └──> Uninstall patch (wusa /uninstall /kb:NNNNN)
    │
    ├──> Blue Screen / Kernel Panic
    │       └──> Boot to safe mode, remove update
    │
    └──> Network Connectivity Lost
            └──> Console access, rollback patch
```
