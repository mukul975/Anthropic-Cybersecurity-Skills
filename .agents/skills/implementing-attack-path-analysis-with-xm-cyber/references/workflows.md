# Workflows - XM Cyber Attack Path Analysis

## Workflow 1: Continuous Exposure Management Lifecycle

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Define Critical  │────>│ Deploy Sensors   │────>│ Run Attack Graph │
│ Assets (Crown    │     │ (On-prem + Cloud)│     │ Analysis         │
│ Jewels)          │     │                  │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
        ┌────────────────────────────────────────────────┘
        v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Identify Choke   │────>│ Prioritize       │────>│ Remediate &      │
│ Points           │     │ Remediation      │     │ Validate         │
└──────────────────┘     └──────────────────┘     └──────────────────┘
        │
        v
┌──────────────────┐
│ Continuous       │ (Loop back to Attack Graph Analysis)
│ Monitoring       │
└──────────────────┘
```

## Workflow 2: Choke Point Remediation

```
For each identified choke point:
    1. Document the entity (host, credential, misconfiguration)
    2. Map all attack paths passing through this choke point
    3. List all critical assets protected if choke point is fixed
    4. Determine remediation action (patch, reconfig, credential rotation)
    5. Estimate fix complexity (easy/moderate/complex)
    6. Calculate risk reduction score (paths * assets / complexity)
    7. Assign to remediation team with priority and SLA
    8. After fix: re-run analysis to confirm path elimination
    9. Document residual risk if paths still exist
```

## Workflow 3: Attack Path to Remediation Ticket

```
XM Cyber Finding:
    "Cached Domain Admin credential on WORKSTATION-042
     enables 47 attack paths to Domain Controller DC-01"
         │
         v
    Remediation Ticket:
        Priority: P1-Emergency
        Title: "Remove cached DA cred on WORKSTATION-042"
        Action: Clear credential cache, implement LAPS,
                restrict DA logon to Tier 0 only
        Impact: Eliminates 47 attack paths to DC-01
        SLA: 48 hours
```
