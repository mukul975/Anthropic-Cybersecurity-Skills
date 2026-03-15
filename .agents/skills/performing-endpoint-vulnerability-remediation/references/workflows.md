# Workflows - Performing Endpoint Vulnerability Remediation

## Workflow 1: Standard Vulnerability Remediation Cycle

```
[Vulnerability Scan Complete]
    │
    ▼
[Import scan results into tracking system]
    │
    ▼
[Risk-based prioritization]
    │
    ├── CVSS + EPSS + CISA KEV + Asset criticality
    │
    ▼
[Assign priorities: P1/P2/P3/P4]
    │
    ▼
[Identify remediation action per CVE]
    │
    ├── Patch available ──► [Schedule patch deployment]
    ├── Config change needed ──► [Create change request]
    ├── No patch available ──► [Apply workaround/compensating control]
    └── Accept risk ──► [Document with CISO approval]
    │
    ▼
[Test patches in staging environment]
    │
    ▼
[Deploy to production (phased rollout)]
    │
    ▼
[Re-scan to validate remediation]
    │
    ├── Vulnerability closed ──► [Mark resolved in tracker]
    │
    └── Still open ──► [Investigate failure, re-remediate]
```

## Workflow 2: Emergency Zero-Day Response

```
[Zero-day CVE announced (CISA alert / vendor advisory)]
    │
    ▼
[Assess exposure: How many endpoints affected?]
    │
    ▼
[Is patch available?]
    │
    ├── Yes ──► [Emergency patch deployment (skip staging)]
    │               │
    │               ▼
    │          [Monitor for deployment failures]
    │               │
    │               ▼
    │          [Validate patch across fleet]
    │
    └── No ──► [Apply vendor workaround immediately]
                    │
                    ├── Disable vulnerable service/feature
                    ├── Deploy network-level mitigation
                    ├── Create EDR detection rule
                    │
                    ▼
               [Monitor for patch release]
                    │
                    ▼
               [Deploy patch when available]
                    │
                    ▼
               [Remove workaround, validate fix]
```

## Workflow 3: Patch Deployment Pipeline

```
[Patch Tuesday (or vendor release)]
    │
    ▼
[Download and catalog new patches]
    │
    ▼
[Risk assessment: Which patches are critical?]
    │
    ▼
[Deploy to test ring (5% of fleet) - Day 1-3]
    │
    ├── Test application compatibility
    ├── Monitor for BSOD, crashes, performance issues
    │
    ▼
[Deploy to pilot ring (20% of fleet) - Day 4-7]
    │
    ├── Broader application testing
    ├── User feedback collection
    │
    ▼
[Deploy to production ring (remaining fleet) - Day 8-14]
    │
    ▼
[Generate compliance report]
    │
    ├── Endpoints patched: X%
    ├── Pending reboot: Y
    └── Failed deployments: Z (investigate)
```

## Workflow 4: SLA Compliance Tracking

```
[Weekly SLA Review]
    │
    ▼
[Query open vulnerabilities grouped by SLA status]
    │
    ├── Within SLA ──► [Track progress, no action needed]
    │
    ├── Approaching SLA (7 days) ──► [Escalate to endpoint team]
    │
    └── Overdue (past SLA) ──► [Escalate to management]
                                     │
                                     ├── Remediation feasible ──► [Emergency remediation]
                                     │
                                     └── Blocked (dependency) ──► [Document exception, compensating control]
```
