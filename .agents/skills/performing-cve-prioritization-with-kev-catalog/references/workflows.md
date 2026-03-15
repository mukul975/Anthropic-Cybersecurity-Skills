# Workflows - CVE Prioritization with KEV Catalog

## Workflow 1: Daily KEV Integration Pipeline

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Fetch KEV JSON   │────>│ Compare with     │────>│ Identify New     │
│ Feed (daily)     │     │ Previous Version │     │ KEV Entries      │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
        ┌────────────────────────────────────────────────┘
        v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Cross-Reference  │────>│ Flag Matching    │────>│ Escalate to P1   │
│ Scan Results     │     │ Vulns in Env     │     │ Emergency        │
└──────────────────┘     └──────────────────┘     └──────────────────┘
        │
        v
┌──────────────────┐     ┌──────────────────┐
│ Notify Remediation│───>│ Track Against    │
│ Teams            │     │ KEV Due Date     │
└──────────────────┘     └──────────────────┘
```

## Workflow 2: Multi-Factor Scoring Pipeline

```
For each CVE in scan results:
    1. Look up CVSS base score from NVD API
    2. Fetch EPSS probability from FIRST API
    3. Check presence in CISA KEV catalog
    4. Check if ransomware-associated in KEV
    5. Look up asset criticality from CMDB
    6. Determine network exposure (internet/DMZ/internal)
    7. Calculate composite risk score
    8. Assign priority level (P1-P5)
    9. Set remediation SLA based on priority
   10. Generate ticket in ITSM system
```

## Workflow 3: KEV-Triggered Threat Hunt

```
When new CVE added to KEV:
    ├── Check if vulnerability exists in environment
    │   ├── Yes: Immediate P1 escalation
    │   │   ├── Search SIEM for exploitation indicators
    │   │   ├── Check EDR for related TTPs
    │   │   └── Initiate incident response if exploitation found
    │   └── No: Document non-applicability
    └── Update threat intelligence feeds with KEV IOCs
```
