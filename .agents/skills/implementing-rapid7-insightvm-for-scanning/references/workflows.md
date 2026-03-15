# Workflows - Rapid7 InsightVM Deployment

## Workflow 1: InsightVM Deployment Pipeline

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Install Security │────>│ Deploy Scan      │────>│ Pair Engines     │
│ Console          │     │ Engines          │     │ with Console     │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
        ┌────────────────────────────────────────────────┘
        v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Configure Scan   │────>│ Set Up Credential│────>│ Create Sites &   │
│ Templates        │     │ Store            │     │ Asset Groups     │
└──────────────────┘     └──────────────────┘     └──────────────────┘
        │
        v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Schedule Scans   │────>│ Deploy Insight   │────>│ Configure        │
│                  │     │ Agents           │     │ Reports & Alerts │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

## Workflow 2: Scan Execution Cycle

```
For each scheduled scan:
    1. Console dispatches scan job to assigned Scan Engine
    2. Engine performs host discovery (ARP, ICMP, TCP SYN)
    3. Engine fingerprints OS and services on discovered hosts
    4. Engine selects vulnerability checks based on fingerprint
    5. If credentials configured: authenticate and perform local checks
    6. Engine reports findings back to Console database
    7. Console correlates with previous scan data (new/fixed/unchanged)
    8. Console updates risk scores and remediation projects
    9. Notifications sent for new critical/high findings
   10. Dashboard and reports refreshed automatically
```

## Workflow 3: Hybrid Scanning Strategy

```
┌─────────────────────────────────────────────────────┐
│                 Enterprise Network                    │
├─────────────────────────────────────────────────────┤
│                                                       │
│  ┌──────────────┐  Engine Scan   ┌────────────────┐ │
│  │ Data Center  │ <───────────── │ DC Scan Engine │ │
│  │ Servers      │                └────────────────┘ │
│  └──────────────┘                                    │
│                                                       │
│  ┌──────────────┐  Engine Scan   ┌────────────────┐ │
│  │ DMZ Servers  │ <───────────── │ DMZ Scan Engine│ │
│  └──────────────┘                └────────────────┘ │
│                                                       │
│  ┌──────────────┐  Agent-Based   ┌────────────────┐ │
│  │ Laptops /    │ <───────────── │ Insight Agent  │ │
│  │ Remote Users │                │ (on endpoint)  │ │
│  └──────────────┘                └────────────────┘ │
│                                                       │
│  ┌──────────────┐  Agent-Based   ┌────────────────┐ │
│  │ Cloud VMs    │ <───────────── │ Insight Agent  │ │
│  │ (AWS/Azure)  │                │ (on instance)  │ │
│  └──────────────┘                └────────────────┘ │
│                                                       │
│           All results ──> Security Console            │
│                        ──> Insight Platform (Cloud)   │
└─────────────────────────────────────────────────────┘
```

## Workflow 4: Remediation Tracking

| Phase | Action | Owner | Timeline |
|-------|--------|-------|----------|
| Discovery | Scan identifies vulnerability | InsightVM | Automated |
| Triage | Severity confirmed, assigned to team | Security Ops | 24 hours |
| Remediation | Patch/config change applied | IT Operations | Per SLA |
| Validation | Re-scan confirms fix | InsightVM | Next scan cycle |
| Closure | Remediation project updated | Security Ops | Automated |
