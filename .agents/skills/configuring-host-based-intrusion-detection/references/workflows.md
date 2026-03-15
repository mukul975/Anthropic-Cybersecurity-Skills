# Workflows - Configuring Host-Based Intrusion Detection

## Workflow 1: Wazuh HIDS Deployment

```
[Deploy Wazuh Manager]
    │
    ▼
[Configure FIM, rootcheck, and log analysis modules]
    │
    ▼
[Deploy agents to pilot endpoints]
    │
    ▼
[Establish baseline (48 hours)]
    │
    ▼
[Tune rules: suppress false positives, add exclusions]
    │
    ▼
[Deploy agents to production fleet]
    │
    ▼
[Integrate with SIEM]
    │
    ▼
[Create dashboards and alert workflows]
```

## Workflow 2: FIM Alert Investigation

```
[FIM alert: File modified]
    │
    ▼
[Check file path and change details]
    │
    ├── Known system update ──► [Correlate with patch window, close alert]
    ├── Authorized config change ──► [Verify change ticket, close alert]
    └── Unauthorized change ──► [Investigate]
                                     │
                                     ├── Determine who/what changed the file
                                     ├── Review process tree and timeline
                                     │
                                     ├── Malicious ──► [Escalate to IR]
                                     └── Operational ──► [Update change process]
```
