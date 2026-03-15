# Workflows - Detecting Evasion Techniques in Endpoint Logs

## Workflow 1: Evasion Technique Threat Hunt

```
[Select evasion technique to hunt]
    │
    ├── T1055 Process Injection
    ├── T1070 Log Tampering
    ├── T1036 Masquerading
    ├── T1562 Security Tool Disabling
    │
    ▼
[Craft detection query (Splunk/KQL/Elastic)]
    │
    ▼
[Execute across 30-90 days of endpoint telemetry]
    │
    ▼
[Triage results]
    │
    ├── Known-good (allowlist) ──► [Add to baseline, refine query]
    ├── Suspicious ──► [Deep investigation]
    │                       │
    │                       ├── Correlate with other telemetry
    │                       ├── Check process tree
    │                       ├── Review network connections
    │                       │
    │                       ├── True positive ──► [Escalate to IR]
    │                       └── False positive ──► [Tune detection]
    │
    └── No results ──► [Validate logging covers technique]
```

## Workflow 2: Detection Rule Deployment

```
[Create Sigma/SIEM detection rule]
    │
    ▼
[Test against historical data]
    │
    ├── High false positive rate ──► [Refine exclusions]
    │
    └── Acceptable FP rate ──► [Deploy in alert mode]
                                     │
                                     ▼
                                [Monitor for 2 weeks]
                                     │
                                     ▼
                                [Review alert quality]
                                     │
                                     ▼
                                [Promote to production detection]
```

## Workflow 3: Evasion Incident Response

```
[Evasion technique detected]
    │
    ▼
[Assess scope: Which endpoints affected?]
    │
    ▼
[Correlate with initial access and persistence]
    │
    ▼
[Determine if adversary achieved objectives]
    │
    ├── Active intrusion ──► [Full incident response]
    │
    └── Isolated event ──► [Remediate endpoint, enhance detection]
```
