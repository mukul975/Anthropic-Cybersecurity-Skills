# Workflows - Deploying EDR Agent with CrowdStrike

## Workflow 1: Enterprise Sensor Rollout

```
[Plan Deployment]
    │
    ├── Obtain Falcon Console access and CID
    ├── Download sensor installer for each OS
    ├── Create deployment groups (Workstations, Servers, VDI)
    │
    ▼
[Configure Policies Before Deployment]
    │
    ├── Create prevention policies per group
    ├── Configure sensor update policies (pinned vs. auto-update)
    ├── Set sensor grouping tags for auto-assignment
    │
    ▼
[Pilot Deployment (5% of endpoints)]
    │
    ├── Deploy via SCCM/Intune to pilot group
    ├── Monitor for 1 week: performance impact, false positives
    ├── Tune exclusions for LOB applications
    │
    ▼
[Validation]
    │
    ├── All pilot hosts show "Online" in Falcon Console
    ├── Test detection with CsTestDetect
    ├── No critical application breakage
    │
    ▼
[Production Rollout (phased)]
    │
    ├── Phase 1: Workstations (2 weeks)
    ├── Phase 2: Standard servers (2 weeks)
    ├── Phase 3: Critical servers (1 week, change window)
    │
    ▼
[Post-Deployment]
    │
    ├── Enable SIEM integration
    ├── Configure automated response policies
    ├── Establish exclusion review cadence (monthly)
    └── Train SOC on Falcon Console workflows
```

## Workflow 2: Detection Triage in Falcon Console

```
[New Detection Alert]
    │
    ▼
[Review Detection in Falcon Console]
    │
    ├── Severity: Critical/High/Medium/Low/Informational
    ├── Tactic & Technique (ATT&CK mapping)
    ├── Process tree visualization
    ├── Network connections
    │
    ▼
[Assess: True Positive or False Positive?]
    │
    ├── True Positive ──► [Contain Host via Network Containment]
    │                          │
    │                          ▼
    │                     [Launch RTR session for investigation]
    │                          │
    │                          ▼
    │                     [Collect artifacts, kill malicious processes]
    │                          │
    │                          ▼
    │                     [Remediate and release from containment]
    │
    └── False Positive ──► [Create exclusion rule]
                                │
                                ▼
                           [Document exclusion with justification]
                                │
                                ▼
                           [Mark detection as false positive]
```

## Workflow 3: Sensor Troubleshooting

```
[Sensor Issue Reported]
    │
    ▼
[Check Falcon Console Host Status]
    │
    ├── Online ──► [Issue is not connectivity; check policy assignment]
    │
    └── Offline / RFM ──► [Check network connectivity]
                               │
                               ├── Can reach ts01-b.cloudsink.net:443?
                               │     │
                               │     ├── Yes ──► [Check proxy settings]
                               │     │              ▼
                               │     │          [Reconfigure: falconctl -s --apd=false --aph=proxy --app=8080]
                               │     │
                               │     └── No ──► [Firewall blocking; add CrowdStrike domains to allowlist]
                               │
                               ▼
                          [Check sensor service status]
                               │
                               ├── Service running ──► [Review sensor logs in C:\Windows\System32\drivers\CrowdStrike\]
                               │
                               └── Service stopped ──► [Restart: sc start csagent (Windows) or systemctl start falcon-sensor (Linux)]
```

## Workflow 4: Sensor Version Upgrade

```
[New Sensor Version Available]
    │
    ▼
[Review Release Notes in Falcon Console]
    │
    ▼
[Test on pilot group (N-1 update policy)]
    │
    ├── No issues after 1 week ──► [Move production to N update policy]
    │
    └── Issues found ──► [Hold on current version, file support ticket]
                              │
                              ▼
                         [Pin current version in sensor update policy]
```
