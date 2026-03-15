# Workflows - Configuring Windows Defender Advanced Settings

## Workflow 1: ASR Rule Deployment

```
[Identify ASR rules to deploy]
    │
    ▼
[Deploy all rules in Audit mode via Intune/GPO]
    │
    ▼
[Monitor ASR audit events for 2-4 weeks]
    │
    ├── Review events in M365 Defender portal
    ├── Identify false positives per rule
    │
    ▼
[Create exclusions for legitimate applications]
    │
    ▼
[Switch low-risk rules to Block mode]
    │  (Office rules, email content, USB)
    │
    ▼
[Monitor for 1 week]
    │
    ├── No issues ──► [Switch remaining rules to Block mode]
    │
    └── Issues found ──► [Add exclusions, maintain Audit mode for affected rules]
                              │
                              ▼
                         [Re-evaluate after 2 weeks]
```

## Workflow 2: Controlled Folder Access Deployment

```
[Enable Controlled Folder Access in Audit mode]
    │
    ▼
[Monitor Event ID 1124 for blocked write attempts]
    │
    ▼
[Categorize blocked applications]
    │
    ├── Legitimate business app ──► [Add to allowed applications list]
    │
    ├── Backup/sync software ──► [Add to allowed applications list]
    │
    └── Unknown/suspicious ──► [Investigate, potentially malicious]
    │
    ▼
[Switch to Enabled (Block) mode]
    │
    ▼
[Add custom protected folders beyond defaults]
    │
    ▼
[Ongoing monitoring via M365 Defender dashboard]
```

## Workflow 3: Defender Configuration Audit

```
[Quarterly Defender Configuration Review]
    │
    ▼
[Export current Defender settings from all endpoints]
    │
    ├── PowerShell: Get-MpPreference | Export-Clixml
    ├── Intune: Endpoint security reports
    │
    ▼
[Compare against security baseline]
    │
    ├── All settings match baseline ──► [Document compliance, next review]
    │
    └── Drift detected ──► [Investigate cause]
                                │
                                ├── Unauthorized change ──► [Security incident, restore settings]
                                │
                                └── Authorized exception ──► [Document, update baseline]
```

## Workflow 4: False Positive Handling

```
[User reports blocked application]
    │
    ▼
[Identify which Defender feature blocked it]
    │
    ├── ASR rule ──► [Check ASR event log for specific rule GUID]
    │                     │
    │                     ▼
    │                [Create ASR exclusion for file/folder/process]
    │
    ├── Controlled Folder ──► [Add application to allowed list]
    │
    ├── Network Protection ──► [Review URL/domain, submit false positive to Microsoft]
    │
    └── Real-time AV ──► [Submit file for analysis, create AV exclusion if clean]
    │
    ▼
[Deploy exclusion via Intune/GPO]
    │
    ▼
[Verify application works, document exclusion]
```
