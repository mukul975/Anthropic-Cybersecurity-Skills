# Workflows - Agentless Vulnerability Scanning

## Workflow 1: Multi-Protocol Scanning Pipeline

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Asset Discovery  │────>│ Classify by      │────>│ Select Scanning  │
│ (CMDB/Network)   │     │ OS / Platform    │     │ Protocol         │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
        ┌──────────────┬──────────────┬─────────────────┘
        v              v              v
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ SSH Scan     │ │ WinRM Scan   │ │ Cloud API    │
│ (Linux)      │ │ (Windows)    │ │ Snapshot Scan│
└──────────────┘ └──────────────┘ └──────────────┘
        │              │              │
        └──────────────┴──────────────┘
                       │
                       v
              ┌──────────────────┐
              │ Normalize &      │
              │ Correlate Results│
              └──────────────────┘
```

## Workflow 2: Cloud Snapshot Scan Process

```
For each cloud VM:
    1. Identify attached volumes (root + data)
    2. Create snapshot of root volume via cloud API
    3. Mount snapshot in isolated analysis environment
    4. Extract OS metadata (packages, configs, users)
    5. Compare against vulnerability databases (NVD, vendor)
    6. Generate findings with CVE mappings
    7. Delete temporary snapshot
    8. Report findings to central dashboard
```

## Workflow 3: Credential Validation Before Scan

```
Pre-Scan Credential Check:
    For each target:
        1. Test SSH/WinRM connectivity (TCP handshake)
        2. Authenticate with stored credentials
        3. Execute lightweight test command
        4. Verify sudo/admin privileges if required
        5. Log result: Success / Auth Failure / Network Error
        6. Only proceed with scan if credential test passes
```
