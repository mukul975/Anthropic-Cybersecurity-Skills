# Standards and References - Suspicious Scheduled Tasks

## MITRE ATT&CK References
| Technique | Name | Usage |
|-----------|------|-------|
| T1053.005 | Scheduled Task | Primary persistence/execution technique |
| T1053.003 | Cron (Linux) | Scheduled execution on Linux |
| T1078 | Valid Accounts | Tasks running under legitimate accounts |

## Windows Event IDs
| Event ID | Source | Description |
|----------|--------|-------------|
| 4698 | Security | Scheduled task created |
| 4699 | Security | Scheduled task deleted |
| 4700 | Security | Scheduled task enabled |
| 4701 | Security | Scheduled task disabled |
| 4702 | Security | Scheduled task updated |
| 106 | TaskScheduler/Operational | Task registered |
| 200 | TaskScheduler/Operational | Action started |
| 201 | TaskScheduler/Operational | Action completed |

## Suspicious Task Indicators
| Indicator | Description |
|-----------|-------------|
| User-writable paths | Actions executing from TEMP, AppData, Downloads |
| Encoded commands | Base64 or -EncodedCommand in arguments |
| Script interpreters | PowerShell, cmd, wscript, cscript as actions |
| Short intervals | Trigger repeating every 1-5 minutes |
| System startup trigger | Task runs at boot for persistence |
| Remote creation | Task created from remote system |
| Name mimicry | Task name similar to legitimate Windows tasks |
| Hidden SD | Security Descriptor modified to hide task |
