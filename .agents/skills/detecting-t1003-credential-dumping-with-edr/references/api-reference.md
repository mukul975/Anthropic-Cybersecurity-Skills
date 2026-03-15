# API Reference: T1003 Credential Dumping Detection

## MITRE ATT&CK T1003 Sub-Techniques

| Sub-technique | Name | Detection |
|---------------|------|-----------|
| T1003.001 | LSASS Memory | Sysmon Event 10 |
| T1003.002 | SAM Registry | Event 4688 |
| T1003.003 | NTDS.dit | Event 4688, VSS events |
| T1003.004 | LSA Secrets | Registry access |
| T1003.005 | Cached Domain Creds | Registry access |
| T1003.006 | DCSync | Event 4662 |

## Sysmon Events for Credential Dumping

### Event ID 10 — ProcessAccess
| Field | Description |
|-------|-------------|
| SourceProcessId | PID of accessing process |
| SourceImage | Path of accessing process |
| TargetProcessId | PID of target (lsass.exe) |
| TargetImage | Path of target process |
| GrantedAccess | Access mask |

### Suspicious Access Masks
| Mask | Meaning |
|------|---------|
| 0x1010 | QUERY_LIMITED + VM_READ |
| 0x1FFFFF | PROCESS_ALL_ACCESS |
| 0x1410 | QUERY_INFO + VM_READ |
| 0x0040 | DUP_HANDLE |

### Event ID 1 — ProcessCreate
```xml
<Data Name="Image">C:\tools\mimikatz.exe</Data>
<Data Name="CommandLine">mimikatz.exe "sekurlsa::logonpasswords"</Data>
```

## Windows Security Event Log

### Event 4688 — Process Creation
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688}
```

### Event 4662 — Object Access (DCSync detection)
```
Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  # DS-Replication-Get-Changes
Properties: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  # DS-Replication-Get-Changes-All
```

## CrowdStrike Falcon — Detection Query

### Search for credential access alerts
```http
GET https://api.crowdstrike.com/detects/queries/detects/v1
    ?filter=behaviors.tactic:'Credential Access'
Authorization: Bearer {token}
```

## Microsoft Defender ATP — Advanced Hunting

### LSASS Access KQL
```kql
DeviceProcessEvents
| where FileName == "lsass.exe"
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName !in ("svchost.exe", "csrss.exe")
) on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName
```

## Sigma Rules

### LSASS Memory Access
```yaml
title: LSASS Memory Access by Non-System Process
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1FFFFF'
    filter:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
    condition: selection and not filter
level: critical
```
