# Detailed Hunting Workflow - Credential Dumping Detection

## Phase 1: LSASS Memory Access Hunting

### Step 1.1 - Sysmon Event ID 10 Analysis
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(?i)(csrss|svchost|services|lsass|wininit|MsMpEng|MsSense|CrowdStrike)")
| eval suspicious_access=case(
    GrantedAccess="0x1FFFFF", "CRITICAL-Full_Access",
    GrantedAccess="0x1010", "HIGH-VM_Read_Query",
    GrantedAccess="0x1038", "HIGH-Credential_Dump_Mask",
    GrantedAccess="0x0410", "MEDIUM-Query_VM_Read",
    1=1, "LOW-Other"
)
| stats count by SourceImage, GrantedAccess, suspicious_access, Computer, User
| sort -count
```

### Step 1.2 - KQL for Microsoft Defender for Endpoint
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessFileName !in~ ("csrss.exe","svchost.exe","services.exe","MsMpEng.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

### Step 1.3 - CrowdStrike Falcon Query
```
event_simpleName=ProcessRollup2 TargetProcessImageFileName=lsass.exe
| where ContextProcessImageFileName!="csrss.exe" AND ContextProcessImageFileName!="svchost.exe"
| stats count by ContextProcessImageFileName ComputerName UserName
```

## Phase 2: SAM/SECURITY Hive Access

### Step 2.1 - Registry Save Operations
```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)reg\s+(save|export)\s+.*(SAM|SECURITY|SYSTEM)")
| table _time Computer User Image CommandLine ParentImage
```

### Step 2.2 - Shadow Copy for SAM Access
```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)(vssadmin|wmic)\s+.*(shadow|create)")
| append [
    search index=sysmon EventCode=1
    | where match(CommandLine, "(?i)copy.*\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy")
]
| table _time Computer User CommandLine ParentImage
```

## Phase 3: DCSync Detection

### Step 3.1 - Directory Replication Monitoring
```spl
index=wineventlog EventCode=4662
| where match(Properties, "(?i)(1131f6aa|1131f6ad|89e95b76)")
| where NOT match(SubjectUserName, "(?i)(\\$|DomainController)")
| table _time SubjectUserName SubjectDomainName ObjectName Properties
```

The GUIDs to monitor:
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` = DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` = DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c` = DS-Replication-Get-Changes-In-Filtered-Set

### Step 3.2 - Non-DC Source Validation
```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where Computer !in (known_domain_controllers)
| project TimeGenerated, Computer, SubjectAccount, SubjectDomainName
```

## Phase 4: Tool-Specific Detection

### Step 4.1 - Mimikatz Indicators
```spl
index=sysmon (EventCode=1 OR EventCode=10)
| where match(CommandLine, "(?i)(sekurlsa|lsadump|kerberos::list|crypto::cng|privilege::debug)")
    OR (EventCode=10 AND TargetImage="*\\lsass.exe" AND GrantedAccess IN ("0x1010","0x1038"))
| table _time EventCode Computer User Image CommandLine GrantedAccess
```

### Step 4.2 - Comsvcs.dll MiniDump Detection
```spl
index=sysmon EventCode=1 Image="*\\rundll32.exe"
| where match(CommandLine, "(?i)comsvcs.*MiniDump")
| table _time Computer User CommandLine ParentImage
```

### Step 4.3 - ProcDump LSASS Detection
```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)procdump.*(-ma|-accepteula).*lsass")
| table _time Computer User CommandLine ParentImage
```

## Phase 5: Correlation and Impact Assessment

### Step 5.1 - Post-Credential-Dump Lateral Movement
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010","0x1038","0x1FFFFF")
| rename Computer as src_host
| join src_host [
    search index=wineventlog EventCode=4624 Logon_Type=3
    | rename Computer as src_host
]
| table _time src_host User SourceImage dest_host
```

### Step 5.2 - Timeline Construction
Build a timeline correlating:
1. Initial LSASS access event (credential dump)
2. Subsequent authentication events (Pass-the-Hash/Ticket)
3. Lateral movement to new hosts
4. Additional credential dumping on new hosts

## Phase 6: Reporting

### Key Metrics to Report
- Number of unique hosts with LSASS access anomalies
- Tools identified (known vs. custom)
- Accounts potentially compromised
- Lateral movement scope
- Time from initial dump to last detected activity
