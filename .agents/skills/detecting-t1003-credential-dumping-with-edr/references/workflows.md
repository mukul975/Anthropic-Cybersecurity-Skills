# Detailed Hunting Workflow - T1003 Credential Dumping

## Phase 1: LSASS Memory Access Detection

### Step 1.1 - Sysmon Event 10 Analysis
```spl
index=sysmon EventCode=10
| where match(TargetImage, "(?i)lsass\.exe$")
| where NOT match(SourceImage, "(?i)(csrss|lsass|svchost|MsMpEng|WmiPrvSE|SecurityHealthService|smartscreen)\.exe$")
| stats count values(GrantedAccess) as access_masks by SourceImage Computer
| sort -count
```

### Step 1.2 - EDR LSASS Alerts
```kql
AlertInfo
| where Title has_any ("LSASS", "credential", "Mimikatz")
| join AlertEvidence on AlertId
| project Timestamp, Title, DeviceName, FileName, ProcessCommandLine
```

## Phase 2: Credential Tool Detection

### Step 2.1 - Known Tool Command Lines
```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)(sekurlsa|lsadump|kerberos::list|crypto::certificates|privilege::debug)")
    OR match(OriginalFileName, "(?i)mimikatz")
    OR (match(CommandLine, "(?i)procdump") AND match(CommandLine, "(?i)lsass"))
    OR match(CommandLine, "(?i)comsvcs.*MiniDump")
| table _time Computer User Image CommandLine Hashes
```

### Step 2.2 - NTDS.dit Extraction
```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)(vssadmin.*create\s+shadow|wmic\s+shadowcopy|ntdsutil.*ifm|esentutl.*ntds)")
| table _time Computer User CommandLine ParentImage
```

### Step 2.3 - Registry Hive Export
```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)reg\s+(save|export)\s+hklm\\\\(sam|security|system)")
| table _time Computer User CommandLine
```

## Phase 3: Post-Dump Lateral Movement

### Step 3.1 - Pass-the-Hash Detection
```spl
index=wineventlog EventCode=4624 LogonType=9
| where AuthenticationPackageName="Negotiate"
| table _time TargetUserName IpAddress WorkstationName LogonProcessName
```

### Step 3.2 - Suspicious Remote Logons After Dump
```spl
index=wineventlog EventCode=4624 LogonType=3
| where _time > [credential_dump_timestamp]
| stats count by TargetUserName IpAddress WorkstationName
| sort -count
```

## Phase 4: Response Actions
1. Isolate affected endpoints
2. Reset ALL credentials that were potentially on compromised systems
3. Rotate KRBTGT if domain-level compromise suspected
4. Enable Credential Guard and RunAsPPL
5. Deploy ASR rules for LSASS protection
