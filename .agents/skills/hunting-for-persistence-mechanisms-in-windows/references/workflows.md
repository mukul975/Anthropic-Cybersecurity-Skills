# Detailed Hunting Workflow - Windows Persistence

## Phase 1: Registry Persistence Hunting

### Step 1.1 - Run Key Monitoring
```spl
index=sysmon (EventCode=12 OR EventCode=13)
| where match(TargetObject, "(?i)\\\\CurrentVersion\\\\(Run|RunOnce|Policies\\\\Explorer\\\\Run)")
| table _time Computer User EventType TargetObject Details Image
| sort -_time
```

### Step 1.2 - Winlogon Modification
```spl
index=sysmon EventCode=13
| where match(TargetObject, "(?i)\\\\Winlogon\\\\(Shell|Userinit|Notify)")
| table _time Computer User TargetObject Details Image
```

### Step 1.3 - IFEO Injection
```spl
index=sysmon EventCode=13
| where match(TargetObject, "(?i)Image File Execution Options.*\\\\(Debugger|GlobalFlag)")
| table _time Computer User TargetObject Details Image
```

### Step 1.4 - KQL for Registry Persistence
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("CurrentVersion\\Run","Winlogon\\Shell","Image File Execution Options")
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

## Phase 2: Service Persistence Hunting

### Step 2.1 - New Service Installation
```spl
index=wineventlog (EventCode=7045 OR EventCode=4697)
| where NOT match(Service_File_Name, "(?i)(windows|program files|system32)")
| table _time Computer Service_Name Service_File_Name Service_Start_Type Service_Account
| sort -_time
```

### Step 2.2 - Service Binary Path Anomalies
```spl
index=wineventlog EventCode=7045
| where match(Service_File_Name, "(?i)(temp|appdata|public|programdata|users)")
    OR match(Service_File_Name, "(?i)(powershell|cmd\.exe|wscript|cscript|mshta)")
| table _time Computer Service_Name Service_File_Name
```

## Phase 3: WMI Persistence Hunting

### Step 3.1 - WMI Event Subscription
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time Computer User EventType Operation Destination Consumer Filter
| sort -_time
```

### Step 3.2 - PowerShell WMI Creation
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| where match(CommandLine, "(?i)(Register-WmiEvent|Set-WmiInstance|__EventFilter|CommandLineEventConsumer)")
| table _time Computer User CommandLine
```

## Phase 4: COM Hijacking

### Step 4.1 - InprocServer32 Modifications
```spl
index=sysmon EventCode=13
| where match(TargetObject, "(?i)\\\\InprocServer32\\\\$")
| where NOT match(Details, "(?i)(system32|syswow64|program files|windows)")
| table _time Computer User TargetObject Details Image
```

## Phase 5: Scheduled Task Persistence

### Step 5.1 - New Scheduled Tasks
```spl
index=wineventlog (EventCode=4698 OR source="Microsoft-Windows-TaskScheduler/Operational" EventCode=106)
| table _time Computer User Task_Name Task_Content
| sort -_time
```

## Phase 6: Cross-Reference and Validate

### Step 6.1 - Autoruns Comparison
- Export Autoruns data from reference system: `autorunsc.exe -a * -c -h -s -v -vt > autoruns_baseline.csv`
- Export from suspect system: `autorunsc.exe -a * -c -h -s -v -vt > autoruns_current.csv`
- Diff the two outputs to find new entries

### Step 6.2 - Verify Binary Signatures
For each suspicious persistence entry:
1. Check digital signature validity
2. Verify file hash against threat intel
3. Check VirusTotal reputation
4. Analyze with YARA rules
5. Submit to sandbox if needed
