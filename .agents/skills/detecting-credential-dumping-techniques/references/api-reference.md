# Credential Dumping Detection API Reference

## Sysmon Event ID 10 - ProcessAccess

### Key Fields
```
SourceImage       - Process accessing LSASS
SourceProcessId   - PID of accessing process
TargetImage       - Should be C:\Windows\System32\lsass.exe
GrantedAccess     - Access rights bitmask
CallTrace         - DLL call stack of the access
```

### Suspicious GrantedAccess Values
| Value | Meaning | Tool Association |
|-------|---------|-----------------|
| 0x1010 | VM_READ + QUERY_LIMITED | Mimikatz |
| 0x1410 | VM_READ + QUERY_INFO | ProcDump |
| 0x1FFFFF | PROCESS_ALL_ACCESS | Various dumpers |
| 0x1438 | VM_READ + QUERY + DUP_HANDLE | Cobalt Strike |
| 0x40 | DUP_HANDLE only | Handle duplication |

## Sysmon Event ID 1 - Process Creation

### Command Line Patterns for Credential Theft
```
# SAM hive export
reg save hklm\sam C:\temp\sam.hiv
reg save hklm\security C:\temp\security.hiv
reg save hklm\system C:\temp\system.hiv

# comsvcs.dll LSASS dump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> dump.bin full

# NTDS.dit extraction
ntdsutil "activate instance ntds" ifm "create full C:\temp"
vssadmin create shadow /for=C:
```

## Splunk SPL Queries

### LSASS Access Detection
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
  GrantedAccess IN ("0x1010","0x1FFFFF","0x1410","0x1438")
  SourceImage!="*\\csrss.exe" SourceImage!="*\\svchost.exe"
| stats count by SourceImage, GrantedAccess, Computer, User
| sort -count
```

### comsvcs.dll MiniDump Detection
```spl
index=sysmon EventCode=1
  (CommandLine="*comsvcs*MiniDump*" OR CommandLine="*comsvcs*#24*")
| table _time, Computer, User, ParentImage, CommandLine
```

### SAM/SECURITY Hive Export
```spl
index=sysmon EventCode=1 Image="*\\reg.exe"
  (CommandLine="*save*hklm\\sam*" OR CommandLine="*save*hklm\\security*")
| table _time, Computer, User, CommandLine
```

## Elastic / KQL Queries

### LSASS Access in Elastic
```kql
event.code: "10" AND
  winlog.event_data.TargetImage: *lsass.exe AND
  winlog.event_data.GrantedAccess: ("0x1010" OR "0x1FFFFF")
```

### Process Creation with Credential Theft Commands
```kql
event.code: "1" AND
  (process.command_line: *comsvcs*MiniDump* OR
   process.command_line: *reg*save*hklm\\sam*)
```

## MITRE ATT&CK Mapping

| Sub-technique | ID | Detection Method |
|---|---|---|
| LSASS Memory | T1003.001 | Sysmon EID 10 GrantedAccess |
| Security Account Manager | T1003.002 | reg.exe save commands |
| NTDS | T1003.003 | ntdsutil / vssadmin commands |
| DCSync | T1003.006 | Event ID 4662 with replication GUIDs |

## CLI Usage

```bash
# Analyze Sysmon XML export
python agent.py --sysmon-xml sysmon_events.xml --output cred_report.json

# Print Splunk detection queries
python agent.py --show-splunk
```
