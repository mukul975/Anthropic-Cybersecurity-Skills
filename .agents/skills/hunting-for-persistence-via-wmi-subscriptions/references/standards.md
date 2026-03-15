# Standards and References - WMI Event Subscription Persistence

## MITRE ATT&CK References

| Technique | Name | Description |
|-----------|------|-------------|
| T1546.003 | WMI Event Subscription | Primary persistence technique |
| T1047 | WMI | WMI execution for lateral movement |
| T1059.005 | Visual Basic | VBScript in ActiveScriptEventConsumer |
| T1059.007 | JavaScript | JScript in ActiveScriptEventConsumer |

## WMI Subscription Components

| Component | WMI Class | Purpose |
|-----------|-----------|---------|
| Event Filter | __EventFilter | Defines the trigger (WQL query) |
| Event Consumer | __EventConsumer | Defines the action |
| Binding | __FilterToConsumerBinding | Links filter to consumer |

## Consumer Types and Risk

| Consumer Class | Risk Level | Description |
|---------------|-----------|-------------|
| ActiveScriptEventConsumer | Critical | Executes VBScript/JScript code |
| CommandLineEventConsumer | Critical | Executes arbitrary commands |
| LogFileEventConsumer | Low | Writes to a log file |
| NTEventLogEventConsumer | Low | Writes to Windows Event Log |
| SMTPEventConsumer | Medium | Sends email notifications |

## Common Malicious Filter Queries

| Filter Type | WQL Query | Usage |
|-------------|-----------|-------|
| Process Start | SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' | Execute on specific process start |
| System Startup | SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' | Execute shortly after boot |
| Timer-Based | SELECT * FROM __TimerEvent WHERE TimerID='MyTimer' | Execute at intervals |
| User Logon | SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_LogonSession' | Execute on user logon |

## Detection Events

| Source | Event ID | Description |
|--------|----------|-------------|
| Sysmon | 19 | WmiEventFilter activity detected |
| Sysmon | 20 | WmiEventConsumer activity detected |
| Sysmon | 21 | WmiEventConsumerToFilter activity detected |
| WMI-Activity | 5861 | WMI permanent event subscription created |
| Security | 4688 | Process creation (mofcomp.exe, WmiPrvSe.exe children) |

## Known APT Usage

| Group | Technique Details |
|-------|-------------------|
| APT29 | ActiveScriptEventConsumer with encoded VBScript backdoor |
| APT32 (OceanLotus) | WMI subscription for persistence in targeted attacks |
| FIN8 | CommandLineEventConsumer for PowerShell execution |
| Turla | WMI event subscription combined with COM hijacking |
| HEXANE | WMI persistence in Middle Eastern energy sector attacks |
