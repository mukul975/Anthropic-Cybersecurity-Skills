# Standards and References - Windows Persistence Hunting

## MITRE ATT&CK Persistence Techniques (TA0003)

### Boot or Logon Autostart Execution (T1547)
| Sub-Technique | Name | Registry/Location |
|---------------|------|-------------------|
| T1547.001 | Registry Run Keys / Startup Folder | HKLM/HKCU Run, RunOnce, Startup |
| T1547.002 | Authentication Package | HKLM\SYSTEM\CurrentControlSet\Control\Lsa |
| T1547.003 | Time Providers | HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders |
| T1547.004 | Winlogon Helper DLL | HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon |
| T1547.005 | Security Support Provider | HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages |
| T1547.006 | Kernel Modules and Extensions | Driver loading |
| T1547.009 | Shortcut Modification | .lnk files in Startup |
| T1547.010 | Port Monitors | HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors |
| T1547.012 | Print Processors | HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments |
| T1547.014 | Active Setup | HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components |
| T1547.015 | Login Items | (macOS) |

### Create or Modify System Process (T1543)
| Sub-Technique | Name |
|---------------|------|
| T1543.003 | Windows Service |
| T1543.004 | Launch Daemon (macOS/Linux) |

### Scheduled Task/Job (T1053)
| Sub-Technique | Name |
|---------------|------|
| T1053.005 | Scheduled Task |
| T1053.003 | Cron |
| T1053.002 | At |

### Event Triggered Execution (T1546)
| Sub-Technique | Name |
|---------------|------|
| T1546.001 | Change Default File Association |
| T1546.002 | Screensaver |
| T1546.003 | WMI Event Subscription |
| T1546.004 | Unix Shell Configuration Modification |
| T1546.007 | Netsh Helper DLL |
| T1546.008 | Accessibility Features (sethc, utilman, narrator) |
| T1546.010 | AppInit DLLs |
| T1546.011 | Application Shimming |
| T1546.012 | Image File Execution Options Injection |
| T1546.013 | PowerShell Profile |
| T1546.015 | COM Hijacking |
| T1546.016 | Installer Packages |

### Hijack Execution Flow (T1574)
| Sub-Technique | Name |
|---------------|------|
| T1574.001 | DLL Search Order Hijacking |
| T1574.002 | DLL Side-Loading |
| T1574.006 | Dynamic Linker Hijacking |
| T1574.008 | Path Interception by Search Order Hijacking |
| T1574.009 | Path Interception by Unquoted Service Path |
| T1574.011 | Services Registry Permissions Weakness |
| T1574.012 | COR_PROFILER |

## Key Registry Persistence Locations

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit
HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
```

## Detection Event IDs

| Source | Event ID | Meaning |
|--------|----------|---------|
| Sysmon | 12 | Registry object created/deleted |
| Sysmon | 13 | Registry value set |
| Sysmon | 14 | Registry object renamed |
| Sysmon | 19 | WMI EventFilter created |
| Sysmon | 20 | WMI EventConsumer created |
| Sysmon | 21 | WMI ConsumerToFilter binding |
| Windows Security | 4697 | Service installed |
| Windows Security | 4698 | Scheduled task created |
| Windows Security | 4699 | Scheduled task deleted |
| Windows Security | 7045 | New service installed |
| Task Scheduler | 106 | Task registered |
| Task Scheduler | 140 | Task updated |
