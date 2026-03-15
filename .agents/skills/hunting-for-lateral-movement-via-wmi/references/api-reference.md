# API Reference: Hunting for Lateral Movement via WMI

## Detection Event IDs

| Source | Event ID | Description |
|--------|----------|-------------|
| Security | 4688 | Process creation (enable command line auditing) |
| Sysmon | 1 | Process creation with full details |
| WMI-Activity | 5857 | WMI provider loaded |
| WMI-Activity | 5860 | WMI temporary event consumer |
| WMI-Activity | 5861 | WMI permanent event consumer |

## WMI Lateral Movement Process Chain

```
Source Host:                    Destination Host:
wmic.exe                  -->  WmiPrvSE.exe
  process call create            -> cmd.exe /q /c <command>
                                    -> 1> \\127.0.0.1\admin$\__<timestamp> 2>&1
```

## Key Detection Patterns

| Pattern | Indicator | MITRE |
|---------|-----------|-------|
| WmiPrvSE -> cmd.exe | Remote command execution | T1047 |
| WmiPrvSE -> powershell.exe | Remote PowerShell via WMI | T1047 |
| cmd.exe /q /c ... admin$ | WMI output redirection | T1047 |
| Event 5861 consumer | WMI event subscription persistence | T1546.003 |
| wmic process call create | Direct WMI process creation | T1047 |

## Suspicious Child Processes of WmiPrvSE.exe

| Process | Risk Level | Context |
|---------|------------|---------|
| cmd.exe | High | Command execution |
| powershell.exe | High | Script execution |
| mshta.exe | Critical | HTA script execution |
| cscript.exe | High | VBScript/JScript |
| regsvr32.exe | High | COM object registration |
| rundll32.exe | High | DLL execution |

## Command Line Regex Patterns

```python
# WMI remote execution via cmd
r"cmd\.exe\s+/[qQ]\s+/[cC]"

# Output to admin$ share
r"\\\\127\.0\.0\.1\\admin\$\\__\d+"

# WMIC process creation
r"wmic\s+.*process\s+call\s+create"
```

## Sysmon Event 1 Key Fields

| Field | Description |
|-------|-------------|
| Image | Full path of created process |
| ParentImage | Full path of parent process |
| CommandLine | Process command line arguments |
| User | Account that created the process |
| ProcessGuid | Unique process identifier |
| ParentProcessGuid | Parent process identifier |

## WMI-Activity Log Location

```
%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx
```

## References

- MITRE T1047 (WMI): https://attack.mitre.org/techniques/T1047/
- MITRE T1546.003 (WMI Event Subscription): https://attack.mitre.org/techniques/T1546/003/
- Detecting WMI Lateral Movement: https://imphash.medium.com/detecting-lateral-movement-101-part-2
- JPCERT Lateral Movement: https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf
