# API Reference: Detecting Privilege Escalation Attempts

## Windows Privilege Escalation Techniques

| Technique | MITRE ID | Detection |
|-----------|----------|-----------|
| UAC Bypass | T1548.002 | eventvwr.exe, fodhelper.exe |
| Token Manipulation | T1134 | SeDebugPrivilege (Event 4672) |
| Service Modification | T1543.003 | sc config binpath= |
| Potato Exploits | T1134.001 | JuicyPotato, PrintSpoofer |
| Scheduled Task | T1053.005 | schtasks /ru SYSTEM |

## Linux Privilege Escalation Techniques

| Technique | MITRE ID | Detection |
|-----------|----------|-----------|
| SUID Abuse | T1548.001 | find -perm 4000 |
| Sudo Exploitation | T1548.003 | sudo -l enumeration |
| Kernel Exploit | T1068 | DirtyPipe, PwnKit |
| Cron Abuse | T1053.003 | crontab modification |

## Key Windows Event IDs

| Event ID | Detection |
|----------|-----------|
| 4672 | Special Privileges Assigned |
| 4688 | Process Creation |
| Sysmon 1 | Process Create with cmdline |

## Splunk SPL

```spl
index=wineventlog (EventCode=4672 OR EventCode=4688)
| where match(PrivilegeList, "SeDebugPrivilege")
   OR match(CommandLine, "(?i)(fodhelper|juicypotato)")
| table _time User CommandLine Computer
```

## CLI Usage

```bash
python agent.py --evtx-file Sysmon.evtx
python agent.py --text-log auth.log
```
