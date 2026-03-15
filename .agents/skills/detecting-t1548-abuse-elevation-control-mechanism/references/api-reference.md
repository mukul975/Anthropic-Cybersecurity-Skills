# API Reference: T1548 Abuse Elevation Control Mechanism

## MITRE ATT&CK T1548 Sub-Techniques

| Sub-technique | Name | Platform |
|---------------|------|----------|
| T1548.001 | Setuid and Setgid | Linux/macOS |
| T1548.002 | Bypass User Account Control | Windows |
| T1548.003 | Sudo and Sudo Caching | Linux/macOS |
| T1548.004 | Elevated Execution with Prompt | macOS |

## UAC Bypass — Auto-Elevate Binaries

### Known Auto-Elevate Targets
| Binary | Bypass Method |
|--------|---------------|
| `fodhelper.exe` | Registry key hijack |
| `computerdefaults.exe` | ms-settings handler |
| `eventvwr.exe` | mscfile handler |
| `sdclt.exe` | App paths hijack |
| `wsreset.exe` | Bypasses defender |
| `cmstp.exe` | INF file execution |

### Registry Keys for UAC Bypass
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
HKCU\Software\Classes\mscfile\Shell\Open\command
```

## Windows UAC Configuration

### Check UAC Level
```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# EnableLUA = 1 (UAC enabled)
# ConsentPromptBehaviorAdmin = 0-5
```

### ConsentPromptBehaviorAdmin Values
| Value | Behavior |
|-------|----------|
| 0 | Elevate without prompting |
| 1 | Prompt for credentials on secure desktop |
| 2 | Prompt for consent on secure desktop |
| 5 | Prompt for consent (default) |

## Linux Privilege Escalation

### sudo Configuration Check
```bash
sudo -l                    # List allowed commands
cat /etc/sudoers           # Full sudoers file
visudo -c                  # Validate syntax
```

### Find SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null   # SGID
```

### GTFOBins Sudo Escapes
| Binary | Escape |
|--------|--------|
| `vim` | `sudo vim -c ':!/bin/bash'` |
| `find` | `sudo find . -exec /bin/bash \;` |
| `python` | `sudo python -c 'import os; os.system("/bin/bash")'` |
| `nmap` | `sudo nmap --interactive` (old versions) |

## Sysmon Detection Rules

### Event 13 — Registry Value Set
```xml
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">ms-settings\Shell\Open\command</TargetObject>
  <TargetObject condition="contains">mscfile\Shell\Open\command</TargetObject>
</RegistryEvent>
```

## Sigma Rule — UAC Bypass
```yaml
title: UAC Bypass via Fodhelper
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: 'ms-settings\Shell\Open\command'
    condition: selection
level: critical
```
