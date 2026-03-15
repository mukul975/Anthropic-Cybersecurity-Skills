# API Reference: Detecting Living Off the Land Attacks

## LOLBAS Project
- Website: https://lolbas-project.github.io/
- API: https://lolbas-project.github.io/api/lolbas.json
- GitHub: https://github.com/LOLBAS-Project/LOLBAS

## Key LOLBins and MITRE Mappings
| Binary | MITRE ATT&CK | Abuse Type |
|--------|-------------|------------|
| certutil.exe | T1140, T1105 | File download, decode |
| mshta.exe | T1218.005 | Script execution via HTA |
| rundll32.exe | T1218.011 | Proxy execution |
| regsvr32.exe | T1218.010 | COM scriptlet execution |
| msbuild.exe | T1127.001 | Code compilation |
| bitsadmin.exe | T1197, T1105 | File download, persistence |
| wmic.exe | T1047 | WMI execution |
| cscript.exe | T1059.005 | VBS/JS script execution |
| installutil.exe | T1218.004 | .NET install bypass |
| powershell.exe | T1059.001 | Script execution |

## Sysmon Event IDs for Detection
| Event ID | Description |
|----------|------------|
| 1 | Process Create (CommandLine, ParentImage) |
| 3 | Network Connection (detect downloads) |
| 7 | Image Loaded (DLL side-loading) |
| 11 | File Create (dropped payloads) |
| 15 | FileCreateStreamHash (ADS abuse) |

## Sigma Rules for LOLBin Detection
```yaml
title: Certutil File Download
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains|all:
            - 'urlcache'
            - 'split'
            - 'http'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1140
```

## Splunk SPL Detection
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|bitsadmin)\\.exe$")
| eval suspicious=case(
    like(CommandLine, "%urlcache%"), "certutil download",
    like(CommandLine, "%javascript:%"), "script execution",
    like(CommandLine, "%-enc %"), "encoded command",
    true(), "review")
| where suspicious!="review"
| table _time Computer User Image CommandLine ParentImage suspicious
```

## Suspicious Parent-Child Relationships
| Parent | Suspicious Child |
|--------|-----------------|
| winword.exe | cmd.exe, powershell.exe, mshta.exe |
| excel.exe | cmd.exe, powershell.exe, wmic.exe |
| outlook.exe | powershell.exe, cmd.exe |
| wmiprvse.exe | powershell.exe, cmd.exe |
