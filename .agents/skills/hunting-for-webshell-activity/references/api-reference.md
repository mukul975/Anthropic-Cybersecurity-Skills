# API Reference: Hunting for Webshell Activity

## Process Tree Detection

| Parent Process | Child Process | Severity |
|----------------|---------------|----------|
| w3wp.exe | cmd.exe, powershell.exe | CRITICAL |
| httpd/apache2 | bash, sh, python | CRITICAL |
| tomcat/java | cmd.exe, bash | CRITICAL |
| nginx | bash, sh | CRITICAL |

## Splunk SPL - Web Server Shell Spawn

```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(w3wp|httpd|apache2|nginx|tomcat)")
| where match(Image, "(?i)(cmd\.exe|powershell|bash|whoami|net\.exe)")
| table _time Computer ParentImage Image CommandLine User
```

## KQL - Web Shell Process Chain

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd", "apache2", "nginx")
| where FileName in~ ("cmd.exe", "powershell.exe", "bash", "whoami.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## Web Access Log Patterns

```python
webshell_patterns = [
    r"POST\s+.*\.(asp|aspx|php|jsp)\s+",   # POST to script files
    r"cmd=|exec=|command=|shell=",           # Command parameters
    r"c99shell|r57shell|b374k|weevely",      # Known webshell names
]
```

## Sigma Rule - Webshell Detection

```yaml
title: Webshell Spawning Shell Process
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith: '\w3wp.exe'
  child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: parent and child
level: critical
tags:
  - attack.persistence
  - attack.t1505.003
```

### References

- MITRE T1505.003: https://attack.mitre.org/techniques/T1505/003/
- SANS Webshell Detection: https://www.sans.org/white-papers/
- Sigma webshell rules: https://github.com/SigmaHQ/sigma
