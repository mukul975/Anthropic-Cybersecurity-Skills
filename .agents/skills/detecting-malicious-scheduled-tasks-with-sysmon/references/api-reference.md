# Detecting Malicious Scheduled Tasks with Sysmon — API Reference

## Relevant Event IDs

| Event ID | Source | Description |
|----------|--------|-------------|
| 1 | Sysmon | Process Create — captures schtasks.exe with full command line |
| 11 | Sysmon | File Create — task XML written to System32\Tasks |
| 12/13 | Sysmon | Registry Create/Set — task registry modifications |
| 4698 | Security | Scheduled task registered (includes task XML content) |
| 4702 | Security | Scheduled task updated |
| 4699 | Security | Scheduled task deleted |

## schtasks.exe Suspicious Flags

| Flag | Description | Detection Value |
|------|-------------|----------------|
| `/create` | Create new task | Baseline detection |
| `/s <host>` | Remote system target | Lateral movement indicator |
| `/ru SYSTEM` | Run as SYSTEM | Privilege escalation |
| `/sc onstart` | Run at system boot | Persistence |
| `/tr "powershell -enc"` | Encoded PowerShell payload | Obfuscation |
| `/tn \Microsoft\Windows\*` | Masquerade as Microsoft task | Evasion |

## Splunk Detection Queries

```spl
index=sysmon EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*"
| eval suspicious=if(match(CommandLine,"(?i)(\\\\users\\\\public|\\\\temp\\\\|\\-enc)"),"YES","NO")
| where suspicious="YES"
```

```spl
index=wineventlog EventCode=4698
| spath input=TaskContent
| search Command="*powershell*" OR Command="*cmd.exe*"
```

## Sysmon Configuration (Task Monitoring)

```xml
<RuleGroup groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="end with">schtasks.exe</Image>
    <Image condition="end with">at.exe</Image>
  </ProcessCreate>
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">\Windows\System32\Tasks\</TargetFilename>
  </FileCreate>
</RuleGroup>
```

## MITRE ATT&CK

| Technique | ID | Description |
|-----------|----|-------------|
| Scheduled Task/Job | T1053.005 | Create/modify scheduled tasks for persistence |
| Lateral Movement | T1021 | Remote task creation via schtasks /s |

## External References

- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Scheduled Task Detection](https://research.splunk.com/endpoint/7feb7972-7ac3-11eb-bac8-acde48001122/)
- [Red Canary: Scheduled Task](https://redcanary.com/threat-detection-report/techniques/scheduled-task/)
