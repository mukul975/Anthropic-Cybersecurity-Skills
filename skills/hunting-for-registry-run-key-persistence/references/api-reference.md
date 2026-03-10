# Registry Run Key Persistence (T1547.001) Detection Reference

## Sysmon Event ID 13 - RegistryEvent (Value Set)

### Event Fields
| Field | Description |
|-------|-------------|
| `UtcTime` | Timestamp of registry modification |
| `ProcessGuid` | Unique process identifier |
| `Image` | Full path of modifying process |
| `TargetObject` | Full registry key path + value name |
| `Details` | New registry value data |
| `User` | User account context |

### Registry Paths to Monitor

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
```

## Sysmon Configuration

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="RegistryPersistence" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">Explorer\Shell Folders</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## Splunk Detection Query

```spl
index=sysmon EventCode=13
| where match(TargetObject, "(?i)CurrentVersion\\\\Run")
| eval suspicious=if(match(Details, "(?i)(temp|appdata|downloads|programdata)"), "yes", "no")
| where suspicious="yes"
| stats count by Image, TargetObject, Details, User, host
```

## Sigma Rule

```yaml
title: Suspicious Run Key Persistence
status: stable
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    EventType: SetValue
    TargetObject|contains: '\CurrentVersion\Run'
  filter_legitimate:
    Details|contains:
      - 'SecurityHealth'
      - 'WindowsDefender'
  condition: selection and not filter_legitimate
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## Windows Registry Query (reg.exe)

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

## CLI Usage

```bash
python agent.py --input sysmon_events.json --output report.json
python agent.py --input registry_snapshot.json --output report.json
```

## MITRE ATT&CK Reference

- **Technique**: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
- **Tactic**: Persistence
- **Platforms**: Windows
- **Detection**: Sysmon Event 13, Windows Security Event 4657

## References

- Sysmon Event 13: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013
- Splunk Detection: https://research.splunk.com/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/
- Nextron T1547.001: https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/
