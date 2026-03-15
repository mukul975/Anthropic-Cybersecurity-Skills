# API Reference: Hunting for Shadow Copy Deletion

## python-evtx

```python
import Evtx.Evtx as evtx

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        xml_str = record.xml()       # full XML of event
        ts = record.timestamp()      # datetime object
```

## Detection Patterns

| Pattern | Technique | Severity |
|---------|-----------|----------|
| `vssadmin delete shadows` | T1490 | CRITICAL |
| `wmic shadowcopy delete` | T1490 | CRITICAL |
| `bcdedit /set recoveryenabled no` | T1490 | HIGH |
| `wbadmin delete catalog` | T1490 | HIGH |
| `Win32_ShadowCopy.Delete()` | T1490 | CRITICAL |

## Splunk SPL

```spl
index=wineventlog (EventCode=4688 OR EventCode=1)
| where match(CommandLine, "(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)")
| table _time Computer User CommandLine ParentImage
```

## KQL (Microsoft Sentinel)

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete",
    "bcdedit /set", "wbadmin delete catalog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## Sigma Rule Format

```yaml
title: Shadow Copy Deletion
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  condition: selection
level: critical
tags:
  - attack.impact
  - attack.t1490
```

### References

- MITRE T1490: https://attack.mitre.org/techniques/T1490/
- python-evtx: https://github.com/williballenthin/python-evtx
- Sigma Rules: https://github.com/SigmaHQ/sigma
