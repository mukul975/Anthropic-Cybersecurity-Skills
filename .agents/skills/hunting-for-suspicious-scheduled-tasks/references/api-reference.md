# API Reference: Hunting for Suspicious Scheduled Tasks

## Windows Event IDs

| Event ID | Source | Description |
|----------|--------|-------------|
| 4698 | Security | Scheduled task created |
| 4699 | Security | Scheduled task deleted |
| 4702 | Security | Scheduled task updated |
| 106 | TaskScheduler | Task registered |
| 200/201 | TaskScheduler | Task executed / completed |

## python-evtx

```python
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        eid = root.find(".//ns:EventID", ns).text
        if eid == "4698":
            data = {d.get("Name"): d.text
                    for d in root.findall(".//ns:Data", ns)}
```

## Splunk SPL

```spl
index=wineventlog EventCode=4698
| spath output=TaskName path=EventData.TaskName
| spath output=TaskContent path=EventData.TaskContent
| where NOT match(TaskName, "\\\\Microsoft\\\\Windows\\\\")
| where match(TaskContent, "(?i)(powershell|cmd|wscript|http)")
| table _time Computer SubjectUserName TaskName TaskContent
```

## KQL (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID == 4698
| extend TaskContent = tostring(EventData.TaskContent)
| where TaskContent has_any ("powershell", "cmd.exe", "Temp", "AppData")
| project TimeGenerated, Computer, Account, TaskContent
```

## PowerShell Enumeration

```powershell
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -match 'powershell|cmd|wscript' -or
    $_.Actions.Execute -match '\\Temp\\|\\AppData\\'
} | Select-Object TaskName, TaskPath, @{N='Action';E={$_.Actions.Execute}}
```

### References

- MITRE T1053.005: https://attack.mitre.org/techniques/T1053/005/
- python-evtx: https://github.com/williballenthin/python-evtx
- Sigma rules for schtasks: https://github.com/SigmaHQ/sigma
