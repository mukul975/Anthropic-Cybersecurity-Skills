# API Reference: PowerShell Script Block Logging Analysis

## python-evtx Library

### FileHeader
```python
from Evtx.Evtx import FileHeader
with open(evtx_path, "rb") as f:
    fh = FileHeader(f)
    for record in fh.records():
        xml_string = record.xml()  # Returns XML string of the event
```

### Event XML Structure (Event ID 4104)
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data>
    <Data Name="MessageTotal">3</Data>
    <Data Name="ScriptBlockText">...powershell code...</Data>
    <Data Name="ScriptBlockId">guid-string</Data>
    <Data Name="Path">C:\script.ps1</Data>
  </EventData>
</Event>
```

## lxml etree Parsing
```python
from lxml import etree
NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
root = etree.fromstring(xml_bytes)
event_id = root.find(".//evt:System/evt:EventID", NS).text
data_elems = root.findall(".//evt:EventData/evt:Data", NS)
for elem in data_elems:
    name = elem.get("Name")
    value = elem.text
```

## Script Block Reconstruction
Large PowerShell scripts are split across multiple Event 4104 entries:
- `ScriptBlockId`: Unique GUID shared across all parts
- `MessageNumber`: Part index (1-based)
- `MessageTotal`: Total number of parts
- Reconstruct: concatenate parts ordered by MessageNumber

## Key Detection Patterns
| Pattern | MITRE | Risk |
|---------|-------|------|
| `-EncodedCommand` | T1059.001 | High |
| `FromBase64String` | T1140 | High |
| `Invoke-Expression` / `iex` | T1059.001 | High |
| `DownloadString` / `Net.WebClient` | T1105 | Critical |
| `AmsiUtils` / `amsiInitFailed` | T1562.001 | Critical |
| `Invoke-Mimikatz` | T1003 | Critical |
| High entropy (>5.5) | T1027 | Medium |
