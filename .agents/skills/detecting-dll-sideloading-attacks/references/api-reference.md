# API Reference: Detecting DLL Sideloading Attacks

## Sysmon Event ID 7 (Image Loaded)

```xml
<EventID>7</EventID>
<Data Name="Image">C:\Users\victim\app\signed.exe</Data>
<Data Name="ImageLoaded">C:\Users\victim\app\malicious.dll</Data>
<Data Name="Signed">false</Data>
<Data Name="SignatureStatus">Unavailable</Data>
<Data Name="Hashes">SHA256=abc123...</Data>
```

## python-evtx Usage

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Sysmon.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Filter EventID 7, check Signed=false, non-standard path
```

## Known Sideloading Targets

| Legitimate Executable | Vulnerable DLL |
|----------------------|----------------|
| vmwaretray.exe | vmtools.dll |
| colorcpl.exe | colorui.dll |
| consent.exe | comctl32.dll |
| bginfo.exe | version.dll |
| teams.exe | version.dll |
| winword.exe | wwlib.dll |

## Splunk SPL Detection

```spl
index=sysmon EventCode=7 Signed=false
| where NOT match(ImageLoaded, "(?i)(System32|SysWOW64|Program Files)")
| stats count by Image, ImageLoaded, SignatureStatus, Computer
| where count > 0
```

## Sigma Rule Fields

```yaml
logsource:
  product: windows
  category: image_load
detection:
  selection:
    EventID: 7
    Signed: "false"
  filter:
    ImageLoaded|startswith:
      - "C:\\Windows\\System32\\"
      - "C:\\Program Files\\"
```

## CLI Usage

```bash
python agent.py --sysmon-log Sysmon.evtx
python agent.py --scan-dir C:\Users\victim\Downloads\app\
python agent.py --generate-sigma
```
