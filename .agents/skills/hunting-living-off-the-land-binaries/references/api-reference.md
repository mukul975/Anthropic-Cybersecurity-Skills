# API Reference: Hunting Living Off The Land Binaries

## LOLBAS Project API

```python
import requests
resp = requests.get("https://lolbas-project.github.io/api/lolbas.json")
lolbas = resp.json()
# Each entry: {"Name": "Certutil.exe", "Commands": [...], "Paths": [...]}
for entry in lolbas:
    for cmd in entry.get("Commands", []):
        print(cmd["Command"], cmd["Category"])
        # Categories: Download, Execute, Compile, Encode, ...
```

## python-evtx (Event Log Parsing)

```python
import Evtx.Evtx as evtx
from xml.etree import ElementTree as ET

with evtx.Evtx("Security.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        # Event ID 4688 = process creation
        # Sysmon Event ID 1 = process create
```

## Key LOLBAS Detection Patterns

| Binary | Suspicious Pattern | ATT&CK |
|--------|--------------------|--------|
| certutil.exe | `-urlcache -split -f` | T1105 |
| mshta.exe | `vbscript:Execute` | T1218.005 |
| regsvr32.exe | `/s /n /u /i:http` | T1218.010 |
| rundll32.exe | `javascript:` | T1218.011 |
| wmic.exe | `process call create` | T1047 |
| bitsadmin.exe | `/transfer` | T1197 |
| cmstp.exe | `/s .inf` | T1218.003 |

## Windows Event IDs

| ID | Source | Description |
|----|--------|-------------|
| 4688 | Security | Process Creation |
| 1 | Sysmon | Process Create (with command line) |
| 7 | Sysmon | Image Loaded |
| 11 | Sysmon | FileCreate |

### References

- LOLBAS Project: https://lolbas-project.github.io/
- python-evtx: https://github.com/williballenthin/python-evtx
- LOLBAS API: https://lolbas-project.github.io/api/lolbas.json
