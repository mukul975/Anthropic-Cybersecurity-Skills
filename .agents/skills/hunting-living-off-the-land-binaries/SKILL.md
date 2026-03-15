---
name: hunting-living-off-the-land-binaries
description: >
  Detects abuse of Living Off The Land Binaries (LOLBAS) such as certutil, wmic, mshta,
  regsvr32, and rundll32 in Windows event logs and Sysmon telemetry. Builds detection
  rules by cross-referencing process creation events against the LOLBAS project database.
  Use when threat hunting for fileless attack techniques or building SIEM detection rules.
domain: cybersecurity
subdomain: security-operations
tags: [hunting, living, off, the]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Hunting Living Off The Land Binaries

## Instructions

Detect LOLBAS abuse by analyzing Windows process creation events (Event ID 4688 / Sysmon 1)
and matching command lines against known malicious patterns from the LOLBAS project.

```python
import json
import requests

# Fetch LOLBAS database
resp = requests.get("https://lolbas-project.github.io/api/lolbas.json")
lolbas_db = resp.json()

# Extract binary names and suspicious commands
for entry in lolbas_db:
    print(entry["Name"], [cmd["Command"] for cmd in entry.get("Commands", [])])
```

Key detection patterns:
1. certutil -urlcache -split -f (download)
2. mshta vbscript:Execute (script execution)
3. regsvr32 /s /n /u /i:http (squiblydoo)
4. rundll32 javascript: (script execution)
5. wmic process call create (process creation)
6. bitsadmin /transfer (download)

## Examples

```python
# Match Sysmon Event ID 1 against LOLBAS patterns
import Evtx.Evtx as evtx
with evtx.Evtx("Microsoft-Windows-Sysmon.evtx") as log:
    for record in log.records():
        xml = record.xml()
        if "certutil" in xml.lower() and "urlcache" in xml.lower():
            print(f"LOLBAS detected: {xml}")
```
