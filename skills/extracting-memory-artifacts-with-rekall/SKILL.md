---
name: extracting-memory-artifacts-with-rekall
description: 'Uses Rekall memory forensics framework to analyze memory dumps for process
  hollowing, injected code via VAD anomalies, hidden processes, and rootkit detection.
  Applies plugins like pslist, psscan, vadinfo, malfind, and dlllist to extract forensic
  artifacts from Windows memory images. Use during incident response memory analysis.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- memory-forensics
- rekall
- process-hollowing
- code-injection
- vad-analysis
- incident-response
- security-operations
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1078
- T1190
- T1059
- T1055
- T1005
---

# Extracting Memory Artifacts with Rekall


## When to Use

- When performing authorized security testing that involves extracting memory artifacts with rekall
- When analyzing malware samples or attack artifacts in a controlled environment
- When conducting red team exercises or penetration testing engagements
- When building detection capabilities based on offensive technique understanding

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Use Rekall to analyze memory dumps for signs of compromise including process
injection, hidden processes, and suspicious network connections.

```python
from rekall import session
from rekall import plugins

# Create a Rekall session with a memory image
s = session.Session(
    filename="/path/to/memory.raw",
    autodetect=["rsds"],
    profile_path=["https://github.com/google/rekall-profiles/raw/master"]
)

# List processes
for proc in s.plugins.pslist():
    print(proc)

# Detect injected code
for result in s.plugins.malfind():
    print(result)
```

Key analysis steps:
1. Load memory image and auto-detect profile
2. Run pslist and psscan to find hidden processes
3. Use malfind to detect injected/hollowed code in process VADs
4. Examine network connections with netscan
5. Extract suspicious DLLs and drivers with dlllist/modules

## Examples

```python
from rekall import session
s = session.Session(filename="memory.raw")
# Compare pslist vs psscan for hidden processes
pslist_pids = set(p.pid for p in s.plugins.pslist())
psscan_pids = set(p.pid for p in s.plugins.psscan())
hidden = psscan_pids - pslist_pids
print(f"Hidden PIDs: {hidden}")
```
