---
name: detecting-process-injection-techniques
description: >
  Detects and analyzes process injection techniques used by malware including classic DLL
  injection, process hollowing, APC injection, thread hijacking, and reflective loading.
  Uses memory forensics, API monitoring, and behavioral analysis to identify injection
  artifacts. Activates for requests involving process injection detection, code injection
  analysis, hollowed process investigation, or in-memory threat detection.
domain: cybersecurity
subdomain: malware-analysis
tags: [malware, process-injection, detection, memory-forensics, defense-evasion]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Detecting Process Injection Techniques

## When to Use

- EDR alerts on suspicious API call sequences (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
- A legitimate process (explorer.exe, svchost.exe) exhibits unexpected network connections or file operations
- Memory forensics reveals executable code in memory regions that should not contain it
- Investigating living-off-the-land attacks where malware hides inside trusted processes
- Building detection logic for specific injection techniques in EDR or SIEM rules

**Do not use** for standard DLL loading analysis; injection implies unauthorized code placement in a process without that process's cooperation.

## Prerequisites

- Volatility 3 for memory forensics analysis of injection artifacts
- Sysmon configured with Event IDs 8 (CreateRemoteThread) and 10 (ProcessAccess)
- API Monitor or x64dbg for observing injection API calls in real-time
- Process Hacker or Process Explorer for inspecting process memory regions
- Understanding of Windows memory management (VirtualAlloc, VAD, page protections)
- Isolated analysis environment for safe malware execution and monitoring

## Workflow

### Step 1: Identify Injection via Memory Forensics

Use Volatility to detect injected code in process memory:

```bash
# malfind: Primary injection detection plugin
vol3 -f memory.dmp windows.malfind

# malfind detects:
# - Memory regions with PAGE_EXECUTE_READWRITE (RWX) protection
# - PE headers (MZ signature) in non-image VAD entries
# - Executable memory not backed by a file on disk

# Filter by specific process
vol3 -f memory.dmp windows.malfind --pid 852

# Dump injected memory regions for analysis
vol3 -f memory.dmp windows.malfind --dump

# Check VAD (Virtual Address Descriptor) tree for anomalies
vol3 -f memory.dmp windows.vadinfo --pid 852

# Detect hollowed processes (mapped image doesn't match disk)
vol3 -f memory.dmp windows.hollowfind
```

### Step 2: Classify the Injection Technique

Identify which injection method was used based on artifacts:

```
Process Injection Techniques and Detection Artifacts:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Classic DLL Injection
   APIs: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
   Artifact: Loaded DLL in target process not present in known-good baseline
   Detection: New DLL in dlllist not matching disk hash, CreateRemoteThread event

2. Process Hollowing (RunPE)
   APIs: CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> VirtualAllocEx ->
         WriteProcessMemory -> SetThreadContext -> ResumeThread
   Artifact: Process image in memory doesn't match file on disk
   Detection: hollowfind plugin, mismatched PE headers vs disk file

3. APC Injection
   APIs: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC
   Artifact: Alertable thread has queued APC pointing to injected code
   Detection: Thread start addresses outside known modules

4. Thread Hijacking
   APIs: OpenProcess -> VirtualAllocEx -> WriteProcessMemory ->
         SuspendThread -> GetThreadContext -> SetThreadContext -> ResumeThread
   Artifact: Thread instruction pointer changed to injected code
   Detection: Thread context modification, EIP/RIP outside module boundaries

5. Reflective DLL Injection
   APIs: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread (to reflective loader)
   Artifact: DLL loaded in memory but NOT in loaded module list
   Detection: malfind (PE in non-image memory), module not in ldrmodules

6. Process Doppelganging
   APIs: NtCreateTransaction -> NtCreateFile(transacted) -> NtWriteFile ->
         NtCreateSection -> NtRollbackTransaction -> NtCreateProcessEx
   Artifact: Process created from transacted file that was rolled back
   Detection: Process with no corresponding file on disk

7. AtomBombing
   APIs: GlobalAddAtom -> NtQueueApcThread (with GlobalGetAtomName)
   Artifact: Code stored in global atom table, APC triggers copy to target
   Detection: Unusual atom table entries, APC injection indicators
```

### Step 3: Detect Injection via Sysmon Events

Analyze Sysmon and Windows Event Log data:

```bash
# Sysmon Event ID 8: CreateRemoteThread
# Detect when one process creates a thread in another
wevtutil qe "Microsoft-Windows-Sysmon/Operational" \
  /q:"*[System[EventID=8]]" /f:text /c:20

# Sysmon Event ID 10: ProcessAccess
# Detect suspicious access rights to other processes
# DesiredAccess containing PROCESS_VM_WRITE (0x0020) + PROCESS_CREATE_THREAD (0x0002)
wevtutil qe "Microsoft-Windows-Sysmon/Operational" \
  /q:"*[System[EventID=10]]" /f:text /c:20

# Sysmon Event ID 1: Process Creation
# Detect process hollowing via suspicious parent-child relationships
wevtutil qe "Microsoft-Windows-Sysmon/Operational" \
  /q:"*[System[EventID=1]]" /f:text /c:20
```

```python
# Parse Sysmon events for injection indicators
import xml.etree.ElementTree as ET
import subprocess

# Query CreateRemoteThread events
result = subprocess.run(
    ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
     "/q:*[System[EventID=8]]", "/f:xml", "/c:100"],
    capture_output=True, text=True
)

suspicious_injections = []
for event_xml in result.stdout.split("</Event>"):
    if not event_xml.strip():
        continue
    try:
        root = ET.fromstring(event_xml + "</Event>")
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        data = {}
        for d in root.findall(".//e:EventData/e:Data", ns):
            data[d.get("Name")] = d.text

        source = data.get("SourceImage", "")
        target = data.get("TargetImage", "")

        # Flag injections from unusual sources into system processes
        system_procs = ["svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe"]
        if any(p in target.lower() for p in system_procs):
            if not any(p in source.lower() for p in ["csrss.exe", "services.exe", "lsass.exe"]):
                print(f"[!] Suspicious injection: {source} -> {target}")
                suspicious_injections.append(data)
    except:
        pass
```

### Step 4: Analyze Injected Code

Examine the injected payload to understand its purpose:

```bash
# Dump injected code from Volatility malfind
vol3 -f memory.dmp windows.malfind --pid 852 --dump

# Analyze the dumped region
file malfind.*.dmp

# If it contains a PE (MZ header), analyze as a standalone executable
python3 << 'PYEOF'
import pefile

# Attempt to parse as PE
try:
    pe = pefile.PE("malfind.852.0x400000.dmp")
    print("Injected PE detected!")
    print(f"  Architecture: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
    print(f"  Imports:")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"    {entry.dll.decode()}: {len(entry.imports)} functions")
except:
    print("Not a valid PE - likely shellcode")
    # Analyze as shellcode
    with open("malfind.852.0x400000.dmp", "rb") as f:
        shellcode = f.read()
    print(f"  Size: {len(shellcode)} bytes")
    print(f"  First bytes: {shellcode[:32].hex()}")
PYEOF

# Disassemble shellcode
python3 -c "
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
with open('malfind.852.0x400000.dmp', 'rb') as f:
    code = f.read()[:256]
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(code, 0x400000):
    print(f'  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}')
"

# Scan with YARA for known payloads
vol3 -f memory.dmp yarascan.YaraScan --pid 852 --yara-file malware_rules.yar
```

### Step 5: Map to MITRE ATT&CK

Classify detected techniques in the ATT&CK framework:

```
MITRE ATT&CK Process Injection Sub-Techniques (T1055):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
T1055.001  Dynamic-link Library Injection
T1055.002  Portable Executable Injection
T1055.003  Thread Execution Hijacking
T1055.004  Asynchronous Procedure Call (APC)
T1055.005  Thread Local Storage
T1055.008  Ptrace System Calls (Linux)
T1055.009  Proc Memory (/proc/pid/mem - Linux)
T1055.011  Extra Window Memory Injection
T1055.012  Process Hollowing
T1055.013  Process Doppelganging
T1055.014  VDSO Hijacking (Linux)
T1055.015  ListPlanting
```

### Step 6: Create Detection Signatures

Build detection rules for the identified technique:

```yaml
# Sigma rule for CreateRemoteThread injection
title: Suspicious CreateRemoteThread into System Process
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetImage|endswith:
            - '\svchost.exe'
            - '\explorer.exe'
            - '\lsass.exe'
    filter:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\services.exe'
            - '\svchost.exe'
    condition: selection and not filter
level: high
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Process Injection** | Technique of executing code within the address space of another process, typically to evade detection and inherit the target's trust level |
| **Process Hollowing** | Creating a legitimate process in suspended state, unmapping its memory, writing malicious code, and resuming execution to masquerade as the legitimate process |
| **Reflective DLL Injection** | Loading a DLL into a process's memory without using the Windows loader, so the DLL does not appear in the loaded module list |
| **APC Injection** | Queuing an Asynchronous Procedure Call to a thread in the target process, causing it to execute injected code when the thread enters an alertable state |
| **VAD (Virtual Address Descriptor)** | Windows kernel structure describing memory regions in a process; anomalous VAD entries (RWX permissions, non-image PE) indicate injection |
| **CreateRemoteThread** | Windows API creating a thread in another process; the primary mechanism for classic DLL injection and many other injection techniques |
| **PAGE_EXECUTE_READWRITE** | Memory protection allowing read, write, and execute; rarely used by legitimate applications, common indicator of injected code |

## Tools & Systems

- **Volatility (malfind)**: Memory forensics plugin detecting injected code through VAD analysis and PE header scanning in non-image memory regions
- **Sysmon**: System Monitor providing detailed Windows event logging including CreateRemoteThread (EID 8) and ProcessAccess (EID 10)
- **Process Hacker**: Advanced process management tool showing detailed memory regions, thread stacks, and injected modules
- **API Monitor**: Windows tool for monitoring and logging API calls made by processes, useful for observing injection sequences in real-time
- **pe-sieve**: Tool scanning running processes for signs of code injection, hooking, and hollowing

## Common Scenarios

### Scenario: Investigating a Hollowed svchost.exe Process

**Context**: EDR alerts on svchost.exe making HTTPS connections to an external IP. Svchost.exe should only communicate with Microsoft services. Memory analysis is needed to confirm process hollowing.

**Approach**:
1. Capture memory dump of the suspicious svchost.exe process
2. Run Volatility `malfind` to detect injected PE in the process memory
3. Compare the in-memory image base with the on-disk svchost.exe file hash
4. Check the process parent (should be services.exe) and creation parameters
5. Dump the hollowed executable from memory and analyze with Ghidra
6. Run `netscan` to confirm the network connections from the hollowed process
7. Scan dumped code with YARA for malware family identification

**Pitfalls**:
- Assuming all svchost.exe instances are identical (each loads different service DLLs)
- Not checking the parent process (hollowed processes often have wrong parents)
- Relying only on process name matching (attackers specifically target svchost.exe because multiple instances are expected)
- Missing the injection source process that may have already terminated

## Output Format

```
PROCESS INJECTION ANALYSIS REPORT
====================================
Dump File:        memory.dmp
Analysis Tool:    Volatility 3.2 + Sysmon

INJECTION DETECTED
Target Process:   svchost.exe (PID: 852)
Source Process:    malware.exe (PID: 2184) [terminated]
Technique:        Process Hollowing (T1055.012)

EVIDENCE
malfind Results:
  PID 852 (svchost.exe):
    Address: 0x00400000
    Size:    184,320 bytes
    Protection: PAGE_EXECUTE_READWRITE
    Header: MZ (PE32 executable)
    NOT backed by disk file

Process Verification:
  Expected Image: C:\Windows\System32\svchost.exe (SHA-256: aaa...)
  In-Memory Image: Unknown PE (SHA-256: bbb...)
  Result: MISMATCH - HOLLOWED PROCESS

Sysmon Events:
  [4688] malware.exe (PID 2184) created svchost.exe (PID 852) SUSPENDED
  [10]   malware.exe accessed svchost.exe with PROCESS_VM_WRITE
  [8]    malware.exe created remote thread in svchost.exe

INJECTED PAYLOAD ANALYSIS
SHA-256:          bbb123def456...
YARA Match:       CobaltStrike_Beacon_x64
Type:             Cobalt Strike Beacon (HTTP)
C2:               hxxps://185.220.101[.]42/updates

MITRE ATT&CK
T1055.012  Process Hollowing
T1071.001  Web Protocols (HTTPS C2)
T1036.005  Match Legitimate Name (svchost.exe)
```
