---
name: conducting-memory-forensics-with-volatility
description: >
  Performs memory forensics analysis using Volatility 3 to extract evidence of
  malware execution, process injection, network connections, and credential theft
  from RAM dumps captured during incident response. Covers memory acquisition,
  process analysis, DLL inspection, and malware detection. Activates for requests
  involving memory forensics, RAM analysis, Volatility framework, memory dump
  investigation, volatile evidence analysis, or live memory acquisition.
domain: cybersecurity
subdomain: incident-response
tags: [memory-forensics, volatility, RAM-analysis, process-injection, DFIR]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Conducting Memory Forensics with Volatility

## When to Use

- An endpoint has been contained during an active incident and volatile evidence must be preserved
- EDR alerts suggest process injection or fileless malware that only exists in memory
- Encryption keys need to be recovered from a ransomware-infected system before shutdown
- Credential theft (Mimikatz, LSASS dumping) is suspected and evidence must be confirmed
- A rootkit or kernel-level compromise is suspected and disk-based analysis is insufficient

**Do not use** for analyzing disk images or file system artifacts; use disk forensics tools (Autopsy, FTK) for those tasks.

## Prerequisites

- Memory acquisition tool deployed or available: WinPmem, Magnet RAM Capture, DumpIt, or AVML (Linux)
- Volatility 3 installed with Python 3.8+ and required symbol tables
- Sufficient storage for memory dumps (equal to system RAM size, typically 8-64 GB)
- YARA rules for malware detection in memory (Florian Roth's signature-base, custom rules)
- Reference baseline of normal processes and DLLs for the OS version being analyzed
- Chain of custody documentation for evidence handling

## Workflow

### Step 1: Acquire Memory Image

Capture RAM from the target system using a forensically sound method:

**Windows (WinPmem):**
```
winpmem_mini_x64.exe output.raw
```

**Windows (Magnet RAM Capture):**
```
MagnetRAMCapture.exe
# GUI-based, select output path, generates .raw file
```

**Windows (DumpIt):**
```
DumpIt.exe
# Creates memory dump in current directory automatically
```

**Linux (AVML - Acquire Volatile Memory for Linux):**
```
./avml output.lime
```

Document acquisition metadata:
```
Acquisition Record:
━━━━━━━━━━━━━━━━━
Target Host:      WKSTN-042
RAM Size:         16 GB
Dump File:        WKSTN-042_20251115_1445.raw
Dump Size:        16,843,612,160 bytes
SHA-256:          a4b3c2d1e5f6...
Acquisition Tool: WinPmem 4.0
Acquired By:      [Analyst Name]
Timestamp:        2025-11-15T14:45:00Z
```

### Step 2: Identify the Operating System and Profile

Volatility 3 automatically identifies the OS, but verify:

```bash
# Get system information
vol -f WKSTN-042_20251115_1445.raw windows.info

# Output includes:
# OS: Windows 10 22H2 (Build 19045.3693)
# Kernel Base: 0xf8066c200000
# DTB: 0x1aa000
# Symbols: ntkrnlmp.pdb
```

### Step 3: Analyze Running Processes

Examine the process tree for suspicious activity:

```bash
# List all running processes
vol -f memory.raw windows.pslist

# Show process tree (parent-child relationships)
vol -f memory.raw windows.pstree

# Scan for hidden/unlinked processes (rootkit detection)
vol -f memory.raw windows.psscan

# Compare pslist vs psscan to find hidden processes
# Processes in psscan but NOT in pslist may be hidden by rootkits
```

Key indicators of compromise in process analysis:
- `svchost.exe` running without `-k` parameter or with wrong parent (should be `services.exe`)
- `csrss.exe` or `lsass.exe` with abnormal parent process
- Processes with misspelled names (`scvhost.exe`, `lssas.exe`)
- Unusual processes spawned by `outlook.exe`, `winword.exe`, or `excel.exe`
- Multiple instances of processes that should be singletons (`lsass.exe`, `smss.exe`)

### Step 4: Investigate Network Connections

Extract active and recently closed network connections:

```bash
# List all network connections
vol -f memory.raw windows.netscan

# Focus output fields:
# Offset    Proto  LocalAddr     LocalPort  ForeignAddr    ForeignPort  State     PID  Owner
# 0xe10...  TCPv4  10.1.5.42     49721     185.220.101.42  443         ESTAB     3847  update.exe
```

Cross-reference suspicious connections with the process tree to identify C2 communications. Look for:
- Connections to external IPs from unexpected processes
- High port numbers connecting to port 443/80 from non-browser processes
- Connections from `svchost.exe` or system processes to external IPs

### Step 5: Detect Process Injection and Malware

Use malfind to identify injected code and memory-resident malware:

```bash
# Detect injected code in processes
vol -f memory.raw windows.malfind

# Output shows:
# PID  Process       Start      End        Tag  Protection  Hexdump/Disassembly
# 3847 explorer.exe  0x2a10000  0x2a14000  VadS PAGE_EXECUTE_READWRITE
# MZ header detected - injected PE

# Dump suspicious process memory
vol -f memory.raw windows.memmap --pid 3847 --dump

# List DLLs loaded by a suspicious process
vol -f memory.raw windows.dlllist --pid 3847

# Scan memory with YARA rules
vol -f memory.raw windows.yarascan --yara-file malware_rules.yar
```

### Step 6: Extract Credentials and Artifacts

Recover sensitive data from memory:

```bash
# Dump registry hives from memory (for password hash extraction)
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.hashdump

# Extract command line history
vol -f memory.raw windows.cmdline

# List handles (files, registry keys, mutexes)
vol -f memory.raw windows.handles --pid 3847

# Extract clipboard contents
vol -f memory.raw windows.clipboard

# Dump cached files from memory
vol -f memory.raw windows.dumpfiles --pid 3847
```

### Step 7: Generate Forensic Report

Compile findings into a structured analysis report documenting all evidence extracted from memory:

- Process anomalies with PIDs, parent processes, and timestamps
- Network connections with associated process context
- Injected code regions with memory protection flags
- Extracted IOCs (hashes, IPs, domains, mutexes, registry keys)
- YARA rule matches with rule names and match offsets
- Credential exposure (hashes found, accounts at risk)

## Key Concepts

| Term | Definition |
|------|------------|
| **Volatile Evidence** | Data that exists only in RAM and is lost when a system is powered off; includes running processes, network connections, encryption keys |
| **Process Injection** | Technique where malware inserts code into a legitimate process's memory space to evade detection (malfind detects this) |
| **EPROCESS** | Windows kernel data structure representing a process; psscan searches for these structures even when unlinked from the active process list |
| **VAD (Virtual Address Descriptor)** | Windows kernel structure tracking memory regions allocated to a process; malfind examines VADs for executable but non-file-backed regions |
| **Symbol Tables** | OS-specific data structures that Volatility 3 uses to parse memory; downloaded automatically based on detected OS version |
| **PAGE_EXECUTE_READWRITE** | Memory protection flag indicating a region is readable, writable, and executable; common indicator of injected malicious code |
| **Memory-Resident Malware** | Malware that operates entirely in RAM without writing persistent files to disk, making it invisible to traditional disk-based antivirus |

## Tools & Systems

- **Volatility 3**: Primary open-source memory forensics framework; Python 3 rewrite with automatic symbol resolution
- **WinPmem / DumpIt / Magnet RAM Capture**: Memory acquisition tools for Windows systems
- **AVML (Acquire Volatile Memory for Linux)**: Microsoft's open-source Linux memory acquisition tool
- **YARA**: Pattern matching engine for scanning memory dumps against malware signatures and behavioral rules
- **MemProcFS**: Memory analysis tool that presents memory as a virtual file system for intuitive browsing

## Common Scenarios

### Scenario: Detecting Cobalt Strike Beacon in Memory

**Context**: EDR detects suspicious named pipe activity but cannot identify the source. A memory dump is acquired from the suspect endpoint for analysis.

**Approach**:
1. Run `windows.pstree` to identify the process hierarchy and spot abnormal parent-child relationships
2. Run `windows.malfind` to detect injected code regions, particularly in `svchost.exe` or `rundll32.exe`
3. Dump the injected memory region and scan with YARA rules for Cobalt Strike beacon signatures
4. Run `windows.netscan` to identify C2 connections and correlate with the injected process PID
5. Extract the beacon configuration (C2 URLs, sleep time, jitter, watermark) using CobaltStrikeParser
6. Run `windows.cmdline` to identify any post-exploitation commands executed

**Pitfalls**:
- Analyzing only the process list without running malfind (missing injected code in legitimate processes)
- Not capturing memory before isolating the endpoint (EDR containment may trigger malware self-deletion)
- Using Volatility 2 profiles instead of Volatility 3 automatic symbol resolution on newer Windows versions

## Output Format

```
MEMORY FORENSICS ANALYSIS REPORT
==================================
Incident:         INC-2025-1547
Evidence File:    WKSTN-042_20251115_1445.raw
SHA-256:          a4b3c2d1e5f6...
OS Identified:    Windows 10 22H2 (Build 19045)
Analysis Tool:    Volatility 3.2.0

PROCESS ANOMALIES
PID    Process         Parent       Anomaly
3847   update.exe      powershell   Suspicious executable in Temp directory
5102   svchost.exe     explorer     Wrong parent (expected services.exe)
---    [hidden]        ---          Found in psscan but not pslist

INJECTED CODE
PID    Process        Address Range        Protection              Finding
5102   svchost.exe    0x00A10000-0x00A14   PAGE_EXECUTE_READWRITE  MZ header (PE injection)

NETWORK CONNECTIONS
PID    Process      Local              Foreign             State
3847   update.exe   10.1.5.42:49721    185.220.101.42:443  ESTABLISHED
5102   svchost.exe  10.1.5.42:51003    91.215.85.17:8443   ESTABLISHED

YARA MATCHES
Rule: CobaltStrike_Beacon_x64
Match PID: 5102 (svchost.exe)
Offset: 0x00A10240

EXTRACTED IOCS
Hashes:     [SHA-256 of dumped injected code]
C2 IPs:     185.220.101.42, 91.215.85.17
C2 Domains: [extracted from beacon config]
Mutexes:    Global\MSCTF.Shared.MUTEX.ZRQ
```
