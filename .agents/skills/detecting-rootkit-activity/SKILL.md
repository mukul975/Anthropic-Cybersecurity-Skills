---
name: detecting-rootkit-activity
description: >
  Detects rootkit presence on compromised systems by identifying hidden processes, hooked
  system calls, modified kernel structures, hidden files, and covert network connections
  using memory forensics, cross-view detection, and integrity checking techniques.
  Activates for requests involving rootkit detection, hidden process discovery, kernel
  integrity checking, or system call hook analysis.
domain: cybersecurity
subdomain: malware-analysis
tags: [malware, rootkit, detection, kernel-analysis, memory-forensics]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Detecting Rootkit Activity

## When to Use

- System shows signs of compromise but standard tools (Task Manager, netstat) show nothing abnormal
- Antivirus/EDR detects rootkit signatures but cannot identify the specific hiding mechanism
- Memory forensics reveals discrepancies between kernel data structures and user-mode tool output
- Investigating a persistent threat that survives remediation attempts and system reboots
- Validating system integrity after a suspected kernel-level compromise

**Do not use** as a first-line detection method; start with standard malware triage and escalate to rootkit analysis when hiding behavior is suspected.

## Prerequisites

- Volatility 3 for memory forensics and kernel structure analysis
- GMER or Rootkit Revealer (Windows) for live system scanning
- rkhunter and chkrootkit (Linux) for filesystem and process integrity checks
- Sysinternals tools (Process Explorer, Autoruns, RootkitRevealer) for Windows analysis
- Memory dump from the suspected system (WinPmem, LiME)
- Clean baseline of the OS for comparison (known-good kernel module hashes)

## Workflow

### Step 1: Cross-View Detection for Hidden Processes

Compare process lists from different data sources to find discrepancies:

```bash
# Volatility: Compare process enumeration methods
# pslist - walks ActiveProcessLinks (EPROCESS linked list - what rootkits manipulate)
vol3 -f memory.dmp windows.pslist > pslist_output.txt

# psscan - scans physical memory for EPROCESS pool tags (rootkit-resistant)
vol3 -f memory.dmp windows.psscan > psscan_output.txt

# Compare outputs to find hidden processes
python3 << 'PYEOF'
pslist_pids = set()
psscan_pids = set()

with open("pslist_output.txt") as f:
    for line in f:
        parts = line.split()
        if len(parts) > 1 and parts[1].isdigit():
            pslist_pids.add(int(parts[1]))

with open("psscan_output.txt") as f:
    for line in f:
        parts = line.split()
        if len(parts) > 1 and parts[1].isdigit():
            psscan_pids.add(int(parts[1]))

hidden = psscan_pids - pslist_pids
if hidden:
    print(f"[!] HIDDEN PROCESSES DETECTED (in psscan but not pslist):")
    for pid in hidden:
        print(f"    PID: {pid}")
else:
    print("[*] No hidden processes detected via cross-view analysis")
PYEOF
```

### Step 2: Detect System Call Hooking

Identify hooks in the System Service Descriptor Table (SSDT) and Import Address Tables:

```bash
# Check SSDT for hooked system calls
vol3 -f memory.dmp windows.ssdt

# Identify hooks pointing outside ntoskrnl.exe or win32k.sys
vol3 -f memory.dmp windows.ssdt | grep -v "ntoskrnl\|win32k"

# Check for Inline hooks (detour patching)
vol3 -f memory.dmp windows.apihooks --pid 4  # System process

# IDT (Interrupt Descriptor Table) analysis
vol3 -f memory.dmp windows.idt

# Check for IRP (I/O Request Packet) hooking on drivers
vol3 -f memory.dmp windows.driverscan
vol3 -f memory.dmp windows.driverirp
```

```
Types of Rootkit Hooks:
━━━━━━━━━━━━━━━━━━━━━
SSDT Hook:         Modifies System Service Descriptor Table entries to redirect
                   system calls through rootkit code (filters process/file listings)

IAT Hook:          Patches Import Address Table of a process to intercept API calls
                   before they reach the kernel

Inline Hook:       Overwrites the first bytes of a function with a JMP to rootkit code
                   (detour/trampoline technique)

IRP Hook:          Intercepts I/O Request Packets to filter disk/network operations
                   at the driver level

DKOM:              Direct Kernel Object Manipulation - unlinking structures like
                   EPROCESS from the ActiveProcessLinks list without hooking
```

### Step 3: Analyze Kernel Modules and Drivers

Identify unauthorized kernel drivers that may be rootkit components:

```bash
# List all loaded kernel modules
vol3 -f memory.dmp windows.modules

# Scan for drivers in memory (including hidden/unlinked)
vol3 -f memory.dmp windows.driverscan

# Compare module lists to find hidden drivers
vol3 -f memory.dmp windows.modscan > modscan.txt
vol3 -f memory.dmp windows.modules > modules.txt

# Check driver signatures and verify against known-good baselines
vol3 -f memory.dmp windows.verinfo

# Dump suspicious driver for static analysis
vol3 -f memory.dmp windows.moddump --base 0xFFFFF80012340000 --dump
```

### Step 4: Detect File and Registry Hiding

Identify files and registry keys hidden by the rootkit:

```bash
# Linux rootkit detection with rkhunter
rkhunter --check --skip-keypress --report-warnings-only

# chkrootkit scanning
chkrootkit -q

# Windows: Compare filesystem views
# Live system file listing vs Volatility filescan
vol3 -f memory.dmp windows.filescan > mem_files.txt

# Check for hidden registry keys
vol3 -f memory.dmp windows.registry.hivelist
vol3 -f memory.dmp windows.registry.printkey --key "SYSTEM\CurrentControlSet\Services"

# Look for hidden services (loaded but not in service registry)
vol3 -f memory.dmp windows.svcscan | grep -i "kernel"
```

### Step 5: Network Connection Analysis

Find hidden network connections and backdoors:

```bash
# Memory-based network connection enumeration
vol3 -f memory.dmp windows.netscan

# Compare with live netstat (if available) to find hidden connections
# Hidden connections: present in memory but not shown by netstat

# Look for raw sockets (often used by rootkits for covert communication)
vol3 -f memory.dmp windows.netscan | grep RAW

# Check for network filter drivers (NDIS hooks)
vol3 -f memory.dmp windows.driverscan | grep -i "ndis\|tcpip\|afd"

# Analyze callback routines registered by drivers
vol3 -f memory.dmp windows.callbacks
```

### Step 6: Integrity Verification

Verify system file and kernel integrity:

```bash
# Check kernel code integrity (compare in-memory kernel to on-disk copy)
vol3 -f memory.dmp windows.moddump --base 0xFFFFF80070000000 --dump
# Compare SHA-256 of dumped ntoskrnl.exe with known-good copy

# Windows: System File Checker (on live system)
sfc /scannow

# Linux: Package integrity verification
rpm -Va  # RPM-based systems
debsums -c  # Debian-based systems

# Compare critical system binaries
find /bin /sbin /usr/bin /usr/sbin -type f -exec sha256sum {} \; > current_hashes.txt
# Compare against baseline: diff baseline_hashes.txt current_hashes.txt

# YARA scan for known rootkit signatures
vol3 -f memory.dmp yarascan.YaraScan --yara-file rootkit_rules.yar
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Rootkit** | Malware designed to maintain persistent, privileged access while hiding its presence from system administrators and security tools |
| **DKOM** | Direct Kernel Object Manipulation; technique of modifying kernel data structures (e.g., unlinking EPROCESS) to hide objects without hooking |
| **SSDT Hooking** | Replacing entries in the System Service Descriptor Table to intercept and filter system call results (hide processes, files, connections) |
| **Inline Hooking** | Patching the first instructions of a function with a jump to rootkit code; the rootkit can filter the function output before returning |
| **Cross-View Detection** | Comparing results from multiple enumeration methods (linked list walk vs memory scan) to identify discrepancies caused by hiding |
| **Kernel Driver** | Code running in kernel mode (Ring 0) with full system access; rootkits use malicious drivers to gain kernel-level control |
| **Bootkits** | Rootkits that infect the boot process (MBR, VBR, or UEFI firmware) to load before the operating system and security tools |

## Tools & Systems

- **Volatility**: Memory forensics framework providing cross-view detection, SSDT analysis, and kernel structure inspection for rootkit detection
- **GMER**: Free Windows rootkit detection tool scanning for SSDT hooks, IDT hooks, IRP hooks, and hidden processes/files/registry
- **rkhunter**: Linux rootkit detection tool checking for known rootkit signatures, suspicious files, and system binary modifications
- **chkrootkit**: Linux tool for detecting rootkit presence through signature-based and anomaly-based checks
- **Sysinternals RootkitRevealer**: Microsoft tool comparing Windows API results with raw filesystem/registry scans to find discrepancies

## Common Scenarios

### Scenario: Investigating a System Where Standard Tools Show No Compromise

**Context**: An endpoint shows network beaconing to a known C2 IP in firewall logs, but the local EDR, Task Manager, and netstat show no suspicious processes or connections. A memory dump has been acquired for analysis.

**Approach**:
1. Run Volatility `psscan` and compare with `pslist` to identify processes hidden via DKOM
2. Run `windows.ssdt` to check for system call hooks that filter process and network listings
3. Run `windows.malfind` to detect injected code in legitimate processes
4. Run `windows.netscan` to find network connections hidden from user-mode tools
5. Run `windows.driverscan` to identify malicious kernel drivers enabling the hiding
6. Dump the rootkit driver and analyze with Ghidra to understand its hooking mechanism
7. Check for boot persistence (MBR/VBR modifications, UEFI firmware implants)

**Pitfalls**:
- Running detection tools on the live compromised system (rootkit may hide from or subvert them)
- Assuming kernel integrity because no SSDT hooks are found (rootkit may use DKOM or inline hooks instead)
- Not checking for both user-mode and kernel-mode rootkit components (many rootkits have both)
- Trusting the rootkit scanner results on a live system; always verify with offline memory forensics

## Output Format

```
ROOTKIT DETECTION ANALYSIS REPORT
====================================
Dump File:        memory.dmp
System:           Windows 10 21H2 x64
Analysis Tool:    Volatility 3.2

CROSS-VIEW DETECTION
Process List Comparison:
  pslist processes:  127
  psscan processes:  129
  [!] HIDDEN PROCESSES: 2
    PID 6784: sysmon64.exe (hidden rootkit component)
    PID 6812: netfilter.exe (hidden network filter)

SSDT HOOK ANALYSIS
[!] Entry 0x004A (NtQuerySystemInformation) hooked -> driver.sys+0x1200
[!] Entry 0x0055 (NtQueryDirectoryFile) hooked -> driver.sys+0x1400
[!] Entry 0x0119 (NtDeviceIoControlFile) hooked -> driver.sys+0x1600
Hook Target: driver.sys at 0xFFFFF800ABCD0000 (unsigned, suspicious)

KERNEL DRIVER ANALYSIS
[!] driver.sys - No digital signature, loaded at 0xFFFFF800ABCD0000
    Size: 45,056 bytes
    SHA-256: abc123def456...
    IRP Hooks: IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL
    Registry: HKLM\SYSTEM\CurrentControlSet\Services\MalDriver

HIDDEN NETWORK CONNECTIONS
PID 6812: 10.1.5.42:49152 -> 185.220.101.42:443 (ESTABLISHED)
  - Not visible via netstat or user-mode tools
  - Filtered by NtDeviceIoControlFile SSDT hook

ROOTKIT CAPABILITIES
- Process hiding (DKOM + SSDT)
- File hiding (NtQueryDirectoryFile hook)
- Network connection hiding (NtDeviceIoControlFile hook)
- Kernel-mode persistence (driver service)

REMEDIATION
- Boot from clean media for offline remediation
- Remove malicious driver from offline registry
- Verify MBR/VBR/UEFI integrity for boot persistence
- Full system rebuild recommended for kernel-level compromise
```
