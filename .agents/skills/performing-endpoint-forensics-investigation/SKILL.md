---
name: performing-endpoint-forensics-investigation
description: >
  Performs digital forensics investigation on compromised endpoints including memory acquisition,
  disk imaging, artifact analysis, and timeline reconstruction. Use when investigating security
  incidents, collecting evidence for legal proceedings, or analyzing endpoint compromise scope.
  Activates for requests involving endpoint forensics, memory analysis, disk forensics, or
  incident investigation.
domain: cybersecurity
subdomain: endpoint-security
tags: [endpoint, forensics, memory-analysis, disk-imaging, incident-investigation, Volatility]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Performing Endpoint Forensics Investigation

## When to Use

Use this skill when:
- Investigating a confirmed or suspected endpoint compromise requiring forensic analysis
- Collecting volatile and non-volatile evidence for incident response or legal proceedings
- Analyzing memory dumps for malware, injected code, or credential theft artifacts
- Reconstructing attacker timelines from endpoint artifacts (prefetch, shimcache, amcache)

**Do not use** this skill for live threat hunting (use EDR/SIEM) or network forensics.

## Prerequisites

- Forensic workstation with analysis tools (Volatility 3, KAPE, Autopsy, Eric Zimmerman tools)
- Write-blocker for disk imaging (hardware or software)
- Secure evidence storage with chain-of-custody documentation
- Memory acquisition tool (WinPMEM, FTK Imager, Magnet RAM Capture)
- Administrative access to the target endpoint (or physical access)

## Workflow

### Step 1: Evidence Preservation (Order of Volatility)

Collect evidence from most volatile to least volatile:
```
1. System memory (RAM) - Most volatile
2. Network connections and routing tables
3. Running processes and open files
4. Disk contents (file system)
5. Removable media
6. Logs and backup data - Least volatile
```

**Memory Acquisition**:
```powershell
# WinPMEM (Windows)
winpmem_mini_x64.exe memdump.raw

# FTK Imager - Create memory capture via GUI
# File → Capture Memory → Destination path → Capture Memory

# Linux (LiME kernel module)
sudo insmod lime.ko "path=/evidence/memory.lime format=lime"
```

**Volatile Data Collection**:
```powershell
# Capture running processes
Get-Process | Export-Csv "evidence\processes.csv" -NoTypeInformation
tasklist /v > "evidence\tasklist.txt"

# Capture network connections
netstat -anob > "evidence\netstat.txt"
Get-NetTCPConnection | Export-Csv "evidence\tcp_connections.csv"

# Capture logged-on users
query user > "evidence\logged_users.txt"

# Capture scheduled tasks
schtasks /query /fo CSV /v > "evidence\scheduled_tasks.csv"

# Capture services
Get-Service | Export-Csv "evidence\services.csv"

# Capture DNS cache
ipconfig /displaydns > "evidence\dns_cache.txt"
```

### Step 2: Disk Imaging

```powershell
# FTK Imager - Create forensic disk image
# File → Create Disk Image → Physical Drive → E01 format
# Always verify image hash (MD5/SHA1) matches source

# dd (Linux)
sudo dc3dd if=/dev/sda of=/evidence/disk.dd hash=sha256 log=/evidence/imaging.log

# Verify image integrity
sha256sum /evidence/disk.dd
# Compare with hash generated during imaging
```

### Step 3: Memory Analysis with Volatility 3

```bash
# Identify OS profile
vol -f memdump.raw windows.info

# List running processes
vol -f memdump.raw windows.pslist
vol -f memdump.raw windows.pstree

# Find hidden processes
vol -f memdump.raw windows.psscan

# Analyze network connections
vol -f memdump.raw windows.netscan

# Detect process injection
vol -f memdump.raw windows.malfind

# Extract command line arguments
vol -f memdump.raw windows.cmdline

# Analyze DLLs loaded by processes
vol -f memdump.raw windows.dlllist --pid 1234

# Extract files from memory
vol -f memdump.raw windows.filescan | grep -i "suspicious"
vol -f memdump.raw windows.dumpfiles --pid 1234

# Detect credential theft
vol -f memdump.raw windows.hashdump
vol -f memdump.raw windows.lsadump

# Registry analysis from memory
vol -f memdump.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

### Step 4: Windows Artifact Analysis

```
Key forensic artifacts and their tools:

Prefetch Files (C:\Windows\Prefetch\):
  Tool: PECmd.exe (Eric Zimmerman)
  Shows: Program execution history with timestamps and run counts
  Command: PECmd.exe -d "C:\Windows\Prefetch" --csv output\

ShimCache (AppCompatCache):
  Tool: AppCompatCacheParser.exe
  Shows: Programs that existed on system (even if deleted)
  Command: AppCompatCacheParser.exe -f SYSTEM --csv output\

AmCache (C:\Windows\appcompat\Programs\Amcache.hve):
  Tool: AmcacheParser.exe
  Shows: Program execution with SHA1 hashes and install timestamps
  Command: AmcacheParser.exe -f Amcache.hve --csv output\

NTFS artifacts ($MFT, $UsnJrnl, $LogFile):
  Tool: MFTECmd.exe
  Shows: Complete file system timeline including deleted files
  Command: MFTECmd.exe -f "$MFT" --csv output\

Event Logs:
  Tool: EvtxECmd.exe
  Shows: Security, System, PowerShell, Sysmon events
  Command: EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv output\

Registry Hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT):
  Tool: RECmd.exe with batch files
  Shows: User accounts, services, installed software, USB history
  Command: RECmd.exe -d "C:\Windows\System32\config" --bn BatchExamples\RECmd_Batch_MC.reb --csv output\
```

### Step 5: Timeline Reconstruction

```bash
# Use KAPE for automated artifact collection
kape.exe --tsource C: --tdest C:\evidence\kape_output \
  --target KapeTriage --module !EZParser

# Create super timeline with plaso/log2timeline
log2timeline.py timeline.plaso disk_image.E01
psort.py -o l2tcsv timeline.plaso -w timeline.csv

# Filter timeline around incident timeframe
psort.py -o l2tcsv timeline.plaso "date > '2026-02-20' AND date < '2026-02-22'" -w filtered_timeline.csv
```

### Step 6: Document Findings

Structure forensic report:
```
1. Executive Summary
2. Scope and Methodology
3. Evidence Inventory (with chain of custody)
4. Timeline of Events
5. Findings and Analysis
   - Initial access vector
   - Persistence mechanisms
   - Lateral movement
   - Data access/exfiltration
6. Indicators of Compromise (IOCs)
7. Recommendations
8. Appendices (tool output, hashes, raw evidence)
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Order of Volatility** | Evidence collection priority from most volatile (RAM) to least volatile (backups) |
| **Chain of Custody** | Documented record of evidence handling from collection to presentation |
| **Write Blocker** | Hardware or software device that prevents modification of source evidence |
| **Super Timeline** | Consolidated chronological view of all artifact timestamps for incident reconstruction |
| **Prefetch** | Windows artifact recording program execution history |
| **ShimCache** | Application compatibility artifact tracking program existence on endpoint |

## Tools & Systems

- **Volatility 3**: Memory forensics framework for analyzing RAM dumps
- **KAPE (Kroll Artifact Parser and Extractor)**: Automated triage collection and parsing
- **Eric Zimmerman Tools**: Suite of Windows artifact parsers (PECmd, MFTECmd, RECmd, etc.)
- **Autopsy/Sleuth Kit**: Disk forensics platform for file system analysis
- **FTK Imager**: Forensic imaging and memory acquisition tool
- **Plaso/log2timeline**: Super timeline creation framework

## Common Pitfalls

- **Modifying evidence on live system**: Always image before analysis. Running tools on a live system alters timestamps and memory state.
- **Forgetting chain of custody**: Evidence without documented chain of custody is inadmissible in legal proceedings.
- **Analyzing only disk, ignoring memory**: In-memory-only malware (fileless attacks) leaves no disk artifacts. Always capture memory first.
- **Not hashing evidence**: All evidence must be cryptographically hashed at collection time to prove integrity.
- **Tunnel vision**: Focusing on one artifact when the timeline tells a broader story. Always build a comprehensive timeline.
