---
name: performing-disk-forensics-investigation
description: >
  Conducts disk forensics investigations using forensic imaging, file system analysis,
  artifact recovery, and timeline reconstruction to support incident response cases.
  Utilizes tools such as FTK Imager, Autopsy, and The Sleuth Kit for evidence acquisition,
  deleted file recovery, and artifact examination. Activates for requests involving disk
  forensics, hard drive analysis, forensic imaging, file recovery, evidence acquisition,
  or digital forensic investigation.
domain: cybersecurity
subdomain: incident-response
tags: [disk-forensics, forensic-imaging, evidence-acquisition, file-recovery, chain-of-custody]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing Disk Forensics Investigation

## When to Use

- A security incident requires forensic analysis of a system's persistent storage
- Evidence preservation is needed for potential legal proceedings or HR investigations
- Deleted files, browser history, or application artifacts must be recovered
- A timeline of user or adversary activity must be reconstructed from file system metadata
- Malware persistence mechanisms stored on disk need identification and documentation

**Do not use** for volatile evidence (running processes, network connections); use memory forensics with Volatility instead.

## Prerequisites

- Forensic workstation with write-blocking hardware or software (Tableau T35u, Arsenal Image Mounter)
- Forensic imaging software: FTK Imager, Guymager, or dd with dcfldd
- Analysis platform: Autopsy, FTK (Forensic Toolkit), or X-Ways Forensics
- Sufficient storage (2-3x the target drive size for image plus working copies)
- Chain of custody forms and evidence bags for physical media
- Hash verification tools for evidence integrity (SHA-256)

## Workflow

### Step 1: Secure and Document the Evidence

Before touching any storage media, establish chain of custody:

- Photograph the system, noting serial numbers, labels, and cable connections
- Document the evidence source: device type, make, model, serial number, capacity
- Complete chain of custody form with date, time, handler name, and reason for acquisition
- Use a hardware write blocker when connecting the evidence drive to the forensic workstation

```
Chain of Custody Record:
━━━━━━━━━━━━━━━━━━━━━━━
Case ID:          INC-2025-1547
Evidence ID:      EVD-001
Description:      Samsung 870 EVO 500GB SSD
Serial Number:    S5XXNJ0R912345
Source Host:      WKSTN-042
Acquired By:      [Analyst Name]
Date/Time:        2025-11-15T16:30:00Z
Write Blocker:    Tableau T35u (S/N: T35U-12345)
```

### Step 2: Create a Forensic Image

Produce a bit-for-bit copy of the evidence drive:

**Using FTK Imager (Windows):**
1. Connect evidence drive through write blocker
2. File > Create Disk Image > Select source drive
3. Choose E01 (Expert Witness Format) for compression and metadata
4. Set destination path and evidence item information
5. Enable "Verify images after they are created"
6. Record source and image hash values

**Using dcfldd (Linux):**
```bash
# Create raw image with hash verification
dcfldd if=/dev/sdb of=/evidence/WKSTN-042.dd \
  hash=sha256 hashlog=/evidence/WKSTN-042.sha256 \
  bs=4096 conv=noerror,sync

# Verify image integrity
sha256sum /evidence/WKSTN-042.dd
```

```
Imaging Summary:
Source Drive:    /dev/sdb (Samsung 870 EVO 500GB)
Image File:     WKSTN-042.E01
Image Format:   E01 (Expert Witness)
Source Hash:     SHA-256: a1b2c3d4e5f6...
Image Hash:      SHA-256: a1b2c3d4e5f6...  (MATCH)
Sectors Read:    976,773,168
Errors:          0
Duration:        47 minutes
```

### Step 3: Analyze File System Structure

Open the forensic image in Autopsy or FTK and examine the file system:

- Identify partition layout (MBR/GPT, NTFS/ext4/APFS partitions)
- Examine the Master File Table (MFT) for NTFS or inode tables for ext4
- Identify deleted files and directories (marked as unallocated but not yet overwritten)
- Recover files from unallocated space using file carving
- Examine alternate data streams (NTFS ADS) for hidden data

**Key Windows Artifacts to Examine:**
```
User Activity:
- NTUSER.DAT (registry hive per user)
- UsrClass.dat (shellbags, file access history)
- Recent files: %AppData%\Microsoft\Windows\Recent\
- Jump lists: %AppData%\Microsoft\Windows\Recent\AutomaticDestinations\

Program Execution:
- Prefetch: C:\Windows\Prefetch\*.pf
- Amcache: C:\Windows\appcompat\Programs\Amcache.hve
- SRUM: C:\Windows\System32\SRU\SRUDB.dat
- ShimCache: SYSTEM registry hive

Persistence:
- Scheduled Tasks: C:\Windows\System32\Tasks\
- Startup folders: %AppData%\Microsoft\Windows\Start Menu\Programs\Startup\
- Services: SYSTEM registry hive

Network:
- WLAN profiles: C:\ProgramData\Microsoft\Wlansvc\Profiles\
- Browser history: Chrome, Firefox, Edge profile directories
```

### Step 4: Reconstruct the Timeline

Build a comprehensive timeline of file system activity:

**Using Autopsy Timeline Module:**
1. Generate timeline from all available sources (MFT, event logs, browser history, prefetch)
2. Filter to the investigation timeframe
3. Identify clusters of activity correlating with the incident
4. Document the sequence of attacker actions based on file creation, modification, and access timestamps

**Using The Sleuth Kit (command line):**
```bash
# Generate body file from NTFS image
fls -r -m / WKSTN-042.dd > bodyfile.txt

# Create timeline from body file
mactime -b bodyfile.txt -d > timeline.csv

# Filter timeline to investigation period
grep "2025-11-15" timeline.csv | sort > incident_timeline.csv
```

### Step 5: Recover and Analyze Artifacts

Extract and analyze specific forensic artifacts:

- **Prefetch files**: Parse with PECmd to determine program execution times and loaded DLLs
- **Event logs**: Parse with EvtxECmd for Windows XML Event Logs
- **Registry**: Parse with RegRipper or Registry Explorer for user activity and system configuration
- **Browser artifacts**: Parse with Hindsight (Chrome), KAPE, or DB Browser for SQLite databases
- **USB device history**: Extract from SYSTEM\CurrentControlSet\Enum\USBSTOR registry key
- **$MFT analysis**: Parse with MFTECmd for detailed file metadata including $SI and $FN timestamps

### Step 6: Document Findings

Compile a forensic analysis report suitable for legal proceedings:

- Maintain evidence integrity documentation (hash chain)
- Document every tool used and its version
- Record all analysis steps in a reproducible manner
- Present findings factually without conjecture
- Clearly distinguish between facts (observed data) and interpretations (analyst conclusions)

## Key Concepts

| Term | Definition |
|------|------------|
| **Forensic Image** | Bit-for-bit copy of storage media that preserves all data including deleted files and unallocated space |
| **Write Blocker** | Hardware or software device that prevents any modification to evidence media during acquisition |
| **E01 Format** | Expert Witness Format used by EnCase and FTK; supports compression, metadata, and built-in hash verification |
| **File Carving** | Recovery technique that searches unallocated disk space for file headers and footers to reconstruct deleted files |
| **MFT (Master File Table)** | NTFS metadata structure containing entries for every file and directory, including deleted entries |
| **MAC Timestamps** | Modified, Accessed, Created timestamps on files used for timeline reconstruction (NTFS also has Entry Modified) |
| **Prefetch** | Windows artifact recording program execution metadata; contains execution count, timestamps, and loaded DLLs |
| **Unallocated Space** | Disk sectors not assigned to any file; may contain remnants of deleted files recoverable through carving |

## Tools & Systems

- **FTK Imager**: Free forensic imaging tool supporting E01, AFF, and raw formats with built-in hash verification
- **Autopsy**: Open-source digital forensics platform built on The Sleuth Kit for comprehensive disk analysis
- **KAPE (Kroll Artifact Parser and Extractor)**: Triage collection and parsing tool for rapid artifact extraction
- **X-Ways Forensics**: Commercial forensic analysis tool known for speed and efficiency on large datasets
- **Eric Zimmerman's Tools**: Suite of free forensic parsers (PECmd, MFTECmd, EvtxECmd, RegRipper) for Windows artifacts

## Common Scenarios

### Scenario: Employee Data Theft Investigation

**Context**: An employee submitted a resignation and is suspected of copying proprietary files to a USB drive before departing. HR requests a forensic investigation of the employee's workstation.

**Approach**:
1. Image the workstation disk using FTK Imager with a write blocker
2. Parse USB device history from SYSTEM registry to identify connected devices
3. Examine ShellBags and Jump Lists for evidence of file browsing and copying to removable media
4. Parse LNK files in the Recent folder to identify recently accessed documents
5. Analyze browser history for personal cloud storage uploads (Google Drive, Dropbox)
6. Build a timeline correlating USB connections with file access events

**Pitfalls**:
- Failing to image the drive before the IT department reassigns the workstation
- Not checking cloud storage browser history alongside USB evidence
- Overlooking Volume Shadow Copies that may contain earlier versions of deleted files
- Presenting analysis conclusions as fact without supporting evidence documentation

## Output Format

```
DISK FORENSICS INVESTIGATION REPORT
=====================================
Case ID:          INC-2025-1547
Evidence:         EVD-001 (Samsung 870 EVO 500GB SSD)
Examiner:         [Name]
Date of Analysis: 2025-11-16

EVIDENCE INTEGRITY
Source Hash:      SHA-256: a1b2c3d4e5f6...
Image Hash:       SHA-256: a1b2c3d4e5f6... (VERIFIED MATCH)
Write Blocker:    Tableau T35u

PARTITION LAYOUT
Partition 1:  NTFS  100 MB   (System Reserved)
Partition 2:  NTFS  465 GB   (C: - OS and Data)
Partition 3:  NTFS  500 MB   (Recovery)

KEY FINDINGS
1. [Timestamp] - Malware dropper created in %TEMP% (update.exe)
2. [Timestamp] - Scheduled task "WindowsUpdate" created for persistence
3. [Timestamp] - Prefetch shows 14 executions of update.exe
4. [Timestamp] - USB device "Kingston DataTraveler" connected
5. [Timestamp] - 847 files copied to E:\ drive (ShellBag evidence)

RECOVERED ARTIFACTS
- 3 deleted malware samples recovered from unallocated space
- Browser history showing C2 panel access
- Registry evidence of disabled security software

TIMELINE
[Chronological event listing with timestamps and evidence sources]

TOOLS USED
- FTK Imager 4.7.1 (imaging)
- Autopsy 4.21.0 (analysis)
- PECmd 1.5.0 (prefetch parsing)
- MFTECmd 1.2.2 (MFT analysis)
```
