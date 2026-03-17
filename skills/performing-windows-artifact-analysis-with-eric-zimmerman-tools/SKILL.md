---
name: performing-windows-artifact-analysis-with-eric-zimmerman-tools
description: Perform comprehensive Windows forensic artifact analysis using Eric Zimmerman's open-source EZ Tools suite including KAPE, MFTECmd, PECmd, LECmd, JLECmd, and Timeline Explorer for parsing registry hives, prefetch files, event logs, and file system metadata.
domain: cybersecurity
subdomain: digital-forensics
tags: [eric-zimmerman, ez-tools, kape, mftecmd, pecmd, lecmd, jlecmd, registry-forensics, windows-forensics, timeline-explorer, dfir, artifact-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Windows Artifact Analysis with Eric Zimmerman Tools

## Overview

Eric Zimmerman's EZ Tools suite is a collection of open-source forensic utilities that have become the global standard for Windows digital forensics investigations. Originally developed by a former FBI agent and current SANS instructor, these tools parse and analyze critical Windows artifacts including the Master File Table ($MFT), registry hives, prefetch files, event logs, shortcut (LNK) files, and jump lists. The suite integrates with KAPE (Kroll Artifact Parser and Extractor) for automated artifact collection and processing, producing structured CSV output that can be ingested into Timeline Explorer for visual analysis. EZ Tools are widely used by law enforcement, corporate incident responders, and forensic consultants worldwide.


## When to Use

- When conducting security assessments that involve performing windows artifact analysis with eric zimmerman tools
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Windows 10/11 or Windows Server 2016+ analysis workstation
- .NET 6 Runtime installed (required for EZ Tools v2.x+)
- Administrative privileges on the analysis workstation
- Forensic disk image or triage collection from target system
- At least 8 GB RAM (16 GB recommended for large datasets)
- Familiarity with NTFS file system structures and Windows internals

## Tool Suite Components

### KAPE (Kroll Artifact Parser and Extractor)

KAPE is the primary orchestration tool that automates artifact collection (Targets) and processing (Modules). It uses configuration files (.tkape and .mkape) to define what artifacts to collect and which EZ Tools to run against them.

**Installation and Setup:**

```powershell
# Download KAPE from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
# Extract to C:\Tools\KAPE

# Update KAPE targets and modules
C:\Tools\KAPE\gkape.exe  # GUI version
C:\Tools\KAPE\kape.exe   # CLI version

# Sync latest EZ Tools binaries
C:\Tools\KAPE\Get-KAPEUpdate.ps1
```

**Running KAPE Collection and Processing:**

```powershell
# Collect artifacts from E: drive (mounted forensic image) and process with EZ Tools
kape.exe --tsource E: --tdest C:\Cases\Case001\Collection --target KapeTriage --mdest C:\Cases\Case001\Processed --module !EZParser

# Collect specific artifact categories
kape.exe --tsource E: --tdest C:\Cases\Case001\Collection --target FileSystem,RegistryHives,EventLogs --mdest C:\Cases\Case001\Processed --module MFTECmd,RECmd,EvtxECmd

# Live system triage collection (run as administrator)
kape.exe --tsource C: --tdest D:\LiveTriage\Collection --target KapeTriage --mdest D:\LiveTriage\Processed --module !EZParser --vhdx LiveTriageImage
```

### MFTECmd - Master File Table Parser

MFTECmd parses the NTFS $MFT, $J (USN Journal), $Boot, $SDS, and $LogFile into human-readable CSV format.

```powershell
# Parse the $MFT file
MFTECmd.exe -f "C:\Cases\Evidence\$MFT" --csv C:\Cases\Output --csvf MFT_output.csv

# Parse the USN Journal ($J)
MFTECmd.exe -f "C:\Cases\Evidence\$J" --csv C:\Cases\Output --csvf USNJournal_output.csv

# Parse $Boot for volume information
MFTECmd.exe -f "C:\Cases\Evidence\$Boot" --csv C:\Cases\Output --csvf Boot_output.csv

# Parse $SDS for security descriptors
MFTECmd.exe -f "C:\Cases\Evidence\$SDS" --csv C:\Cases\Output --csvf SDS_output.csv
```

**Key Fields in MFT Output:**

| Field | Description |
|-------|-------------|
| EntryNumber | MFT record number |
| ParentEntryNumber | Parent directory MFT record |
| InUse | Whether the record is active or deleted |
| FileName | Name of the file or directory |
| Created0x10 | $STANDARD_INFORMATION creation timestamp |
| Created0x30 | $FILE_NAME creation timestamp |
| LastModified0x10 | $STANDARD_INFORMATION modification timestamp |
| IsDirectory | Boolean indicating directory or file |
| FileSize | Logical file size in bytes |
| Extension | File extension |

### PECmd - Prefetch File Parser

PECmd parses Windows Prefetch files (.pf) to provide evidence of program execution, including run counts and timestamps.

```powershell
# Parse all prefetch files from a directory
PECmd.exe -d "C:\Cases\Evidence\Windows\Prefetch" --csv C:\Cases\Output --csvf Prefetch_output.csv

# Parse a single prefetch file with verbose output
PECmd.exe -f "C:\Cases\Evidence\Windows\Prefetch\CMD.EXE-4A81B364.pf" --json C:\Cases\Output

# Parse prefetch with keyword filtering
PECmd.exe -d "C:\Cases\Evidence\Windows\Prefetch" -k "powershell,cmd,wscript,cscript,mshta" --csv C:\Cases\Output --csvf SuspiciousExec.csv
```

### RECmd - Registry Explorer Command Line

RECmd processes Windows registry hives using batch files that define which keys and values to extract.

```powershell
# Process all registry hives with the default batch file
RECmd.exe --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb -d "C:\Cases\Evidence\Registry" --csv C:\Cases\Output --csvf Registry_output.csv

# Process a single NTUSER.DAT hive
RECmd.exe -f "C:\Cases\Evidence\Users\suspect\NTUSER.DAT" --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb --csv C:\Cases\Output

# Process SYSTEM hive for USB device history
RECmd.exe -f "C:\Cases\Evidence\Registry\SYSTEM" --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb --csv C:\Cases\Output
```

### EvtxECmd - Windows Event Log Parser

EvtxECmd parses Windows Event Log (.evtx) files into structured CSV format with customizable event ID maps.

```powershell
# Parse all event logs from a directory
EvtxECmd.exe -d "C:\Cases\Evidence\Windows\System32\winevt\Logs" --csv C:\Cases\Output --csvf EventLogs_output.csv

# Parse a single event log
EvtxECmd.exe -f "C:\Cases\Evidence\Security.evtx" --csv C:\Cases\Output --csvf Security_output.csv

# Parse with custom maps for enhanced field extraction
EvtxECmd.exe -d "C:\Cases\Evidence\Logs" --csv C:\Cases\Output --maps C:\Tools\KAPE\Modules\bin\EvtxECmd\Maps
```

### LECmd and JLECmd - Shortcut and Jump List Parsers

```powershell
# Parse LNK files from Recent directory
LECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Cases\Output --csvf LNK_output.csv

# Parse Jump Lists (automatic destinations)
JLECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\Cases\Output --csvf JumpLists_auto.csv

# Parse Jump Lists (custom destinations)
JLECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" --csv C:\Cases\Output --csvf JumpLists_custom.csv
```

### SBECmd - Shellbag Explorer Command Line

```powershell
# Parse shellbags from a directory of registry hives
SBECmd.exe -d "C:\Cases\Evidence\Registry" --csv C:\Cases\Output --csvf Shellbags_output.csv

# Parse shellbags from a live system (requires admin)
SBECmd.exe --live --csv C:\Cases\Output --csvf LiveShellbags_output.csv
```

### Timeline Explorer - Visual Analysis

Timeline Explorer is the GUI tool for analyzing CSV output from all EZ Tools. It supports filtering, sorting, column grouping, and conditional formatting.

```powershell
# Launch Timeline Explorer and open CSV output
TimelineExplorer.exe "C:\Cases\Output\MFT_output.csv"
```

**Key Timeline Explorer Features:**
- Column-level filtering with regular expressions
- Conditional formatting for timestamp anomalies
- Multi-column sorting for chronological analysis
- Export filtered results to new CSV files
- Bookmarking rows of interest

## Investigation Workflow

### Step 1: Artifact Collection with KAPE

```powershell
# Full triage collection from forensic image mounted at E:
kape.exe --tsource E: --tdest C:\Cases\Case001\Collected --target KapeTriage --vhdx TriageImage --zv false
```

### Step 2: Artifact Processing with EZ Tools

```powershell
# Process all collected artifacts
kape.exe --msource C:\Cases\Case001\Collected --mdest C:\Cases\Case001\Processed --module !EZParser
```

### Step 3: Timeline Analysis

1. Open processed CSV files in Timeline Explorer
2. Sort by timestamp columns to establish chronological order
3. Filter for specific file extensions, paths, or event IDs
4. Cross-reference MFT timestamps with event log entries
5. Identify timestomping by comparing $SI and $FN timestamps
6. Document findings with bookmarks and exported filtered views

### Step 4: Timestomping Detection

```powershell
# In Timeline Explorer, compare these columns:
# Created0x10 ($STANDARD_INFORMATION) vs Created0x30 ($FILE_NAME)
# If Created0x10 < Created0x30, timestomping is indicated
# $FILE_NAME timestamps are harder to manipulate than $STANDARD_INFORMATION
```

## Forensic Artifacts Reference

| Tool | Artifact | Location |
|------|----------|----------|
| MFTECmd | $MFT | Root of NTFS volume |
| MFTECmd | $J (USN Journal) | $Extend\$UsnJrnl:$J |
| PECmd | Prefetch files | C:\Windows\Prefetch\*.pf |
| RECmd | NTUSER.DAT | C:\Users\{user}\NTUSER.DAT |
| RECmd | SYSTEM hive | C:\Windows\System32\config\SYSTEM |
| RECmd | SAM hive | C:\Windows\System32\config\SAM |
| RECmd | SOFTWARE hive | C:\Windows\System32\config\SOFTWARE |
| EvtxECmd | Event logs | C:\Windows\System32\winevt\Logs\*.evtx |
| LECmd | LNK files | C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\ |
| JLECmd | Jump lists | C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ |
| SBECmd | Shellbags | NTUSER.DAT and UsrClass.dat registry hives |

## Common Investigation Scenarios

### Malware Execution Evidence
1. Parse Prefetch with PECmd to identify executed binaries
2. Cross-reference with MFT for file creation timestamps
3. Check Amcache.hve with RECmd for SHA1 hashes of executables
4. Correlate with Event Log entries for process creation (Event ID 4688)

### Data Exfiltration Investigation
1. Parse USN Journal with MFTECmd for file rename/delete operations
2. Analyze LNK files with LECmd for recently accessed documents
3. Review Shellbags with SBECmd for directory browsing activity
4. Check for USB device connections in SYSTEM registry with RECmd

### Lateral Movement Detection
1. Parse Security.evtx with EvtxECmd for logon events (4624, 4625)
2. Analyze RDP-related event logs (Microsoft-Windows-TerminalServices)
3. Cross-reference with network share access from SMB logs
4. Review scheduled tasks and services for persistence mechanisms

## Output Format and Integration

All EZ Tools produce CSV output that can be:
- Analyzed in Timeline Explorer for visual investigation
- Imported into Splunk, Elastic, or other SIEM platforms
- Processed by Python/PowerShell scripts for automated analysis
- Combined into super timelines using log2timeline/Plaso

## References

- Eric Zimmerman's Tools: https://ericzimmerman.github.io/
- KAPE Documentation: https://ericzimmerman.github.io/KapeDocs/
- SANS EZ Tools Training: https://www.sans.org/tools/ez-tools
- SANS FOR508: Advanced Incident Response and Threat Hunting
- SANS FOR498: Battlefield Forensics & Data Acquisition
