---
name: analyzing-windows-amcache-artifacts
description: 'Parses and analyzes the Windows Amcache.hve registry hive to extract
  evidence of program execution, application installation, and driver loading for
  digital forensics investigations. Uses Eric Zimmerman''s AmcacheParser and Timeline
  Explorer for artifact extraction, SHA-1 hash correlation with threat intel, and
  timeline reconstruction. Activates for requests involving Amcache forensics, program
  execution evidence, Windows artifact analysis, or application compatibility cache
  investigation.

  '
domain: cybersecurity
subdomain: digital-forensics
tags:
- amcache
- windows-forensics
- program-execution
- AmcacheParser
- eric-zimmerman
- timeline-analysis
- DFIR
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
mitre_attack:
- T1070.004
- T1070.006
- T1036.005
- T1014
- T1005
---

# Analyzing Windows Amcache Artifacts

## When to Use

- Determining which programs have existed or executed on a Windows system during incident response
- Correlating SHA-1 hashes from Amcache against known malware databases (VirusTotal, CIRCL, MISP)
- Building an application installation and execution timeline for forensic investigations
- Identifying deleted executables that leave traces in Amcache even after file removal
- Investigating insider threats by documenting which portable or unauthorized applications were present
- Analyzing driver loading history to detect rootkits or malicious kernel modules

**Do not use** as sole proof of program execution. Amcache proves file existence and metadata registration, but ShimCache (AppCompatCache) and Prefetch provide stronger execution evidence. Use all three artifacts together for conclusive analysis.

## Prerequisites

- A forensic image or live triage copy of `C:\Windows\appcompat\Programs\Amcache.hve` (and associated `.LOG1`, `.LOG2` transaction logs)
- Eric Zimmerman's AmcacheParser (`AmcacheParser.exe`) downloaded from https://ericzimmerman.github.io/
- Eric Zimmerman's Timeline Explorer for viewing parsed CSV output
- Optionally: Registry Explorer for manual hive inspection
- A SHA-1 whitelist of known-good executables (e.g., NSRL hashset) for filtering
- .NET 6+ runtime installed (required by current EZ tools)
- Write access to an output directory for CSV results

## Workflow

### Step 1: Acquire the Amcache.hve File

Extract the Amcache hive from a forensic image or live system:

```powershell
# From a live system (requires elevated privileges and raw copy tool)
# Amcache.hve is locked by the system; use a raw disk copy tool
# Option A: FTK Imager - mount image and navigate to:
# C:\Windows\appcompat\Programs\Amcache.hve
# Also collect: Amcache.hve.LOG1, Amcache.hve.LOG2

# Option B: Using KAPE for automated triage collection
kape.exe --tsource C: --tdest D:\Evidence\%m --target Amcache

# Option C: From a mounted forensic image (E: = mounted image)
copy "E:\Windows\appcompat\Programs\Amcache.hve" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG1" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG2" D:\Evidence\
```

Always collect the transaction log files (`.LOG1`, `.LOG2`) alongside the hive. AmcacheParser replays uncommitted transactions from these logs to recover the most complete data.

### Step 2: Parse Amcache with AmcacheParser

Run AmcacheParser against the acquired hive:

```powershell
# Basic parsing with CSV output
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output"

# Parse with a SHA-1 whitelist to exclude known-good entries (NSRL)
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -w "D:\Whitelists\nsrl_sha1.txt" --csv "D:\Evidence\Output"

# Parse with a SHA-1 inclusion list (only show matches against known-bad hashes)
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -b "D:\IOCs\malware_sha1.txt" --csv "D:\Evidence\Output"

# Include deleted entries with high-precision timestamps
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output" -i --mp
```

AmcacheParser produces multiple CSV files in the output directory:

| Output File | Contents |
|-------------|----------|
| `Amcache_AssociatedFileEntries.csv` | File entries with SHA-1 hashes, paths, sizes, and timestamps |
| `Amcache_UnassociatedFileEntries.csv` | Orphaned file entries from older Amcache format |
| `Amcache_ProgramEntries.csv` | Installed program metadata (name, publisher, version, install date) |
| `Amcache_DeviceContainers.csv` | USB and device connection history |
| `Amcache_DevicePnps.csv` | Plug-and-Play device driver information |
| `Amcache_DriverBinaries.csv` | Loaded driver binaries with paths and hashes |

### Step 3: Analyze File Entries for Suspicious Programs

Open the `AssociatedFileEntries.csv` in Timeline Explorer and examine key columns:

```
Key columns to review:
- ProgramId          : Links file to its parent program entry
- SHA1               : Hash for threat intel lookups
- FullPath           : Original file location on disk
- FileSize           : Size of the executable
- FileKeyLastWriteTimestamp : When the Amcache entry was last updated
- Name               : File name
- Publisher           : Code signing publisher (blank = unsigned)
- BinProductVersion  : Version string from the PE header
- LinkDate           : PE compilation timestamp (useful for detecting timestomping)
```

Filter for suspicious indicators:

```
# In Timeline Explorer, apply these filters:

# 1. Find unsigned executables (potentially malicious)
Publisher column = (empty)

# 2. Find executables from suspicious paths
FullPath contains: \temp\, \appdata\, \downloads\, \public\, \programdata\

# 3. Find executables with recent timestamps during incident window
FileKeyLastWriteTimestamp between: 2026-03-15 00:00:00 and 2026-03-16 00:00:00

# 4. Find executables with suspicious compilation dates (timestomping)
LinkDate year < 2015 AND FileKeyLastWriteTimestamp year = 2026
```

### Step 4: Correlate SHA-1 Hashes with Threat Intelligence

Extract SHA-1 hashes and check against malware databases:

```powershell
# Extract unique SHA-1 hashes from the parsed output
# Using PowerShell to extract the SHA1 column
Import-Csv "D:\Evidence\Output\Amcache_AssociatedFileEntries.csv" |
  Select-Object -ExpandProperty SHA1 -Unique |
  Where-Object { $_ -ne "" } |
  Out-File "D:\Evidence\Output\extracted_hashes.txt"

# Check hashes against VirusTotal using vt-cli
foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    vt file $hash --format json | Select-Object -Property meaningful_name, last_analysis_stats
}

# Check hashes against CIRCL hashlookup
foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha1/$hash"
}

# Cross-reference with NSRL to identify known-good vs. unknown
# Unknown hashes that are not in NSRL warrant closer investigation
```

### Step 5: Analyze Program Entries for Unauthorized Installations

Review the `ProgramEntries.csv` for software the attacker may have installed:

```
Key columns in ProgramEntries:
- ProgramName        : Display name of installed application
- ProgramVersion     : Version string
- Publisher          : Software publisher
- InstallDate        : When the program was installed
- Source             : Installation source (msi, exe, etc.)
- UninstallKey       : Registry uninstall path
- PathsList         : Installation directories
```

Look for:
- Remote access tools (AnyDesk, TeamViewer, ngrok, Chisel)
- Hacking tools (Mimikatz, PsExec, Cobalt Strike)
- Tunneling utilities (plink, socat, WireGuard)
- Programs installed during the incident window
- Programs installed to non-standard locations

### Step 6: Analyze Driver Binaries for Rootkit Evidence

Review the `DriverBinaries.csv` for suspicious loaded drivers:

```
Key columns in DriverBinaries:
- DriverName         : Name of the driver
- DriverInBox        : Whether it shipped with Windows (false = third-party)
- DriverSigned       : Whether the driver has a valid signature
- DriverTimeStamp    : Compilation timestamp
- Product            : Product associated with the driver
- ProductVersion     : Driver version
- SHA1               : Hash of the driver binary
```

Filter for `DriverInBox = false` and `DriverSigned = false` to find unsigned third-party drivers that may be rootkits or vulnerable drivers used in BYOVD (Bring Your Own Vulnerable Driver) attacks.

### Step 7: Build a Timeline from Amcache Data

Combine Amcache data with other artifacts for a comprehensive timeline:

```powershell
# Merge Amcache CSV with other EZ Tools output using Timeline Explorer
# Load the following CSVs into Timeline Explorer:
# - Amcache_AssociatedFileEntries.csv (file evidence)
# - Amcache_ProgramEntries.csv (install evidence)
# - Prefetch output from PECmd.exe (execution evidence)
# - ShimCache output from AppCompatCacheParser.exe (execution evidence)

# Sort all entries by timestamp to reconstruct the attack sequence
# Timeline Explorer supports multi-file loading and column-based sorting

# Export the combined timeline
# File > Save to CSV > combined_timeline.csv
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Amcache.hve** | A Windows registry hive at `C:\Windows\appcompat\Programs\Amcache.hve` that stores metadata about applications, files, and drivers for application compatibility purposes |
| **Associated File Entry** | An Amcache record linked to a specific program installation, containing file path, size, hash, and timestamps |
| **Unassociated File Entry** | An orphaned Amcache record from an older format that is not linked to a program entry; common on Windows 7/8 systems |
| **Program Entry** | Amcache record containing installation metadata: program name, version, publisher, install date, and uninstall key |
| **SHA-1 Hash** | Cryptographic hash stored in Amcache for each registered file, enabling malware identification through threat intelligence lookups |
| **LinkDate** | The PE compilation timestamp embedded in the executable header; discrepancy with file system timestamps may indicate timestomping |
| **Transaction Logs** | `.LOG1` and `.LOG2` files containing uncommitted registry transactions that AmcacheParser replays for complete data recovery |
| **NSRL (National Software Reference Library)** | NIST-maintained database of SHA-1 hashes for known commercial software, used as a whitelist to filter benign entries |

## Verification

- [ ] Amcache.hve and transaction logs (LOG1, LOG2) were collected from the forensic image
- [ ] AmcacheParser produced all expected CSV output files without errors
- [ ] SHA-1 hashes were extracted and checked against VirusTotal or CIRCL hashlookup
- [ ] Unsigned executables in suspicious paths have been flagged for further analysis
- [ ] Program entries show all software installations within the incident window
- [ ] Driver binaries have been checked for unsigned or out-of-box entries
- [ ] LinkDate vs. FileKeyLastWriteTimestamp comparison has been performed to detect timestomping
- [ ] Amcache findings are correlated with Prefetch and ShimCache for execution confirmation
- [ ] Final timeline integrates Amcache data with other forensic artifacts
