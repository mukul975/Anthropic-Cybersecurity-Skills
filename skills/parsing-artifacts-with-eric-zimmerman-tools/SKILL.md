---
name: parsing-artifacts-with-eric-zimmerman-tools
description: Parse Windows forensic artifacts—$MFT/$J (MFTECmd), Prefetch (PECmd), registry hives (RECmd), shellbags, and Amcache—into normalized CSV/JSON with Eric Zimmerman's EZ Tools, then load results into Timeline Explorer for analysis. Use during DFIR/incident-response investigations, after triage collection (e.g. with KAPE), to establish program execution, file/folder access, and persistence evidence from acquired forensic images.
domain: cybersecurity
subdomain: digital-forensics
tags:
- digital-forensics
- eric-zimmerman
- registry-forensics
- prefetch
- shellbags
- mft
- dfir
- artifact-parsing
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.AN-03
mitre_attack:
- T1112
---
# Parsing Artifacts with Eric Zimmerman Tools

> **Authorized Use Only:** These tools parse evidence acquired from systems. Only analyze data you are authorized to handle, maintain chain of custody, and work from forensic copies rather than originals.

## Overview

Eric Zimmerman's Tools (EZ Tools) are a free, open-source suite of high-fidelity Windows forensic parsers, each focused on a specific artifact class and each producing analyst-ready CSV/JSON output. They are the de facto standard for Windows artifact analysis and are what KAPE's `!EZParser` module invokes under the hood. Key tools include:

- **MFTECmd** — parses `$MFT`, `$J` ($UsnJrnl), `$Boot`, `$SDS`, and `$LogFile` from NTFS volumes.
- **PECmd** — parses Windows Prefetch (`.pf`) for evidence of program execution.
- **RECmd** — registry hive parser/searcher driven by batch plugins (RECmd Batch files).
- **SBECmd** — parses ShellBags (folder access history) from `UsrClass.dat`/`NTUSER.DAT`.
- **AmcacheParser** — parses `Amcache.hve` for application execution and metadata.
- **AppCompatCacheParser** — parses ShimCache (AppCompatCache) from `SYSTEM` hive.
- **LECmd** — parses LNK shortcut files. **JLECmd** — parses Jump Lists. **EvtxECmd** — parses EVTX event logs to a normalized schema.

Output is designed to load into **Timeline Explorer** (also by Eric Zimmerman), a fast CSV/Excel viewer purpose-built for filtering, tagging, and pivoting across forensic CSVs. The 2025+ releases run on .NET and also work natively on Linux.

## When to Use

- After triage collection (e.g. with KAPE) when you need to parse raw artifacts into structured, searchable evidence.
- To establish program execution, file/folder access, and persistence during incident response.
- To build artifact-specific CSVs that feed timelines, Timesketch, or SIEM ingestion.

## Prerequisites

- Download EZ Tools via the official downloader (keeps tools current):
  ```powershell
  # Download/update all .NET 6 tools into C:\Tools\EZ
  .\Get-ZimmermanTools.ps1 -Dest C:\Tools\EZ
  ```
  Source: https://ericzimmerman.github.io/ and https://github.com/EricZimmerman/Get-ZimmermanTools
- .NET runtime (bundled with current releases).
- Forensic copies of the artifacts (mounted image, KAPE collection, or extracted hives).

## Objectives

- Parse the MFT, prefetch, shellbags, registry, and amcache from a collection.
- Produce normalized CSV/JSON per artifact.
- Load results into Timeline Explorer for analysis.
- Establish execution and access evidence supporting the investigation.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1112 | Modify Registry | RECmd, AmcacheParser, and AppCompatCacheParser parse registry-resident artifacts; analysts use them to detect adversary registry modification (persistence, defense evasion) recorded in hives. |

These are defensive parsers; the mapping reflects the artifact (registry) most relevant to the adversary behavior they help uncover.

## Workflow

### 1. Download/update the tools
Keep parsers current so they handle the latest artifact formats.
```powershell
.\Get-ZimmermanTools.ps1 -Dest C:\Tools\EZ
```

### 2. Parse the MFT for file-system activity
`-f` points at a single `$MFT`; `--csv` sets the output directory and `--csvf` the filename. Add `--csvf` for $J/UsnJrnl with `-f $J`.
```cmd
MFTECmd.exe -f "E:\collection\C\$MFT" --csv "E:\out\mft" --csvf MFT.csv

REM Parse the USN Journal change log
MFTECmd.exe -f "E:\collection\C\$Extend\$J" --csv "E:\out\mft" --csvf UsnJrnl.csv
```

### 3. Parse Prefetch for execution evidence
`-d` recurses a directory of `.pf` files. Output CSV + JSON.
```cmd
PECmd.exe -d "E:\collection\C\Windows\Prefetch" --csv "E:\out\prefetch" --csvf Prefetch.csv --json "E:\out\prefetch\json"
```

### 4. Parse ShellBags for folder-access history
`-d` points at the directory containing the user's `UsrClass.dat`/`NTUSER.DAT` (or `-f` a single hive).
```cmd
SBECmd.exe -d "E:\collection\C\Users\jsmith" --csv "E:\out\shellbags"
```

### 5. Parse the registry with RECmd batch plugins
RECmd is driven by batch files (`--bn`) that bundle plugins; the `Kroll_Batch` file is comprehensive. `-d` recurses a directory of hives.
```cmd
RECmd.exe -d "E:\collection\C\Windows\System32\config" --bn "C:\Tools\EZ\RECmd\BatchExamples\Kroll_Batch.reb" --csv "E:\out\registry" --csvf Registry.csv

REM Search a single hive for a value/key
RECmd.exe -f "E:\collection\C\Users\jsmith\NTUSER.DAT" --sk "Run" --csv "E:\out\registry"
```

### 6. Parse Amcache and ShimCache
```cmd
AmcacheParser.exe -f "E:\collection\C\Windows\AppCompat\Programs\Amcache.hve" --csv "E:\out\amcache" -i

AppCompatCacheParser.exe -f "E:\collection\C\Windows\System32\config\SYSTEM" --csv "E:\out\shimcache"
```

### 7. Parse LNK, Jump Lists, and EVTX
```cmd
LECmd.exe -d "E:\collection\C\Users\jsmith\AppData\Roaming\Microsoft\Windows\Recent" --csv "E:\out\lnk"

JLECmd.exe -d "E:\collection\C\Users\jsmith\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "E:\out\jumplists"

EvtxECmd.exe -d "E:\collection\C\Windows\System32\winevt\Logs" --csv "E:\out\evtx" --csvf EventLogs.csv
```

### 8. Analyze in Timeline Explorer
Open the resulting CSVs in Timeline Explorer (`TimelineExplorer.exe`). Use column filters, conditional formatting, and tagging to pivot on time, file path, and user. CSVs from all EZ Tools share consistent timestamp columns for cross-artifact correlation.

### 9. Cross-correlate
Build a working theory by correlating PECmd (execution time) with MFTECmd (file creation), Amcache/ShimCache (program presence), and ShellBags/LNK (access), all anchored on UTC timestamps.

## Tools and Resources

| Tool | Artifact parsed | Link |
|------|-----------------|------|
| MFTECmd | $MFT, $J, $Boot, $SDS, $LogFile | https://github.com/EricZimmerman/MFTECmd |
| PECmd | Prefetch | https://github.com/EricZimmerman/PECmd |
| RECmd | Registry hives | https://github.com/EricZimmerman/RECmd |
| SBECmd | ShellBags | https://ericzimmerman.github.io/ |
| AmcacheParser | Amcache.hve | https://github.com/EricZimmerman/AmcacheParser |
| AppCompatCacheParser | ShimCache | https://github.com/EricZimmerman/AppCompatCacheParser |
| LECmd / JLECmd | LNK / Jump Lists | https://ericzimmerman.github.io/ |
| EvtxECmd | EVTX event logs | https://github.com/EricZimmerman/evtx |
| Timeline Explorer | CSV analysis viewer | https://ericzimmerman.github.io/ |
| Get-ZimmermanTools | Downloader/updater | https://github.com/EricZimmerman/Get-ZimmermanTools |

## Common Flags

| Flag | Meaning |
|------|---------|
| `-f <file>` | Parse a single file |
| `-d <dir>` | Recurse a directory |
| `--csv <dir>` | CSV output directory |
| `--csvf <name>` | CSV output filename |
| `--json <dir>` | JSON output directory |
| `--bn <file>` | RECmd batch (.reb) file |
| `-i` | AmcacheParser: include file entries (unassociated) |

## Validation Criteria

- [ ] EZ Tools downloaded/updated via Get-ZimmermanTools
- [ ] $MFT (and $J) parsed to CSV
- [ ] Prefetch parsed for execution evidence
- [ ] ShellBags parsed for folder-access history
- [ ] Registry parsed with Kroll_Batch (RECmd)
- [ ] Amcache and ShimCache parsed
- [ ] LNK/Jump Lists/EVTX parsed as needed
- [ ] Output loaded and reviewed in Timeline Explorer
- [ ] Cross-artifact correlation performed on UTC timestamps
