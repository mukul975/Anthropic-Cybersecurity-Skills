---
name: triaging-windows-with-kape
description: Runs KAPE (Kroll Artifact Parser and Extractor) to collect targeted forensic artifacts (registry hives, $MFT, event logs, prefetch, browser data) via Targets and parse them with Modules wrapping Eric Zimmerman's EZ Tools (PECmd, MFTECmd, RECmd). Use during early incident containment/triage when full disk imaging is impractical but a defensible, parseable Windows artifact set is needed quickly, including at-scale remote collection. Do not use for the detailed hands-on analysis of already-collected Windows artifacts with Eric Zimmerman tools - use performing-windows-artifact-analysis-with-eric-zimmerman-tools.
domain: cybersecurity
subdomain: digital-forensics
tags:
- digital-forensics
- kape
- triage
- artifact-collection
- incident-response
- eric-zimmerman
- dfir
- windows-forensics
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.AN-03
mitre_attack:
- T1005
---
# Triaging Windows with KAPE

> **Authorized Use Only:** KAPE collects forensic artifacts from systems. Only run KAPE against systems you own or are explicitly authorized in writing to acquire and analyze. Preserve chain of custody and follow your organization's evidence-handling procedures.

## Overview

KAPE (Kroll Artifact Parser and Extractor) is a free, Windows-native triage tool authored by Eric Zimmerman and distributed by Kroll. It performs two distinct phases controlled by separate configuration sets:

- **Targets** (`.tkape` files) define *what to collect*. KAPE uses the raw NTFS file system (via direct volume access) to copy locked/in-use files such as registry hives, `$MFT`, event logs, prefetch, browser databases, and LNK files without triggering anti-tamper protections. Targets can be chained into "compound" targets (for example `KapeTriage`, `!SANS_Triage`) that pull a forensically rich subset in minutes.
- **Modules** (`.mkape` files) define *how to process* collected (or live) data. Modules wrap external binaries — primarily Eric Zimmerman's tools (PECmd, MFTECmd, RECmd, etc.) — and emit normalized CSV/JSON output. The `!EZParser` compound module runs the full EZ Tools suite against a target collection.

KAPE ships with both a CLI (`kape.exe`) and a GUI front end (`gkape.exe`). Because of its speed, KAPE lets responders prioritize which hosts warrant deep forensic imaging, making it a cornerstone of modern remote/at-scale DFIR triage.

## When to Use

- During the early containment/triage phase of an incident when you need execution, persistence, and account artifacts from one or many hosts quickly.
- When full disk imaging is impractical (large disks, remote sites, time pressure) but you still need a defensible, parseable artifact set.
- When automating collection across a fleet via remote execution (PSExec, EDR live response, SOAR) using batch-mode `_kape.cli` files.
- When you need to collect from Volume Shadow Copies to recover historical artifact states.

## Prerequisites

- Windows host (KAPE runs on Windows; EZ Tools modules require the .NET runtime bundled with the tools).
- Download KAPE from the official source (free, registration required): https://www.kroll.com/kape
- Administrator privileges (required for raw volume access and VSS).
- Update Targets, Modules, and the bundled binaries:
  ```cmd
  REM From the KAPE directory, sync community Targets/Modules from GitHub
  kape.exe --sync

  REM Download/update the EZ Tools binaries that Modules invoke
  Get-KAPEUpdate.ps1
  ```
- A clean, write-protected destination (external drive or network share) separate from the evidence source.

## Objectives

- Collect a forensically sound triage artifact set from a target volume.
- Optionally include Volume Shadow Copies for historical recovery.
- Package output as a VHDX/ZIP container with hashing for chain of custody.
- Run modules to parse the collection into analyst-ready CSV/JSON.
- Build a repeatable batch-mode collection for fleet deployment.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1005 | Data from Local System | KAPE reads artifacts directly from the local file system; defenders use the same capability to forensically acquire that data for analysis. |

KAPE is a defensive DFIR tool. The mapping reflects the data-source artifacts (local file system) that adversary actions leave behind and that KAPE preserves for investigation.

## Workflow

### 1. Sync configurations and update binaries
Always work from current Targets/Modules and EZ Tools binaries so parsers match the latest artifact formats.
```cmd
cd C:\KAPE
kape.exe --sync
```

### 2. Inventory available Targets and Modules
List what is available before building a collection so you scope precisely.
```cmd
REM Show all Targets
kape.exe --tlist

REM Show all Modules
kape.exe --mlist
```

### 3. Collect a triage target set
Targets require the three switches `--tsource`, `--target`, and `--tdest`. `--tflush` clears the destination first. Use a compound target such as `KapeTriage` for a fast, broad pull.
```cmd
kape.exe --tsource C: ^
         --target KapeTriage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --tflush
```

### 4. Include Volume Shadow Copies
Add `--vss` to also process every VSS snapshot on the source volume, recovering historical artifact states.
```cmd
kape.exe --tsource C: ^
         --target !SANS_Triage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --vss --tflush
```

### 5. Package the collection as a container with hashing
`--vhdx` (or `--zip`) wraps the output into a single mountable/transportable container. `--vhdx` takes a base name (an identifier), NOT a filename. KAPE writes a console log and copy log you should retain.
```cmd
kape.exe --tsource C: ^
         --target KapeTriage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --vhdx HOST01 --tflush --gui
```

### 6. Process the collection with Modules
Modules require `--module` and `--mdest`. Point `--msource` at the collected target output and run `!EZParser` to parse everything into CSV/JSON.
```cmd
kape.exe --msource E:\kape_out\HOST01\tdest\C ^
         --mdest E:\kape_out\HOST01\mdest ^
         --module !EZParser ^
         --mflush
```

### 7. One-shot collect + parse
You can collect and process in a single invocation by supplying both Target and Module switches.
```cmd
kape.exe --tsource C: ^
         --target KapeTriage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --mdest E:\kape_out\HOST01\mdest ^
         --module !EZParser ^
         --tflush --mflush --vss
```

### 8. Build a batch-mode `_kape.cli` for fleet deployment
KAPE reads a `_kape.cli` file (one argument set per line) placed next to `kape.exe` and executes each line in sequence — ideal for pushing identical collection via EDR/PSExec. Generate the exact CLI from the GUI's "Copy command line" button, then drop it into `_kape.cli`.
```cmd
REM Contents of _kape.cli (each line = one full KAPE run):
--tsource C: --target KapeTriage --tdest %%d\Disk\%%m --vhdx %%m --zv false
```
`%%d` resolves to the KAPE directory and `%%m` to the machine name, so a single CLI auto-names output per host. Launch by running `kape.exe` with no arguments.

### 9. Verify integrity
Confirm KAPE's `CopyLog`, `ConsoleLog`, and `SkipLog` CSVs are present in the target output, and validate the SHA-1 hashes KAPE records for each copied file against the source where possible.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| KAPE download | Official Kroll distribution (free) | https://www.kroll.com/kape |
| KAPE Documentation | MDwiki docs for switches and config | https://ericzimmerman.github.io/KapeDocs/ |
| KapeFiles repo | Community Targets and Modules | https://github.com/EricZimmerman/KapeFiles |
| EZ Tools | Parsers invoked by KAPE Modules | https://ericzimmerman.github.io/ |
| KAPE on SANS | Background, history, methodology | https://www.sans.org/tools/kape/ |

## Key Switches

| Switch | Phase | Purpose |
|--------|-------|---------|
| `--tsource` | Target | Source volume/drive to collect from |
| `--target` | Target | Target or compound target name |
| `--tdest` | Target | Destination for collected files |
| `--tflush` | Target | Empty `--tdest` before collecting |
| `--vss` | Target | Process all Volume Shadow Copies |
| `--vhdx` / `--zip` | Target | Package output into a container (base name) |
| `--module` | Module | Module or compound module name |
| `--msource` | Module | Source data for module processing |
| `--mdest` | Module | Destination for parsed output |
| `--mflush` | Module | Empty `--mdest` before processing |
| `--sync` | Both | Update Targets/Modules from GitHub |
| `--tlist` / `--mlist` | Both | List available Targets / Modules |

## Validation Criteria

- [ ] KAPE Targets/Modules and EZ Tools binaries synced to current versions
- [ ] Triage target collected with `--tsource`, `--target`, `--tdest`
- [ ] Volume Shadow Copies included where historical state is needed
- [ ] Output packaged as VHDX or ZIP for transport/chain of custody
- [ ] CopyLog/ConsoleLog/SkipLog present and reviewed
- [ ] Modules run (`!EZParser`) producing CSV/JSON in `--mdest`
- [ ] File hashes recorded and verified against source
- [ ] Batch `_kape.cli` validated for fleet deployment where applicable
