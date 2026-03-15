---
name: analyzing-windows-prefetch-with-python
description: Parse Windows Prefetch files using the windowsprefetch Python library to reconstruct application execution history, detect renamed or masquerading binaries, and identify suspicious program execution patterns.
domain: cybersecurity
subdomain: digital-forensics
tags: [digital-forensics, windows, prefetch, execution-history, incident-response, malware-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Windows Prefetch with Python

## Overview

Windows Prefetch files (.pf) record application execution data including executable names, run counts, timestamps, loaded DLLs, and accessed directories. This skill covers parsing Prefetch files using the windowsprefetch Python library to reconstruct execution timelines, detect renamed or masquerading binaries by comparing executable names with loaded resources, and identifying suspicious programs that may indicate malware execution or lateral movement.

## Prerequisites

- Python 3.9+ with `windowsprefetch` library (pip install windowsprefetch)
- Windows Prefetch files from C:\Windows\Prefetch\ (versions 17-30 supported)
- Understanding of Windows Prefetch file naming conventions (EXECUTABLE-HASH.pf)

## Steps

### Step 1: Collect Prefetch Files
Gather .pf files from target system's C:\Windows\Prefetch\ directory.

### Step 2: Parse Execution History
Extract executable name, run count, last execution timestamps, and volume information.

### Step 3: Detect Suspicious Execution
Flag known attack tools (mimikatz, psexec, etc.), renamed binaries, and unusual execution patterns.

### Step 4: Build Execution Timeline
Reconstruct chronological execution timeline from all Prefetch files.

## Expected Output

JSON report with execution history, suspicious executables, renamed binary indicators, and timeline reconstruction.
