---
name: analyzing-lnk-file-and-jump-list-artifacts
description: Analyze Windows LNK shortcut files and Jump List artifacts to establish evidence of file access, program execution, and user activity using LECmd, JLECmd, and manual binary parsing of the Shell Link Binary format.
domain: cybersecurity
subdomain: digital-forensics
tags: [lnk-files, jump-lists, lecmd, jlecmd, windows-forensics, shell-link, user-activity, file-access, program-execution, recent-files]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing LNK File and Jump List Artifacts

## Overview

Windows LNK (shortcut) files and Jump Lists are critical forensic artifacts that provide evidence of file access, program execution, and user behavior. LNK files are created automatically when a user opens a file through Windows Explorer or the Open/Save dialog, storing metadata about the target file including its original path, timestamps, volume serial number, NetBIOS name, and MAC address of the host system. Jump Lists, introduced in Windows 7, extend this by maintaining per-application lists of recently and frequently accessed files. These artifacts persist even after the target files are deleted, making them invaluable for establishing that a user accessed specific files at specific times.

## Prerequisites

- LECmd (Eric Zimmerman) for LNK file parsing
- JLECmd (Eric Zimmerman) for Jump List parsing
- Python 3.8+ with pylnk3 or LnkParse3 libraries
- Forensic image or triage collection from Windows system
- Timeline Explorer for CSV analysis

## LNK File Locations

| Location | Description |
|----------|-------------|
| `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\` | Recent files accessed |
| `%USERPROFILE%\Desktop\` | User-created shortcuts |
| `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\` | Start Menu shortcuts |
| `%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\` | Office recent documents |

## LNK File Structure

### Shell Link Header (76 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | HeaderSize (always 0x0000004C) |
| 0x04 | 16 | LinkCLSID (always 00021401-0000-0000-C000-000000000046) |
| 0x14 | 4 | LinkFlags |
| 0x18 | 4 | FileAttributes |
| 0x1C | 8 | CreationTime (FILETIME) |
| 0x24 | 8 | AccessTime (FILETIME) |
| 0x2C | 8 | WriteTime (FILETIME) |
| 0x34 | 4 | FileSize of target |
| 0x38 | 4 | IconIndex |
| 0x3C | 4 | ShowCommand |
| 0x40 | 2 | HotKey |

### Key Forensic Fields in LNK Files

- **Target file timestamps**: Creation, access, modification times of the referenced file
- **Volume information**: Serial number, drive type, volume label
- **Network share information**: UNC path, share name
- **Machine identifiers**: NetBIOS name, MAC address (from TrackerDataBlock)
- **Distributed Link Tracking**: Machine ID and object GUID

## Analysis with EZ Tools

### LECmd - LNK File Parser

```powershell
# Parse all LNK files in Recent folder
LECmd.exe -d "C:\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Output --csvf lnk_analysis.csv

# Parse a single LNK file with full details
LECmd.exe -f "C:\Evidence\Users\suspect\Desktop\Confidential.docx.lnk" --json C:\Output

# Parse LNK files with additional detail levels
LECmd.exe -d "C:\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Output --csvf lnk_all.csv --all
```

### JLECmd - Jump List Parser

```powershell
# Parse Automatic Jump Lists
JLECmd.exe -d "C:\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\Output --csvf jumplists_auto.csv

# Parse Custom Jump Lists
JLECmd.exe -d "C:\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" --csv C:\Output --csvf jumplists_custom.csv

# Parse all jump lists with detailed output
JLECmd.exe -d "C:\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\Output --csvf jumplists_auto.csv --ld
```

## Jump List Structure

### Automatic Destinations (automaticDestinations-ms)

These are OLE Compound files (Structured Storage) identified by AppID hash in the filename:

| AppID Hash | Application |
|-----------|-------------|
| 5f7b5f1e01b83767 | Windows Explorer Pinned/Frequent |
| 1b4dd67f29cb1962 | Windows Explorer Recent |
| 9b9cdc69c1c24e2b | Notepad |
| a7bd71699cd38d1c | Notepad++ |
| 12dc1ea8e34b5a6 | Microsoft Paint |
| 7e4dca80246863e3 | Control Panel |
| 1cf97c38a5881255 | Microsoft Edge |
| f01b4d95cf55d32a | Windows Explorer |
| 9d1f905ce5044aee | Microsoft Excel |
| a4a5324453625195 | Microsoft Word |
| d00655d2aa12ff6d | Microsoft PowerPoint |
| bc03160ee1a59fc1 | Outlook |

### Custom Destinations (customDestinations-ms)

Created when users pin items to application jump lists. These files contain sequential LNK entries.

## Python Analysis Script

```python
import struct
import os
from datetime import datetime, timedelta

FILETIME_EPOCH = datetime(1601, 1, 1)

def filetime_to_datetime(filetime_bytes: bytes) -> datetime:
    """Convert Windows FILETIME (100-ns intervals since 1601) to datetime."""
    ft = struct.unpack("<Q", filetime_bytes)[0]
    if ft == 0:
        return None
    return FILETIME_EPOCH + timedelta(microseconds=ft // 10)

def parse_lnk_header(lnk_path: str) -> dict:
    """Parse the Shell Link header from an LNK file."""
    with open(lnk_path, "rb") as f:
        header = f.read(76)

    header_size = struct.unpack("<I", header[0:4])[0]
    if header_size != 0x4C:
        return {"error": "Invalid LNK header"}

    link_flags = struct.unpack("<I", header[0x14:0x18])[0]
    file_attrs = struct.unpack("<I", header[0x18:0x1C])[0]

    result = {
        "header_size": header_size,
        "link_flags": hex(link_flags),
        "file_attributes": hex(file_attrs),
        "creation_time": filetime_to_datetime(header[0x1C:0x24]),
        "access_time": filetime_to_datetime(header[0x24:0x2C]),
        "write_time": filetime_to_datetime(header[0x2C:0x34]),
        "file_size": struct.unpack("<I", header[0x34:0x38])[0],
        "has_target_id_list": bool(link_flags & 0x01),
        "has_link_info": bool(link_flags & 0x02),
        "has_name": bool(link_flags & 0x04),
        "has_relative_path": bool(link_flags & 0x08),
        "has_working_dir": bool(link_flags & 0x10),
        "has_arguments": bool(link_flags & 0x20),
        "has_icon_location": bool(link_flags & 0x40),
    }
    return result
```

## Investigation Use Cases

### Evidence of File Access
1. Parse LNK files from Recent folder to identify accessed documents
2. Cross-reference with MFT timestamps and USN Journal entries
3. Note that LNK files persist even after target files are deleted

### Removable Media Access
1. LNK files referencing drive letters E:, F:, G: indicate removable media usage
2. Volume serial number in LNK identifies the specific device
3. MAC address in TrackerDataBlock identifies the source machine

### Network Share Activity
1. LNK files with UNC paths (\\server\share) indicate network file access
2. NetBIOS name identifies the remote server
3. Timestamps establish when access occurred

## Differences Between Windows 10 and Windows 11

Recent research (IEEE 2025) shows that Windows 11 produces different LNK and Jump List artifacts:
- Fewer automatic LNK files generated for certain file types
- Modified Jump List behavior for modern applications
- UWP/MSIX applications may not generate traditional Jump Lists
- Windows 11 Quick Access replaces some Recent functionality

## References

- Shell Link Binary File Format: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
- Magnet Forensics LNK Analysis: https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/
- Jump Lists Forensics 2025: https://www.cybertriage.com/blog/jump-list-forensics-2025/
- Eric Zimmerman's LECmd/JLECmd: https://ericzimmerman.github.io/
