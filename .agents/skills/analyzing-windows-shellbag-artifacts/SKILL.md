---
name: analyzing-windows-shellbag-artifacts
description: Analyze Windows Shellbag registry artifacts to reconstruct folder browsing activity, detect access to removable media and network shares, and establish user interaction with directories even after deletion using SBECmd and ShellBags Explorer.
domain: cybersecurity
subdomain: digital-forensics
tags: [shellbags, windows-registry, sbecmd, shellbags-explorer, folder-access, user-activity, removable-media, network-shares, bagmru, dfir]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Windows Shellbag Artifacts

## Overview

Shellbags are Windows registry artifacts that track how users interact with folders through Windows Explorer, storing view settings such as icon size, window position, sort order, and view mode. From a forensic perspective, Shellbags provide definitive evidence of folder access -- even folders that no longer exist on the system. When a user browses to a folder via Windows Explorer, the Open/Save dialog, or the Control Panel, a Shellbag entry is created or updated in the user's registry hive. These entries persist after folder deletion, drive disconnection, and even across user profile resets, making them invaluable for proving that a user navigated to specific directories on local drives, USB devices, network shares, or zip archives.

## Registry Locations

### Windows 7/8/10/11

| Hive | Key Path | Stores |
|------|---------|--------|
| NTUSER.DAT | Software\Microsoft\Windows\Shell\BagMRU | Folder hierarchy tree |
| NTUSER.DAT | Software\Microsoft\Windows\Shell\Bags | View settings per folder |
| UsrClass.dat | Local Settings\Software\Microsoft\Windows\Shell\BagMRU | Desktop/Explorer shell |
| UsrClass.dat | Local Settings\Software\Microsoft\Windows\Shell\Bags | Additional view settings |

### BagMRU Structure

The BagMRU key contains a hierarchical tree of numbered subkeys representing the directory structure. Each subkey value contains a Shell Item (SHITEMID) binary blob encoding the folder identity:

- **Root (BagMRU)**: Desktop namespace root
- **BagMRU\0**: Typically "My Computer"
- **BagMRU\0\0**: First drive (e.g., C:)
- **BagMRU\0\0\0**: First subfolder on C:

Each Shell Item contains:
- Item type (folder, drive, network, zip, control panel)
- Short name (8.3 format)
- Long name (Unicode)
- Creation/modification timestamps
- MFT entry/sequence for NTFS folders

## Analysis with EZ Tools

### SBECmd (Command Line)

```powershell
# Parse shellbags from a directory of registry hives
SBECmd.exe -d "C:\Evidence\Registry" --csv C:\Output --csvf shellbags.csv

# Parse from a live system (requires admin)
SBECmd.exe --live --csv C:\Output --csvf live_shellbags.csv

# Key output columns:
# AbsolutePath - Full reconstructed path
# CreatedOn - When the folder was first browsed
# ModifiedOn - When view settings were last changed
# AccessedOn - Last access timestamp
# ShellType - Type of shell item (Directory, Drive, Network, etc.)
# Value - Raw shell item data
```

### ShellBags Explorer (GUI)

```powershell
# Launch GUI tool for interactive analysis
ShellBagsExplorer.exe

# Load registry hives: File > Load Hive
# Navigate the tree structure to see folder hierarchy
# Right-click entries for detailed shell item properties
```

## Forensic Investigation Scenarios

### Proving USB Device Browsing

```
Shellbag Path: My Computer\E:\Confidential\Project_Files
ShellType: Directory (on removable volume)
CreatedOn: 2025-03-15 09:30:00 UTC

This proves the user navigated to E:\Confidential\Project_Files
via Windows Explorer, even if the USB drive is no longer connected.
The volume letter E: and directory timestamps can be correlated
with USBSTOR and MountPoints2 registry entries.
```

### Detecting Network Share Access

```
Shellbag Path: \\FileServer01\Finance\Q4_Reports
ShellType: Network Location
AccessedOn: 2025-02-20 14:15:00 UTC

This proves the user browsed to a network share, even if
the share has been decommissioned or access revoked.
```

### Identifying Deleted Folder Knowledge

```
Shellbag Path: C:\Users\suspect\Documents\Exfiltration_Staging
ShellType: Directory
CreatedOn: 2025-01-10 08:00:00 UTC

Even though C:\Users\suspect\Documents\Exfiltration_Staging
no longer exists, the Shellbag entry proves the user
created and navigated to this folder.
```

## Limitations

- Shellbags only record folder-level interactions, not individual file access
- Only created through Windows Explorer shell and Open/Save dialogs
- Command-line access (cmd, PowerShell) does not generate Shellbag entries
- Programmatic file access via APIs does not generate Shellbag entries
- Timestamps may reflect view setting changes, not necessarily folder access
- Windows may batch-update Shellbag entries during Explorer shutdown

## References

- Shellbags Forensic Analysis 2025: https://www.cybertriage.com/blog/shellbags-forensic-analysis-2025/
- SANS Shellbag Forensics: https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags
- Magnet Forensics Shellbag Analysis: https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/
- ShellBags Explorer: https://ericzimmerman.github.io/
