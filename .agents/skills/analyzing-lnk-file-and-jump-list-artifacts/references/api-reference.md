# API Reference: LNK File and Jump List Forensics

## LECmd (Eric Zimmerman) - LNK Parser

### Syntax
```bash
LECmd.exe -f <file.lnk>                  # Single file
LECmd.exe -d <directory> --all            # All files in directory
LECmd.exe -d <dir> --csv <output_dir>     # CSV export
LECmd.exe -d <dir> --json <output_dir>    # JSON export
LECmd.exe -f <file.lnk> -q               # Quiet mode
LECmd.exe -d <dir> -r                     # Only removable drives
```

### Output Fields
| Field | Description |
|-------|-------------|
| SourceFile | Path to the .lnk file |
| TargetCreated | Target file creation timestamp |
| TargetModified | Target file modification timestamp |
| TargetAccessed | Target file access timestamp |
| FileSize | Target file size |
| RelativePath | Relative path to target |
| WorkingDirectory | Working directory for target |
| Arguments | Command-line arguments |
| LocalPath | Full local path to target |
| VolumeSerialNumber | Volume serial of target drive |
| DriveType | Fixed, Removable, Network |
| MachineID | NetBIOS name from tracker block |
| MacAddress | MAC from distributed tracker |

## JLECmd (Eric Zimmerman) - Jump List Parser

### Syntax
```bash
JLECmd.exe -f <jumplist_file>             # Single file
JLECmd.exe -d <directory>                 # All jump lists
JLECmd.exe -d <dir> --csv <output>        # CSV export
JLECmd.exe -d <dir> --fd                  # Full LNK details
JLECmd.exe -d <dir> --dumpTo <dir>        # Extract embedded LNK files
```

### Jump List Locations
```
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\
```

## LnkParse3 (Python)

### Installation
```bash
pip install LnkParse3
```

### Usage
```python
import LnkParse3

with open("shortcut.lnk", "rb") as f:
    lnk = LnkParse3.lnk_file(f)

info = lnk.get_json()
print(info["data"]["relative_path"])
print(info["header"]["creation_time"])
print(info["link_info"]["local_base_path"])

# Extra data blocks
extra = info.get("extra", {})
tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK", {})
print(tracker.get("machine_id"))
print(tracker.get("mac_address"))
```

## Shell Link Binary Format (MS-SHLLINK)

### Header Structure (76 bytes)
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | HeaderSize (0x0000004C) |
| 4 | 16 | LinkCLSID |
| 20 | 4 | LinkFlags |
| 24 | 4 | FileAttributes |
| 28 | 8 | CreationTime (FILETIME) |
| 36 | 8 | AccessTime (FILETIME) |
| 44 | 8 | WriteTime (FILETIME) |
| 52 | 4 | FileSize |
| 56 | 4 | IconIndex |
| 60 | 4 | ShowCommand |

### Common App IDs (Jump Lists)
| App ID | Application |
|--------|-------------|
| 1b4dd67f29cb1962 | Windows Explorer |
| 5d696d521de238c3 | Google Chrome |
| ecd21b58c2f65a4f | Firefox |
| 1bc392b8e104a00e | Remote Desktop (mstsc) |
| b8ab77100df80ab2 | Microsoft Word |
| cfb56c56fa0f0478 | PuTTY |
| b74736c2bd8cc8a5 | WinSCP |

## Suspicious LNK Indicators
| Pattern | Concern |
|---------|---------|
| PowerShell in arguments | Script execution via shortcut |
| cmd.exe /c in target | Command execution chain |
| UNC path to IP | Network-based payload delivery |
| Base64 encoded arguments | Obfuscated commands |
| mshta/wscript target | Living-off-the-land execution |
