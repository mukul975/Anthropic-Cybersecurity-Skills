# API Reference: Windows ShellBag Forensics

## SBECmd (Eric Zimmerman)

### Syntax
```bash
SBECmd.exe -d <registry_dir>              # Process directory of hives
SBECmd.exe --hive <NTUSER.DAT>            # Single hive
SBECmd.exe -d <dir> --csv <output_dir>    # CSV export
SBECmd.exe -d <dir> -l                    # Live system registry
```

### Output Fields
| Field | Description |
|-------|-------------|
| AbsolutePath | Full reconstructed folder path |
| CreatedOn | Folder creation timestamp |
| ModifiedOn | Folder modification timestamp |
| AccessedOn | Folder access timestamp |
| MFTEntryNumber | NTFS MFT reference |
| ShellType | Folder, network, zip, etc. |

## ShellBags Explorer (GUI)

### Features
- Tree view of folder access history
- Timeline view of access patterns
- Filtering by date range
- Export to CSV/JSON

## Registry Paths

### NTUSER.DAT
```
Software\Microsoft\Windows\Shell\BagMRU
Software\Microsoft\Windows\Shell\Bags
Software\Microsoft\Windows\ShellNoRoam\BagMRU
```

### UsrClass.dat
```
Local Settings\Software\Microsoft\Windows\Shell\BagMRU
Local Settings\Software\Microsoft\Windows\Shell\Bags
```

## regipy (Python)

### Installation
```bash
pip install regipy
```

### Usage
```python
from regipy.registry import RegistryHive

hive = RegistryHive("NTUSER.DAT")
key = hive.get_key("Software\Microsoft\Windows\Shell\BagMRU")
for value in key.iter_values():
    print(value.name, type(value.value))
```

## Shell Item Types
| Type Byte | Description |
|-----------|-------------|
| 0x1F | Root folder (GUID - Desktop, My Computer) |
| 0x2F | Volume (drive letter) |
| 0x31 | File entry (directory) |
| 0x32 | File entry (file) |
| 0x41 | Network location |
| 0x42 | Compressed folder |
| 0x46 | Network share (UNC path) |
| 0x71 | Control Panel item |

## Forensic Value
| Artifact | Intelligence |
|----------|-------------|
| Network paths | Remote share access (lateral movement) |
| USB paths | Removable media (data exfiltration) |
| Deleted folders | Evidence of anti-forensics awareness |
| Temp directories | Staging areas for tools/malware |
| AppData paths | Persistence mechanism locations |
| Recycle Bin | Awareness of deleted content |
