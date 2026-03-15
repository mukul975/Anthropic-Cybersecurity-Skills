# API Reference: Analyzing Windows LNK Files for Artifacts

## LnkParse3

### Parse a Single LNK File

```python
import LnkParse3

with open("shortcut.lnk", "rb") as f:
    lnk = LnkParse3.lnk_file(f)
    info = lnk.get_json()

# Access header timestamps
header = info["header"]
print(header["creation_time"], header["modified_time"], header["accessed_time"])

# Access target path
link_info = info.get("link_info", {})
print(link_info.get("local_base_path"))

# Access volume info
vol = link_info.get("volume_id", {})
print(vol.get("drive_type"), vol.get("drive_serial_number"))

# Access tracker data (machine ID, MAC)
extra = info.get("extra", {})
tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK", {})
print(tracker.get("machine_id"), tracker.get("mac_address"))
```

### LNK JSON Structure

```json
{
  "header": {
    "creation_time": "2024-01-15 14:32:00",
    "modified_time": "2024-01-15 14:32:00",
    "accessed_time": "2024-01-15 14:32:00",
    "file_size": 45056
  },
  "link_info": {
    "local_base_path": "E:\\Documents\\report.xlsx",
    "volume_id": {
      "drive_type": "DRIVE_REMOVABLE",
      "drive_serial_number": "1234-ABCD",
      "volume_label": "KINGSTON"
    }
  },
  "string_data": {
    "working_dir": "E:\\Documents",
    "command_line_arguments": ""
  },
  "extra": {
    "DISTRIBUTED_LINK_TRACKER_BLOCK": {
      "machine_id": "DESKTOP-ABC123",
      "mac_address": "AA:BB:CC:DD:EE:FF"
    }
  }
}
```

## Key LNK File Locations

| Location | Description |
|----------|-------------|
| `%APPDATA%\Microsoft\Windows\Recent\` | Recently accessed files |
| `%APPDATA%\...\Recent\AutomaticDestinations\` | Jump Lists |
| `%APPDATA%\...\Recent\CustomDestinations\` | Pinned Jump List items |
| `%USERPROFILE%\Desktop\` | Desktop shortcuts |
| `%APPDATA%\...\Startup\` | User startup (persistence) |
| `%PROGRAMDATA%\...\Startup\` | System startup (persistence) |

## Drive Types

| Value | Meaning |
|-------|---------|
| DRIVE_REMOVABLE | USB, SD card |
| DRIVE_FIXED | Internal HDD/SSD |
| DRIVE_REMOTE | Network share |
| DRIVE_CDROM | Optical media |

### References

- LnkParse3: https://pypi.org/project/LnkParse3/
- Shell Link Binary Format: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
- LECmd: https://github.com/EricZimmerman/LECmd
