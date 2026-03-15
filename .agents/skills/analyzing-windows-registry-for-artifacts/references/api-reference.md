# API Reference: Analyzing Windows Registry for Artifacts

## regipy

### Open Registry Hive

```python
from regipy.registry import RegistryHive

reg = RegistryHive("/path/to/NTUSER.DAT")
key = reg.get_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
print(key.header.last_modified)
for val in key.iter_values():
    print(val.name, val.value)
```

### Iterate Subkeys

```python
key = reg.get_key("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
for subkey in key.iter_subkeys():
    print(subkey.name, subkey.header.last_modified)
```

## Key Forensic Registry Paths

| Path | Hive | Artifact |
|------|------|----------|
| `Microsoft\Windows\CurrentVersion\Run` | SOFTWARE / NTUSER | Autostart entries |
| `Microsoft\Windows\CurrentVersion\RunOnce` | SOFTWARE / NTUSER | One-time autostart |
| `CurrentVersion\Explorer\UserAssist` | NTUSER | Program execution (ROT13) |
| `CurrentVersion\Explorer\RecentDocs` | NTUSER | Recently opened documents |
| `CurrentVersion\Explorer\TypedPaths` | NTUSER | Explorer address bar history |
| `ControlSet00X\Enum\USBSTOR` | SYSTEM | USB device history |
| `MountedDevices` | SYSTEM | Drive letter assignments |
| `CurrentVersion\Uninstall` | SOFTWARE | Installed software |
| `ControlSet00X\Control\ComputerName` | SYSTEM | Computer name |
| `ControlSet00X\Control\TimeZoneInformation` | SYSTEM | System timezone |

## UserAssist Decoding

```python
import codecs, struct
from datetime import datetime, timedelta

decoded_name = codecs.decode(rot13_name, "rot_13")
run_count = struct.unpack_from("<I", data, 4)[0]
timestamp = struct.unpack_from("<Q", data, 60)[0]
ts = datetime(1601, 1, 1) + timedelta(microseconds=timestamp // 10)
```

## RegRipper Plugins

```bash
# NTUSER.DAT analysis
rip.pl -r NTUSER.DAT -p userassist
rip.pl -r NTUSER.DAT -p recentdocs
rip.pl -r NTUSER.DAT -p typedurls

# SYSTEM hive
rip.pl -r SYSTEM -p compname
rip.pl -r SYSTEM -p usbstor
rip.pl -r SYSTEM -p shutdown
```

### References

- regipy: https://pypi.org/project/regipy/
- RegRipper: https://github.com/keydet89/RegRipper3.0
- Registry Explorer: https://ericzimmerman.github.io/#!index.md
