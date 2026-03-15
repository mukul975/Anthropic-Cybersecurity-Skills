# API Reference: Analyzing Windows Amcache Artifacts

## Amcache.hve Location
```
C:\Windows\AppCompat\Programs\Amcache.hve
```

## Registry Keys
| Key Path | Contents |
|----------|---------|
| Root\InventoryApplicationFile | File execution evidence with SHA-1 |
| Root\InventoryApplication | Installed application metadata |
| Root\InventoryDevicePnp | PnP device connection history |
| Root\InventoryDriverBinary | Driver binary metadata |

## regipy Python Library
```bash
pip install regipy
```

```python
from regipy.registry import RegistryHive

reg = RegistryHive('/path/to/Amcache.hve')
for subkey in reg.get_key('Root\\InventoryApplicationFile').iter_subkeys():
    values = {v.name: v.value for v in subkey.iter_values()}
    print(values.get('Name'), values.get('LowerCaseLongPath'))
```

## AmcacheParser (Eric Zimmerman)
```bash
# Parse Amcache.hve to CSV
AmcacheParser.exe -f C:\evidence\Amcache.hve --csv C:\output\

# Include device and driver entries
AmcacheParser.exe -f Amcache.hve --csv output\ -i
```

### Output CSV Columns
| Column | Description |
|--------|------------|
| Name | Application/file name |
| LowerCaseLongPath | Full lowercase path |
| Publisher | Software publisher |
| FileId | SHA-1 hash (prefixed with 0000) |
| Size | File size in bytes |
| LinkDate | PE compilation timestamp |
| Version | File version string |
| ProgramId | Associated program GUID |

## Forensic Value
| Artifact | Evidence |
|----------|---------|
| SHA-1 hash | File identification even after deletion |
| LowerCaseLongPath | Execution path including USB/temp |
| LinkDate | PE compile time (timestomping detection) |
| Publisher | Legitimacy verification |
| Last Modified | Registry key update timestamp |

## Suspicious Indicators
| Pattern | Concern |
|---------|---------|
| Path contains \\Temp\\ | Execution from temp directory |
| Path contains \\Downloads\\ | User-downloaded execution |
| Missing Publisher | Unsigned/unknown binary |
| LinkDate far from file date | Possible timestomping |
| Known tool names (mimikatz, psexec) | Attacker tooling |
