# API Reference: Windows Prefetch Analysis Tools

## Prefetch File Format

### Location
```
C:\Windows\Prefetch\
```

### Filename Convention
```
EXECUTABLE_NAME-XXXXXXXX.pf
```
- `EXECUTABLE_NAME` - Uppercase name of the executed program
- `XXXXXXXX` - Hash of the executable path (8 hex characters)
- `.pf` - Prefetch file extension

### Version History
| Version | Windows OS | Notes |
|---------|-----------|-------|
| 17 | XP | Basic format |
| 23 | Vista, 7 | Added run count, timestamps |
| 26 | 8, 8.1 | Extended timestamps (8 entries) |
| 30 | 10, 11 | MAM compressed, 8 timestamps |

### Header Structure (Uncompressed)
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Version |
| 4 | 4 | Signature (SCCA) |
| 12 | 4 | File size |
| 16 | 60 | Executable name (UTF-16LE) |
| 76 | 4 | Prefetch hash |

## PECmd (Eric Zimmerman) - Full Parser

### Syntax
```bash
PECmd.exe -f <prefetch_file>              # Single file
PECmd.exe -d <prefetch_directory>          # Entire directory
PECmd.exe -d <dir> --csv <output_dir>     # Export to CSV
PECmd.exe -d <dir> --json <output_dir>    # Export to JSON
PECmd.exe -f <file> -q                    # Quiet mode
```

### Output Fields
| Field | Description |
|-------|-------------|
| `SourceFilename` | Original executable path |
| `RunCount` | Number of times executed |
| `LastRun` | Most recent execution timestamp |
| `PreviousRun0-7` | Up to 8 previous run timestamps (Win8+) |
| `FilesLoaded` | DLLs and files accessed during execution |
| `Directories` | Directories accessed |
| `VolumeSerialNumber` | Volume where executable resided |

## WinPrefetchView (NirSoft)

### GUI Features
- Lists all prefetch files with execution details
- Shows run count, timestamps, referenced files
- Export to CSV, HTML, or text
- Sort by any column for analysis

## Python Prefetch Parsing

### Structure Parsing
```python
import struct

with open("APP.EXE-HASH.pf", "rb") as f:
    data = f.read()

version = struct.unpack_from("<I", data, 0)[0]
signature = data[4:8]   # Should be b"SCCA"
exe_name = data[16:76].decode("utf-16-le").rstrip("\x00")
pf_hash = struct.unpack_from("<I", data, 76)[0]
```

### FILETIME Conversion
```python
import datetime

def filetime_to_datetime(filetime):
    epoch = datetime.datetime(1601, 1, 1)
    delta = datetime.timedelta(microseconds=filetime // 10)
    return epoch + delta
```

## Suspicious Prefetch Indicators

### Offensive Tools
| Tool | Prefetch Name |
|------|---------------|
| Mimikatz | `MIMIKATZ.EXE-*.pf` |
| PsExec | `PSEXEC.EXE-*.pf`, `PSEXESVC.EXE-*.pf` |
| BloodHound | `SHARPHOUND.EXE-*.pf` |
| Rubeus | `RUBEUS.EXE-*.pf` |
| LaZagne | `LAZAGNE.EXE-*.pf` |

### LOLBins (Living Off the Land)
| Binary | Concern |
|--------|---------|
| `CERTUTIL.EXE` | File download, Base64 decode |
| `MSHTA.EXE` | Script execution via HTA |
| `REGSVR32.EXE` | COM scriptlet execution |
| `BITSADMIN.EXE` | File download |
| `MSBUILD.EXE` | Code execution via project files |

## Timeline Integration

### Plaso / log2timeline
```bash
log2timeline.py timeline.plaso /path/to/prefetch/
psort.py -o l2tcsv timeline.plaso > prefetch_timeline.csv
```
