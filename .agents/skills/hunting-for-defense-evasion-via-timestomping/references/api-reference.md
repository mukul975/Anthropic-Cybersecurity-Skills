# API Reference: Hunting for Timestomping (T1070.006)

## NTFS Timestamp Attributes
| Attribute | Modifiable By | Updated On |
|-----------|--------------|------------|
| $STANDARD_INFORMATION | User-level APIs (SetFileTime) | Create, modify, access, MFT change |
| $FILE_NAME | Windows kernel only | File create, rename, move |

## Detection Logic
| Indicator | Description |
|-----------|------------|
| SI < FN Created | $SI creation before $FN creation (most reliable) |
| Zero nanoseconds | .0000000 in timestamp (tool artifacts) |
| Future timestamp | Date beyond current time |
| Pre-OS timestamp | $SI before OS install but $FN after |
| Round seconds | No fractional seconds (unusual for NTFS) |

## analyzeMFT (Python)
```bash
pip install analyzemft

# Parse MFT to CSV
analyzeMFT.py -f /path/to/$MFT -o mft_output.csv

# With body file output (for timeline)
analyzeMFT.py -f $MFT -o mft.csv -b body.txt
```

## MFTECmd (Eric Zimmerman)
```bash
# Parse MFT to CSV
MFTECmd.exe -f C:\evidence\$MFT --csv C:\output\

# With $J (USN Journal)
MFTECmd.exe -f $MFT --csv output\ --json output\
```

### CSV Columns
| Column | Description |
|--------|------------|
| Record Number | MFT entry number |
| Filename | File name |
| SI Created/Modified/Accessed | $STANDARD_INFORMATION timestamps |
| FN Created/Modified/Accessed | $FILE_NAME timestamps |
| In Use | Active record flag |

## USN Journal Analysis
```bash
# Parse USN Journal for corroboration
MFTECmd.exe -f $J --csv output\

# fsutil on live system
fsutil usn readjournal C: csv > usn_journal.csv
```

## Timestomping Tools (for detection awareness)
| Tool | Method |
|------|--------|
| timestomp (Metasploit) | SetFileTime API |
| PowerShell Set-ItemProperty | .NET DateTime |
| NirSoft BulkFileChanger | Batch timestamp edit |
| $STANDARD_INFORMATION patch | Direct MFT edit |

## MITRE ATT&CK
- **T1070.006** - Indicator Removal: Timestomp
- **Tactic**: Defense Evasion
- **Platforms**: Windows
