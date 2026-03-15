# API Reference: NTFS MFT Analysis

## MFT Entry Structure (1024 bytes)
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Signature ("FILE") |
| 18 | 2 | Sequence number |
| 20 | 2 | First attribute offset |
| 22 | 2 | Flags (0x01=in use, 0x02=directory) |

## MFT Attribute Types
| Type ID | Name | Description |
|---------|------|-------------|
| 0x10 | $STANDARD_INFORMATION | Timestamps, flags, owner |
| 0x20 | $ATTRIBUTE_LIST | List of attributes in other entries |
| 0x30 | $FILE_NAME | Filename and parent reference |
| 0x40 | $OBJECT_ID | Unique object identifier |
| 0x50 | $SECURITY_DESCRIPTOR | ACL and ownership |
| 0x60 | $VOLUME_NAME | Volume label |
| 0x80 | $DATA | File content (resident or non-resident) |
| 0x90 | $INDEX_ROOT | Directory index root |
| 0xA0 | $INDEX_ALLOCATION | Directory index entries |
| 0xB0 | $BITMAP | Bitmap for index allocation |

## $STANDARD_INFORMATION Timestamps
| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Creation time (FILETIME) |
| 8 | 8 | Modification time |
| 16 | 8 | MFT modification time |
| 24 | 8 | Access time |

## $FILE_NAME Structure
| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Parent directory reference |
| 64 | 1 | Filename length (chars) |
| 65 | 1 | Namespace (0=POSIX, 1=Win32, 2=DOS) |
| 66 | var | Filename (UTF-16LE) |

## FILETIME Conversion
```python
FILETIME_EPOCH = datetime(1601, 1, 1)
dt = FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
```

## Tools
```bash
# Extract MFT with FTK Imager or raw copy
icat /dev/sda1 0 > $MFT
# analyzeMFT
analyzeMFT.py -f $MFT -o mft.csv
# MFTECmd (Eric Zimmerman)
MFTECmd.exe -f $MFT --csv output/
```
