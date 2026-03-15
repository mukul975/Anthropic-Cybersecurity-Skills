# API Reference: Analyzing Slack Space and File System Artifacts

## The Sleuth Kit (TSK) CLI Tools

### blkls - Extract Slack Space

```bash
# Extract slack space from partition at offset 2048
blkls -s -o 2048 evidence.dd > slack_space.raw
```

### fls - List Files and Alternate Data Streams

```bash
# Recursive file listing with ADS
fls -r -o 2048 evidence.dd

# Filter for ADS entries (lines containing ":")
fls -r -o 2048 evidence.dd | grep ":"
```

### icat - Extract File Content by Inode

```bash
# Extract $MFT (inode 0)
icat -o 2048 evidence.dd 0 > MFT

# Extract ADS content
icat -o 2048 evidence.dd 14523:Zone.Identifier
```

### istat - Display Inode Details

```bash
istat -o 2048 evidence.dd 14523
```

## analyzeMFT (Python)

```bash
pip install analyzeMFT

analyzeMFT.py -f MFT -o mft_output.csv -c
```

## USN Journal Parsing

### Record Structure (USN_RECORD_V2)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Record length |
| 4 | 2 | Major version |
| 8 | 8 | MFT reference |
| 16 | 8 | Parent MFT reference |
| 32 | 8 | Timestamp (FILETIME) |
| 40 | 4 | Reason flags |
| 56 | 2 | Filename length |
| 58 | 2 | Filename offset |

### Reason Flags

| Flag | Meaning |
|------|---------|
| `0x100` | FILE_CREATE |
| `0x200` | FILE_DELETE |
| `0x1000` | RENAME_OLD_NAME |
| `0x2000` | RENAME_NEW_NAME |
| `0x80000000` | CLOSE |

## bulk_extractor

```bash
bulk_extractor -o output_dir/ slack_space.raw
```

## MFTECmd (Eric Zimmerman)

```bash
MFTECmd.exe -f MFT --csv output/ --csvf mft_analysis.csv
MFTECmd.exe -f UsnJrnl_J --csv output/ --csvf usn_journal.csv
```

## foremost - File Carving

```bash
foremost -t jpg,pdf,zip -i slack_space.raw -o carved_files/
```

### References

- The Sleuth Kit: https://sleuthkit.org/sleuthkit/
- analyzeMFT: https://pypi.org/project/analyzeMFT/
- MFTECmd: https://github.com/EricZimmerman/MFTECmd
- bulk_extractor: https://github.com/simsong/bulk_extractor
