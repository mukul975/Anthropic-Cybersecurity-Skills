# API Reference: Autopsy and The Sleuth Kit (TSK)

## mmls - Partition Layout

### Syntax
```bash
mmls <image_file>
mmls -t dos <image_file>    # Force DOS partition table
mmls -t gpt <image_file>    # Force GPT partition table
```

### Output Format
```
DOS Partition Table
Offset Sector: 0
     Slot    Start        End          Length       Description
     00:  00:00   0000002048   0001026047   0001024000   NTFS (0x07)
```

## fls - File Listing

### Syntax
```bash
fls -o <offset> <image>              # List root directory
fls -r -o <offset> <image>           # Recursive listing
fls -rd -o <offset> <image>          # Deleted files only, recursive
fls -m "/" -r -o <offset> <image>    # Bodyfile format for mactime
```

### Flags
| Flag | Description |
|------|-------------|
| `-r` | Recursive listing |
| `-d` | Deleted entries only |
| `-D` | Directories only |
| `-m "/"` | Output in bodyfile format with mount point |
| `-o` | Partition sector offset |

## icat - File Extraction by Inode

### Syntax
```bash
icat -o <offset> <image> <inode> > recovered_file
icat -r -o <offset> <image> <inode> > file   # Recover slack space
```

## istat - File Metadata

### Syntax
```bash
istat -o <offset> <image> <inode>
```

### Output Includes
- MFT entry number and sequence
- File creation, modification, access, MFT change timestamps
- File size and data run locations
- Attribute list (NTFS: $STANDARD_INFORMATION, $FILE_NAME, $DATA)

## mactime - Timeline Generation

### Syntax
```bash
mactime -b <bodyfile> -d > timeline.csv
mactime -b <bodyfile> -d 2024-01-15..2024-01-20 > filtered.csv
mactime -b <bodyfile> -z UTC -d > timeline_utc.csv
```

### Output Columns
```
Date,Size,Type,Mode,UID,GID,Meta,File Name
```

## img_stat - Image Information

### Syntax
```bash
img_stat <image_file>
```

## sigfind - File Signature Search

### Syntax
```bash
sigfind -o <offset> <image> <hex_signature>
sigfind -o 2048 evidence.dd 25504446    # Find %PDF headers
sigfind -o 2048 evidence.dd 504B0304    # Find ZIP/DOCX headers
```

### Common Signatures
| Hex | File Type |
|-----|-----------|
| `FFD8FF` | JPEG |
| `89504E47` | PNG |
| `25504446` | PDF |
| `504B0304` | ZIP/DOCX/XLSX |
| `D0CF11E0` | OLE (DOC/XLS) |

## srch_strings - Keyword Search

### Syntax
```bash
srch_strings -a -o <offset> <image> | grep -i "keyword"
srch_strings -t d <image>    # Print offset in decimal
```

## Autopsy GUI Ingest Modules

| Module | Function |
|--------|----------|
| Recent Activity | Browser history, downloads, cookies |
| Hash Lookup | NSRL and known-bad hash matching |
| File Type Identification | Signature-based file type detection |
| Keyword Search | Full-text content indexing |
| Email Parser | PST/MBOX/EML extraction |
| Extension Mismatch | Wrong file extension detection |
| Embedded File Extractor | ZIP, Office, PDF extraction |
| Encryption Detection | Encrypted container identification |
