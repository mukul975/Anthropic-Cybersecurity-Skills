---
name: analyzing-mft-for-deleted-file-recovery
description: Analyze the NTFS Master File Table ($MFT) to recover metadata and content of deleted files by examining MFT record entries, $LogFile, $UsnJrnl, and MFT slack space using MFTECmd, analyzeMFT, and X-Ways Forensics.
domain: cybersecurity
subdomain: digital-forensics
tags: [mft, ntfs, deleted-files, file-recovery, mftecmd, usn-journal, logfile, mft-slack-space, file-system-forensics, dfir]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing MFT for Deleted File Recovery

## Overview

The NTFS Master File Table ($MFT) is the central metadata repository for every file and directory on an NTFS volume. Each file is represented by at least one 1024-byte MFT record containing attributes such as $STANDARD_INFORMATION (timestamps, permissions), $FILE_NAME (name, parent directory, timestamps), and $DATA (file content or cluster run pointers). When a file is deleted, its MFT record is marked as inactive (InUse flag cleared) but the metadata remains until the entry is reallocated by a new file. This persistence makes MFT analysis a primary technique for recovering deleted file evidence, reconstructing file system timelines, and detecting anti-forensic activity such as timestomping.

## Prerequisites

- Forensic disk image (E01, raw/dd, VMDK, or VHDX format)
- MFTECmd (Eric Zimmerman) or analyzeMFT (Python-based)
- FTK Imager, Arsenal Image Mounter, or similar for image mounting
- Timeline Explorer or Excel for CSV analysis
- Python 3.8+ for custom analysis scripts
- Understanding of NTFS file system internals

## MFT Structure and Record Layout

### MFT Record Header

Each MFT record begins with the signature "FILE" (0x46494C45) and contains:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 bytes | Signature ("FILE") |
| 0x04 | 2 bytes | Offset to update sequence |
| 0x06 | 2 bytes | Size of update sequence |
| 0x08 | 8 bytes | $LogFile sequence number |
| 0x10 | 2 bytes | Sequence number |
| 0x12 | 2 bytes | Hard link count |
| 0x14 | 2 bytes | Offset to first attribute |
| 0x16 | 2 bytes | Flags (0x01 = InUse, 0x02 = Directory) |
| 0x18 | 4 bytes | Used size of MFT record |
| 0x1C | 4 bytes | Allocated size of MFT record |
| 0x20 | 8 bytes | Base file record reference |
| 0x28 | 2 bytes | Next attribute ID |

### Key MFT Attributes

| Type ID | Name | Description |
|---------|------|-------------|
| 0x10 | $STANDARD_INFORMATION | Timestamps, flags, owner ID, security ID |
| 0x30 | $FILE_NAME | Filename, parent MFT reference, timestamps |
| 0x40 | $OBJECT_ID | Unique GUID for the file |
| 0x50 | $SECURITY_DESCRIPTOR | ACL permissions |
| 0x60 | $VOLUME_NAME | Volume label (volume metadata files only) |
| 0x80 | $DATA | File content (resident if <700 bytes) or cluster run list |
| 0x90 | $INDEX_ROOT | B-tree index root for directories |
| 0xA0 | $INDEX_ALLOCATION | B-tree index entries for large directories |
| 0xB0 | $BITMAP | Allocation bitmap for index or MFT |

## Deleted File Recovery Techniques

### Technique 1: MFT Record Analysis with MFTECmd

```powershell
# Extract $MFT from forensic image using KAPE or FTK Imager
# Parse the $MFT with MFTECmd
MFTECmd.exe -f "C:\Evidence\$MFT" --csv C:\Output --csvf mft_full.csv

# Filter for deleted files (InUse = FALSE) in Timeline Explorer
# Look for entries where InUse column is False
```

**Identifying Deleted Files in CSV Output:**
- `InUse` = False indicates a deleted or reallocated record
- `ParentPath` shows original file location before deletion
- `FileSize` shows the original size (may still be recoverable)
- Timestamps in `$STANDARD_INFORMATION` and `$FILE_NAME` attributes persist

### Technique 2: USN Journal ($UsnJrnl:$J) Analysis

The USN Journal records all changes to files on an NTFS volume, including creation, deletion, rename, and data modification events.

```powershell
# Parse USN Journal with MFTECmd
MFTECmd.exe -f "C:\Evidence\$J" --csv C:\Output --csvf usn_journal.csv

# Key USN reason codes for deletion evidence:
# USN_REASON_FILE_DELETE     = 0x00000200
# USN_REASON_CLOSE           = 0x80000000
# USN_REASON_RENAME_OLD_NAME = 0x00001000
# USN_REASON_RENAME_NEW_NAME = 0x00002000
```

### Technique 3: $LogFile Transaction Analysis

The $LogFile stores NTFS transaction records that can reveal file operations even after the USN Journal has been cycled.

```powershell
# Parse $LogFile with LogFileParser
LogFileParser.exe -l "C:\Evidence\$LogFile" -o C:\Output

# Look for REDO and UNDO operations indicating file deletion:
# - DeallocateFileRecordSegment
# - DeleteAttribute
# - UpdateResidentValue (clearing InUse flag)
```

### Technique 4: MFT Slack Space Analysis

MFT slack space exists between the end of the used portion of an MFT record and the end of the allocated 1024 bytes. This area may contain remnants of previous file records.

```python
import struct

def parse_mft_slack(mft_path: str, output_path: str):
    """Extract and analyze MFT slack space for deleted file remnants."""
    with open(mft_path, "rb") as f:
        record_size = 1024
        record_num = 0
        slack_findings = []

        while True:
            record = f.read(record_size)
            if len(record) < record_size:
                break

            # Verify FILE signature
            if record[:4] != b"FILE":
                record_num += 1
                continue

            # Get used size from offset 0x18
            used_size = struct.unpack("<I", record[0x18:0x1C])[0]

            if used_size < record_size:
                slack = record[used_size:]
                # Check if slack contains readable strings or attribute headers
                if any(c > 0x20 and c < 0x7F for c in slack[:50]):
                    slack_findings.append({
                        "record": record_num,
                        "used_size": used_size,
                        "slack_size": record_size - used_size,
                        "slack_preview": slack[:100].hex()
                    })

            record_num += 1

    return slack_findings
```

## Correlation with Supporting Artifacts

### Cross-Reference MFT with $Recycle.Bin

```powershell
# Parse Recycle Bin with RBCmd
RBCmd.exe -d "C:\Evidence\$Recycle.Bin" --csv C:\Output --csvf recycle_bin.csv

# Correlate: $I files contain original path and deletion timestamp
# Match MFT entry numbers from $R files back to original MFT records
```

### Cross-Reference MFT with Volume Shadow Copies

```powershell
# List volume shadow copies
vssadmin list shadows

# Mount shadow copies and extract $MFT from each
# Compare MFT records across shadow copies to track file changes over time
```

## Forensic Value

- **Deleted file metadata recovery**: Original filename, path, size, and timestamps
- **Timeline reconstruction**: File creation, modification, access, and deletion events
- **Timestomping detection**: Comparing $SI vs $FN timestamps
- **Data carving guidance**: MFT cluster runs point to file content on disk
- **Anti-forensic detection**: Identifying wiped or manipulated MFT records

## References

- NTFS MFT Advanced Forensic Analysis: https://www.deaddisk.com/posts/ntfs-mft-advanced-forensic-analysis-guide/
- MFT Slack Space Forensic Value: https://www.sygnia.co/blog/the-forensic-value-of-mft-slack-space/
- MFTECmd Documentation: https://ericzimmerman.github.io/
- SANS FOR500: Windows Forensic Analysis

## Example Output

```text
$ MFTECmd.exe -f "C:\Evidence\$MFT" --csv /analysis/mft_output

MFTECmd v1.2.2 - MFT Parser
==============================
Input: C:\Evidence\$MFT (Size: 384 MB)
Total MFT Entries: 395,264

Parsing MFT entries... Done (12.4 seconds)

--- Deleted File Recovery Summary ---
Total Entries:          395,264
Active Files:           245,832
Deleted Files:          149,432
  Recoverable:          87,234 (resident data or clusters not reallocated)
  Partially Recoverable: 31,456 (some clusters overwritten)
  Unrecoverable:        30,742 (all clusters reallocated)

--- Recently Deleted Files (Incident Window: 2024-01-15 to 2024-01-18) ---
MFT Entry | Filename                          | Path                               | Size      | Deleted (UTC)         | Recoverable
----------|-----------------------------------|------------------------------------|-----------|-----------------------|------------
148923    | exfil_tool.exe                    | C:\ProgramData\Updates\            | 1,258,496 | 2024-01-17 02:45:12   | YES
148924    | exfil_tool.log                    | C:\ProgramData\Updates\            | 45,312    | 2024-01-17 02:45:14   | YES
149001    | passwords.txt                     | C:\Users\jsmith\Desktop\           | 2,048     | 2024-01-17 02:50:33   | YES
149150    | scan_results.csv                  | C:\Users\jsmith\AppData\Local\Temp | 892,416   | 2024-01-17 03:00:01   | PARTIAL
149200    | mimikatz.exe                      | C:\Windows\Temp\                   | 1,250,816 | 2024-01-18 01:15:22   | YES
149201    | sekurlsa.log                      | C:\Windows\Temp\                   | 32,768    | 2024-01-18 01:15:25   | YES
149302    | .bash_history                     | C:\Users\jsmith\                   | 4,096     | 2024-01-18 03:00:00   | NO
149400    | ClearEventLogs.ps1                | C:\Windows\Temp\                   | 1,536     | 2024-01-18 03:01:12   | YES

--- $STANDARD_INFORMATION vs $FILE_NAME Timestamp Analysis (Timestomping Detection) ---
MFT Entry | Filename            | $SI Created          | $FN Created          | Delta     | Verdict
----------|---------------------|----------------------|----------------------|-----------|----------
148923    | exfil_tool.exe      | 2023-06-15 10:00:00  | 2024-01-15 14:34:02  | -214 days | TIMESTOMPED
149200    | mimikatz.exe        | 2022-01-01 00:00:00  | 2024-01-16 02:30:15  | -745 days | TIMESTOMPED

Recovered files exported to: /analysis/mft_output/recovered/
Full CSV report: /analysis/mft_output/mft_analysis.csv (395,264 rows)
Timeline CSV: /analysis/mft_output/mft_timeline.csv
```
