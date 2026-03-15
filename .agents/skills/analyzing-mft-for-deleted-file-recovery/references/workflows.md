# Workflows - MFT Deleted File Recovery

## Workflow 1: Basic Deleted File Discovery
```
Extract $MFT from forensic image
    |
Parse with MFTECmd to CSV
    |
Filter for InUse = False (deleted records)
    |
Analyze ParentPath, FileName, FileSize
    |
Cross-reference with USN Journal for deletion timestamps
    |
Document findings with original paths and timestamps
```

## Workflow 2: MFT Slack Space Recovery
```
Extract raw $MFT binary
    |
Parse each 1024-byte record
    |
Compare used_size vs allocated_size (1024)
    |
Extract slack bytes between used and allocated
    |
Search for attribute headers (0x10, 0x30, 0x80)
    |
Reconstruct partial file metadata from slack data
```

## Workflow 3: Timeline Reconstruction
```
Parse $MFT for all timestamps ($SI and $FN)
    |
Parse $J (USN Journal) for change records
    |
Parse $LogFile for transaction records
    |
Merge into unified timeline
    |
Identify file creation, modification, deletion sequences
    |
Flag timestomping indicators ($SI Created < $FN Created)
```
