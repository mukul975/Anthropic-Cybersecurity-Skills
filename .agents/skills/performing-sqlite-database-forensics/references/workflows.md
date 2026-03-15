# Workflows - SQLite Database Forensics

## Workflow 1: Complete Database Analysis
```
Identify SQLite databases in evidence
    |
Create forensic copies (preserve WAL and journal files)
    |
Analyze database header (page size, encoding, freelist)
    |
Query active tables for evidence
    |
Analyze freelist pages for deleted records
    |
Parse WAL file for transaction history
    |
Examine unallocated space within pages
    |
Decode timestamps (Chrome, Unix, Mac Absolute, Mozilla)
    |
Document and export findings
```

## Workflow 2: Deleted Record Recovery
```
Open database in hex editor
    |
Identify freelist trunk/leaf pages from header
    |
Extract raw page data from freelist
    |
Parse B-tree cell format to decode records
    |
Check WAL for pre-deletion snapshots
    |
Examine unallocated space between cell pointers and content area
    |
Carve recoverable records
```
