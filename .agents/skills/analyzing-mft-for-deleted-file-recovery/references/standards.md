# Standards and References - MFT Deleted File Recovery

## Standards
- NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response
- ISO/IEC 27037: Guidelines for identification, collection, acquisition and preservation of digital evidence
- SWGDE Best Practices for Computer Forensics

## Key Technical References
- NTFS Documentation (Microsoft): File system internals and MFT structure
- MFTECmd by Eric Zimmerman: Primary parsing tool for $MFT, $J, $LogFile, $Boot
- analyzeMFT (Python): Open-source MFT parser for cross-platform analysis
- ntfstool (GitHub): Forensics tool for NTFS parsing, MFT, BitLocker, deleted files

## MITRE ATT&CK Mappings
- T1070.004 - Indicator Removal: File Deletion
- T1070.006 - Indicator Removal: Timestomping
- T1485 - Data Destruction
- T1561 - Disk Wipe

## NTFS Specifications
- MFT Record Size: 1024 bytes (default)
- MFT Entry 0: $MFT (self-reference)
- MFT Entry 1: $MFTMirr (mirror of first 4 entries)
- MFT Entry 2: $LogFile (transaction log)
- MFT Entry 5: Root directory
- MFT Entry 6: $Bitmap (cluster allocation)
- MFT Entry 8: $BadClus (bad cluster list)
- MFT Entry 11: $Extend (extended metadata)
