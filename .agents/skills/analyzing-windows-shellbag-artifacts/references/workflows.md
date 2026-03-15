# Workflows - Shellbag Analysis
## Workflow 1: Folder Access Investigation
```
Extract NTUSER.DAT and UsrClass.dat from evidence
    |
Parse with SBECmd to CSV
    |
Open in Timeline Explorer
    |
Filter by path patterns (USB drives, network shares)
    |
Correlate with MFT and LNK file timestamps
    |
Document folder access timeline
```
