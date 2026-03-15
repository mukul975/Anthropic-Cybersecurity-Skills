# Workflows - EZ Tools Windows Forensic Analysis

## Workflow 1: Full Triage Collection and Processing

```
Step 1: Mount forensic image as read-only drive (E:)
    |
Step 2: Run KAPE with KapeTriage target
    |-- Collects: $MFT, $J, Registry, Event Logs, Prefetch, LNK, Jump Lists
    |
Step 3: Run KAPE with !EZParser module
    |-- Processes all collected artifacts with appropriate EZ Tools
    |
Step 4: Open CSV outputs in Timeline Explorer
    |-- Sort by timestamp, filter by artifact type
    |
Step 5: Build investigation timeline
    |-- Cross-reference MFT, Event Logs, Prefetch, Registry
    |
Step 6: Document findings and export filtered results
```

## Workflow 2: Timestomping Detection

```
Step 1: Parse $MFT with MFTECmd
    |
Step 2: Open MFT CSV in Timeline Explorer
    |
Step 3: Compare $SI timestamps (Created0x10) vs $FN timestamps (Created0x30)
    |-- Flag entries where Created0x10 < Created0x30
    |-- Flag entries where all four $SI timestamps are identical
    |
Step 4: Cross-reference flagged files with USN Journal entries
    |
Step 5: Verify with event log correlation (process creation, file access)
```

## Workflow 3: Program Execution Timeline

```
Step 1: Parse Prefetch with PECmd
    |
Step 2: Parse Amcache.hve with AmcacheParser
    |
Step 3: Parse ShimCache with AppCompatCacheParser
    |
Step 4: Parse UserAssist from NTUSER.DAT with RECmd
    |
Step 5: Merge and correlate execution timestamps
    |-- Prefetch: Run count + last 8 execution times
    |-- Amcache: First execution + SHA1 hash
    |-- ShimCache: Last modified time (execution indicator)
    |-- UserAssist: GUI program execution tracking
    |
Step 6: Build execution timeline in Timeline Explorer
```

## Workflow 4: Lateral Movement Investigation

```
Step 1: Parse Security.evtx with EvtxECmd
    |-- Filter Event ID 4624 (Logon Type 3, 10)
    |-- Filter Event ID 4625 (Failed logons)
    |
Step 2: Parse TerminalServices event logs
    |-- Microsoft-Windows-TerminalServices-LocalSessionManager
    |-- Microsoft-Windows-TerminalServices-RDPClient
    |
Step 3: Correlate with registry RDP MRU entries
    |-- NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers
    |
Step 4: Analyze LNK files for network path access
    |
Step 5: Review scheduled task creation from event logs
    |
Step 6: Map lateral movement path across systems
```

## Workflow 5: USB Device Investigation

```
Step 1: Parse SYSTEM hive with RECmd
    |-- SYSTEM\CurrentControlSet\Enum\USBSTOR
    |-- SYSTEM\CurrentControlSet\Enum\USB
    |-- SYSTEM\MountedDevices
    |
Step 2: Parse NTUSER.DAT with RECmd
    |-- MountPoints2 for user-level device associations
    |
Step 3: Parse setupapi.dev.log for device installation timestamps
    |
Step 4: Analyze LNK files referencing removable drive letters
    |
Step 5: Check Shellbags for folder browsing on USB devices
    |
Step 6: Correlate with Event Logs (Microsoft-Windows-Partition/Diagnostic)
```
