# Workflows - LNK and Jump List Analysis

## Workflow 1: User File Access Investigation
```
Collect LNK files from Recent directory
    |
Parse with LECmd to CSV
    |
Filter by target path for specific files/locations
    |
Extract timestamps, volume serial, NetBIOS name
    |
Correlate with MFT and Event Log timestamps
    |
Document file access timeline
```

## Workflow 2: Jump List Application Activity
```
Collect AutomaticDestinations and CustomDestinations
    |
Parse with JLECmd to CSV
    |
Map AppID hashes to applications
    |
Extract embedded LNK entries per application
    |
Build per-application file access timeline
    |
Identify removable media and network paths
```

## Workflow 3: Removable Media Usage
```
Filter LNK files for drive letters (E:, F:, G:)
    |
Extract volume serial numbers
    |
Match with SYSTEM registry USBSTOR entries
    |
Identify specific USB devices accessed
    |
Build user-device-file timeline
```
