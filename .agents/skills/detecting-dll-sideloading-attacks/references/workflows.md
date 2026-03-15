# Detailed Hunting Workflow - DLL Sideloading

## Phase 1: Sysmon DLL Load Analysis

### Step 1.1 - Unsigned DLLs Loaded by Signed Applications
```spl
index=sysmon EventCode=7 Signed=false
| where match(Image, "(?i)\\\\(Program Files|Windows)\\\\")
| where NOT match(ImageLoaded, "(?i)\\\\(Windows|Program Files)\\\\")
| stats count by Image ImageLoaded Signature Computer
| sort -count
```

### Step 1.2 - DLL Loads from Unusual Directories
```spl
index=sysmon EventCode=7
| where match(ImageLoaded, "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\downloads\\\\)")
| where Signed=false OR Signature="?"
| stats count by Image ImageLoaded Computer User
| sort -count
```

### Step 1.3 - KQL for MDE DLL Sideloading
```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("OneDriveUpdater.exe","DismHost.exe","WerFault.exe")
| where not(FolderPath startswith "C:\\Windows" or FolderPath startswith "C:\\Program Files")
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName, SHA256
```

## Phase 2: Legitimate App in Wrong Location

### Step 2.1 - Signed Binaries Running Outside Standard Paths
```spl
index=sysmon EventCode=1
| where NOT match(Image, "(?i)^(C:\\\\Windows|C:\\\\Program Files)")
| where match(Image, "(?i)(svchost|explorer|rundll32|dllhost|OneDrive|Teams)\.exe$")
| table _time Computer User Image CommandLine ParentImage Hashes
```

## Phase 3: Hash-Based Detection

### Step 3.1 - Known-Bad DLL Hashes
Compare loaded DLL hashes against threat intelligence:
```spl
index=sysmon EventCode=7
| rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| lookup threat_intel_hashes sha256 OUTPUT malware_family confidence
| where isnotnull(malware_family)
| table _time Computer Image ImageLoaded sha256 malware_family
```

## Phase 4: Behavioral Correlation

### Step 4.1 - Network Activity After DLL Load
Correlate DLL loads with subsequent network connections:
```spl
index=sysmon EventCode=7 Signed=false
| rename Image as proc_image
| join proc_image Computer [
    search index=sysmon EventCode=3
    | rename Image as proc_image
    | where NOT match(DestinationIp, "^(10\.|172\.|192\.168\.)")
]
| table _time Computer proc_image ImageLoaded DestinationIp DestinationPort
```
