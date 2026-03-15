# Detailed Hunting Workflow - T1055 Process Injection

## Phase 1: CreateRemoteThread Detection (Sysmon Event 8)

### Step 1.1 - Identify All Remote Thread Creation
```spl
index=sysmon EventCode=8
| where SourceImage!=TargetImage
| stats count by SourceImage TargetImage Computer
| sort -count
```

### Step 1.2 - Filter to High-Value Target Processes
```spl
index=sysmon EventCode=8
| where match(TargetImage, "(?i)(svchost|explorer|lsass|winlogon|spoolsv|dllhost|RuntimeBroker)\.exe$")
| where NOT match(SourceImage, "(?i)(csrss|lsass|services|svchost|MsMpEng|vmtoolsd)\.exe$")
| stats count values(Computer) as hosts by SourceImage TargetImage
| sort -count
```

## Phase 2: ProcessAccess Analysis (Sysmon Event 10)

### Step 2.1 - High-Privilege Cross-Process Access
```spl
index=sysmon EventCode=10
| where GrantedAccess IN ("0x1FFFFF", "0x1F3FFF", "0x143A", "0x1F0FFF")
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|lsass|services|svchost|taskmgr|procexp)\.exe$")
| where match(TargetImage, "(?i)(lsass|svchost|explorer|winlogon)\.exe$")
| table _time Computer SourceImage TargetImage GrantedAccess CallTrace
```

### Step 2.2 - LSASS Access for Credential Theft
```spl
index=sysmon EventCode=10
| where match(TargetImage, "(?i)lsass\.exe$")
| where match(GrantedAccess, "(0x1FFFFF|0x1F3FFF|0x0040|0x143A)")
| where NOT match(SourceImage, "(?i)(csrss|lsass|svchost|MsMpEng|WmiPrvSE)\.exe$")
| table _time Computer SourceImage GrantedAccess CallTrace
```

## Phase 3: DLL Injection Detection (Sysmon Event 7)

### Step 3.1 - DLLs Loaded from User-Writable Paths
```spl
index=sysmon EventCode=7
| where match(ImageLoaded, "(?i)\\(temp|appdata|downloads|users\\[^\\]+\\desktop)\\")
| where match(Image, "(?i)(svchost|explorer|winlogon|services)\.exe$")
| table _time Computer Image ImageLoaded Hashes Signed
```

### Step 3.2 - Unsigned DLLs in System Processes
```spl
index=sysmon EventCode=7
| where Signed="false"
| where match(Image, "(?i)\\(svchost|services|lsass|explorer)\.exe$")
| table _time Computer Image ImageLoaded Hashes SignatureStatus
```

## Phase 4: Process Hollowing Detection (Sysmon Event 25)

### Step 4.1 - ProcessTampering Events
```spl
index=sysmon EventCode=25
| table _time Computer Image Type RuleName User
```

## Phase 5: Correlation and Investigation

### Step 5.1 - Build Full Attack Chain
```spl
index=sysmon (EventCode=1 OR EventCode=8 OR EventCode=10 OR EventCode=25)
| where match(SourceImage, "[suspected_injector]") OR match(Image, "[suspected_injector]")
| sort _time
| table _time EventCode Image SourceImage TargetImage CommandLine GrantedAccess
```

### Step 5.2 - Memory Analysis
For confirmed injection, capture process memory using:
- PE-sieve for automated scan of hollow/injected processes
- Moneta for memory region anomaly detection
- Volatility malfind plugin for offline memory forensics

## Phase 6: Response

1. Isolate affected endpoint via EDR
2. Capture memory dump before cleanup
3. Identify and remove injecting malware
4. Check for persistence mechanisms deployed by injected code
5. Sweep environment for same injection technique indicators
