# Detailed Hunting Workflow - Process Hollowing Detection

## Phase 1: Sysmon-Based Detection

### Step 1.1 - Process Tampering Events (Sysmon v13+)
```spl
index=sysmon EventCode=25
| table _time Computer User Image Type
| sort -_time
```

### Step 1.2 - Suspicious Process Creation Patterns
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(svchost|explorer|rundll32|dllhost|conhost|taskhost)\.exe$")
| where NOT match(ParentImage, "(?i)(services\.exe|explorer\.exe|svchost\.exe|userinit\.exe|winlogon\.exe)")
| table _time Computer User Image ParentImage CommandLine
```

### Step 1.3 - KQL for MDE ProcessTampering
```kql
DeviceEvents
| where ActionType == "ProcessTampering"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

## Phase 2: Parent-Child Process Validation

### Step 2.1 - Invalid Parent-Child Relationships
Known legitimate parent-child pairs:
- services.exe -> svchost.exe
- explorer.exe -> user applications
- winlogon.exe -> userinit.exe
- svchost.exe -> specific service children

```spl
index=sysmon EventCode=1
| eval expected_parent=case(
    match(Image,"(?i)svchost\.exe$"), "services.exe",
    match(Image,"(?i)taskhost\.exe$"), "svchost.exe",
    match(Image,"(?i)userinit\.exe$"), "winlogon.exe",
    match(Image,"(?i)smss\.exe$"), "System",
    1=1, "any"
)
| eval parent_name=mvindex(split(ParentImage,"\\"),-1)
| where expected_parent!="any" AND NOT match(parent_name, expected_parent)
| table _time Computer Image ParentImage expected_parent parent_name CommandLine
```

## Phase 3: Memory Analysis

### Step 3.1 - pe-sieve Scanning
```powershell
# Scan all processes for hollowing
Get-Process | ForEach-Object {
    $pid = $_.Id
    & pe-sieve64.exe /pid $pid /shellc /dmode 1 /json
}
```

### Step 3.2 - Hollows Hunter Full Scan
```powershell
# Run Hollows Hunter for automated detection
hollows_hunter64.exe /loop /json /dir C:\hunt_output
```

### Step 3.3 - Volatility Malfind
```bash
# Detect injected/modified process memory
python vol.py -f memory.raw windows.malfind

# Dump suspicious processes
python vol.py -f memory.raw windows.pslist --dump
```

## Phase 4: Behavioral Analysis

### Step 4.1 - Process Behavior Mismatches
Look for processes whose network/file behavior contradicts their identity:
```spl
index=sysmon EventCode=3
| where match(Image, "(?i)(svchost|dllhost|taskhost|conhost)\.exe$")
| where NOT match(DestinationIp, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
| where DestinationPort NOT IN (53, 80, 443, 123)
| stats count by Image DestinationIp DestinationPort Computer
```

### Step 4.2 - Hollowed Process C2 Indicators
```spl
index=sysmon EventCode=3
| where match(Image, "(?i)(svchost|explorer|rundll32)\.exe$")
| bin _time span=1s
| streamstats current=f last(_time) as prev by Image Computer DestinationIp
| eval interval=_time-prev
| stats count avg(interval) as avg_interval stdev(interval) as sd by Image Computer DestinationIp
| eval cv=sd/avg_interval
| where cv < 0.3 AND count > 20
```

## Phase 5: API Call Monitoring

### Step 5.1 - Critical API Sequences
Monitor for this specific API call chain:
1. `CreateProcessW` / `CreateProcessA` with `CREATE_SUSPENDED` (0x00000004)
2. `NtUnmapViewOfSection` / `ZwUnmapViewOfSection`
3. `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE`
4. `WriteProcessMemory`
5. `SetThreadContext` / `NtSetContextThread`
6. `ResumeThread` / `NtResumeThread`

### Step 5.2 - ETW Process Hollowing Detection
```powershell
# Monitor for suspicious API patterns via ETW
# Requires elevated privileges
$session = New-EtwTraceSession -Name "ProcessHollowHunt"
Add-EtwTraceProvider -SessionName "ProcessHollowHunt" `
    -Guid "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}" `
    -Level 5
```
