# Detailed Hunting Workflow - T1548 Elevation Control Abuse

## Phase 1: Registry-Based UAC Bypass Detection

### Step 1.1 - Monitor UAC Registry Keys
```spl
index=sysmon (EventCode=12 OR EventCode=13)
| where match(TargetObject, "(?i)(ms-settings|mscfile|exefile|Folder)\\\\shell\\\\open\\\\command")
| table _time Computer User Image TargetObject Details EventCode
```

### Step 1.2 - Detect UAC Policy Changes
```spl
index=sysmon EventCode=13
| where match(TargetObject, "(?i)Policies\\\\System\\\\(EnableLUA|ConsentPromptBehaviorAdmin)")
| table _time Computer User Image TargetObject Details
```

## Phase 2: Auto-Elevating Process Chain Detection

### Step 2.1 - Suspicious Auto-Elevate Launches
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(fodhelper|computerdefaults|eventvwr|sdclt|slui)\.exe$")
| where NOT match(ParentImage, "(?i)(explorer\.exe|svchost\.exe)$")
| stats count by Image ParentImage Computer User
```

### Step 2.2 - Children of Auto-Elevate Processes
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(fodhelper|computerdefaults|eventvwr|sdclt|slui)\.exe$")
| where match(Image, "(?i)(cmd|powershell|wscript|cscript|mshta)\.exe$")
| table _time Computer Image CommandLine ParentImage User
```

## Phase 3: Linux Elevation Abuse

### Step 3.1 - Setuid Binary Hunting
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

### Step 3.2 - Sudo Abuse Detection
```spl
index=linux sourcetype=syslog
| where match(_raw, "(?i)sudo.*COMMAND=")
| where NOT match(_raw, "(?i)(apt-get|yum|systemctl|service)")
| table _time host user command
```

## Phase 4: Response
1. Revert malicious registry modifications
2. Investigate what was executed with elevated privileges
3. Set UAC to highest level (Always Notify)
4. Deploy ASR rules against UAC bypasses
5. Monitor for repeated escalation attempts
