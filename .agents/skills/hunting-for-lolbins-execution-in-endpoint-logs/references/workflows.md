# Detailed Hunting Workflow - LOLBins Execution Detection

## Phase 1: Establish LOLBin Baseline

### Step 1.1 - Profile Normal LOLBin Usage
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msbuild|installutil|cmstp|bitsadmin|wmic)\.exe$")
| stats count by Image CommandLine ParentImage User Computer
| sort -count
```

### Step 1.2 - Identify Standard Parent-Child Relationships
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32)\.exe$")
| stats count by ParentImage Image
| sort -count
| head 50
```

## Phase 2: Hunt for Download Cradles

### Step 2.1 - Certutil Download Detection
```spl
index=sysmon EventCode=1 Image="*\\certutil.exe"
| where match(CommandLine, "(?i)(-urlcache|-decode|-encode|-verifyctl)")
| table _time Computer User Image CommandLine ParentImage
```

### Step 2.2 - Bitsadmin Transfer Detection
```spl
index=sysmon EventCode=1 Image="*\\bitsadmin.exe"
| where match(CommandLine, "(?i)(/transfer|/create|/addfile|/resume)")
| table _time Computer User CommandLine ParentImage
```

### Step 2.3 - PowerShell Download Cradles
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| where match(CommandLine, "(?i)(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|iwr|wget|curl|Start-BitsTransfer|Net\.WebClient)")
| table _time Computer User CommandLine ParentImage
```

## Phase 3: Hunt for Proxy Execution

### Step 3.1 - Regsvr32 Squiblydoo
```spl
index=sysmon EventCode=1 Image="*\\regsvr32.exe"
| where match(CommandLine, "(?i)(/s.*(/n|/i:))|scrobj\.dll|http")
| table _time Computer User CommandLine ParentImage
```

### Step 3.2 - MSBuild Inline Task Execution
```spl
index=sysmon EventCode=1 Image="*\\MSBuild.exe"
| where NOT match(ParentImage, "(?i)(devenv|msbuild|visual studio)")
| where match(CommandLine, "(?i)\\\\(temp|appdata|users|public)")
| table _time Computer User CommandLine ParentImage
```

### Step 3.3 - Mshta Remote Execution
```spl
index=sysmon EventCode=1 Image="*\\mshta.exe"
| where match(CommandLine, "(?i)(http|https|javascript|vbscript)")
| table _time Computer User CommandLine ParentImage
```

## Phase 4: Hunt for Unusual Parent Processes

### Step 4.1 - Office Applications Spawning LOLBins
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(winword|excel|powerpnt|outlook|onenote)\.exe$")
| where match(Image, "(?i)(cmd|powershell|certutil|mshta|rundll32|regsvr32|wscript|cscript)\.exe$")
| table _time Computer User ParentImage Image CommandLine
```

### Step 4.2 - Web Server Spawning System Binaries
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(w3wp|httpd|nginx|tomcat)\.exe$")
| where match(Image, "(?i)(cmd|powershell|certutil|whoami|net|net1|nltest)\.exe$")
| table _time Computer User ParentImage Image CommandLine
```

## Phase 5: Correlate with Network Activity

### Step 5.1 - LOLBin Network Connections
```spl
index=sysmon EventCode=3
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msbuild|bitsadmin|wscript)\.exe$")
| where NOT cidrmatch("10.0.0.0/8", DestinationIp)
| table _time Computer Image DestinationIp DestinationPort DestinationHostname
```

## Phase 6: Response Actions

1. Block identified malicious URLs and IPs at proxy/firewall
2. Isolate endpoint if active compromise confirmed
3. Collect process memory dump for malware analysis
4. Deploy targeted detection rules for observed patterns
5. Update application control policies to restrict LOLBin abuse
