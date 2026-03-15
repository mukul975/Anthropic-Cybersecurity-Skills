# Detailed Hunting Workflow - Lateral Movement with Splunk

## Phase 1: Network Logon Analysis

### Step 1.1 - Type 3 Network Logons (SMB, WinRM)
```spl
index=wineventlog EventCode=4624 Logon_Type=3
| where NOT match(Account_Name, "(?i)(SYSTEM|ANONYMOUS|\\$)")
| stats count dc(Computer) as unique_destinations values(Computer) as destinations by Account_Name Source_Network_Address
| where unique_destinations > 3
| sort -unique_destinations
```

### Step 1.2 - Type 10 RDP Logons
```spl
index=wineventlog EventCode=4624 Logon_Type=10
| stats count by Account_Name Source_Network_Address Computer
| lookup dnslookup clientip as Source_Network_Address OUTPUT clienthost as src_hostname
| table Account_Name src_hostname Source_Network_Address Computer count
| sort -count
```

### Step 1.3 - Explicit Credential Logons (PsExec, RunAs)
```spl
index=wineventlog EventCode=4648
| where NOT match(Target_Server_Name, "(?i)(localhost|\\$)")
| stats count values(Target_Server_Name) as targets by Account_Name Process_Name Computer
| sort -count
```

## Phase 2: Admin Share Access Detection

### Step 2.1 - ADMIN$ and C$ Share Access
```spl
index=wineventlog EventCode=5140
| where Share_Name IN ("\\\\*\\ADMIN$", "\\\\*\\C$", "\\\\*\\IPC$")
| where NOT match(Account_Name, "(?i)(\\$|SYSTEM)")
| stats count values(Share_Name) as shares by Account_Name Source_Address Computer
| sort -count
```

### Step 2.2 - SMB File Operations on Admin Shares
```spl
index=wineventlog EventCode=5145
| where match(Share_Name, "(?i)(ADMIN\\$|C\\$)")
| where match(Relative_Target_Name, "(?i)(\\.exe|\\.dll|\\.ps1|\\.bat|\\.cmd)")
| stats count by Account_Name Source_Address Share_Name Relative_Target_Name Computer
```

## Phase 3: Service-Based Lateral Movement

### Step 3.1 - PsExec Service Installation
```spl
index=wineventlog EventCode=7045
| where match(Service_File_Name, "(?i)(psexec|PSEXESVC|cmd\.exe|powershell)")
| table _time Computer Service_Name Service_File_Name Service_Account
```

### Step 3.2 - Remote Service Creation Correlation
```spl
index=wineventlog EventCode=7045
| eval is_suspicious=if(match(Service_File_Name, "(?i)(temp|appdata|cmd|powershell)"), 1, 0)
| where is_suspicious=1
| join Computer [
    search index=wineventlog EventCode=4624 Logon_Type=3
    | rename Computer as Computer, Source_Network_Address as lateral_src
]
| table _time Computer Service_Name Service_File_Name lateral_src
```

## Phase 4: WMI and DCOM Lateral Movement

### Step 4.1 - Remote WMI Execution
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)WmiPrvSE\.exe") AND NOT match(Image, "(?i)(WmiApSrv|scrcons)")
| table _time Computer User ParentImage Image CommandLine
```

### Step 4.2 - DCOM Lateral Movement
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(mmc\.exe|excel\.exe|outlook\.exe)")
| where match(Image, "(?i)(cmd\.exe|powershell\.exe|mshta\.exe)")
| table _time Computer User ParentImage Image CommandLine
```

## Phase 5: Authentication Graph Analysis

### Step 5.1 - Build Lateral Movement Graph
```spl
index=wineventlog EventCode=4624 Logon_Type IN (3, 10)
| where NOT match(Account_Name, "(?i)(\\$|SYSTEM|ANONYMOUS)")
| eval connection=Source_Network_Address."->".Computer
| stats count first(_time) as first_seen last(_time) as last_seen by connection Account_Name
| sort -count
```

### Step 5.2 - First-Time Source-Destination Pairs
```spl
index=wineventlog EventCode=4624 Logon_Type IN (3, 10) earliest=-1d
| where NOT match(Account_Name, "(?i)(\\$|SYSTEM)")
| eval pair=Account_Name.":".Source_Network_Address."->".Computer
| search NOT [
    | search index=wineventlog EventCode=4624 Logon_Type IN (3, 10) earliest=-30d latest=-1d
    | eval pair=Account_Name.":".Source_Network_Address."->".Computer
    | dedup pair
    | fields pair
]
| stats count by pair
| sort -count
```

## Phase 6: Anomaly Detection

### Step 6.1 - Velocity Anomaly (Rapid Multi-Host Access)
```spl
index=wineventlog EventCode=4624 Logon_Type=3
| where NOT match(Account_Name, "(?i)(\\$|SYSTEM)")
| bin _time span=10m
| stats dc(Computer) as hosts_accessed values(Computer) as destinations by _time Account_Name Source_Network_Address
| where hosts_accessed > 5
| sort -hosts_accessed
```

### Step 6.2 - Off-Hours Lateral Movement
```spl
index=wineventlog EventCode=4624 Logon_Type IN (3, 10)
| where NOT match(Account_Name, "(?i)(\\$|SYSTEM)")
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by Account_Name Source_Network_Address Computer hour
| sort -count
```

### Step 6.3 - Service Account Lateral Movement
```spl
index=wineventlog EventCode=4624 Logon_Type=10
| where match(Account_Name, "(?i)(svc_|service|admin)")
| stats count by Account_Name Source_Network_Address Computer
| sort -count
```
