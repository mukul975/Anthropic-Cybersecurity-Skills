# Detailed Hunting Workflow - LOLBins

## Phase 1: Intelligence Gathering

### Step 1.1 - Review Current Threat Landscape
- Check LOLBAS Project for newly added binaries
- Review threat intel feeds for active campaigns abusing LOLBins
- Correlate with CISA advisories and vendor threat reports
- Identify LOLBins relevant to your environment's OS versions

### Step 1.2 - Prioritize Target LOLBins
- Rank LOLBins by prevalence in current threat campaigns
- Consider which LOLBins have no existing detection rules
- Focus on LOLBins with download, execute, and encode capabilities
- Map to MITRE ATT&CK navigator for coverage gaps

## Phase 2: Data Collection

### Step 2.1 - Sysmon Process Creation Query (Event ID 1)
```
EventID=1 AND (
  Image CONTAINS "certutil.exe" OR
  Image CONTAINS "mshta.exe" OR
  Image CONTAINS "rundll32.exe" OR
  Image CONTAINS "regsvr32.exe" OR
  Image CONTAINS "msiexec.exe" OR
  Image CONTAINS "cmstp.exe" OR
  Image CONTAINS "wmic.exe" OR
  Image CONTAINS "bitsadmin.exe" OR
  Image CONTAINS "msbuild.exe"
)
```

### Step 2.2 - Splunk SPL Query for LOLBin Network Activity
```spl
index=sysmon EventCode=3
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msiexec|bitsadmin)\.exe$")
| stats count by Image, DestinationIp, DestinationPort, User
| where DestinationIp!="10.*" AND DestinationIp!="172.16.*" AND DestinationIp!="192.168.*"
| sort -count
```

### Step 2.3 - KQL Query for Microsoft Defender for Endpoint
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("certutil.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","cmstp.exe")
| where ProcessCommandLine has_any ("http","ftp","urlcache","-decode","/i:","scrobj.dll","-enc")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Phase 3: Baseline Analysis

### Step 3.1 - Establish Normal Usage Patterns
- Count daily executions per LOLBin per endpoint
- Document standard parent processes (explorer.exe -> certutil.exe for IT admin)
- Record typical command-line arguments for legitimate use
- Note time-of-day patterns (business hours vs. off-hours)

### Step 3.2 - Build Frequency Analysis
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32)\.exe$")
| timechart span=1h count by Image
| eventstats avg(certutil.exe) as avg_certutil, stdev(certutil.exe) as stdev_certutil
| where certutil.exe > (avg_certutil + 3*stdev_certutil)
```

## Phase 4: Anomaly Detection

### Step 4.1 - Suspicious Command-Line Indicators
| LOLBin | Suspicious Argument | Reason |
|--------|---------------------|--------|
| certutil.exe | `-urlcache -split -f` | Remote file download |
| certutil.exe | `-encode` / `-decode` | Data encoding/obfuscation |
| mshta.exe | `javascript:` or `vbscript:` | Inline script execution |
| regsvr32.exe | `/s /n /u /i:http` | Remote SCT execution (Squiblydoo) |
| rundll32.exe | `javascript:` | Script execution proxy |
| bitsadmin.exe | `/transfer` with URL | File download |
| msiexec.exe | `/q /i http://` | Silent remote MSI install |
| cmstp.exe | `/s /ns` with INF file | UAC bypass |

### Step 4.2 - Anomalous Parent-Child Relationships
Flag when these parent processes spawn LOLBins:
- `winword.exe` -> `certutil.exe` (document downloading payload)
- `outlook.exe` -> `mshta.exe` (email launching HTA)
- `wmiprvse.exe` -> `rundll32.exe` (WMI lateral movement)
- `svchost.exe` -> `regsvr32.exe` (service spawning proxy execution)

## Phase 5: Correlation and Enrichment

### Step 5.1 - Network Correlation
- Match LOLBin network connections to threat intel domain/IP lists
- Check destination IPs against VirusTotal, AbuseIPDB
- Verify if domains are newly registered (DGA detection)
- Correlate with DNS query logs for suspicious resolutions

### Step 5.2 - File Activity Correlation
- Track files created by LOLBin processes
- Check file hashes against threat intel feeds
- Monitor for files written to unusual directories (Temp, AppData, ProgramData)
- Look for ADS (Alternate Data Streams) usage

## Phase 6: Documentation and Response

### Step 6.1 - Document Findings
- Record all true positive findings with evidence
- Document false positive patterns for tuning
- Update detection analytics with new signatures
- Create IOC lists for identified threats

### Step 6.2 - Update Detection Coverage
- Write or update Sigma rules for identified patterns
- Deploy new EDR detection rules
- Update SIEM correlation rules
- Add findings to MITRE ATT&CK Navigator heatmap
