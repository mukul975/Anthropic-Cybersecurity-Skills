# Standards and References - LOLBins Threat Hunting

## MITRE ATT&CK LOLBin Techniques

| Technique | Binary | Abuse Pattern |
|-----------|--------|---------------|
| T1218.001 | Compiled HTML (hh.exe) | Execute payloads from CHM files |
| T1218.003 | CMSTP | UAC bypass and proxy execution |
| T1218.005 | Mshta | Execute HTA files with scripts |
| T1218.010 | Regsvr32 | Squiblydoo - remote SCT execution |
| T1218.011 | Rundll32 | Proxy execution of malicious DLLs |
| T1127.001 | MSBuild | Execute inline C#/VB tasks |
| T1197 | Bitsadmin | Stealthy file downloads via BITS |
| T1140 | Certutil | Download and decode files |
| T1059.001 | PowerShell | Script execution and download cradles |
| T1059.005 | Wscript/Cscript | VBScript/JScript execution |
| T1047 | WMIC | Remote execution and XSL script execution |
| T1053.005 | Schtasks | Scheduled task creation for persistence |

## Top 8 LOLBins by Threat Actor Usage (CrowdStrike Research)

| LOLBin | Common Abuse | Detection Priority |
|--------|-------------|-------------------|
| PowerShell.exe | Download cradles, encoded commands, AMSI bypass | Critical |
| Cmd.exe | Script execution, chaining with other LOLBins | Critical |
| Rundll32.exe | DLL proxy execution from user directories | Critical |
| Certutil.exe | File download (-urlcache), decode (-decode) | High |
| Mshta.exe | Remote HTA execution, inline scripts | High |
| Regsvr32.exe | SCT execution (Squiblydoo), COM object abuse | High |
| MSBuild.exe | Inline task execution bypassing AppLocker | High |
| WMIC.exe | Remote process creation, XSL execution | Medium |

## Suspicious Parent-Child Process Relationships

| Parent Process | Child LOLBin | Indicates |
|---------------|-------------|-----------|
| winword.exe | mshta.exe | Weaponized Office document |
| excel.exe | certutil.exe | Macro downloading payload |
| outlook.exe | powershell.exe | Phishing payload execution |
| wmiprvse.exe | cmd.exe | WMI-based lateral movement |
| explorer.exe | regsvr32.exe | User-triggered exploitation |
| svchost.exe | msbuild.exe | Service-based code execution |
| w3wp.exe | cmd.exe | Web shell activity |

## Sysmon Events for LOLBin Detection

| Event ID | Description | LOLBin Relevance |
|----------|-------------|-----------------|
| 1 | Process Creation | Primary detection - command line and parent process |
| 3 | Network Connection | LOLBin outbound connections (download/C2) |
| 7 | Image Loaded | DLLs loaded by LOLBins |
| 11 | File Created | Files dropped by LOLBin execution |
| 15 | FileCreateStreamHash | Alternate data stream creation |
| 22 | DNS Query | DNS resolution from LOLBin processes |
