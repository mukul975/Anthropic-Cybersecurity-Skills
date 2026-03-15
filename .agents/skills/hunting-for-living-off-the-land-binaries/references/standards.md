# Standards and References - Hunting for LOLBins

## MITRE ATT&CK Mappings

### Primary Techniques
- **T1218 - Signed Binary Proxy Execution**: Use of trusted binaries to proxy execution of malicious payloads
  - T1218.001 - Compiled HTML File
  - T1218.002 - Control Panel
  - T1218.003 - CMSTP
  - T1218.004 - InstallUtil
  - T1218.005 - Mshta
  - T1218.007 - Msiexec
  - T1218.009 - Regsvcs/Regasm
  - T1218.010 - Regsvr32
  - T1218.011 - Rundll32
  - T1218.012 - Verclsid
  - T1218.013 - Mavinject
  - T1218.014 - MMC

### Supporting Techniques
- **T1197 - BITS Jobs**: Abuse of Background Intelligent Transfer Service
- **T1140 - Deobfuscate/Decode Files or Information**: certutil decode operations
- **T1059.001 - PowerShell**: Script execution through PowerShell LOLBin
- **T1047 - Windows Management Instrumentation**: WMIC-based execution
- **T1216 - Signed Script Proxy Execution**: Trusted script execution (cscript, wscript)
- **T1127 - Trusted Developer Utilities Proxy Execution**: MSBuild, dnx, rcsi

### Tactics Covered
- **TA0002 - Execution**: LOLBins used to execute malicious code
- **TA0005 - Defense Evasion**: Bypassing security controls through trusted binaries
- **TA0003 - Persistence**: Some LOLBins used for persistent execution

## LOLBAS Project Reference

The LOLBAS (Living Off The Land Binaries, Scripts, and Libraries) Project maintains a comprehensive catalog:
- Website: https://lolbas-project.github.io/
- GitHub: https://github.com/LOLBAS-Project/LOLBAS

### High-Priority LOLBins for Hunting

| Binary | ATT&CK ID | Capabilities |
|--------|-----------|-------------|
| certutil.exe | T1140 | Download, encode/decode, ADS |
| mshta.exe | T1218.005 | Execute HTA/VBS, download |
| rundll32.exe | T1218.011 | Execute DLL exports, proxy load |
| regsvr32.exe | T1218.010 | Execute COM scriptlets remotely |
| msiexec.exe | T1218.007 | Install remote MSI packages |
| cmstp.exe | T1218.003 | Execute INF SCT files |
| wmic.exe | T1047 | Remote command execution |
| bitsadmin.exe | T1197 | File transfer, persistence |
| msbuild.exe | T1127.001 | Compile and execute inline tasks |
| installutil.exe | T1218.004 | Execute managed code |
| cscript.exe | T1059.005 | Script execution |
| wscript.exe | T1059.005 | Script execution |
| forfiles.exe | T1202 | Indirect command execution |
| pcalua.exe | T1202 | Program compatibility execution |

## Threat Intelligence References

- CISA Alert AA23-136A: LOLBin abuse in Volt Typhoon campaigns
- Symantec: Living off the Land Techniques in Targeted Attacks
- Microsoft Threat Intelligence: Nation-state LOLBin campaigns
- Red Canary Threat Detection Report: Annual LOLBin detection trends

## Detection Data Sources

| Data Source | Event IDs | Content |
|-------------|----------|---------|
| Sysmon | 1 | Process creation with command line |
| Sysmon | 3 | Network connection from LOLBin |
| Sysmon | 7 | Image loaded (DLL loads) |
| Sysmon | 11 | File creation by LOLBin |
| Windows Security | 4688 | Process creation (enhanced) |
| Windows PowerShell | 4103, 4104 | Script block logging |
| Firewall/Proxy | - | Outbound connections from LOLBins |
