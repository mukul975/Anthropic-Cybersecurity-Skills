# Standards and References - DLL Sideloading Detection

## MITRE ATT&CK Mappings

### T1574.002 - Hijack Execution Flow: DLL Side-Loading
- **Tactic**: Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005)
- **Platforms**: Windows
- **Data Sources**: File monitoring, DLL monitoring, Process monitoring

### Related Techniques
| Technique | Name |
|-----------|------|
| T1574.001 | DLL Search Order Hijacking |
| T1574.006 | Dynamic Linker Hijacking |
| T1574.008 | Path Interception by Search Order |
| T1574.009 | Path Interception by Unquoted Service Path |
| T1574.011 | Services Registry Permissions Weakness |
| T1574.012 | COR_PROFILER |

## Windows DLL Search Order

1. Directory of the executable (or directory specified by SetDllDirectory)
2. System32 directory
3. 16-bit system directory
4. Windows directory
5. Current working directory
6. PATH environment variable directories

## Known Vulnerable Applications

| Application | Vulnerable DLL | Vendor | Notes |
|-------------|---------------|--------|-------|
| OneDriveUpdater.exe | version.dll | Microsoft | Frequently abused by APTs |
| Teams.exe | CRYPTSP.dll | Microsoft | Side-loading target |
| DismHost.exe | dismcore.dll | Microsoft | Signed binary side-loading |
| MpCmdRun.exe | mpclient.dll | Microsoft | AV binary abuse |
| WerFault.exe | dbgcore.dll | Microsoft | Error handler abuse |
| Grammarly | Various | Grammarly | User-space application |
| Zoom | Various | Zoom | Meeting application |

## Detection Data Sources

| Source | Event | Purpose |
|--------|-------|---------|
| Sysmon Event 7 | Image Loaded | DLL load with hash and signature |
| Sysmon Event 1 | Process Create | Application launch location |
| Windows Security 4688 | Process Create | Command line monitoring |
| ETW | DLL Load Events | Kernel-level DLL tracking |
| MDE | DeviceImageLoadEvents | DLL load telemetry |
