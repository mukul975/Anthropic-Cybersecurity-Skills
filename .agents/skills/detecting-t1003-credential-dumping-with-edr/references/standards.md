# Standards and References - T1003 Credential Dumping Detection

## MITRE ATT&CK Credential Dumping Sub-Techniques

| Sub-Technique | Target | Common Tools | Primary Detection |
|--------------|--------|-------------|-------------------|
| T1003.001 | LSASS Memory | Mimikatz, ProcDump, comsvcs.dll | Sysmon Event 10, EDR LSASS alerts |
| T1003.002 | SAM Database | reg save, Mimikatz | Registry access auditing |
| T1003.003 | NTDS.dit | ntdsutil, vssadmin, secretsdump | VSS creation + file access |
| T1003.004 | LSA Secrets | Mimikatz, reg save | Registry access to SECURITY hive |
| T1003.005 | Cached Domain Creds | Mimikatz, cachedump | SECURITY hive access |
| T1003.006 | DCSync | Mimikatz, Impacket | Event 4662 replication GUIDs |

## LSASS Access Masks for Credential Dumping

| Access Mask | Meaning | Risk Level |
|-------------|---------|-----------|
| 0x1FFFFF | PROCESS_ALL_ACCESS | Critical |
| 0x1F3FFF | Near-full access | Critical |
| 0x143A | Mimikatz typical access | Critical |
| 0x1F0FFF | Full minus synchronize | Critical |
| 0x0040 | PROCESS_VM_READ | High |
| 0x1010 | PROCESS_VM_READ + QUERY_INFO | High |

## Protection Controls

| Control | Description | Effectiveness |
|---------|-------------|---------------|
| Credential Guard | Virtualizes LSASS secrets | High -- prevents plaintext extraction |
| RunAsPPL | Protected Process Light for LSASS | Medium -- blocks unsigned callers |
| ASR Rules | Attack Surface Reduction for LSASS | Medium -- blocks common tools |
| LSASS SACL | Audit logging for LSASS access | Detection only |
| Windows Defender Credential Guard | Hardware-backed isolation | High |

## Known Credential Dumping Tools

| Tool | Method | Detection Signature |
|------|--------|-------------------|
| Mimikatz | Direct LSASS read via API | sekurlsa::, lsadump:: |
| ProcDump | LSASS dump via MiniDumpWriteDump | procdump -ma lsass |
| comsvcs.dll | Built-in DLL MiniDump function | comsvcs.dll,MiniDump |
| Task Manager | GUI-based LSASS dump | taskmgr.exe accessing lsass |
| ntdsutil | IFM creation for NTDS | "ac i ntds" "ifm" |
| secretsdump.py | Remote NTDS extraction | Impacket network activity |
| LaZagne | Multi-source credential harvesting | lazagne.exe all |
