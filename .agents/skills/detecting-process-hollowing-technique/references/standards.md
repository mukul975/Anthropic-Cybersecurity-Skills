# Standards and References - Process Hollowing Detection

## MITRE ATT&CK Mappings

### T1055.012 - Process Injection: Process Hollowing
- **Tactic**: Defense Evasion (TA0005), Privilege Escalation (TA0004)
- **Platforms**: Windows
- **Data Sources**: Process modification, OS API execution, Process access

### Related Process Injection Sub-Techniques
| Sub-Technique | Name |
|---------------|------|
| T1055.001 | Dynamic-link Library Injection |
| T1055.002 | Portable Executable Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.004 | Asynchronous Procedure Call |
| T1055.005 | Thread Local Storage |
| T1055.008 | Ptrace System Calls |
| T1055.009 | Proc Memory |
| T1055.011 | Extra Window Memory Injection |
| T1055.012 | Process Hollowing |
| T1055.013 | Process Doppelganging |
| T1055.014 | VDSO Hijacking |
| T1055.015 | ListPlanting |

## Process Hollowing API Call Sequence

```
1. CreateProcess(CREATE_SUSPENDED)     -> Create target in suspended state
2. NtQueryInformationProcess           -> Get PEB address
3. ReadProcessMemory(PEB)              -> Read image base from PEB
4. NtUnmapViewOfSection(ImageBase)     -> Unmap original image
5. VirtualAllocEx(ImageBase, size)     -> Allocate memory at same base
6. WriteProcessMemory(PE headers)      -> Write malicious PE headers
7. WriteProcessMemory(PE sections)     -> Write malicious code sections
8. SetThreadContext(EntryPoint)        -> Set new entry point
9. ResumeThread                        -> Resume execution with malicious code
```

## Detection Data Sources

| Source | Event/Indicator | Description |
|--------|----------------|-------------|
| Sysmon Event 1 | Process Create | Process created with suspicious parent |
| Sysmon Event 8 | CreateRemoteThread | Remote thread in target process |
| Sysmon Event 25 | ProcessTampering | Image file replaced (Sysmon v13+) |
| ETW | Microsoft-Windows-Kernel-Process | Kernel-level process events |
| MDE | ProcessTampering | AlertType for hollowing detection |
| Memory | Malfind | Volatility plugin for injected code |
| Memory | VAD analysis | Virtual Address Descriptor anomalies |

## Volatility Forensic Commands

```bash
# Detect injected/hollowed processes
volatility -f memory.dmp --profile=Win10x64 malfind

# Compare process memory to disk image
volatility -f memory.dmp --profile=Win10x64 procdump -p <PID> -D ./dump/

# Analyze process memory sections
volatility -f memory.dmp --profile=Win10x64 vadinfo -p <PID>

# Check process image path vs loaded modules
volatility -f memory.dmp --profile=Win10x64 dlllist -p <PID>
```

## Known Malware Using Process Hollowing

| Malware | Target Process | Notes |
|---------|---------------|-------|
| Emotet | Multiple | Uses hollowing for persistence |
| TrickBot | svchost.exe | Hollows svchost for C2 |
| Dridex | explorer.exe | Financial trojan |
| FormBook | Various | Infostealer using hollowing |
| AgentTesla | RegAsm.exe, MSBuild.exe | Targets .NET processes |
| Remcos | Common utilities | RAT using hollowing |
| NanoCore | Various | RAT with hollowing capability |
| AsyncRAT | Various .NET processes | Open-source RAT |
