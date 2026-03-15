---
name: detecting-t1055-process-injection-with-sysmon
description: Detect process injection techniques (T1055) including classic DLL injection, process hollowing, and APC injection by analyzing Sysmon events for cross-process memory operations, remote thread creation, and anomalous DLL loading patterns.
domain: cybersecurity
subdomain: threat-hunting
tags: [threat-hunting, process-injection, sysmon, mitre-t1055, defense-evasion, dll-injection, process-hollowing]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting T1055 Process Injection with Sysmon

## When to Use

- When hunting for defense evasion techniques that hide malicious code inside legitimate processes
- After EDR alerts for suspicious cross-process memory access or remote thread creation
- When investigating malware that injects into svchost.exe, explorer.exe, or other system processes
- During purple team exercises testing detection of process injection variants
- When validating Sysmon configuration coverage for injection detection

## Prerequisites

- Sysmon deployed with comprehensive configuration capturing Events 1, 7, 8, 10, 25
- Event ID 8 (CreateRemoteThread) enabled for remote thread detection
- Event ID 10 (ProcessAccess) configured with appropriate access mask filters
- Event ID 7 (ImageLoaded) for DLL injection detection
- Event ID 25 (ProcessTampering) for process hollowing on Sysmon 13+
- SIEM platform for correlation and alerting

## Workflow

1. **Monitor CreateRemoteThread (Event 8)**: Detect when one process creates a thread in another process's address space. This is the primary indicator of classic DLL injection and shellcode injection.
2. **Analyze ProcessAccess (Event 10)**: Track cross-process handle requests with PROCESS_VM_WRITE (0x0020), PROCESS_VM_OPERATION (0x0008), and PROCESS_CREATE_THREAD (0x0002) access rights. Legitimate processes rarely need these on other processes.
3. **Detect Anomalous DLL Loading (Event 7)**: Identify DLLs loaded from unusual paths (user temp directories, download folders) into system processes.
4. **Hunt Process Hollowing (Event 25)**: Sysmon 13+ generates ProcessTampering events when the executable image in memory diverges from what was mapped from disk -- a hallmark of process hollowing (T1055.012).
5. **Correlate with Process Creation**: Link injection events to the originating process creation (Event 1) to build the full attack chain from initial execution to injection.
6. **Filter Known-Good Cross-Process Activity**: Exclude legitimate software that performs cross-process operations (debuggers, AV products, accessibility tools, RMM agents).
7. **Map to ATT&CK Sub-Techniques**: Classify detected injection as classic injection (T1055.001), PE injection (T1055.002), thread execution hijacking (T1055.003), APC injection (T1055.004), thread local storage (T1055.005), process hollowing (T1055.012), or process doppelganging (T1055.013).

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1055.001 | Dynamic-link Library Injection |
| T1055.002 | Portable Executable Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.004 | Asynchronous Procedure Call (APC) Injection |
| T1055.005 | Thread Local Storage |
| T1055.012 | Process Hollowing |
| T1055.013 | Process Doppelganging |
| T1055.015 | ListPlanting |
| Sysmon Event 8 | CreateRemoteThread detected |
| Sysmon Event 10 | ProcessAccess with memory write permissions |
| Sysmon Event 25 | ProcessTampering (image mismatch) |
| Access Mask 0x1FFFFF | PROCESS_ALL_ACCESS -- full cross-process control |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Primary telemetry source for injection detection |
| Process Hacker | Manual investigation of process memory regions |
| PE-sieve | Scan running processes for hollowed/injected code |
| Moneta | Detect anomalous memory regions in processes |
| Splunk / Elastic | SIEM correlation of Sysmon events |
| Volatility | Memory forensics for injection artifacts |
| Hollows Hunter | Automated scan for hollowed processes |

## Detection Queries

### Splunk -- Remote Thread Creation
```spl
index=sysmon EventCode=8
| where SourceImage!=TargetImage
| where NOT match(SourceImage, "(?i)(csrss|lsass|services|svchost|MsMpEng|SecurityHealthService|vmtoolsd)\.exe$")
| eval suspicious=if(match(TargetImage, "(?i)(svchost|explorer|lsass|winlogon|csrss|services)\.exe$"), "high_value_target", "normal_target")
| where suspicious="high_value_target"
| table _time Computer SourceImage SourceProcessId TargetImage TargetProcessId StartFunction NewThreadId
```

### Splunk -- Suspicious ProcessAccess Patterns
```spl
index=sysmon EventCode=10
| where SourceImage!=TargetImage
| where match(GrantedAccess, "(0x1FFFFF|0x1F3FFF|0x143A|0x0040)")
| where match(TargetImage, "(?i)(lsass|svchost|explorer|winlogon)\.exe$")
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|svchost|taskmgr|procexp)\.exe$")
| table _time Computer SourceImage TargetImage GrantedAccess CallTrace
```

### KQL -- Process Injection via Remote Thread
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessFileName !in~ ("csrss.exe", "lsass.exe", "services.exe", "svchost.exe")
| where FileName in~ ("svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, ProcessCommandLine
```

### Sigma Rule -- Process Injection Detection
```yaml
title: Process Injection via CreateRemoteThread into System Process
status: stable
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        TargetImage|endswith:
            - '\svchost.exe'
            - '\explorer.exe'
            - '\lsass.exe'
            - '\winlogon.exe'
    filter_legitimate:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\lsass.exe'
            - '\services.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter_legitimate
level: high
tags:
    - attack.defense_evasion
    - attack.t1055
```

## Common Scenarios

1. **Classic DLL Injection**: Malware uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread to load a malicious DLL into a target process. Detected via Sysmon Event 8.
2. **Process Hollowing (RunPE)**: Attacker creates a suspended process, unmaps its image, writes malicious PE, and resumes execution. Detected via Sysmon Event 25.
3. **APC Injection**: Malware queues an Asynchronous Procedure Call to threads of a target process using QueueUserAPC. Harder to detect, requires Event 10 monitoring.
4. **Reflective DLL Injection**: DLL is loaded directly from memory without touching disk, bypassing ImageLoaded detection. Requires memory-level analysis.
5. **Process Doppelganging**: Leverages NTFS transactions to replace a legitimate process image. Detected via process integrity checking.

## Output Format

```
Hunt ID: TH-INJECT-[DATE]-[SEQ]
Host: [Hostname]
Source Process: [Injecting process path]
Source PID: [Process ID]
Target Process: [Target process path]
Target PID: [Process ID]
Injection Type: [DLL/Shellcode/Hollowing/APC]
Sysmon Events: [Event IDs triggered]
Access Mask: [Granted access value]
Risk Level: [Critical/High/Medium/Low]
ATT&CK Sub-Technique: [T1055.xxx]
```
