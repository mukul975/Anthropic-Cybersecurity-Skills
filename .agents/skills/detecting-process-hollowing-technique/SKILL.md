---
name: detecting-process-hollowing-technique
description: Detect process hollowing (T1055.012) by analyzing memory-mapped sections, hollowed process indicators, and parent-child process anomalies in EDR telemetry.
domain: cybersecurity
subdomain: threat-hunting
tags: [threat-hunting, mitre-attack, process-hollowing, process-injection, edr, t1055, proactive-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Process Hollowing Technique

## When to Use

- When investigating suspected fileless malware or in-memory threats
- After EDR alerts on process injection or suspicious memory operations
- When hunting for defense evasion techniques in a compromised environment
- When threat intel reports indicate process hollowing in active campaigns
- During purple team exercises validating T1055.012 detection coverage

## Prerequisites

- EDR with memory protection monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon with Event IDs 1 (Process Create), 8 (CreateRemoteThread), 25 (ProcessTampering)
- Windows ETW providers for process hollowing (Microsoft-Windows-Kernel-Process)
- Memory forensics capabilities (Volatility, WinDbg)
- Process integrity monitoring tools

## Workflow

1. **Understand Hollowing Mechanics**: Process hollowing involves creating a legitimate process in suspended state, unmapping its memory, writing malicious code, then resuming execution.
2. **Monitor Suspended Process Creation**: Hunt for processes created with CREATE_SUSPENDED flag followed by memory writes and thread resumption.
3. **Detect Memory Section Anomalies**: Identify processes where the in-memory image differs from the on-disk binary (image mismatch).
4. **Analyze Parent-Child Process Trees**: Flag processes whose behavior does not match their binary name (e.g., svchost.exe making unusual network connections).
5. **Check Process Integrity**: Compare process memory sections against the legitimate binary on disk.
6. **Correlate with Network Activity**: Hollowed processes often establish C2 connections - correlate suspicious process behavior with network logs.
7. **Document and Contain**: Report findings, isolate affected endpoints, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1055.012 | Process Injection: Process Hollowing |
| T1055 | Process Injection (parent technique) |
| T1055.001 | DLL Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.004 | Asynchronous Procedure Call |
| CREATE_SUSPENDED | Windows flag to create a process in suspended state |
| NtUnmapViewOfSection | API to unmap process memory sections |
| WriteProcessMemory | API to write into another process's memory |
| ResumeThread | API to resume a suspended thread |
| Image Mismatch | Process memory content differs from on-disk binary |
| Process Doppelganging | Related technique using NTFS transactions (T1055.013) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | Memory protection and hollowing detection |
| Microsoft Defender for Endpoint | ProcessTampering alerts |
| Sysmon v13+ | Event ID 25 ProcessTampering detection |
| Volatility | Memory forensics - malfind plugin |
| pe-sieve | Process memory scanner for hollowed processes |
| Hollows Hunter | Automated hollowed process detection |
| Process Hacker | Live process memory inspection |
| API Monitor | Monitor NtUnmapViewOfSection calls |

## Common Scenarios

1. **Svchost.exe Hollowing**: Malware creates svchost.exe suspended, hollows it, injects backdoor code - process appears legitimate but behaves maliciously.
2. **Explorer.exe Hollowing**: Attacker hollows explorer.exe to inherit its network permissions and trusted process context.
3. **Rundll32 Hollowing**: Malicious loader creates rundll32.exe, replaces its memory with implant code for C2 beaconing.
4. **Multi-Stage Hollowing**: Loader uses process hollowing as first stage, then performs additional injection into services.

## Output Format

```
Hunt ID: TH-HOLLOW-[DATE]-[SEQ]
Technique: T1055.012
Hollowed Process: [Process name and PID]
Original Binary: [Expected on-disk path]
Parent Process: [Parent name and PID]
Memory Mismatch: [Yes/No]
Suspicious APIs: [NtUnmapViewOfSection, WriteProcessMemory, etc.]
Network Activity: [C2 connections if any]
Host: [Hostname]
User: [Account context]
Risk Level: [Critical/High/Medium/Low]
```
