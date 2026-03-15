# Process Injection Detection API Reference

## Sysmon Event ID 8 — CreateRemoteThread

```xml
<EventID>8</EventID>
<Data Name="SourceImage">C:\Users\attacker\malware.exe</Data>
<Data Name="TargetImage">C:\Windows\System32\svchost.exe</Data>
<Data Name="StartFunction">LoadLibraryA</Data>
<Data Name="StartModule">C:\Users\attacker\evil.dll</Data>
<Data Name="NewThreadId">12345</Data>
<Data Name="SourceProcessId">1234</Data>
<Data Name="TargetProcessId">5678</Data>
```

## Sysmon Event ID 10 — ProcessAccess

```xml
<EventID>10</EventID>
<Data Name="SourceImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
<Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
<Data Name="GrantedAccess">0x1F0FFF</Data>
<Data Name="SourceProcessId">4444</Data>
<Data Name="TargetProcessId">680</Data>
```

## Dangerous Access Rights Masks

| Hex Value | Meaning | Risk |
|-----------|---------|------|
| `0x1F0FFF` | PROCESS_ALL_ACCESS | Critical |
| `0x0020` | PROCESS_VM_WRITE | High |
| `0x0008` | PROCESS_VM_OPERATION | High |
| `0x0002` | PROCESS_CREATE_THREAD | High |
| `0x001A` | VM_WRITE + VM_OPERATION + CREATE_THREAD | Critical |
| `0x143A` | Classic injection rights combo | Critical |
| `0x0040` | PROCESS_DUP_HANDLE | Medium |
| `0x0010` | PROCESS_VM_READ | Low |

## Sysmon Configuration for Injection Detection

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- CreateRemoteThread -->
    <CreateRemoteThread onmatch="exclude">
      <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
    </CreateRemoteThread>

    <!-- ProcessAccess to LSASS -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

## Splunk Detection Queries

```spl
# CreateRemoteThread from Office apps
index=sysmon EventCode=8
| where match(SourceImage, "(?i)(winword|excel|powerpnt|outlook)\.exe$")
| table _time SourceImage TargetImage StartFunction User

# Suspicious ProcessAccess to LSASS
index=sysmon EventCode=10 TargetImage="*lsass.exe"
  GrantedAccess IN ("0x1F0FFF", "0x143A", "0x001A")
| where NOT match(SourceImage, "(?i)(csrss|MsMpEng|avp)\.exe$")
| stats count by SourceImage GrantedAccess
```

## MITRE ATT&CK T1055 Sub-techniques

| ID | Name | API Calls |
|----|------|-----------|
| T1055.001 | DLL Injection | CreateRemoteThread, LoadLibrary |
| T1055.002 | PE Injection | VirtualAllocEx, WriteProcessMemory |
| T1055.003 | Thread Execution Hijacking | SuspendThread, SetThreadContext |
| T1055.004 | APC Injection | QueueUserAPC |
| T1055.005 | Thread Local Storage | TLS callbacks |
| T1055.012 | Process Hollowing | NtUnmapViewOfSection, WriteProcessMemory |

## Atomic Red Team Tests

```bash
# T1055.001 - DLL Injection via CreateRemoteThread
Invoke-AtomicTest T1055.001

# T1055.012 - Process Hollowing
Invoke-AtomicTest T1055.012
```
