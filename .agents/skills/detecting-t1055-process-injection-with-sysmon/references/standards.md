# Standards and References - T1055 Process Injection Detection

## MITRE ATT&CK Process Injection Sub-Techniques

| Sub-Technique | Name | API Calls | Sysmon Detection |
|--------------|------|-----------|-----------------|
| T1055.001 | Dynamic-link Library Injection | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | Event 8, 10 |
| T1055.002 | Portable Executable Injection | VirtualAllocEx, WriteProcessMemory, SetThreadContext | Event 10 |
| T1055.003 | Thread Execution Hijacking | SuspendThread, SetThreadContext, ResumeThread | Event 10 |
| T1055.004 | Asynchronous Procedure Call | OpenThread, QueueUserAPC | Event 10 |
| T1055.005 | Thread Local Storage | TLS callback manipulation | Event 10 |
| T1055.012 | Process Hollowing | CreateProcess (SUSPENDED), NtUnmapViewOfSection, WriteProcessMemory | Event 25, 10 |
| T1055.013 | Process Doppelganging | NtCreateTransaction, NtCreateSection, NtRollbackTransaction | Event 25 |
| T1055.015 | ListPlanting | SendMessage to set list item text | Limited Sysmon coverage |

## Critical Sysmon Events for Injection Detection

| Event ID | Name | Detection Value |
|----------|------|----------------|
| 1 | Process Create | Baseline the originating process |
| 7 | Image Loaded | Detect DLL injection from unusual paths |
| 8 | CreateRemoteThread | Primary injection indicator |
| 10 | ProcessAccess | Cross-process handle acquisition |
| 25 | ProcessTampering | Process hollowing detection (Sysmon 13+) |

## ProcessAccess Granted Access Masks

| Access Mask | Permissions | Risk |
|-------------|------------|------|
| 0x1FFFFF | PROCESS_ALL_ACCESS | Critical - full process control |
| 0x1F3FFF | Nearly all access rights | Critical |
| 0x0040 | PROCESS_VM_READ | Medium - credential dumping |
| 0x0020 | PROCESS_VM_WRITE | High - memory modification |
| 0x0008 | PROCESS_VM_OPERATION | High - memory allocation |
| 0x0002 | PROCESS_CREATE_THREAD | High - thread creation |
| 0x143A | Combination used by Mimikatz | Critical |

## Common Injection Targets

| Process | Why Targeted |
|---------|-------------|
| svchost.exe | Many instances, network access, elevated privileges |
| explorer.exe | User context, always running, network access |
| lsass.exe | Credential access (T1003 overlap) |
| winlogon.exe | SYSTEM privileges, always running |
| spoolsv.exe | SYSTEM privileges, rarely monitored |
| dllhost.exe | COM surrogate, frequently overlooked |
| RuntimeBroker.exe | Common in modern Windows, rarely scrutinized |

## Recommended Sysmon Configuration for Injection Detection

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="ProcessInjection" groupRelation="or">
      <CreateRemoteThread onmatch="exclude">
        <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
      </CreateRemoteThread>
      <ProcessAccess onmatch="include">
        <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
        <GrantedAccess condition="is">0x1F3FFF</GrantedAccess>
        <GrantedAccess condition="is">0x143A</GrantedAccess>
      </ProcessAccess>
      <ProcessTampering onmatch="include">
        <Type condition="is">Image is replaced</Type>
      </ProcessTampering>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```
