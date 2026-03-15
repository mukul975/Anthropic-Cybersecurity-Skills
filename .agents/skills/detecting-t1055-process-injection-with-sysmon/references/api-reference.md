# API Reference: T1055 Process Injection Detection with Sysmon

## MITRE ATT&CK T1055 Sub-Techniques

| Sub-technique | Method | Sysmon Event |
|---------------|--------|--------------|
| T1055.001 | DLL Injection | Event 7, 8, 10 |
| T1055.002 | PE Injection | Event 8, 10 |
| T1055.003 | Thread Execution Hijacking | Event 8 |
| T1055.004 | Asynchronous Procedure Call | Event 8, 10 |
| T1055.005 | Thread Local Storage | Event 8 |
| T1055.012 | Process Hollowing | Event 1, 10, 25 |

## Sysmon Event IDs

### Event 8 — CreateRemoteThread
| Field | Index | Description |
|-------|-------|-------------|
| SourceProcessGuid | 1 | GUID of injecting process |
| SourceProcessId | 2 | PID of injecting process |
| SourceImage | 4 | Path of injecting binary |
| TargetProcessGuid | 5 | GUID of target process |
| TargetProcessId | 6 | PID of target process |
| TargetImage | 7 | Path of target binary |
| StartAddress | 8 | Thread start address |
| StartFunction | 9 | Thread entry function |

### Event 10 — ProcessAccess
| Field | Index | Description |
|-------|-------|-------------|
| SourceProcessId | 3 | Accessing PID |
| SourceImage | 4 | Accessing binary path |
| TargetProcessId | 7 | Accessed PID |
| TargetImage | 8 | Accessed binary path |
| GrantedAccess | 10 | Access rights mask |

### Event 7 — Image Loaded
| Field | Index | Description |
|-------|-------|-------------|
| Image | 3 | Process that loaded DLL |
| ImageLoaded | 5 | DLL path |
| Signed | 6 | Signature status |
| SignatureStatus | 8 | Valid/Invalid/Unknown |

## Process Access Masks

| Mask | Right | Injection Use |
|------|-------|---------------|
| 0x0008 | PROCESS_VM_OPERATION | VirtualAllocEx |
| 0x0010 | PROCESS_VM_READ | ReadProcessMemory |
| 0x0020 | PROCESS_VM_WRITE | WriteProcessMemory |
| 0x0800 | PROCESS_SUSPEND_RESUME | Hollowing |
| 0x001F0FFF | PROCESS_ALL_ACCESS | Full control |

## Sysmon Configuration for Injection Detection
```xml
<Sysmon>
  <EventFiltering>
    <ProcessAccess onmatch="include">
      <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
      <GrantedAccess condition="is">0x001F0FFF</GrantedAccess>
    </ProcessAccess>
    <CreateRemoteThread onmatch="exclude">
      <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
    </CreateRemoteThread>
  </EventFiltering>
</Sysmon>
```

## Sigma Rule Example
```yaml
title: CreateRemoteThread into System Process
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        TargetImage|endswith:
            - '\svchost.exe'
            - '\explorer.exe'
            - '\lsass.exe'
    filter:
        SourceImage|startswith: 'C:\Windows\System32\'
    condition: selection and not filter
level: critical
```
