# API Reference: Detecting Process Hollowing Technique

## Process Hollowing API Sequence

| Step | API Call | Purpose |
|------|----------|---------|
| 1 | CreateProcess(SUSPENDED) | Create target suspended |
| 2 | NtUnmapViewOfSection | Unmap legitimate code |
| 3 | VirtualAllocEx | Allocate for payload |
| 4 | WriteProcessMemory | Write malicious code |
| 5 | SetThreadContext | Redirect execution |
| 6 | ResumeThread | Execute payload |

## Commonly Hollowed Processes

| Process | Reason |
|---------|--------|
| svchost.exe | Trusted, always running |
| explorer.exe | UI process |
| notepad.exe | Simple, rarely monitored |
| dllhost.exe | COM surrogate |

## Sysmon Detection Events

| Event ID | Detection |
|----------|-----------|
| 1 | Suspicious parent-child |
| 8 | CreateRemoteThread into hollowed target |
| 10 | Process Access with PROCESS_ALL_ACCESS |

## Splunk SPL

```spl
index=sysmon EventCode=10
| where TargetImage IN ("*\svchost.exe","*\explorer.exe")
| where GrantedAccess IN ("0x1FFFFF","0x1F3FFF")
| table _time SourceImage TargetImage GrantedAccess Computer
```

## CLI Usage

```bash
python agent.py --sysmon-log Sysmon.evtx
```
