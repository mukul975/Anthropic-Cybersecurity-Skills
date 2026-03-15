# Process Injection Detection API Reference

## Volatility 3 Plugins

```bash
# Detect injected code (RWX memory, PE headers in non-image VADs)
vol3 -f memory.dmp windows.malfind
vol3 -f memory.dmp windows.malfind --pid 1234

# List processes
vol3 -f memory.dmp windows.pslist

# Scan for hidden processes
vol3 -f memory.dmp windows.psscan

# List DLLs for a process
vol3 -f memory.dmp windows.dlllist --pid 1234

# Dump injected code
vol3 -f memory.dmp windows.malfind --dump --pid 1234

# List threads
vol3 -f memory.dmp windows.threads --pid 1234

# VAD tree (memory regions)
vol3 -f memory.dmp windows.vadinfo --pid 1234
```

## Injection Techniques and API Sequences

| Technique | API Sequence |
|-----------|-------------|
| Classic DLL | OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread |
| Process Hollowing | CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> WriteProcessMemory -> ResumeThread |
| APC Injection | OpenThread -> VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC |
| Reflective DLL | VirtualAlloc -> memcpy -> CreateThread (in-process) |
| Thread Hijacking | OpenThread -> SuspendThread -> SetThreadContext -> ResumeThread |

## Sysmon Event IDs for Injection

| Event ID | Name | Relevance |
|----------|------|-----------|
| 1 | ProcessCreate | Hollowed process creation (SUSPENDED) |
| 7 | ImageLoaded | Reflective DLL loads (unsigned) |
| 8 | CreateRemoteThread | Classic injection indicator |
| 10 | ProcessAccess | PROCESS_VM_WRITE + PROCESS_CREATE_THREAD |
| 25 | ProcessTampering | Image file replaced (hollowing) |

## Sysmon Config for Injection Detection

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessAccess onmatch="include">
      <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
      <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
    </ProcessAccess>
    <CreateRemoteThread onmatch="exclude">
      <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
    </CreateRemoteThread>
  </EventFiltering>
</Sysmon>
```

## python-evtx Usage

```python
import Evtx.Evtx as evtx

with evtx.Evtx("Sysmon.evtx") as log:
    for record in log.records():
        xml = record.xml()
        if "<EventID>8</EventID>" in xml:
            print("CreateRemoteThread:", record.timestamp())
```

## Suspicious Parent-Child Relationships

| Parent | Child | Indicator |
|--------|-------|-----------|
| winword.exe | cmd.exe, powershell.exe | Macro execution |
| svchost.exe | cmd.exe, powershell.exe | Service-based injection |
| explorer.exe | mshta.exe | COM hijack / LNK abuse |
| outlook.exe | powershell.exe | Email macro execution |
