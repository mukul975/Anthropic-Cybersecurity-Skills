# Malware Sandbox Evasion Techniques API Reference

## MITRE ATT&CK T1497 Sub-techniques

| Sub-technique | ID | Evasion Method |
|---|---|---|
| System Checks | T1497.001 | VM artifacts, registry keys, MAC prefixes, process names |
| User Activity Based Checks | T1497.002 | Mouse movement, keyboard input, foreground window |
| Time Based Evasion | T1497.003 | GetTickCount, sleep inflation, RDTSC timing |

## Cuckoo Sandbox Report JSON Structure

### API Call Format
```json
{
  "behavior": {
    "processes": [
      {
        "process_name": "malware.exe",
        "pid": 1234,
        "calls": [
          {
            "api": "GetTickCount",
            "category": "system",
            "arguments": {},
            "return": "123456789"
          }
        ]
      }
    ]
  }
}
```

## Timing API Indicators

| API | Purpose | Evasion Use |
|---|---|---|
| GetTickCount / GetTickCount64 | System uptime in ms | Check if uptime < 20min (sandbox) |
| QueryPerformanceCounter | High-res timer | Measure sleep accuracy |
| GetSystemTimeAsFileTime | System time | Detect time acceleration |
| NtQuerySystemTime | Kernel time query | Compare with user-mode time |
| RDTSC | CPU timestamp counter | Detect VM overhead in timing |

## VM Artifact Indicators

### Registry Keys
```
HKLM\SOFTWARE\VMware, Inc.\VMware Tools
HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
HKLM\HARDWARE\ACPI\DSDT\VBOX__
HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest
```

### VM Process Names
```
vmtoolsd.exe, vmwaretray.exe    # VMware
vboxservice.exe, vboxtray.exe   # VirtualBox
qemu-ga.exe                      # QEMU
prl_tools.exe                    # Parallels
```

### VM MAC Address Prefixes
```
00:0C:29  VMware
00:50:56  VMware
08:00:27  VirtualBox
00:1C:42  Parallels
52:54:00  QEMU/KVM
```

## AnyRun Report API

### Get Report
```
GET https://api.any.run/v1/analysis/{task_id}
Authorization: API-Key <key>
```

## CLI Usage
```bash
python agent.py --report cuckoo_report.json --output evasion_report.json
python agent.py --report report.json --min-sleep-ms 30000
```
