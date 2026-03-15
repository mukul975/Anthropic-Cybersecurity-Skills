# API Reference: Detecting Evasion Techniques in Endpoint Logs

## Key Windows Event IDs for Evasion

| Event ID | Source | Evasion Technique |
|----------|--------|-------------------|
| 1102 | Security | Audit log cleared (T1070.001) |
| Sysmon 2 | Sysmon | Timestomping (T1070.006) |
| Sysmon 8 | Sysmon | CreateRemoteThread (T1055) |
| Sysmon 10 | Sysmon | Process Access / LSASS (T1003) |
| 4688 | Security | Process creation with cmdline |

## python-evtx Usage

```python
import Evtx.Evtx as evtx
with evtx.Evtx("Sysmon.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Parse EventID, CommandLine, SourceImage, TargetImage
```

## Evasion Detection Patterns

```python
# Log clearing
r"wevtutil\s+(cl|clear-log)"
r"Clear-EventLog"
# Security tool disable
r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true"
r"sc\s+(stop|delete)\s+WinDefend"
# AMSI bypass
r"[Ref].Assembly.GetType.*AMSI"
r"amsiInitFailed"
```

## MITRE ATT&CK TA0005 Techniques

| Technique | ID | Detection |
|-----------|----|-----------|
| Indicator Removal | T1070 | Log clearing, file deletion |
| Timestomping | T1070.006 | Sysmon Event ID 2 |
| Process Injection | T1055 | Sysmon Event ID 8 |
| Impair Defenses | T1562.001 | AV/EDR disabling commands |
| AMSI Bypass | T1562.001 | PowerShell AMSI patching |

## Splunk SPL Detection

```spl
index=sysmon (EventCode=2 OR EventCode=8 OR EventCode=10)
| eval technique=case(
    EventCode=2, "Timestomping",
    EventCode=8, "Process Injection",
    EventCode=10, "Process Access")
| stats count by technique, SourceImage, Computer
```

## CLI Usage

```bash
python agent.py --evtx-file Sysmon.evtx
python agent.py --evtx-file Security.evtx
```
