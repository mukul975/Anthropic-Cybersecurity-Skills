# Hunting for Anomalous PowerShell Execution — API Reference

## Windows Event Log IDs

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| 4104 | Microsoft-Windows-PowerShell/Operational | Script Block Logging — full deobfuscated script text |
| 4103 | Microsoft-Windows-PowerShell/Operational | Module Logging — pipeline execution details |
| 4688 | Security | Process Creation with command line auditing |
| 800 | Windows PowerShell | Pipeline execution (classic log) |

## Event 4104 XML Fields

| Field | Path | Description |
|-------|------|-------------|
| ScriptBlockText | EventData/Data[@Name='ScriptBlockText'] | Full script block content |
| ScriptBlockId | EventData/Data[@Name='ScriptBlockId'] | GUID linking multi-part blocks |
| MessageNumber | EventData/Data[@Name='MessageNumber'] | Part number for split blocks |
| MessageTotal | EventData/Data[@Name='MessageTotal'] | Total parts in split block |
| Path | EventData/Data[@Name='Path'] | Script file path (if applicable) |

## AMSI Bypass Indicators

| Indicator | Context |
|-----------|---------|
| `System.Management.Automation.AmsiUtils` | Reflection access to AMSI internals |
| `amsiInitFailed` | Setting AMSI init flag to bypass scanning |
| `AmsiScanBuffer` | Patching the scan buffer function |
| `amsi.dll` | Direct DLL manipulation |
| `VirtualProtect` | Memory protection change for AMSI patching |
| `Marshal::Copy` | Overwriting AMSI function bytes in memory |

## Suspicious PowerShell Keywords

| Keyword | Category |
|---------|----------|
| `Invoke-Mimikatz` | Credential Dumping |
| `Invoke-Kerberoast` | Credential Access |
| `Invoke-ShellCode` | Code Injection |
| `Invoke-ReflectivePEInjection` | Process Injection |
| `PowerView` | Active Directory Enumeration |
| `SharpHound` / `BloodHound` | AD Attack Path Mapping |
| `Rubeus` | Kerberos Ticket Manipulation |
| `Out-Minidump` | LSASS Memory Dumping |

## Download Cradle Patterns

| Pattern | Example |
|---------|---------|
| `Net.WebClient` | `(New-Object Net.WebClient).DownloadString(...)` |
| `Invoke-WebRequest` | `IWR -Uri http://... -OutFile ...` |
| `DownloadString` | `$wc.DownloadString('http://...')` |
| `Start-BitsTransfer` | `Start-BitsTransfer -Source http://...` |
| `Invoke-RestMethod` | `IRM http://... \| IEX` |

## Obfuscation Indicators

| Pattern | Description |
|---------|-------------|
| `-EncodedCommand` / `-enc` | Base64-encoded PowerShell command |
| `IEX` / `Invoke-Expression` | Dynamic execution of string content |
| `[Convert]::FromBase64String` | Base64 decoding in script |
| `-join [char[]]` | Character array concatenation obfuscation |
| `.Replace()` chaining | String substitution for keyword evasion |

## python-evtx Library Usage

```python
import Evtx.Evtx as evtx
from lxml import etree

with evtx.Evtx("PowerShell-Operational.evtx") as log:
    for record in log.records():
        xml = record.xml()
        root = etree.fromstring(xml.encode("utf-8"))
        # Extract EventID, EventData fields
```

## CLI Usage

```bash
# Hunt for suspicious PowerShell in EVTX file
python agent.py --evtx /path/to/PowerShell-Operational.evtx

# Limit events parsed
python agent.py --evtx logs.evtx --max-events 5000

# Save report to JSON
python agent.py --evtx logs.evtx --output hunt_report.json
```

## Group Policy Settings for Script Block Logging

```
Computer Configuration > Administrative Templates > Windows Components
  > Windows PowerShell > Turn on PowerShell Script Block Logging
    -> Enabled
    -> Log script block invocation start / stop events: Checked
```

## External References

- [Splunk: Hunting for Malicious PowerShell using Script Block Logging](https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html)
- [block-parser: PowerShell Script Block Log Parser](https://github.com/matthewdunwoody/block-parser)
- [Windows Forensic Artifacts: EVTX 4104](https://github.com/Psmths/windows-forensic-artifacts/blob/main/execution/evtx-4104-script-block-logging.md)
- [Elastic: AMSI Bypass via PowerShell Detection Rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_amsi_bypass_powershell)
