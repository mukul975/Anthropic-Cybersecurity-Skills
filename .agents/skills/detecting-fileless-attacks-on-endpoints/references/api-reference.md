# API Reference: Detecting Fileless Attacks on Endpoints

## Key Event Sources

| Source | Event ID | Detection |
|--------|----------|-----------|
| PowerShell Script Block | 4104 | Malicious script content |
| Sysmon Process Create | 1 | Encoded command execution |
| Sysmon CreateRemoteThread | 8 | Reflective DLL injection |
| Sysmon WMI EventFilter | 19 | WMI persistence |
| Sysmon WMI EventConsumer | 20 | WMI persistence |
| Sysmon WMI Binding | 21 | WMI persistence |

## python-evtx Usage

```python
import Evtx.Evtx as evtx
with evtx.Evtx("PowerShell-Operational.evtx") as log:
    for record in log.records():
        xml = record.xml()
        # Parse Event 4104 ScriptBlockText
```

## Suspicious PowerShell Patterns

```python
# Dynamic execution
r"Invoke-Expression|IEX\s*\("
# Reflective loading
r"System\.Reflection\.Assembly.*Load"
# Memory injection APIs
r"VirtualAlloc|VirtualProtect|CreateThread"
# WMI persistence
r"Register-WMI|__EventFilter|__EventConsumer"
# Encoded commands
r"-enc\s|-encodedcommand\s"
```

## Splunk SPL - Fileless Detection

```spl
index=powershell EventCode=4104
| where match(ScriptBlockText, "(?i)(Invoke-Expression|IEX|VirtualAlloc|FromBase64)")
| stats count by ScriptBlockText, Computer, UserID
```

## AMSI (Anti-Malware Scan Interface)

```powershell
# Enable AMSI logging
Set-MpPreference -EnableNetworkProtection Enabled
# Check AMSI status
Get-MpComputerStatus | Select AMServiceEnabled, AntispywareEnabled
```

## WMI Persistence Detection

```powershell
# List WMI event subscriptions
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

## CLI Usage

```bash
python agent.py --ps-log PowerShell-Operational.evtx
python agent.py --sysmon-log Sysmon.evtx --check-wmi --check-injection
```
