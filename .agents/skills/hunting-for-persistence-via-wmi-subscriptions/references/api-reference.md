# API Reference — Hunting for Persistence via WMI Subscriptions

## Libraries Used
- **subprocess**: Execute WMIC and PowerShell commands for WMI enumeration
- **python-evtx** (Evtx): Parse Sysmon EVTX for WMI-related events (IDs 19, 20, 21)
- **re**: Pattern matching for suspicious WMI consumer payloads

## CLI Interface

```
python agent.py enumerate                  # WMIC-based WMI subscription enumeration
python agent.py powershell                 # PowerShell Get-WMIObject enumeration
python agent.py sysmon --evtx-file <path>  # Scan Sysmon EVTX for WMI events
```

## Core Functions

### `enumerate_wmi_subscriptions()`
Queries four WMI subscription classes via WMIC and flags entries matching suspicious patterns.

**Returns:** dict with `classes` (EventFilter, EventConsumer, ActiveScriptEventConsumer, FilterToConsumerBinding) and `suspicious` list.

### `scan_sysmon_wmi_events(evtx_file)`
Parses Sysmon EVTX for Event IDs 19 (WmiEventFilter), 20 (WmiEventConsumer), 21 (WmiEventBinding).

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `evtx_file` | str | Path to Sysmon .evtx file |

### `query_powershell_wmi()`
Uses PowerShell `Get-WMIObject` to enumerate WMI subscriptions in `root\Subscription` namespace.

## WMI Classes Enumerated

| Class | Description |
|-------|-------------|
| `__EventFilter` | Defines the WQL query that triggers the subscription |
| `CommandLineEventConsumer` | Executes a command when the filter matches |
| `ActiveScriptEventConsumer` | Runs VBScript/JScript when the filter matches |
| `__FilterToConsumerBinding` | Links a filter to its consumer |

## Sysmon Event IDs

| Event ID | Description |
|----------|-------------|
| 19 | WmiEvent - Filter activity detected |
| 20 | WmiEvent - Consumer activity detected |
| 21 | WmiEvent - Consumer-to-filter binding |

## Dependencies
```
pip install python-evtx  # Optional, for EVTX parsing
```
