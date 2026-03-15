---
name: hunting-for-persistence-via-wmi-subscriptions
description: Hunt for adversary persistence through Windows Management Instrumentation event subscriptions by monitoring WMI consumer, filter, and binding creation events that execute malicious code triggered by system events.
domain: cybersecurity
subdomain: threat-hunting
tags: [threat-hunting, wmi-persistence, mitre-t1546-003, event-subscription, windows, endpoint-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Hunting for Persistence via WMI Subscriptions

## When to Use

- When proactively searching for fileless persistence mechanisms in Windows environments
- After threat intelligence reports indicate WMI-based persistence by APT groups (APT29, APT32, FIN8)
- When investigating systems where malware persists across reboots despite cleanup attempts
- During incident response when standard persistence locations (Run keys, scheduled tasks) are clean
- When WmiPrvSe.exe is observed spawning unexpected child processes

## Prerequisites

- Sysmon Event ID 19, 20, 21 (WMI Event Filter/Consumer/Binding) enabled
- Windows Event ID 5861 (WMI activity logging) from Microsoft-Windows-WMI-Activity
- PowerShell logging enabled (Script Block Logging, Module Logging)
- WMI repository access for enumeration
- SIEM platform for event correlation

## Workflow

1. **Enumerate Existing WMI Subscriptions**: Query all permanent WMI event subscriptions on target systems. A clean system typically has very few or zero permanent subscriptions, making anomalies easy to spot.
2. **Monitor WMI Event Creation (Sysmon 19/20/21)**: Sysmon Event 19 captures WmiEventFilter activity, Event 20 captures WmiEventConsumer activity, and Event 21 captures WmiEventConsumerToFilter binding.
3. **Analyze Consumer Types**: Focus on ActiveScriptEventConsumer (runs VBScript/JScript) and CommandLineEventConsumer (executes commands) -- these are the dangerous types used for persistence.
4. **Check Event Filter Triggers**: Examine what triggers the subscription. Common malicious triggers include system startup (Win32_ProcessStartTrace), user logon, or timer-based execution intervals.
5. **Investigate WmiPrvSe.exe Child Processes**: When a WMI subscription fires, the action is executed by WmiPrvSe.exe. Hunt for unusual child processes of WmiPrvSe.exe.
6. **Correlate with MOF Compilation**: Detect `mofcomp.exe` usage which compiles MOF files to create WMI subscriptions programmatically.
7. **Validate and Respond**: Confirm malicious subscriptions, remove them, and trace back to the initial infection vector.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1546.003 | Event Triggered Execution: WMI Event Subscription |
| __EventFilter | WMI class defining the trigger condition |
| __EventConsumer | WMI class defining the action to perform |
| __FilterToConsumerBinding | Links a filter to a consumer |
| ActiveScriptEventConsumer | Consumer that runs VBScript or JScript |
| CommandLineEventConsumer | Consumer that executes command lines |
| WmiPrvSe.exe | WMI Provider Host that executes subscription actions |
| MOF File | Managed Object Format used to define WMI objects |

## Detection Queries

### Splunk -- WMI Subscription Creation via Sysmon
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval event_type=case(EventCode=19, "EventFilter", EventCode=20, "EventConsumer", EventCode=21, "FilterToConsumerBinding")
| table _time Computer User event_type EventNamespace Name Query Destination Operation
```

### Splunk -- WMI Subscription via Windows Event 5861
```spl
index=wineventlog source="Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| table _time Computer NamespaceName Operation PossibleCause
```

### PowerShell -- Enumerate WMI Subscriptions
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### KQL -- WmiPrvSe.exe Spawning Suspicious Children
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Sigma Rule
```yaml
title: WMI Event Subscription Persistence
status: stable
logsource:
    product: windows
    category: wmi_event
detection:
    selection_consumer:
        EventID: 20
        Destination|contains:
            - 'ActiveScriptEventConsumer'
            - 'CommandLineEventConsumer'
    condition: selection_consumer
level: high
tags:
    - attack.persistence
    - attack.t1546.003
```

## Common Scenarios

1. **APT29 WMI Persistence**: Creates an ActiveScriptEventConsumer that executes a VBScript backdoor on system startup, surviving reboots and credential resets.
2. **Turla WMI Backdoor**: Uses Win32_ProcessStartTrace filter combined with CommandLineEventConsumer for covert command execution.
3. **FIN8 WMI Timer**: Interval-based __IntervalTimerEvent triggering encoded PowerShell downloads every 30 minutes.
4. **MOF-Based Installation**: Adversary drops a .mof file and compiles it with `mofcomp.exe` to silently create persistent subscriptions.

## Output Format

```
Hunt ID: TH-WMI-[DATE]-[SEQ]
Host: [Hostname]
Subscription Name: [Filter/Consumer name]
Filter Query: [WQL trigger condition]
Consumer Type: [ActiveScript/CommandLine]
Consumer Action: [Script content or command]
Binding: [Filter-to-Consumer link]
Created: [Timestamp]
User Context: [SYSTEM/User]
Risk Level: [Critical/High/Medium/Low]
```
