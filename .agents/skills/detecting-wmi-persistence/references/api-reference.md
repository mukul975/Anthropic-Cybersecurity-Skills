# WMI Persistence Detection Reference

## Sysmon Event IDs

| Event ID | Type | Description |
|----------|------|-------------|
| 19 | WmiEventFilter | Logs WMI EventFilter creation with WQL query |
| 20 | WmiEventConsumer | Logs WMI EventConsumer creation (command/script) |
| 21 | WmiEventConsumerToFilter | Logs binding of EventFilter to EventConsumer |

## Sysmon Configuration

Enable WMI event logging in sysmonconfig.xml:

```xml
<RuleGroup groupRelation="or">
  <WmiEvent onmatch="include">
    <Operation condition="is">Created</Operation>
  </WmiEvent>
</RuleGroup>
```

Install: `sysmon64.exe -accepteula -i sysmonconfig.xml`

## PowerShell WMI Enumeration

```powershell
# List all EventFilters
Get-WmiObject -Namespace root\subscription -Class __EventFilter

# List all EventConsumers
Get-WmiObject -Namespace root\subscription -Class __EventConsumer

# List all Bindings
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Remove specific subscription
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='MalFilter'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='MalConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like '*MalFilter*'} | Remove-WmiObject
```

## Suspicious Consumer Types

| Consumer Class | Risk | Description |
|---------------|------|-------------|
| CommandLineEventConsumer | Critical | Executes arbitrary system commands |
| ActiveScriptEventConsumer | Critical | Runs embedded VBScript or JScript |
| LogFileEventConsumer | Low | Writes to log file |
| NTEventLogEventConsumer | Low | Creates Windows event log entry |
| SMTPEventConsumer | Medium | Sends email notification |

## Splunk Detection Query

```spl
index=sysmon EventCode IN (19, 20, 21)
| eval event_type=case(EventCode=19, "EventFilter", EventCode=20, "EventConsumer", EventCode=21, "Binding")
| where Consumer_Type IN ("CommandLineEventConsumer", "ActiveScriptEventConsumer")
| stats count by Computer, event_type, Consumer_Type, Destination, User
| where count > 0
```

## Elastic Detection Rule

```json
{
  "rule": {
    "name": "WMI Persistence via Event Subscription",
    "query": "event.code:(\"19\" OR \"20\" OR \"21\") AND winlog.event_data.EventType:\"WmiConsumerEvent\" AND winlog.event_data.Type:(\"CommandLineEventConsumer\" OR \"ActiveScriptEventConsumer\")",
    "severity": "high",
    "risk_score": 73,
    "tags": ["ATT&CK T1546.003"]
  }
}
```

## MITRE ATT&CK Mapping

- **Technique**: T1546.003 - Event Triggered Execution: WMI Event Subscription
- **Tactic**: Persistence, Privilege Escalation
- **Data Sources**: WMI Objects (WMI Creation), Command Execution, Process Creation

## Autoruns WMI Tab

```cmd
autorunsc64.exe -accepteula -w -nobanner -c
```

Output includes WMI subscriptions under "WMI" category with filter name, consumer, and command details.
