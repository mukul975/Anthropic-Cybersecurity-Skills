# API Reference: Building Cloud SIEM with Sentinel

## azure-monitor-query (KQL Queries)

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="SigninLogs | where ResultType == 0 | take 10",
    timespan=timedelta(hours=24),
)
for table in response.tables:
    for row in table.rows:
        print(row)
```

## azure-mgmt-securityinsight

```python
from azure.mgmt.securityinsight import SecurityInsights

client = SecurityInsights(credential, subscription_id)

# List analytics rules
for rule in client.alert_rules.list(rg, workspace):
    print(rule.display_name, rule.severity)

# List incidents
for incident in client.incidents.list(rg, workspace):
    print(incident.title, incident.severity)
```

## Key KQL Patterns for Sentinel

```kql
// Impossible travel
SigninLogs | where ResultType == 0
| extend Distance = geo_distance_2points(...)

// AWS credential abuse
AWSCloudTrail | where EventName == "AssumeRole"
| summarize dcount(SourceIpAddress) by UserIdentityArn

// Threat intelligence matching
let TI = ThreatIntelligenceIndicator | distinct NetworkIP;
CommonSecurityLog | where DestinationIP in (TI)
```

## Sentinel Data Connectors

| Connector | Data Table |
|-----------|-----------|
| Azure AD | `SigninLogs`, `AuditLogs` |
| AWS CloudTrail | `AWSCloudTrail` |
| Microsoft 365 | `OfficeActivity` |
| Defender for Cloud | `SecurityAlert` |
| Syslog | `Syslog` |
| CEF | `CommonSecurityLog` |

### References

- azure-monitor-query: https://pypi.org/project/azure-monitor-query/
- azure-mgmt-securityinsight: https://pypi.org/project/azure-mgmt-securityinsight/
- KQL reference: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
