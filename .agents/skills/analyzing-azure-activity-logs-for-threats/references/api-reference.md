# API Reference: Analyzing Azure Activity Logs for Threats

## azure-monitor-query

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="AzureActivity | take 10",
    timespan=timedelta(hours=24),
)
if response.status == LogsQueryStatus.SUCCESS:
    for table in response.tables:
        columns = [col.name for col in table.columns]
        for row in table.rows:
            print(dict(zip(columns, row)))
```

## Key Azure Log Tables

| Table | Content |
|-------|---------|
| `AzureActivity` | Control plane operations (ARM) |
| `SigninLogs` | Azure AD sign-in events |
| `AuditLogs` | Azure AD audit trail |
| `AzureDiagnostics` | Resource diagnostics (Key Vault, NSG) |
| `SecurityAlert` | Defender for Cloud alerts |

## Threat Detection KQL Patterns

```kql
// Privilege escalation
AzureActivity | where OperationNameValue has "ROLEASSIGNMENTS/WRITE"

// Impossible travel
SigninLogs | where ResultType == 0
| extend Distance = geo_distance_2points(...)

// Mass deletion
AzureActivity | where OperationNameValue endswith "/DELETE"
| summarize count() by Caller, bin(TimeGenerated, 1h)
```

### References

- azure-monitor-query: https://pypi.org/project/azure-monitor-query/
- KQL reference: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
- Azure Activity Log schema: https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
