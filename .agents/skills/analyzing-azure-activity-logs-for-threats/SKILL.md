---
name: analyzing-azure-activity-logs-for-threats
description: >
  Queries Azure Monitor activity logs and sign-in logs via azure-monitor-query to
  detect suspicious administrative operations, impossible travel, privilege escalation,
  and resource modifications. Builds KQL queries for threat hunting in Azure environments.
  Use when investigating suspicious Azure tenant activity or building cloud SIEM detections.
domain: cybersecurity
subdomain: security-operations
tags: [analyzing, azure, activity, logs]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Azure Activity Logs for Threats

## Instructions

Use azure-monitor-query to execute KQL queries against Azure Log Analytics workspaces,
detecting suspicious admin operations and sign-in anomalies.

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="AzureActivity | where OperationNameValue has 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' | take 10",
    timespan=timedelta(hours=24),
)
```

Key detection queries:
1. Role assignment changes (privilege escalation)
2. Resource group and subscription modifications
3. Key vault secret access from new IPs
4. Network security group rule changes
5. Conditional access policy modifications

## Examples

```python
# Detect new Global Admin role assignments
query = '''
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue has "Global Administrator"
'''
```
