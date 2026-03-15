# API Reference: Detecting Azure Lateral Movement

## Microsoft Graph API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1.0/auditLogs/directoryAudits` | GET | Azure AD audit events |
| `/v1.0/auditLogs/signIns` | GET | Interactive sign-in logs |
| `/beta/auditLogs/signIns` | GET | Non-interactive + SP sign-ins |
| `/v1.0/identityProtection/riskDetections` | GET | Risk detections |
| `/v1.0/servicePrincipals` | GET | List service principals |
| `/v1.0/oauth2PermissionGrants` | GET | Delegated permission grants |

## Authentication (Client Credentials Flow)

```bash
curl -X POST "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id={app_id}" \
  -d "client_secret={secret}" \
  -d "scope=https://graph.microsoft.com/.default"
```

## Sentinel KQL - Lateral Movement Detections

### OAuth Consent Grant (T1550.001)
```kql
AuditLogs
| where OperationName == "Consent to application"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, AppName, Result
```

### Service Principal Credential Addition (T1098.001)
```kql
AuditLogs
| where OperationName has_any ("Add service principal credentials", "Update application")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, Target, OperationName
```

### Token Replay Detection (T1528)
```kql
SigninLogs
| summarize IPCount=dcount(IPAddress), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where IPCount >= 5
| sort by IPCount desc
```

### Cross-Tenant Access (T1078.004)
```kql
SigninLogs
| where ResourceTenantId != HomeTenantId
| project TimeGenerated, UserPrincipalName, IPAddress, ResourceTenantId, AppDisplayName
```

## Required Graph API Permissions

| Permission | Type | Use |
|------------|------|-----|
| AuditLog.Read.All | Application | Read audit logs |
| Directory.Read.All | Application | Read directory data |
| SecurityEvents.Read.All | Application | Read risk detections |
| Policy.Read.All | Application | Read conditional access |

## MITRE ATT&CK Azure Techniques

| Technique | ID | Azure Indicator |
|-----------|----|-----------------|
| Application Access Token | T1550.001 | OAuth consent grant |
| Account Manipulation | T1098.001 | SP credential addition |
| Cloud Accounts | T1078.004 | Cross-tenant sign-in |
| Steal Application Access Token | T1528 | Token from multiple IPs |

### References

- Microsoft Graph Audit API: https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit
- Sentinel Hunting Queries: https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries
- Azure AD Lateral Movement: https://attack.mitre.org/techniques/T1550/001/
