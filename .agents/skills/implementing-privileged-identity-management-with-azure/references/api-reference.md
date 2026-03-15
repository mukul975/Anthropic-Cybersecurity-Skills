# Azure AD PIM Microsoft Graph API Reference

## Authentication

```python
import msal

app = msal.ConfidentialClientApplication(
    client_id="<app-id>",
    authority="https://login.microsoftonline.com/<tenant-id>",
    client_credential="<client-secret>"
)
token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
```

## Required API Permissions

| Permission | Type | Description |
|-----------|------|-------------|
| `RoleManagement.ReadWrite.Directory` | Application | Manage role assignments |
| `RoleEligibilitySchedule.ReadWrite.Directory` | Application | Manage eligible assignments |
| `RoleAssignmentSchedule.ReadWrite.Directory` | Application | Manage active assignments |
| `AuditLog.Read.All` | Application | Read PIM audit logs |
| `Policy.Read.All` | Application | Read role management policies |

## PIM API Endpoints

### List Eligible Role Assignments

```
GET /roleManagement/directory/roleEligibilityScheduleInstances
```

### Create Eligible Assignment

```
POST /roleManagement/directory/roleEligibilityScheduleRequests
{
  "action": "adminAssign",
  "justification": "Business need for temporary access",
  "roleDefinitionId": "<role-id>",
  "directoryScopeId": "/",
  "principalId": "<user-object-id>",
  "scheduleInfo": {
    "startDateTime": "2025-03-01T00:00:00Z",
    "expiration": {
      "type": "afterDuration",
      "duration": "PT8H"
    }
  }
}
```

### Activate Eligible Role (JIT)

```
POST /roleManagement/directory/roleAssignmentScheduleRequests
{
  "action": "selfActivate",
  "justification": "Need Global Admin for security investigation",
  "roleDefinitionId": "<role-id>",
  "directoryScopeId": "/",
  "principalId": "me",
  "scheduleInfo": {
    "startDateTime": "2025-03-01T12:00:00Z",
    "expiration": {
      "type": "afterDuration",
      "duration": "PT1H"
    }
  }
}
```

### List Active Role Assignments

```
GET /roleManagement/directory/roleAssignmentScheduleInstances
```

### List Role Definitions

```
GET /roleManagement/directory/roleDefinitions
```

### Query PIM Audit Logs

```
GET /auditLogs/directoryAudits?$filter=activityDisplayName eq 'Add member to role completed (PIM activation)' and activityDateTime ge 2025-03-01T00:00:00Z
```

### Get Role Management Policies

```
GET /policies/roleManagementPolicies
```

## Key Role Definition IDs

| Role | ID |
|------|-----|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` |
| Security Administrator | `194ae4cb-b126-40b2-bd5b-6091b380977d` |
| User Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` |
| Exchange Administrator | `29232cdf-9323-42fd-ade2-1d097af3e4de` |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` |

## Schedule Action Types

| Action | Description |
|--------|-------------|
| `adminAssign` | Admin assigns active or eligible role |
| `adminRemove` | Admin removes role assignment |
| `adminUpdate` | Admin updates existing assignment |
| `adminExtend` | Admin extends expiring assignment |
| `adminRenew` | Admin renews expired assignment |
| `selfActivate` | User activates eligible role |
| `selfDeactivate` | User deactivates active role |
| `selfExtend` | User requests extension |
| `selfRenew` | User requests renewal |

## Azure CLI Equivalent

```bash
# List PIM eligible assignments
az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"

# List active assignments
az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances"
```
