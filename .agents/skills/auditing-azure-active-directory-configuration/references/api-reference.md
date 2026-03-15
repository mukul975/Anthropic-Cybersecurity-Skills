# API Reference: Auditing Azure Active Directory Configuration

## azure-identity Authentication

```python
from azure.identity import DefaultAzureCredential, ClientSecretCredential

# Default (managed identity, env vars, CLI)
credential = DefaultAzureCredential()

# Service principal
credential = ClientSecretCredential(tenant_id, client_id, client_secret)

# Get Graph API token
token = credential.get_token("https://graph.microsoft.com/.default")
```

## Microsoft Graph API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /organization` | Tenant info and verified domains |
| `GET /directoryRoles` | List directory roles |
| `GET /directoryRoles/{id}/members` | Members of a role |
| `GET /identity/conditionalAccess/policies` | Conditional Access policies |
| `GET /users?$filter=userType eq 'Guest'` | Guest users |
| `GET /users?$select=signInActivity` | User sign-in activity |
| `GET /auditLogs/signIns` | Sign-in logs |
| `GET /reports/authenticationMethods/userRegistrationDetails` | MFA registration |

## Python Graph API Helper

```python
import requests

def graph_get(token, endpoint, params=None):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://graph.microsoft.com/v1.0{endpoint}"
    return requests.get(url, headers=headers, params=params).json()

# List Global Admins
roles = graph_get(token, "/directoryRoles")
for role in roles["value"]:
    if role["displayName"] == "Global Administrator":
        members = graph_get(token, f"/directoryRoles/{role['id']}/members")
```

## Key Conditional Access Policy Fields

```json
{
  "displayName": "Require MFA for admins",
  "state": "enabled",
  "conditions": {
    "users": {"includeUsers": ["All"], "excludeGroups": ["break-glass"]},
    "clientAppTypes": ["all"]
  },
  "grantControls": {
    "builtInControls": ["mfa"]
  }
}
```

## azure-mgmt-authorization (RBAC)

```python
from azure.mgmt.authorization import AuthorizationManagementClient
client = AuthorizationManagementClient(credential, subscription_id)
for assignment in client.role_assignments.list():
    print(assignment.principal_id, assignment.role_definition_id)
```

### References

- azure-identity: https://pypi.org/project/azure-identity/
- MS Graph API: https://learn.microsoft.com/en-us/graph/api/overview
- azure-mgmt-authorization: https://pypi.org/project/azure-mgmt-authorization/
