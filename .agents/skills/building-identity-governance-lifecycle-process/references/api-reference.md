# API Reference: Building Identity Governance Lifecycle Process

## Microsoft Graph API - Identity Governance

```python
import requests

token = "Bearer <access_token>"
headers = {"Authorization": token}

# List all users with sign-in activity
resp = requests.get(
    "https://graph.microsoft.com/v1.0/users",
    headers=headers,
    params={"$select": "id,displayName,userPrincipalName,accountEnabled,"
            "signInActivity,employeeId,department,jobTitle"}
)

# List access reviews
resp = requests.get(
    "https://graph.microsoft.com/v1.0/identityGovernance/"
    "accessReviews/definitions",
    headers=headers,
)

# Check MFA registration status
resp = requests.get(
    "https://graph.microsoft.com/v1.0/reports/"
    "authenticationMethods/userRegistrationDetails",
    headers=headers,
)

# List entitlement management access packages
resp = requests.get(
    "https://graph.microsoft.com/v1.0/identityGovernance/"
    "entitlementManagement/accessPackages",
    headers=headers,
)
```

## Key Graph API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/users` | List/manage user identities |
| `/identityGovernance/accessReviews` | Access review campaigns |
| `/identityGovernance/entitlementManagement` | Access packages and catalogs |
| `/identityGovernance/lifecycleWorkflows` | JML automation workflows |
| `/reports/authenticationMethods` | MFA registration status |
| `/auditLogs/signIns` | Sign-in activity logs |

## SailPoint IdentityNow API

```python
# Search identities
resp = requests.get(
    "https://<tenant>.api.identitynow.com/v3/search/identities",
    headers={"Authorization": "Bearer <token>"},
    json={"query": {"query": "department:Engineering"}}
)

# List access profiles
resp = requests.get(
    "https://<tenant>.api.identitynow.com/v3/access-profiles",
    headers={"Authorization": "Bearer <token>"},
)
```

### References

- Microsoft Graph Identity Governance: https://learn.microsoft.com/en-us/graph/api/resources/identitygovernance-overview
- SailPoint IdentityNow API: https://developer.sailpoint.com/docs/api/v3
- Workday REST API: https://community.workday.com/sites/default/files/file-hosting/restapi/
