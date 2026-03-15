# Email Account Compromise Detection API Reference

## Microsoft Graph API Endpoints

### List Inbox Rules
```http
GET https://graph.microsoft.com/v1.0/users/{userId}/mailFolders/inbox/messageRules
Authorization: Bearer {token}
```

### Get Sign-In Logs
```http
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
  ?$filter=createdDateTime ge {startDate}
  &$top=100
Authorization: Bearer {token}
```

### Risk Detections (Azure AD P2)
```http
GET https://graph.microsoft.com/v1.0/identityProtection/riskDetections
  ?$filter=riskLevel eq 'high'
Authorization: Bearer {token}
```

### OAuth2 Permission Grants
```http
GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants
Authorization: Bearer {token}
```

## Authentication with MSAL

```python
from msal import ConfidentialClientApplication

app = ConfidentialClientApplication(
    client_id="<app-id>",
    client_credential="<secret>",
    authority="https://login.microsoftonline.com/<tenant-id>"
)
token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
headers = {"Authorization": f"Bearer {token['access_token']}"}
```

## Inbox Rule Compromise Indicators

| Indicator | Field | Description |
|-----------|-------|-------------|
| External forwarding | `actions.forwardTo` | Rule forwards to external domain |
| External redirect | `actions.redirectTo` | Rule redirects to external address |
| Auto-delete | `actions.delete` | Rule auto-deletes matching messages |
| Financial keywords | `conditions.subjectContains` | Targets "invoice", "payment", "wire" |

## Sign-In Risk Indicators

| Signal | Detection Method |
|--------|-----------------|
| Impossible travel | Haversine distance / time > 900 km/h |
| Suspicious UA | python-requests, curl, PowerShell in userAgent |
| Unfamiliar location | New country/region for user |
| Token replay | Same token from different IPs |

## CLI Usage

```bash
python agent.py --input audit_data.json --output report.json
```

## Required API Permissions

- `Mail.Read` - Read inbox rules
- `AuditLog.Read.All` - Read sign-in and audit logs
- `IdentityRiskEvent.Read.All` - Read risk detections
- `Directory.Read.All` - Read OAuth permission grants

## References

- Microsoft Graph API: https://learn.microsoft.com/en-us/graph/api/overview
- Identity Protection APIs: https://learn.microsoft.com/en-us/graph/api/resources/identityprotection-overview
- MSAL Python: https://github.com/AzureAD/microsoft-authentication-library-for-python
