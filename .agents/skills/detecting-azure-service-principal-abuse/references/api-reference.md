# Azure Service Principal Abuse Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| azure-identity | `pip install azure-identity` | Azure AD authentication |
| requests | `pip install requests` | Microsoft Graph API client |

## Microsoft Graph API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1.0/servicePrincipals` | List service principals |
| GET | `/v1.0/servicePrincipals/{id}` | Get SP details and credentials |
| GET | `/v1.0/servicePrincipals/{id}/appRoleAssignments` | SP role assignments |
| GET | `/v1.0/directoryRoles` | List directory roles |
| GET | `/v1.0/directoryRoles/{id}/members` | Role members (includes SPs) |
| GET | `/v1.0/auditLogs/signIns` | Sign-in logs for SP activity |
| GET | `/v1.0/auditLogs/directoryAudits` | Directory change audit logs |

## OAuth2 Token Endpoint

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
grant_type=client_credentials
scope=https://graph.microsoft.com/.default
```

## High-Privilege Directory Roles

| Role | Risk |
|------|------|
| Global Administrator | Full tenant control |
| Application Administrator | Can create/manage all apps |
| Cloud Application Administrator | Manage cloud app registrations |
| Privileged Role Administrator | Manage role assignments |

## Service Principal Abuse Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| Multiple password credentials | Possible backdoor persistence | HIGH |
| Expired credentials not removed | Credential hygiene gap | MEDIUM |
| SP with Global Admin role | Overprivileged automation | CRITICAL |
| Unusual sign-in location | Compromised SP credentials | HIGH |
| New credential added to SP | Persistence via credential injection | CRITICAL |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Account Manipulation | T1098 | Add credentials to SP |
| Valid Accounts: Cloud | T1078.004 | Abuse SP credentials |
| Trusted Relationship | T1199 | Abuse multi-tenant SP trust |

## External References

- [Microsoft Graph API: Service Principals](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal)
- [Azure AD Sign-in Logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
- [Detecting Azure AD Backdoors](https://posts.specterops.io/)
