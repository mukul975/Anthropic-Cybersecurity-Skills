# API Reference — Detecting Suspicious OAuth Application Consent

## Libraries Used
- **msal**: Microsoft Authentication Library — client credentials flow for Microsoft Graph
- **requests**: HTTP client for Graph API calls with pagination

## CLI Interface
```
python agent.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET grants
python agent.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET apps
python agent.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET audit-logs
python agent.py --tenant-id TENANT --client-id CLIENT --client-secret SECRET full --days 30
```

## Core Functions

### `get_access_token(tenant_id, client_id, client_secret)` — MSAL client credentials auth
Uses `ConfidentialClientApplication.acquire_token_for_client()` with scope
`https://graph.microsoft.com/.default` to obtain a bearer token.

### `graph_get(token, endpoint, params)` — Paginated Graph API GET
Handles `@odata.nextLink` pagination. Returns aggregated `value` array.

### `enumerate_oauth_grants(token)` — List delegated permission grants
Calls `GET /oauth2PermissionGrants`. Parses scope strings, flags high-risk scopes.

### `list_service_principals(token)` — Enumerate apps with verification status
Calls `GET /servicePrincipals?$top=999`. Checks `verifiedPublisher` field.

### `query_consent_audit_logs(token, days)` — Consent event audit trail
Calls `GET /auditLogs/directoryAudits` filtered by `activityDisplayName eq 'Consent to application'`.
Returns user principal, IP, target app, and result.

### `analyze_risk(grants, service_principals)` — Risk scoring engine
Scoring: +15 per high-risk scope, +25 for unverified publisher, +20 for AllPrincipals consent.
Levels: CRITICAL >= 70, HIGH >= 50, MEDIUM >= 25, LOW < 25.

### `full_audit(token, days)` — Comprehensive consent audit

## Microsoft Graph Endpoints
| Endpoint | Method | Required Permission |
|----------|--------|-------------------|
| `/oauth2PermissionGrants` | GET | `Directory.Read.All` |
| `/servicePrincipals` | GET | `Application.Read.All` |
| `/auditLogs/directoryAudits` | GET | `AuditLog.Read.All` |

## High-Risk OAuth Scopes
Mail.Read, Mail.ReadWrite, Mail.Send, Files.ReadWrite.All, Files.Read.All,
User.ReadWrite.All, Directory.ReadWrite.All, Sites.ReadWrite.All,
Contacts.ReadWrite, MailboxSettings.ReadWrite, People.Read.All,
Calendars.ReadWrite, Notes.ReadWrite.All

## Risk Scoring
| Factor | Points |
|--------|--------|
| Each high-risk scope | +15 |
| Unverified publisher | +25 |
| Admin consent (AllPrincipals) | +20 |

## Dependencies
- `msal` >= 1.24.0
- `requests` >= 2.28.0
- Azure AD app registration with `Application.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`
