# API Reference: Implementing Google Workspace Admin Security

## Libraries

### google-api-python-client + google-auth
- **Install**: `pip install google-api-python-client google-auth`
- **Docs**: https://developers.google.com/admin-sdk/directory/reference/rest

## Admin SDK Directory API

| Method | Description |
|--------|-------------|
| `users().list(domain, projection="full")` | List users with full profile |
| `users().get(userKey)` | Get specific user details |
| `users().update(userKey, body)` | Update user settings |
| `users().list(query="isAdmin=true")` | List admin users |
| `orgunits().list(customerId)` | List organizational units |
| `roles().list(customer)` | List admin roles |
| `roleAssignments().list(customer)` | List role assignments |

## Reports API (Audit Logs)

| Method | Description |
|--------|-------------|
| `activities().list(userKey, applicationName)` | Get audit events |
| Application names: `login`, `admin`, `drive`, `token`, `mobile` |

## Key User Fields for Security

| Field | Description |
|-------|-------------|
| `isEnrolledIn2Sv` | User enrolled in 2-Step Verification |
| `isEnforcedIn2Sv` | 2SV enforcement applied |
| `isAdmin` | Super admin status |
| `isDelegatedAdmin` | Delegated admin status |
| `lastLoginTime` | Last login timestamp |
| `recoveryEmail` | Recovery email (risk if external) |
| `recoveryPhone` | Recovery phone number |
| `isSuspended` | Account suspended |

## OAuth Scopes Required
- `admin.directory.user` -- User management
- `admin.directory.domain` -- Domain settings
- `admin.reports.audit.readonly` -- Audit log access
- `admin.directory.orgunit` -- Org unit management

## Login Event Names
- `login_success` -- Successful login
- `login_failure` -- Failed login attempt
- `login_challenge` -- 2FA challenge issued
- `suspicious_login` -- Flagged by Google
- `account_disabled_password_leak` -- Compromised password

## External References
- Admin SDK: https://developers.google.com/admin-sdk
- Workspace Security Best Practices: https://support.google.com/a/answer/7587183
- CIS Google Workspace Benchmark: https://www.cisecurity.org/benchmark/google_workspace
- Reports API: https://developers.google.com/admin-sdk/reports/reference/rest
