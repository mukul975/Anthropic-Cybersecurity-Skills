# API Reference — Analyzing Office 365 Audit Logs for Compromise

## Libraries Used
- **msal**: Microsoft Authentication Library — client credentials flow for Graph API
- **requests**: HTTP client for Graph API calls with pagination

## CLI Interface
```
python agent.py --tenant-id T --client-id C --client-secret S audit-logs --days 7
python agent.py --tenant-id T --client-id C --client-secret S inbox-rules --user user@domain.com
python agent.py --tenant-id T --client-id C --client-secret S forwarding --user user@domain.com
python agent.py --tenant-id T --client-id C --client-secret S oauth
python agent.py --tenant-id T --client-id C --client-secret S full --users user1@d.com user2@d.com --days 7
```

## Core Functions

### `get_access_token(tenant_id, client_id, client_secret)` — MSAL auth
Uses `ConfidentialClientApplication.acquire_token_for_client()` with
`https://graph.microsoft.com/.default` scope.

### `query_audit_logs(token, days)` — Suspicious operation detection
Queries `/auditLogs/directoryAudits` for 11 suspicious operations:
New-InboxRule, Set-InboxRule, Set-Mailbox, Add-MailboxPermission,
UpdateInboxRules, New-TransportRule, etc.

### `check_inbox_rules(token, user_id)` — Forwarding rule detection
GET `/users/{id}/mailFolders/inbox/messageRules`. Checks `actions` for
`forwardTo`, `forwardAsAttachmentTo`, `redirectTo`. Flags external forwards
and delete-after-forward patterns.

### `check_mailbox_forwarding(token, user_id)` — SMTP forwarding check
GET `/users/{id}/mailboxSettings`. Checks auto-reply status and external audience.

### `check_oauth_grants(token)` — OAuth consent audit
GET `/oauth2PermissionGrants`. Flags grants with Mail.Read, Mail.ReadWrite,
Mail.Send, Files.ReadWrite.All, MailboxSettings.ReadWrite.

### `full_audit(token, users, days)` — Comprehensive compromise analysis

## Microsoft Graph Endpoints
| Endpoint | Method | Permission |
|----------|--------|-----------|
| `/auditLogs/directoryAudits` | GET | `AuditLog.Read.All` |
| `/users/{id}/mailFolders/inbox/messageRules` | GET | `MailboxSettings.Read` |
| `/users/{id}/mailboxSettings` | GET | `MailboxSettings.Read` |
| `/oauth2PermissionGrants` | GET | `Directory.Read.All` |

## Inbox Rule Risk Scoring
| Factor | Points |
|--------|--------|
| Forwarding rule present | +40 |
| Delete after forward | +25 |
| External forward address | +20 |
| Mark as read + forward | +15 |

## Suspicious Operations Monitored
New-InboxRule, Set-InboxRule, Set-Mailbox, Add-MailboxPermission,
Set-MailboxJunkEmailConfiguration, Set-OwaMailboxPolicy, New-TransportRule,
Add-RecipientPermission, Set-TransportRule, UpdateInboxRules,
Set-MailboxAutoReplyConfiguration

## Dependencies
- `msal` >= 1.24.0
- `requests` >= 2.28.0
- Azure AD app with `AuditLog.Read.All`, `MailboxSettings.Read`, `Mail.Read`
