# API Reference: Detecting Email Forwarding Rules Attack

## Microsoft Graph API - Inbox Rules

```http
GET https://graph.microsoft.com/v1.0/users/{user-id}/mailFolders/inbox/messageRules
Authorization: Bearer {token}

# Response
{
  "value": [
    {
      "displayName": "Forward invoices",
      "isEnabled": true,
      "conditions": {"subjectContains": ["invoice", "payment"]},
      "actions": {
        "forwardTo": [{"emailAddress": {"address": "attacker@evil.com"}}],
        "delete": true,
        "markAsRead": true
      }
    }
  ]
}
```

## Exchange Online PowerShell

```powershell
# List all inbox rules for a user
Get-InboxRule -Mailbox user@company.com | FL Name, ForwardTo, RedirectTo, DeleteMessage

# Find forwarding rules across all mailboxes
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-InboxRule -Mailbox $_.UserPrincipalName |
    Where-Object { $_.ForwardTo -or $_.RedirectTo }
}

# Search unified audit log for rule creation
Search-UnifiedAuditLog -Operations "New-InboxRule","Set-InboxRule" -StartDate (Get-Date).AddDays(-30)
```

## Suspicious Rule Indicators

| Indicator | Severity | Description |
|-----------|----------|-------------|
| External forwarding | HIGH | Forwards to non-org domain |
| Forward + delete | CRITICAL | Forwards then deletes original |
| Financial keywords | HIGH | Targets invoice/payment subjects |
| Forward + mark read | HIGH | Hides forwarded messages |
| Move to RSS/Junk | MEDIUM | Hides messages in unused folders |

## Splunk SPL Detection

```spl
index=o365 Operation IN ("New-InboxRule", "Set-InboxRule")
| spath output=forward path=Parameters{}.Value
| where isnotnull(forward) AND NOT match(forward, "@company\\.com")
```

## CLI Usage

```bash
python agent.py --token "eyJ..." --user-id user@company.com --org-domain company.com
python agent.py --audit-log exchange_audit.log
```
