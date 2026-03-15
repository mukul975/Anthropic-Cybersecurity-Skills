# API Reference: Implementing Google Workspace Phishing Protection

## Admin Console Path

```
Admin Console > Apps > Google Workspace > Gmail > Safety
```

## Gmail Safety Controls

| Control | Category | Severity if Missing |
|---------|----------|-------------------|
| Protect against similar domain spoofing | Spoofing | HIGH |
| Protect against employee name spoofing | Spoofing | HIGH |
| Protect against inbound domain spoofing | Spoofing | CRITICAL |
| Enhanced pre-delivery scanning | Scanning | HIGH |
| Attachment protection (encrypted/scripts) | Attachments | HIGH |
| Identify links behind shortened URLs | Links | MEDIUM |
| Show warning for unauthenticated email | Warnings | MEDIUM |
| Enhanced Safe Browsing | Browsing | HIGH |

## Admin SDK Directory API (GAM)

```bash
# List Gmail settings
gam print gmailsettings domain example.com
# List users with Advanced Protection
gam print users query "isAdvancedProtectionProgram=true"
```

## Google Workspace Alert Center API

```python
from google.oauth2 import service_account
from googleapiclient.discovery import build
creds = service_account.Credentials.from_service_account_file("sa.json",
    scopes=["https://www.googleapis.com/auth/apps.alerts"])
service = build("alertcenter", "v1beta1", credentials=creds)
alerts = service.alerts().list().execute()
```

## Recommended Actions for Spoofing

| Detection | Action |
|-----------|--------|
| Similar domain spoofing | Quarantine |
| Employee name spoofing | Show warning + move to spam |
| Inbound domain spoofing | Quarantine |
| Unauthenticated email | Show warning banner |

### References

- Google Workspace Admin Help - Phishing: https://support.google.com/a/answer/9157861
- Advanced Protection Program: https://landing.google.com/advancedprotection/
- Gmail Safety Settings: https://support.google.com/a/answer/7380368
