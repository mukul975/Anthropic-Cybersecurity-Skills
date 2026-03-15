# API Reference: Implementing Mobile Application Management

## Microsoft Intune MAM API (Graph)

```python
import requests
headers = {"Authorization": "Bearer <token>"}
# List MAM policies
policies = requests.get(
    "https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies",
    headers=headers).json()
# List managed apps
apps = requests.get(
    "https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppRegistrations",
    headers=headers).json()
```

## MAM Policy Settings

| Setting | Recommended | Description |
|---------|------------|-------------|
| pinRequired | true | Require app PIN |
| encryptAppData | true | Encrypt app data |
| dataBackupBlocked | true | Block iCloud/Google backup |
| screenCaptureBlocked | true | Block screenshots |
| managedBrowserRequired | true | Force managed browser |
| maxPinRetries | 5 | Wipe after failures |

## Conditional Launch Settings

| Condition | Action | Value |
|-----------|--------|-------|
| Jailbreak/root | Block | true |
| Min OS version | Warn/Block | 16.0 |
| Offline wipe | Wipe | 30 days |
| Max PIN retries | Wipe | 5 |

### References

- Intune MAM: https://learn.microsoft.com/en-us/mem/intune/apps/app-protection-policy
- Graph API MAM: https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-conceptual
