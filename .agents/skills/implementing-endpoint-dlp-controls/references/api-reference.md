# API Reference: Implementing Endpoint DLP Controls

## Sensitive Data Patterns

| Pattern | Regex | Severity |
|---------|-------|----------|
| SSN | `\d{3}-\d{2}-\d{4}` | HIGH |
| Credit Card | `4[0-9]{12}(?:[0-9]{3})?` | HIGH |
| AWS Key | `AKIA[0-9A-Z]{16}` | CRITICAL |
| Private Key | `-----BEGIN.*PRIVATE KEY-----` | CRITICAL |
| API Key | `api[_-]?key\s*[:=]\s*[a-zA-Z0-9]{20,}` | HIGH |

## DLP Channels

| Channel | Monitoring Method |
|---------|-------------------|
| USB/Removable | Device event logs |
| Cloud Storage | URL/domain filtering |
| Email | Attachment scanning |
| Clipboard | Process monitoring |
| Print | Print spooler events |

## Microsoft Purview DLP API

```python
import requests
headers = {"Authorization": "Bearer <token>"}
resp = requests.get(
    "https://graph.microsoft.com/v1.0/security/alerts_v2",
    headers=headers,
    params={"$filter": "category eq 'DataLossPrevention'"})
```

## CrowdStrike Falcon DLP

```bash
curl -X GET "https://api.crowdstrike.com/dlp/entities/policies/v1" \
  -H "Authorization: Bearer $TOKEN"
```

## File Scanning

```python
from pathlib import Path
import re
SENSITIVE_EXTS = {".pem", ".key", ".env", ".kdbx", ".pfx"}
for f in Path("/data").rglob("*"):
    if f.suffix in SENSITIVE_EXTS or re.search(r"AKIA", f.read_text()):
        print(f"ALERT: {f}")
```

### References

- Microsoft Purview DLP: https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
- CrowdStrike Falcon DLP: https://www.crowdstrike.com/platform/data-protection/
