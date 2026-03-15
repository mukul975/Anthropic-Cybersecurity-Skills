# API Reference: Phishing Reporting Button Workflow

## Email Parsing (Python email module)
```python
from email import policy
from email.parser import BytesParser

with open("report.eml", "rb") as f:
    msg = BytesParser(policy=policy.default).parse(f)
headers = {
    "from": msg["From"], "subject": msg["Subject"],
    "reply_to": msg["Reply-To"], "received": msg.get_all("Received")
}
```

## Phishing Indicators
| Indicator | Weight | Description |
|-----------|--------|-------------|
| Reply-To mismatch | 20 | From and Reply-To differ |
| SPF/DKIM fail | 25 | Authentication failure |
| Suspicious language | 10 | Urgency/credential patterns |
| Suspicious URL | 15 | Known bad TLDs or redirectors |
| Dangerous attachment | 30 | Executable file extensions |

## VirusTotal URL Scan
```
GET https://www.virustotal.com/api/v3/urls/{url_id}
x-apikey: YOUR_KEY
```
URL ID = base64url(url) or sha256(url)

## Dangerous File Extensions
| Category | Extensions |
|----------|-----------|
| Executables | `.exe`, `.scr`, `.bat`, `.cmd` |
| Scripts | `.js`, `.vbs`, `.ps1`, `.hta` |
| Disk images | `.iso`, `.img`, `.vhd` |
| Archives | `.zip` (password-protected), `.rar` |
| Documents | `.docm`, `.xlsm` (macro-enabled) |

## Verdict Classification
| Score | Verdict | Action |
|-------|---------|--------|
| >= 50 | Phishing | Block sender, quarantine, create ticket |
| 25-49 | Suspicious | Analyst review required |
| < 25 | Benign | Close report, notify user |

## Ticketing Integration
```
POST /api/v2/tickets
Authorization: Bearer TOKEN
{
  "title": "Phishing Report: ...",
  "severity": "high",
  "description": "...",
  "indicators": ["Reply-To mismatch", ...]
}
```

## Microsoft Report Message Add-in
```
POST https://graph.microsoft.com/v1.0/users/{id}/messages/{msgId}/move
{"destinationId": "phishing-mailbox-id"}
```
