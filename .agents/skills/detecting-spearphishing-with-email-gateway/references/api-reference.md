# API Reference: Spearphishing Detection via Email Gateway

## Python email Module

### Parse EML file
```python
import email
from email import policy

with open("message.eml", "rb") as f:
    msg = email.message_from_binary_file(f, policy=policy.default)
```

### Security Headers
| Header | Purpose |
|--------|---------|
| `Received-SPF` | SPF check result |
| `Authentication-Results` | SPF, DKIM, DMARC combined |
| `DKIM-Signature` | DKIM signing info |
| `ARC-Authentication-Results` | ARC chain results |
| `X-Mailer` | Client used to send |
| `Return-Path` | Envelope sender |

### Authentication-Results Values
```
Authentication-Results: mx.google.com;
    dkim=pass header.d=example.com;
    spf=pass smtp.mailfrom=example.com;
    dmarc=pass
```

## SPF Record Lookup
```bash
dig TXT example.com | grep "v=spf1"
# v=spf1 include:_spf.google.com ~all
```

### SPF Results
| Result | Meaning |
|--------|---------|
| `pass` | Authorized sender |
| `fail` | Unauthorized (reject) |
| `softfail` | Unauthorized (accept with mark) |
| `neutral` | No assertion |
| `none` | No SPF record |

## DKIM Verification
```bash
opendkim-testkey -d example.com -s selector -vvv
```

## DMARC Record
```bash
dig TXT _dmarc.example.com
# v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

## Microsoft Defender for Office 365 API

### Get email threat assessment
```http
POST https://graph.microsoft.com/v1.0/informationProtection/threatAssessmentRequests
Authorization: Bearer {token}

{
  "contentType": "mail",
  "expectedAssessment": "block",
  "category": "phishing",
  "mailInfo": {
    "internetMessageId": "<message-id>"
  }
}
```

## Proofpoint TAP API

### Get blocked messages
```http
GET https://tap-api-v2.proofpoint.com/v2/siem/messages/blocked
    ?sinceSeconds=3600
Authorization: Basic {base64_credentials}
```

### Response Fields
| Field | Description |
|-------|-------------|
| `spamScore` | Spam confidence (0-100) |
| `phishScore` | Phishing confidence (0-100) |
| `threatsInfoMap` | Threat details array |
| `fromAddress` | Envelope sender |

## Mimecast API — URL Protection

### Decode Mimecast URL
```http
POST https://api.mimecast.com/api/ttp/url/decode-url
Authorization: MC {access-key}:{secret-key}

{
  "data": [{"url": "https://protect.mimecast.com/..."}]
}
```
