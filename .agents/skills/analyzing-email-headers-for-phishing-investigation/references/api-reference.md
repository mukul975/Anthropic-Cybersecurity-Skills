# API Reference: Email Header Analysis Tools

## Python email Module

### Parsing EML Files
```python
import email
from email import policy

with open("phishing.eml", "r") as f:
    msg = email.message_from_file(f, policy=policy.default)

msg["From"]           # From header
msg["To"]             # To header
msg["Subject"]        # Subject line
msg["Message-ID"]     # Unique message identifier
msg["Reply-To"]       # Reply-To address
msg["Return-Path"]    # Envelope sender
msg.get_all("Received")  # All Received headers (list)
msg.get_all("Authentication-Results")  # Auth results
```

### Body and Attachment Extraction
```python
body = msg.get_body(preferencelist=("html", "plain"))
content = body.get_content()

for part in msg.walk():
    if part.get_content_disposition() == "attachment":
        filename = part.get_filename()
        data = part.get_payload(decode=True)
```

## dig - DNS Record Lookup

### SPF Record
```bash
dig TXT example.com +short
# Output: "v=spf1 include:_spf.google.com ~all"
```

### DKIM Record
```bash
dig TXT selector1._domainkey.example.com +short
```

### DMARC Record
```bash
dig TXT _dmarc.example.com +short
# Output: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

## pyspf - SPF Validation (Python)

### Syntax
```python
import spf
result, explanation = spf.check2(
    i="203.0.113.45",            # Sending IP
    s="sender@example.com",       # Envelope sender
    h="mail.example.com"          # HELO hostname
)
# Results: pass, fail, softfail, neutral, none, temperror, permerror
```

## dkimpy - DKIM Verification (Python)

### Syntax
```python
import dkim
with open("email.eml", "rb") as f:
    message = f.read()
result = dkim.verify(message)
# Returns True/False
```

## AbuseIPDB - IP Reputation

### API Endpoint
```bash
curl -G "https://api.abuseipdb.com/api/v2/check" \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json" \
  -d "ipAddress=203.0.113.45" -d "maxAgeInDays=90"
```

### Response Fields
| Field | Description |
|-------|-------------|
| `abuseConfidenceScore` | 0-100 confidence of abuse |
| `totalReports` | Number of abuse reports |
| `countryCode` | Source country |
| `isp` | Internet service provider |

## VirusTotal - Domain/URL Reputation

### Domain Lookup
```bash
curl -H "x-apikey: YOUR_KEY" \
  "https://www.virustotal.com/api/v3/domains/suspicious.com"
```

### URL Scan
```bash
curl -X POST "https://www.virustotal.com/api/v3/urls" \
  -H "x-apikey: YOUR_KEY" \
  -d "url=http://suspicious-url.com/login"
```

## whois - Domain Registration

### Syntax
```bash
whois suspicious-domain.com
```

### Key Fields
- `Registrar` - Domain registrar
- `Creation Date` - When domain was registered
- `Registrant` - Domain owner info
- `Name Server` - Authoritative DNS servers
