# API Reference: Phishing Email Header Analysis

## Python email Module

### Parsing Email Files
```python
import email
with open("message.eml", "r") as f:
    msg = email.message_from_string(f.read())

print(msg["From"])
print(msg["Subject"])
print(msg.get_all("Received"))
print(msg["Authentication-Results"])
```

### Extracting Body
```python
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            body = part.get_payload(decode=True).decode()
```

## Key Email Headers for Forensics

| Header | Purpose |
|--------|---------|
| `Received` | Mail server routing chain (bottom = origin) |
| `From` | Claimed sender (can be spoofed) |
| `Return-Path` | Envelope sender for bounces |
| `Reply-To` | Where replies go (phishing: often different from From) |
| `Authentication-Results` | SPF/DKIM/DMARC verdicts |
| `Received-SPF` | SPF check result |
| `DKIM-Signature` | DKIM cryptographic signature |
| `X-Mailer` | Sending software |
| `Message-ID` | Unique message identifier |
| `X-Originating-IP` | Original sender IP |

## Authentication Checks

### SPF Status Values
| Value | Meaning |
|-------|---------|
| `pass` | Sender IP authorized |
| `fail` | Sender IP not authorized |
| `softfail` | Not authorized but not rejected |
| `neutral` | No SPF policy for domain |
| `none` | No SPF record exists |

### DKIM Verification
```bash
opendkim-testmsg < message.eml
# Or in Authentication-Results: dkim=pass header.d=example.com
```

### DMARC Policy Check
```bash
dig _dmarc.example.com TXT
# v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

## Phishing Detection Indicators

| Indicator | Severity | Description |
|-----------|----------|-------------|
| SPF fail | HIGH | Sender IP not in domain's SPF record |
| Reply-To mismatch | HIGH | Reply-To different from From address |
| Email in display name | HIGH | Display name contains email address |
| IP-based URL | HIGH | Links point to raw IP addresses |
| Urgency keywords | MEDIUM | Subject contains "urgent", "action required" |
| URL shortener | MEDIUM | Links use bit.ly, tinyurl, etc. |
| New domain | MEDIUM | Sending domain registered recently |
| PHPMailer X-Mailer | MEDIUM | Bulk mailer software |

## msgconvert (Perl)

### Convert MSG to EML
```bash
msgconvert message.msg               # Outputs message.eml
msgconvert --outfile out.eml msg.msg  # Specify output
```

## emlAnalyzer (Python)

### Installation and Usage
```bash
pip install eml-analyzer
emlAnalyzer -i message.eml --header --html --attachments
```
