# API Reference: Detecting Business Email Compromise

## Python email Library

```python
import email
from email import policy

# Parse .eml file
with open("message.eml") as f:
    msg = email.message_from_file(f, policy=policy.default)

msg.get("From")                # sender header
msg.get("Reply-To")            # reply-to header
msg.get("Authentication-Results")  # SPF/DKIM/DMARC results
body = msg.get_body(preferencelist=("plain", "html"))
body.get_content()             # decoded body text
```

## Authentication Header Patterns

| Result | Meaning |
|--------|---------|
| `spf=pass` | Sender IP authorized by domain SPF record |
| `spf=fail` | Sender IP NOT in SPF record |
| `dkim=pass` | DKIM signature valid |
| `dkim=fail` | DKIM signature invalid or missing |
| `dmarc=pass` | SPF or DKIM aligned with From domain |
| `dmarc=fail` | Neither SPF nor DKIM aligned |

## BEC Attack Types (FBI IC3)

| Type | Description |
|------|-------------|
| CEO Fraud | Impersonates executive requesting wire transfer |
| Invoice Fraud | Fake invoice with changed bank details |
| Account Compromise | Compromised email used for payment requests |
| Attorney Impersonation | Urgent legal matter requiring funds |
| Data Theft | Requests for W-2 / PII from HR |

## BEC Indicator Regex Patterns

```python
# Financial urgency
r"\b(wire transfer|bank transfer|routing number)\b"
# Secrecy pressure
r"\b(confidential|do not share|keep this between us)\b"
# Gift card fraud
r"\b(gift card|bitcoin|crypto|western union)\b"
# Account change
r"\b(change.*(bank|account|payment))\b"
```

## Microsoft Graph API - Mail Security

```http
GET https://graph.microsoft.com/v1.0/me/messages?$filter=internetMessageHeaders/any(h: h/name eq 'Authentication-Results')
Authorization: Bearer {token}
```

## CLI Usage

```bash
python agent.py --email-file suspicious.eml --vip-names "John Smith" "Jane CEO"
python agent.py --scan-dir /var/mail/quarantine/ --vip-names "CFO Name"
```
