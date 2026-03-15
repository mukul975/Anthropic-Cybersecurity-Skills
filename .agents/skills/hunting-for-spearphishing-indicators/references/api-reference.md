# API Reference: Hunting for Spearphishing Indicators

## Email Header Analysis

```python
import email
from email import policy

msg = email.message_from_file(open("suspect.eml"), policy=policy.default)
print(msg["From"], msg["Return-Path"], msg["Received"])
print(msg["Authentication-Results"])  # SPF/DKIM/DMARC
```

## Suspicious Attachment Types

| Extension | Risk | Technique |
|-----------|------|-----------|
| `.exe`, `.scr`, `.dll` | CRITICAL | T1566.001 |
| `.xlsm`, `.docm` | HIGH | T1566.001 (macros) |
| `.iso`, `.img`, `.lnk` | HIGH | T1566.001 (MOTW bypass) |
| `.html`, `.htm` | HIGH | HTML Smuggling |
| `.zip`, `.rar` | MEDIUM | Archive with payload |

## Splunk SPL - Phishing Detection

```spl
index=email sourcetype=exchange
| where match(attachment_name, "(?i)\.(exe|scr|iso|lnk|docm|xlsm|hta)$")
| stats count by sender, recipient, attachment_name, subject
| where count > 3
```

## KQL - Microsoft Defender for Office 365

```kql
EmailAttachmentInfo
| where FileType in ("exe", "scr", "iso", "lnk", "docm", "xlsm")
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName
```

## Phishing URL Patterns

```python
patterns = [
    r"https?://bit\.ly/",           # URL shorteners
    r"https?://\d+\.\d+\.\d+\.\d+", # IP-based URLs
    r"https?://[^/]*login[^/]*\.",   # Credential harvesting
    r"https?://[^/]*\.(top|xyz)/",   # Suspicious TLDs
]
```

## SPF/DKIM/DMARC Validation

```python
import spf
result, _, _ = spf.check2(ip="1.2.3.4", sender="user@example.com", helo="mail.example.com")
# result: 'pass', 'fail', 'softfail', 'neutral', 'none'
```

### References

- MITRE T1566: https://attack.mitre.org/techniques/T1566/
- pyspf: https://pypi.org/project/pyspf/
- python email: https://docs.python.org/3/library/email.html
