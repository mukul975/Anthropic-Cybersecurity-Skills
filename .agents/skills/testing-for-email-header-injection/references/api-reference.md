# API Reference: Testing for Email Header Injection

## CRLF Encoding Variants

| Encoding | Representation | Description |
|----------|---------------|-------------|
| `%0A` | LF | URL-encoded line feed |
| `%0D%0A` | CRLF | URL-encoded carriage return + line feed |
| `%0D` | CR | URL-encoded carriage return |
| `%250A` | Double-encoded LF | Bypasses single decode |
| `\n` | Raw LF | Direct newline character |

## Injectable Headers

| Header | Impact | Severity |
|--------|--------|----------|
| Cc: | Send copy to attacker | High |
| Bcc: | Hidden copy to attacker | High |
| From: | Email spoofing | Medium |
| Reply-To: | Phishing redirect | Medium |
| Subject: | Subject override | Low |
| Content-Type: | Body injection | High |
| To: | Additional recipients | High |

## Common Injection Points

| Endpoint | Field | Risk |
|----------|-------|------|
| /contact | email, name, subject | Header injection |
| /share | to, from | Recipient injection |
| /invite | email | Mass invitation abuse |
| /forgot-password | email | CC token to attacker |
| /api/send-email | to, subject, body | Full control |

## Attack Scenarios

| Scenario | Technique |
|----------|-----------|
| Spam relay | Inject BCC with mass recipients |
| Phishing | Override From/Reply-To |
| Password reset hijack | CC reset token email |
| Content override | MIME boundary injection |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | HTTP form submission |
| `json` | stdlib | Report generation |

## References

- OWASP Email Injection: https://owasp.org/www-community/attacks/Email_Injection
- swaks SMTP testing: https://www.jetmore.org/john/code/swaks/
- mailhog: https://github.com/mailhog/MailHog
