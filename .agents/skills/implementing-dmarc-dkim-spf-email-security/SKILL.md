---
name: implementing-dmarc-dkim-spf-email-security
description: SPF, DKIM, and DMARC form the three pillars of email authentication. Together they prevent domain spoofing, validate message integrity, and define policies for handling unauthenticated mail. Proper im
domain: cybersecurity
subdomain: phishing-defense
tags: [phishing, email-security, social-engineering, dmarc, awareness, dkim, spf, dns]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing DMARC, DKIM, and SPF Email Security

## Overview
SPF, DKIM, and DMARC form the three pillars of email authentication. Together they prevent domain spoofing, validate message integrity, and define policies for handling unauthenticated mail. Proper implementation drastically reduces phishing attacks that impersonate your organization's domain.

## Prerequisites
- DNS management access for your domain
- Access to email server/MTA configuration (Postfix, Exchange, Google Workspace, Microsoft 365)
- Basic understanding of DNS TXT records
- Python 3.8+ for validation scripts

## Key Concepts

### SPF (Sender Policy Framework)
Publishes a DNS TXT record listing authorized IP addresses and mail servers that can send email on behalf of your domain. Receiving servers check the envelope sender's IP against this list.

### DKIM (DomainKeys Identified Mail)
Adds a cryptographic signature to outgoing emails using a private key. The corresponding public key is published in DNS. Receivers verify the signature to ensure the message was not altered in transit.

### DMARC (Domain-based Message Authentication, Reporting and Conformance)
Builds on SPF and DKIM by specifying a policy (none/quarantine/reject) for messages that fail authentication, and provides a reporting mechanism to monitor spoofing attempts.

## Implementation Steps

### Step 1: Audit Current State
```bash
# Check existing SPF record
dig TXT example.com | grep spf

# Check existing DKIM selector
dig TXT selector1._domainkey.example.com

# Check existing DMARC record
dig TXT _dmarc.example.com
```

### Step 2: Implement SPF
```
# DNS TXT record for example.com
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:spf.protection.outlook.com -all
```

Key SPF mechanisms:
- `ip4:` / `ip6:` - Authorize specific IP ranges
- `include:` - Include another domain's SPF record
- `a` - Authorize domain's A record IPs
- `mx` - Authorize domain's MX record IPs
- `-all` - Hard fail all others (recommended)
- `~all` - Soft fail (monitoring phase)

### Step 3: Implement DKIM
```bash
# Generate DKIM key pair (2048-bit RSA)
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

# Format public key for DNS (remove headers, join lines)
grep -v "PUBLIC KEY" dkim_public.pem | tr -d '\n'
```

DNS TXT record at `selector1._domainkey.example.com`:
```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...
```

### Step 4: Implement DMARC
```
# DNS TXT record at _dmarc.example.com
# Phase 1 (Monitor):
v=DMARC1; p=none; rua=mailto:dmarc-aggregate@example.com; ruf=mailto:dmarc-forensic@example.com; pct=100

# Phase 2 (Quarantine):
v=DMARC1; p=quarantine; rua=mailto:dmarc-aggregate@example.com; pct=25

# Phase 3 (Reject):
v=DMARC1; p=reject; rua=mailto:dmarc-aggregate@example.com; pct=100
```

### Step 5: Monitor and Analyze DMARC Reports
Use the `scripts/process.py` to parse DMARC aggregate XML reports and identify authentication failures, unauthorized senders, and spoofing attempts.

## Tools & Resources
- **MXToolbox**: https://mxtoolbox.com/SuperTool.aspx
- **DMARC Analyzer (dmarcian)**: https://dmarcian.com/
- **Google Postmaster Tools**: https://postmaster.google.com/
- **Valimail DMARC Monitor**: https://www.valimail.com/
- **DMARC Report Analyzer**: https://dmarc.postmarkapp.com/

## Validation
- SPF record passes validation at mxtoolbox.com
- DKIM signature verified on test emails
- DMARC record properly formatted and reporting enabled
- Test emails pass all three checks in recipient's Authentication-Results header
