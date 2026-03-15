---
name: analyzing-phishing-email-headers
description: Email headers contain critical metadata that reveals the true origin, routing path, and authentication status of emails. Analyzing these headers is a foundational skill for identifying phishing attemp
domain: cybersecurity
subdomain: phishing-defense
tags: [phishing, email-security, social-engineering, dmarc, awareness, header-analysis, forensics]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Phishing Email Headers

## Overview
Email headers contain critical metadata that reveals the true origin, routing path, and authentication status of emails. Analyzing these headers is a foundational skill for identifying phishing attempts, verifying sender authenticity, and gathering threat intelligence. This skill covers systematic extraction and interpretation of email headers using both manual techniques and automated tools.

## Prerequisites
- Basic understanding of SMTP protocol and email delivery
- Familiarity with DNS records (MX, TXT, SPF, DKIM, DMARC)
- Python 3.8+ installed
- Access to email client that can export raw headers (Outlook, Gmail, Thunderbird)

## Key Concepts

### Critical Header Fields
1. **Received**: Chain of mail servers the message passed through (read bottom to top)
2. **From / Return-Path / Reply-To**: Sender identity fields (often spoofed)
3. **Authentication-Results**: SPF, DKIM, DMARC verification outcomes
4. **X-Originating-IP**: Original sender IP address
5. **Message-ID**: Unique identifier; anomalies indicate spoofing
6. **X-Mailer / User-Agent**: Email client used to compose the message

### Red Flags in Headers
- Mismatched `From` and `Return-Path` domains
- SPF/DKIM/DMARC failures in `Authentication-Results`
- Suspicious `Received` chains with unfamiliar relay servers
- `X-Originating-IP` from unexpected geographies
- Missing or malformed `Message-ID`
- Unusual `X-Mailer` values (e.g., mass-mailing tools)

## Implementation Steps

### Step 1: Extract Raw Email Headers
```
Gmail: Open email -> Three dots -> "Show original"
Outlook: Open email -> File -> Properties -> Internet Headers
Thunderbird: View -> Message Source (Ctrl+U)
```

### Step 2: Parse Headers with Python
Use the `scripts/process.py` script to automate header analysis including IP geolocation, authentication validation, and anomaly detection.

### Step 3: Validate Authentication Chain
- Check SPF alignment: Does the sending IP match the domain's SPF record?
- Check DKIM signature: Is the cryptographic signature valid?
- Check DMARC policy: Does the message pass DMARC alignment?

### Step 4: Trace Mail Route
- Read `Received` headers from bottom to top
- Map each hop's IP to organization/location
- Identify unexpected relays or delays

### Step 5: Correlate with Threat Intelligence
- Look up originating IP on AbuseIPDB, VirusTotal
- Check sending domain age on WHOIS
- Search for known phishing infrastructure patterns

## Tools & Resources
- **MXToolbox Header Analyzer**: https://mxtoolbox.com/EmailHeaders.aspx
- **Google Admin Toolbox**: https://toolbox.googleapps.com/apps/messageheader/
- **AbuseIPDB**: https://www.abuseipdb.com/
- **VirusTotal**: https://www.virustotal.com/
- **PhishTank**: https://phishtank.org/

## Validation
- Successfully parse headers from 3 different email providers
- Correctly identify authentication pass/fail status
- Accurately trace email routing path
- Detect at least 3 phishing indicators in a sample phishing email
