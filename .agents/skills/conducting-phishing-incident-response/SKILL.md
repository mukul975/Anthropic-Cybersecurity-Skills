---
name: conducting-phishing-incident-response
description: >
  Responds to phishing incidents by analyzing reported emails, extracting indicators,
  assessing credential compromise, quarantining malicious messages across the organization,
  and remediating affected accounts. Covers email header analysis, URL/attachment
  sandboxing, and mailbox-wide purge operations. Activates for requests involving
  phishing response, email incident, credential phishing, spear phishing investigation,
  or phishing remediation.
domain: cybersecurity
subdomain: incident-response
tags: [phishing-response, email-security, credential-compromise, email-header-analysis, mailbox-remediation]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Conducting Phishing Incident Response

## When to Use

- A user reports receiving a suspicious email via the phishing report button or abuse mailbox
- Email gateway detects a malicious email that bypassed initial filtering
- Threat intelligence indicates an active phishing campaign targeting the organization
- A user confirms they clicked a link or opened an attachment from a suspicious email
- Credentials have been entered on a suspected phishing page

**Do not use** for business email compromise (BEC) involving compromised internal accounts; use BEC response procedures which focus on account takeover investigation.

## Prerequisites

- Email security gateway with message trace and quarantine capabilities (Microsoft Defender for Office 365, Proofpoint, Mimecast)
- Microsoft 365 admin access or Google Workspace admin for mailbox search and purge
- Malware sandbox for attachment and URL analysis (ANY.RUN, Joe Sandbox, Hybrid Analysis)
- Email header analysis tools (MXToolbox Header Analyzer, Google Admin Toolbox)
- Identity provider access for account remediation (Azure AD, Okta, Duo)
- Phishing report intake process (dedicated mailbox or integrated report button)

## Workflow

### Step 1: Receive and Triage the Phishing Report

Evaluate the reported email to determine if it is malicious:

- Extract the email as an .EML or .MSG file (preserves headers)
- Analyze email headers to determine the true sender, relay path, and authentication results

```
Email Header Analysis Checklist:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Return-Path:     billing@spoofed-domain[.]com
From:            "IT Support" <support@corp-lookalike[.]com>
Reply-To:        attacker@gmail[.]com (different from From)
SPF:             FAIL (sender IP not authorized for domain)
DKIM:            FAIL (signature invalid)
DMARC:           FAIL (policy: none - no enforcement)
Received:        from mail.attacker-infra[.]net [45.33.x.x]
X-Originating-IP: 45.33.x.x
Message-ID:      <random@attacker-infra.net>
```

Classification criteria:
- **Confirmed Phishing**: Malicious URL/attachment, spoofed sender, credential harvesting page
- **Suspicious**: Anomalous headers but no confirmed malicious content
- **Spam/Marketing**: Unwanted but not malicious
- **Legitimate**: Not a phishing email (false report)

### Step 2: Analyze Malicious Content

Examine URLs and attachments in a safe environment:

**URL Analysis:**
- Check URL against VirusTotal, URLscan.io, and Google Safe Browsing
- Open URL in a sandbox browser to capture the landing page
- Check if the URL redirects to a credential harvesting page
- Identify the phishing kit type (Microsoft 365 login clone, Okta clone, generic)
- Determine if the phishing page is still active

**Attachment Analysis:**
- Calculate file hash (SHA-256) and check against VirusTotal
- Detonate in sandbox (ANY.RUN, Joe Sandbox)
- Analyze document for macros (olevba for Office files)
- Check for embedded exploits (CVE exploitation in document parsers)

### Step 3: Determine Scope of Impact

Identify all recipients and assess who interacted with the phishing email:

```
Scope Assessment:
━━━━━━━━━━━━━━━━
Total Recipients:     47 users
Delivered to Inbox:   38 users (9 caught by email gateway)
Opened Email:         24 users (email tracking pixel data)
Clicked Link:         8 users (proxy/firewall logs)
Entered Credentials:  3 users (phishing page submitted form data)
Opened Attachment:    2 users (EDR process execution telemetry)
```

Search methods:
- Microsoft 365: Use Threat Explorer or Content Search to find all instances of the email
- Google Workspace: Use Admin Console > Investigation tool for message search
- Proxy logs: Search for connections to the phishing URL from internal IPs
- EDR: Search for attachment file hash execution across all endpoints

### Step 4: Contain the Threat

Execute containment actions based on impact assessment:

**Email Containment:**
- Purge the phishing email from all mailboxes using Microsoft 365 Content Search and Purge or Google Workspace Admin delete
- Block the sender domain at the email gateway
- Add the phishing URL to the web proxy blocklist
- Add attachment hash to email gateway and EDR blocklists

**Account Containment (for users who entered credentials):**
- Force password reset immediately
- Revoke all active sessions and OAuth tokens
- Enable or re-verify MFA enrollment
- Review mailbox rules for attacker-created forwarding rules
- Check for unauthorized OAuth application grants
- Review recent sign-in activity for suspicious locations

```powershell
# Microsoft 365: Revoke sessions and reset password
Connect-AzureAD
Revoke-AzureADUserAllRefreshToken -ObjectId "user@corp.com"
Set-AzureADUserPassword -ObjectId "user@corp.com" -ForceChangePasswordNextLogin $true

# Check for mailbox forwarding rules
Get-InboxRule -Mailbox "user@corp.com" | Where-Object {$_.ForwardTo -or $_.RedirectTo}

# Remove suspicious forwarding rules
Remove-InboxRule -Mailbox "user@corp.com" -Identity "Rule Name"
```

### Step 5: Eradicate and Recover

Remove all traces of the phishing attack:

- Confirm email purge completed successfully across all mailboxes
- Verify compromised accounts have been secured (password changed, sessions revoked, MFA verified)
- Remove any malware installed via phishing attachments from affected endpoints
- Monitor compromised accounts for 72 hours for signs of continued unauthorized access
- Check for data exfiltration from compromised accounts during the exposure window

### Step 6: Post-Incident Actions

Strengthen defenses against similar phishing attacks:

- Report the phishing URL to Google Safe Browsing and Microsoft SmartScreen
- Submit the phishing domain for takedown via the domain registrar abuse contact
- Update email gateway filtering rules based on observed evasion techniques
- Send targeted security awareness notification to affected users
- Update phishing simulation program to include the observed technique

## Key Concepts

| Term | Definition |
|------|------------|
| **Spear Phishing** | Targeted phishing attack crafted for a specific individual or organization using personalized content |
| **Credential Harvesting** | Phishing technique that mimics a legitimate login page to capture usernames and passwords |
| **SPF (Sender Policy Framework)** | Email authentication protocol that specifies which mail servers are authorized to send email for a domain |
| **DKIM (DomainKeys Identified Mail)** | Email authentication method using cryptographic signatures to verify that an email was not altered in transit |
| **DMARC** | Policy framework that uses SPF and DKIM to determine email authenticity and instructs receivers on handling failures |
| **OAuth Consent Phishing** | Attack that tricks users into granting malicious OAuth applications access to their email and data |
| **Email Header** | Metadata embedded in every email containing routing, authentication, and sender information used for forensic analysis |

## Tools & Systems

- **Microsoft Defender for Office 365**: Email threat protection with Threat Explorer for investigation and automated purge
- **Proofpoint TAP (Targeted Attack Protection)**: Email security platform with URL rewriting and attachment sandboxing
- **URLscan.io**: Online service that scans URLs and captures screenshots of phishing pages for evidence
- **PhishTool**: Phishing analysis platform that automates header analysis, URL inspection, and IOC extraction
- **GoPhish**: Open-source phishing simulation platform for security awareness testing

## Common Scenarios

### Scenario: Microsoft 365 Credential Phishing via QR Code

**Context**: Users report an email claiming to be from IT requiring MFA re-enrollment. The email contains a QR code that links to a convincing Microsoft 365 login page clone hosted on a compromised WordPress site.

**Approach**:
1. Scan the QR code in a sandbox to extract the URL
2. Analyze the phishing page: captures credentials and MFA tokens (adversary-in-the-middle attack)
3. Search email gateway for all recipients using message subject and sender as search criteria
4. Cross-reference with proxy logs to identify users who visited the phishing URL
5. Force password reset and revoke sessions for all users who visited the URL
6. Purge the email from all mailboxes and block the sender domain
7. Notify users about the specific campaign with visual examples of the phishing email

**Pitfalls**:
- Not checking for adversary-in-the-middle (AiTM) capability that captures session tokens even with MFA
- Only resetting passwords without revoking active sessions (attacker retains access via stolen session cookies)
- Not searching for mailbox forwarding rules created by the attacker after compromising an account
- Missing QR code phishing (quishing) because URL scanning tools cannot decode QR code images

## Output Format

```
PHISHING INCIDENT RESPONSE REPORT
===================================
Incident:          INC-2025-1602
Date Reported:     2025-11-16T09:15:00Z
Reported By:       jdoe@corp.example.com
Classification:    Credential Phishing (AiTM)

EMAIL ANALYSIS
Subject:       "Action Required: MFA Re-enrollment"
Sender:        it-support@corp-security[.]com (spoofed)
SPF:           FAIL | DKIM: FAIL | DMARC: FAIL
Phishing URL:  hxxps://compromised-site[.]com/ms365/login
Phishing Type: Microsoft 365 AiTM credential harvester

IMPACT ASSESSMENT
Recipients:        47
Clicked Link:      8
Credentials Entered: 3 (confirmed via proxy POST data)

CONTAINMENT ACTIONS
[x] Email purged from all 47 mailboxes
[x] Phishing domain blocked at web proxy
[x] Sender domain blocked at email gateway
[x] 3 compromised accounts: passwords reset, sessions revoked
[x] Mailbox forwarding rules reviewed (1 malicious rule removed)
[x] OAuth app grants reviewed (no unauthorized grants found)

IOCs EXTRACTED
Domain:  corp-security[.]com
URL:     hxxps://compromised-site[.]com/ms365/login
IP:      104.21.x.x (Cloudflare-hosted)
Sender:  it-support@corp-security[.]com

RECOMMENDATIONS
1. Implement DMARC enforcement (p=reject) for corp domain
2. Deploy QR code scanning in email gateway
3. Send targeted awareness notification to all 47 recipients
4. Request domain takedown via registrar abuse contact
```
