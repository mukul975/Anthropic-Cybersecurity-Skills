---
name: conducting-spearphishing-simulation-campaign
description: Spearphishing simulation is a targeted social engineering attack vector used by red teams to gain initial access. Unlike broad phishing campaigns, spearphishing uses OSINT-derived intelligence to craf
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, adversary-simulation, mitre-attack, exploitation, post-exploitation, spearphishing, social-engineering]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Conducting Spearphishing Simulation Campaign

## Overview

Spearphishing simulation is a targeted social engineering attack vector used by red teams to gain initial access. Unlike broad phishing campaigns, spearphishing uses OSINT-derived intelligence to craft highly personalized messages targeting specific individuals. This skill covers developing pretexts, building payloads, setting up email infrastructure, executing the campaign, and tracking results.

## Objectives

- Develop convincing pretexts tailored to specific target personnel
- Create weaponized payloads that bypass email security controls
- Set up email delivery infrastructure with proper SPF/DKIM/DMARC configuration
- Execute phishing campaigns with real-time tracking and metrics
- Document results for engagement reporting and security awareness improvement

## MITRE ATT&CK Mapping

- **T1566.001** - Phishing: Spearphishing Attachment
- **T1566.002** - Phishing: Spearphishing Link
- **T1566.003** - Phishing: Spearphishing via Service
- **T1598.003** - Phishing for Information: Spearphishing Link
- **T1204.001** - User Execution: Malicious Link
- **T1204.002** - User Execution: Malicious File
- **T1608.001** - Stage Capabilities: Upload Malware
- **T1608.005** - Stage Capabilities: Link Target
- **T1583.001** - Acquire Infrastructure: Domains
- **T1585.002** - Establish Accounts: Email Accounts

## Implementation Steps

### Phase 1: Pretext Development
1. Review OSINT findings for target personnel profiles
2. Identify current organizational events (mergers, projects, new hires)
3. Select pretext theme (IT helpdesk, HR benefits, vendor communication, executive request)
4. Craft email templates with appropriate urgency and authority cues
5. Create landing pages that mirror target organization's branding

### Phase 2: Payload Development
1. Select payload type based on target security controls:
   - HTML smuggling for email gateway bypass
   - Macro-enabled documents (if macros not blocked)
   - ISO/IMG files containing LNK payloads
   - OneNote files with embedded scripts
   - QR codes linking to credential harvesting pages
2. Test payload against target's known security stack
3. Implement payload obfuscation techniques
4. Configure callback to C2 infrastructure

### Phase 3: Infrastructure Setup
1. Register convincing look-alike domain
2. Age domain and build reputation (minimum 2 weeks recommended)
3. Configure SPF, DKIM, and DMARC records
4. Set up SMTP relay with GoPhish or custom mail server
5. Deploy credential harvesting pages with SSL certificates
6. Configure tracking pixels and click tracking

### Phase 4: Campaign Execution
1. Send test emails to verify delivery and rendering
2. Launch campaign in waves (avoid mass sending)
3. Monitor email delivery rates and opens in real-time
4. Track link clicks and credential submissions
5. Deploy payloads to users who interact with phishing emails
6. Capture screenshots and evidence for reporting

### Phase 5: Post-Campaign Analysis
1. Calculate campaign metrics (delivery rate, open rate, click rate, credential capture rate)
2. Identify users who reported phishing to SOC
3. Document bypass of email security controls
4. Map successful compromises to MITRE ATT&CK
5. Compile findings for engagement report

## Tools and Resources

| Tool | Purpose | License |
|------|---------|---------|
| GoPhish | Phishing campaign management | Open Source |
| Evilginx2 | Real-time credential harvesting with MFA bypass | Open Source |
| King Phisher | Phishing campaign toolkit | Open Source |
| SET (Social Engineering Toolkit) | Multi-vector social engineering | Open Source |
| Modlishka | Reverse proxy phishing | Open Source |
| CredSniper | Credential harvesting framework | Open Source |
| Fierce Phish | Phishing framework | Open Source |

## Validation Criteria

- [ ] Pretext tailored to specific targets with OSINT data
- [ ] Payload tested against email security controls
- [ ] Infrastructure configured with proper email authentication
- [ ] Campaign tracked with delivery and interaction metrics
- [ ] Evidence collected for engagement report
- [ ] Cleanup performed on infrastructure post-campaign
