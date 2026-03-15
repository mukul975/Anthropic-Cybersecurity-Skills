---
name: performing-initial-access-with-evilginx3
description: Perform authorized initial access using EvilGinx3 adversary-in-the-middle phishing framework to capture session tokens and bypass multi-factor authentication during red team engagements.
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, initial-access, phishing, evilginx, mfa-bypass, adversary-in-the-middle, credential-theft]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Initial Access with EvilGinx3

## Overview

EvilGinx3 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, enabling bypass of multi-factor authentication (MFA). Unlike traditional credential phishing that only captures usernames and passwords, EvilGinx3 operates as a transparent reverse proxy between the victim and the legitimate authentication service, intercepting the full authentication flow including MFA tokens and session cookies. This makes it the primary tool for red teams demonstrating the risk of adversary-in-the-middle (AiTM) attacks against organizations relying solely on MFA for protection.

## Objectives

- Deploy EvilGinx3 with custom phishlets targeting authorized scope
- Configure DNS and SSL certificates for the phishing domain
- Capture session tokens that bypass MFA protections
- Import stolen session cookies into a browser to hijack authenticated sessions
- Integrate with GoPhish or custom delivery mechanisms for phishing email campaigns
- Document the complete attack chain from phishing email to authenticated access

## MITRE ATT&CK Mapping

- **T1566.002** - Phishing: Spearphishing Link
- **T1557** - Adversary-in-the-Middle
- **T1539** - Steal Web Session Cookie
- **T1078** - Valid Accounts
- **T1556** - Modify Authentication Process
- **T1550.004** - Use Alternate Authentication Material: Web Session Cookie

## Implementation Steps

### Phase 1: Infrastructure Setup
1. Register a convincing lookalike domain (e.g., using homoglyphs or typosquatting)
2. Provision a VPS and point the domain's DNS A record to the server IP
3. Install EvilGinx3:
   ```bash
   git clone https://github.com/kgretzky/evilginx2.git
   cd evilginx2
   make
   sudo ./bin/evilginx -p ./phishlets
   ```
4. Configure the domain and IP in EvilGinx3:
   ```
   config domain example-phish.com
   config ipv4 <server-ip>
   ```
5. EvilGinx3 automatically provisions Let's Encrypt certificates for configured hostnames

### Phase 2: Phishlet Configuration
1. Select or create a phishlet for the target service (e.g., Microsoft 365, Google Workspace):
   ```
   phishlets hostname o365 login.example-phish.com
   phishlets enable o365
   ```
2. Verify phishlet is active and SSL certificate is issued:
   ```
   phishlets
   ```
3. Create a lure URL for the phishing campaign:
   ```
   lures create o365
   lures get-url 0
   ```
4. Optionally configure a redirect URL for post-capture:
   ```
   lures edit 0 redirect_url https://legitimate-site.com
   ```

### Phase 3: Phishing Delivery
1. Craft a pretext email with the lure URL embedded
2. Use GoPhish or manual SMTP for email delivery:
   ```
   # Integration with EvilGoPhish for combined campaigns
   # Provides GoPhish email tracking + EvilGinx3 credential capture
   ```
3. Implement URL masking or shortening if needed for link obfuscation
4. Deploy landing page with appropriate social engineering pretext

### Phase 4: Session Hijacking
1. Monitor EvilGinx3 for captured sessions:
   ```
   sessions
   sessions <session-id>
   ```
2. Extract captured session cookies from the session:
   ```
   # Session output includes:
   # - Username and password
   # - Session cookies (authentication tokens)
   # - Custom captured parameters
   ```
3. Import session cookies into a browser using a cookie editor extension:
   - Export cookies in JSON format
   - Use Cookie-Editor or EditThisCookie browser extension
   - Navigate to the target service to validate session hijack
4. Establish persistent access by creating application passwords or OAuth tokens

### Phase 5: Post-Access Activities
1. Enumerate mailbox contents, contacts, and shared drives
2. Identify additional targets for lateral phishing
3. Check for access to connected cloud applications (SharePoint, Teams, OneDrive)
4. Document all captured credentials and access achieved

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| EvilGinx3 | AiTM phishing framework | Linux |
| GoPhish | Phishing campaign management | Cross-platform |
| EvilGoPhish | Combined EvilGinx3 + GoPhish integration | Linux |
| Cookie-Editor | Browser cookie import/export | Browser Extension |
| Modlishka | Alternative AiTM proxy framework | Linux |
| Muraena | Alternative AiTM phishing proxy | Linux |

## Phishlet Targets

| Target Service | Phishlet | Captured Data |
|---------------|----------|---------------|
| Microsoft 365 | o365 | Session cookies, credentials |
| Google Workspace | google | Session cookies, credentials |
| Okta | okta | Session tokens, credentials |
| GitHub | github | Session cookies, credentials |
| AWS Console | aws | Session tokens, credentials |

## Detection Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| Newly registered lookalike domains | Domain monitoring and certificate transparency logs |
| SSL certificates for suspicious domains | CT log monitoring (crt.sh, Censys) |
| Unusual login locations after phishing | SIEM correlation of authentication events |
| Session cookie replay from different IP | Conditional access policy alerts |
| AiTM proxy headers in traffic | Network inspection for proxy artifacts |

## Validation Criteria

- [ ] EvilGinx3 deployed with valid SSL certificates
- [ ] Phishlet configured and enabled for target service
- [ ] Lure URL generated and accessible
- [ ] Test credentials captured successfully through phishing flow
- [ ] Session cookies captured and validated for MFA bypass
- [ ] Session hijack demonstrated in browser with stolen cookies
- [ ] Post-authentication access to target service confirmed
- [ ] Evidence documented with screenshots and session logs
