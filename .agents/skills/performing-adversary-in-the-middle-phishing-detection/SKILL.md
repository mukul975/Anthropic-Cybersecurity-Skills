---
name: performing-adversary-in-the-middle-phishing-detection
description: Detect and respond to Adversary-in-the-Middle (AiTM) phishing attacks that use reverse proxy kits like EvilProxy, Evilginx, and Tycoon 2FA to bypass MFA and steal session tokens.
domain: cybersecurity
subdomain: phishing-defense
tags: [aitm, evilproxy, evilginx, phishing, mfa-bypass, session-hijacking, reverse-proxy, credential-theft]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Adversary-in-the-Middle Phishing Detection

## Overview
Adversary-in-the-Middle (AiTM) phishing attacks use reverse-proxy infrastructure to sit between the victim and the legitimate authentication service, intercepting both credentials and session cookies in real time. This allows attackers to bypass multi-factor authentication (MFA). The most prevalent PhaaS kits in 2025 include Tycoon 2FA, Sneaky 2FA, EvilProxy, and Evilginx. Over 1 million PhaaS attacks were detected in January-February 2025 alone. These attacks have evolved from QR codes to HTML attachments and SVG files for link distribution.

## Prerequisites
- Azure AD / Entra ID Conditional Access policies
- SIEM with authentication log ingestion (Azure AD sign-in logs)
- Web proxy with SSL inspection and URL categorization
- Endpoint Detection and Response (EDR) solution
- FIDO2/phishing-resistant MFA capability

## Key Concepts

### How AiTM Works
1. Victim receives phishing email with link to attacker-controlled domain
2. Attacker domain runs reverse proxy that mirrors legitimate login page
3. Victim enters credentials on proxied page; credentials captured in transit
4. Reverse proxy forwards credentials to real authentication service
5. MFA challenge sent to victim; victim completes MFA on proxied page
6. Attacker captures session cookie returned by legitimate service
7. Attacker replays session cookie to access victim's account without MFA

### Major AiTM Kits (2025)
| Kit | Type | Primary Targets | Evasion |
|---|---|---|---|
| Tycoon 2FA | PhaaS | Microsoft 365, Google | CAPTCHA, Cloudflare turnstile |
| EvilProxy | PhaaS | Microsoft 365, Google, Okta | Random URLs, IP rotation |
| Evilginx | Open-source | Any web application | Custom phishlets |
| Sneaky 2FA | PhaaS | Microsoft 365 | Anti-bot checks |
| NakedPages | PhaaS | Multiple | Minimal infrastructure |

### Detection Indicators
- Authentication from unusual IP not matching user profile
- Session cookie reuse from different IP/device than authentication
- Login page served from non-Microsoft/non-Google infrastructure
- CDN requests to legitimate auth providers from phishing domains
- Impossible travel between authentication and session usage

## Implementation Steps

### Step 1: Deploy Phishing-Resistant MFA
- Implement FIDO2 security keys or Windows Hello for Business for high-value accounts
- Configure Conditional Access to require phishing-resistant MFA for admins
- Enable certificate-based authentication where possible
- Disable SMS and voice MFA for privileged accounts
- AiTM cannot intercept FIDO2 because authentication is bound to origin domain

### Step 2: Configure Conditional Access Policies
- Require compliant/managed device for sensitive application access
- Block authentication from anonymous proxies and Tor exit nodes
- Enforce token binding to limit session cookie replay
- Configure continuous access evaluation (CAE) for real-time token revocation
- Implement sign-in risk policies that require re-authentication for risky sign-ins

### Step 3: Build AiTM Detection Rules
- Alert on sign-in followed by session from different IP within 10 minutes
- Detect authentication where proxy IP does not match user's expected location
- Monitor for impossible travel patterns in session usage
- Alert on inbox rules created immediately after authentication (common post-compromise)
- Detect new MFA method registration from suspicious sign-in

### Step 4: Monitor Web Proxy for AiTM Infrastructure
- Log and analyze DNS queries to newly registered domains
- Detect connections to known PhaaS infrastructure IPs
- Alert on authentication page backgrounds loaded from legitimate CDNs through proxy domains
- Monitor for SSL certificates issued to domains mimicking corporate login pages
- Block access to known EvilProxy/Evilginx infrastructure via threat intelligence

### Step 5: Implement Post-Compromise Detection
- Alert on mailbox forwarding rules created after suspicious authentication
- Detect OAuth app consent after AiTM sign-in
- Monitor for email sending patterns indicating BEC follow-up
- Alert on SharePoint/OneDrive mass download after session hijack
- Track lateral movement from compromised account

## Tools & Resources
- **Microsoft Entra ID Protection**: Risk-based Conditional Access
- **Azure AD Sign-in Logs**: Authentication event analysis
- **Okta ThreatInsight**: AiTM proxy detection at IdP level
- **Sekoia TDR**: AiTM campaign tracking and intelligence
- **Evilginx (defensive)**: Understanding attack mechanics for detection

## Validation
- Phishing-resistant MFA blocks AiTM session capture in test scenario
- Conditional Access denies session replay from different device/IP
- SIEM alerts fire on simulated AiTM sign-in patterns
- Web proxy blocks connections to known PhaaS infrastructure
- Post-compromise rules detect inbox rule creation after suspicious auth
