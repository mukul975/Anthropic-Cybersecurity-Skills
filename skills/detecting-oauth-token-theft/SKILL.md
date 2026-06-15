---
name: detecting-oauth-token-theft
description: 'Detects and responds to OAuth token theft and replay attacks in cloud
  environments, focusing on Microsoft Entra ID (Azure AD) token protection, conditional
  access policies, and sign-in anomaly detection. Covers access token theft, refresh
  token replay, Primary Refresh Token (PRT) abuse, and pass-the-cookie attacks. Activates
  for requests involving OAuth token theft detection, token replay prevention, Azure
  AD conditional access token protection, or cloud identity attack investigation.

  '
domain: cybersecurity
subdomain: cloud-security
tags:
- oauth
- token-theft
- azure-ad
- entra-id
- conditional-access
- token-replay
- identity-security
- PRT
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
---

# Detecting OAuth Token Theft

## When to Use

- Investigating alerts for impossible travel or anomalous token usage in Microsoft Entra ID
- Responding to a suspected session hijacking or pass-the-cookie attack
- Configuring proactive defenses against OAuth token theft in an Azure/M365 environment
- Detecting OAuth device code phishing campaigns that bypass MFA
- Analyzing sign-in logs for token replay indicators
- Implementing Token Protection conditional access policies to bind tokens to devices

**Do not use** for on-premises Kerberos ticket attacks (pass-the-ticket, golden ticket); use Active Directory-specific investigation techniques for those scenarios.

## Prerequisites

- Microsoft Entra ID P2 license (required for Identity Protection risk detections and conditional access)
- Global Administrator or Security Administrator role in the Entra admin center
- Microsoft Defender for Cloud Apps (MDCA) license for session anomaly detection
- Access to Entra ID Sign-in Logs and Audit Logs (requires Diagnostic Settings configured to Log Analytics or Sentinel)
- Familiarity with OAuth 2.0 authorization flows (authorization code, device code, client credentials)
- Microsoft Sentinel or equivalent SIEM ingesting Entra ID sign-in and audit logs

## Workflow

### Step 1: Understand the Token Theft Attack Surface

Identify which token types are at risk and how they are stolen:

```
Token Type            | Lifetime     | Theft Vector                    | Impact
----------------------|-------------|----------------------------------|------------------
Access Token          | 60-90 min   | Memory dump, proxy interception  | API access for token lifetime
Refresh Token         | Up to 90 days| Browser cookie theft, malware   | Persistent access, new access tokens
Primary Refresh Token | Session-based| Mimikatz, AADInternals, malware | Full SSO to all M365/Azure apps
Session Cookie        | Varies      | XSS, browser exploit, AitM proxy | Full session hijacking
Device Code Token     | 15 min auth | Phishing (device code flow abuse)| Attacker gets refresh token via social engineering
```

Common attack techniques:
- **AitM Phishing (Adversary-in-the-Middle)**: Attacker proxies the legitimate login page via tools like Evilginx2, capturing session cookies and tokens after the user completes MFA
- **Device Code Phishing**: Attacker generates a device code, sends it to the victim via email/Teams, victim authenticates, attacker receives the token
- **PRT Extraction**: Attacker with local admin on a device extracts the Primary Refresh Token using Mimikatz (`sekurlsa::cloudap`) or AADInternals
- **Browser Cookie Theft**: Malware or infostealer exfiltrates browser cookies containing session tokens

### Step 2: Configure Entra ID Sign-in Risk Detection

Enable Identity Protection to flag anomalous token usage:

```
Entra Admin Center > Protection > Identity Protection > Risk Detections

Key risk detections for token theft:
- Anomalous Token        : Token has unusual characteristics (claim anomalies)
- Token Issuer Anomaly   : Token issued by an unusual token issuer
- Unfamiliar Sign-in     : Sign-in from a location not seen before for the user
- Impossible Travel      : Sign-ins from geographically distant locations in impossible time
- Malicious IP Address   : Sign-in from a known malicious IP
- Suspicious Browser     : Sign-in from a suspicious or attacker-controlled browser
```

Configure risk-based conditional access:

```
Entra Admin Center > Protection > Conditional Access > New Policy

Policy Name: "Block High-Risk Sign-ins - Token Theft Protection"
Assignments:
  Users: All users (exclude break-glass accounts)
  Cloud Apps: All cloud apps
Conditions:
  Sign-in Risk: High
Grant:
  Block access

Policy Name: "Require MFA for Medium-Risk Sign-ins"
Assignments:
  Users: All users
  Cloud Apps: All cloud apps
Conditions:
  Sign-in Risk: Medium
Grant:
  Require multifactor authentication
  Require password change
```

### Step 3: Enable Token Protection (Preview)

Configure Token Protection to bind sign-in session tokens to the device:

```
Entra Admin Center > Protection > Conditional Access > New Policy

Policy Name: "Enforce Token Protection for Desktop Sessions"
Assignments:
  Users: All users (start with a pilot group)
  Cloud Apps: Office 365 Exchange Online, Office 365 SharePoint Online
  Conditions:
    Device Platforms: Windows
Session:
  Require token protection for sign-in sessions (Preview): Enabled
Grant:
  Require device to be marked as compliant
  OR Require Hybrid Azure AD joined device
```

Token Protection ensures that access tokens are cryptographically bound to the device's Trusted Platform Module (TPM). If an attacker steals a token and replays it from a different device, the token is rejected because the proof-of-possession key does not match.

### Step 4: Detect Token Replay in Sign-in Logs

Query Entra sign-in logs for indicators of token theft:

```kusto
// KQL query for Microsoft Sentinel or Log Analytics
// Detect sign-ins where the token was issued in one location and used in another
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskDetail contains "token" or RiskEventTypes_V2 has "anomalousToken"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          RiskDetail, RiskLevelDuringSignIn, AppDisplayName,
          DeviceDetail, ClientAppUsed, TokenIssuerType
| sort by TimeGenerated desc

// Detect impossible travel with token reuse
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0  // Successful sign-ins only
| summarize Locations=make_set(Location), IPs=make_set(IPAddress),
            Count=count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1
| sort by TimeGenerated desc

// Detect device code flow abuse (often used in phishing)
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, DeviceDetail, ResultType
| sort by TimeGenerated desc

// Detect token replay: same token used from multiple IPs
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize IPs=make_set(IPAddress), IPCount=dcount(IPAddress)
            by UserPrincipalName, CorrelationId
| where IPCount > 1
| sort by IPCount desc
```

### Step 5: Investigate and Respond to Token Theft

When a token theft event is detected, follow this response procedure:

```powershell
# Step 5a: Revoke all refresh tokens for the compromised user
# Microsoft Graph PowerShell
Connect-MgGraph -Scopes "User.ReadWrite.All"
Revoke-MgUserSignInSession -UserId "user@contoso.com"

# Step 5b: Force password reset
Update-MgUser -UserId "user@contoso.com" -PasswordProfile @{
    ForceChangePasswordNextSignIn = $true
}

# Step 5c: Review and revoke OAuth app consent grants
# Check for malicious app consent (common post-compromise persistence)
Get-MgUserOauth2PermissionGrant -UserId "user@contoso.com" |
    Select-Object ClientId, ConsentType, Scope

# Remove suspicious OAuth grants
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<grant-id>"

# Step 5d: Review enterprise app registrations for rogue apps
Get-MgServicePrincipal -Filter "displayName eq 'Suspicious App'" |
    Select-Object AppId, DisplayName, SignInAudience

# Step 5e: Check for mail forwarding rules (common post-compromise action)
Get-MgUserMailFolderRule -UserId "user@contoso.com" -MailFolderId "Inbox" |
    Where-Object { $_.Actions.ForwardTo -ne $null -or $_.Actions.RedirectTo -ne $null }
```

### Step 6: Implement Continuous Access Evaluation (CAE)

Enable CAE to revoke tokens in near-real-time when conditions change:

```
Entra Admin Center > Protection > Conditional Access > Continuous Access Evaluation

Settings:
  Strictly enforce location policies: Enabled

CAE ensures that when you revoke a user's session or change their
risk level, the enforcement happens within minutes rather than waiting
for the access token to naturally expire (60-90 minutes).

Critical events that trigger immediate token revocation with CAE:
- User account disabled or deleted
- Password changed or reset
- MFA enabled for the user
- Admin explicitly revokes refresh tokens
- Azure AD Identity Protection detects elevated user risk
- Network location change violates conditional access policy
```

### Step 7: Configure Defender for Cloud Apps Session Policies

Set up real-time session monitoring to detect and block suspicious token usage:

```
Microsoft Defender for Cloud Apps > Policies > Session Policies

Policy: "Block download from unmanaged device with stolen token"
  Session Control Type: Monitor and block activities
  Activity Source: App = Office 365, SharePoint Online
  Activity Filter: Device tag does not equal "Compliant"
  Activity Type: Download
  Action: Block

Policy: "Alert on mass file download (exfiltration via stolen token)"
  Session Control Type: Monitor only
  Activity Source: App = Office 365
  Activity Filter: Repeated activity > 10 downloads in 5 minutes
  Action: Alert administrators
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Primary Refresh Token (PRT)** | A long-lived token issued to a registered device that provides SSO to all Azure AD-integrated applications, cryptographically bound to the device's TPM |
| **Token Protection** | Entra ID conditional access feature that binds sign-in session tokens to the device, preventing replay from other devices |
| **Continuous Access Evaluation (CAE)** | Protocol that enables near-real-time enforcement of security policies by allowing resource providers to subscribe to Entra ID critical events |
| **AitM (Adversary-in-the-Middle)** | Phishing technique where an attacker proxies the legitimate authentication flow to capture session cookies after the victim completes MFA |
| **Device Code Flow** | OAuth 2.0 authorization grant for input-constrained devices; abused by attackers who send device codes to victims via phishing |
| **Proof of Possession (PoP)** | Cryptographic mechanism where a token includes a claim tied to a device key, ensuring the token can only be used by the device that obtained it |
| **Refresh Token** | Long-lived OAuth token (up to 90 days) used to obtain new access tokens without re-authentication; primary target for persistent access |

## Verification

- [ ] Identity Protection risk detections are enabled and generating alerts for anomalous token activity
- [ ] Conditional access policies block high-risk sign-ins and require MFA for medium-risk
- [ ] Token Protection policy is applied to pilot group and confirmed working (test from unregistered device fails)
- [ ] KQL queries in Sentinel return results when tested against synthetic token anomaly events
- [ ] Continuous Access Evaluation is enabled and verified (revoke session, confirm access blocked within minutes)
- [ ] Defender for Cloud Apps session policies are active and monitoring download activity
- [ ] Device code flow is restricted via conditional access (block or require compliant device)
- [ ] Incident response runbook includes token revocation, password reset, and OAuth consent review steps
- [ ] Mail forwarding rules and OAuth app grants are audited for compromised accounts
