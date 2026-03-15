---
name: building-identity-federation-with-saml-azure-ad
description: Establish SAML 2.0 identity federation between on-premises Active Directory and Azure AD (Microsoft Entra ID) for seamless cross-domain authentication and SSO to cloud applications.
domain: cybersecurity
subdomain: identity-access-management
tags: [saml, azure-ad, entra-id, federation, identity, sso, adfs, hybrid-identity]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Building Identity Federation with SAML Azure AD

## Overview

Identity federation enables users authenticated by one identity provider to access resources managed by another without maintaining separate credentials. This skill covers establishing SAML 2.0 federation between an organization's on-premises Active Directory (via AD FS or third-party IdP) and Microsoft Entra ID (formerly Azure AD), as well as configuring federated SSO for third-party SaaS applications. Federation eliminates password synchronization concerns and keeps authentication authority on-premises while extending SSO to cloud resources.

## Prerequisites

- On-premises Active Directory domain
- AD FS 2019+ or third-party SAML IdP (Okta, Ping, etc.)
- Microsoft Entra ID tenant (P1 or P2 license recommended)
- Azure AD Connect (if using hybrid identity with password hash sync as backup)
- Public TLS certificate for federation endpoint
- DNS records for federation service name

## Core Concepts

### Federation Models

| Model | Authentication Authority | Use Case |
|-------|------------------------|----------|
| Federated (AD FS) | On-premises AD FS | Regulatory requirement to keep auth on-prem |
| Managed (PHS) | Azure AD with password hash sync | Simplest cloud auth, AD FS not needed |
| Managed (PTA) | On-premises via pass-through agent | Cloud auth validated against on-prem AD |
| Third-Party Federation | External IdP (Okta, Ping) | Multi-IdP environment |

### SAML Federation Architecture

```
User → Cloud App (SP)
   │
   └── Redirect to Azure AD
          │
          ├── Azure AD checks federated domain
          │
          └── Redirect to on-premises AD FS
                 │
                 ├── AD FS authenticates against Active Directory
                 │
                 ├── AD FS issues SAML token
                 │
                 └── Token posted back to Azure AD
                        │
                        ├── Azure AD validates federation trust
                        │
                        ├── Azure AD issues its own token
                        │
                        └── User receives access token for cloud app
```

### Federation Trust Components

| Component | Description |
|-----------|-------------|
| Token-Signing Certificate | X.509 certificate used by IdP to sign SAML assertions |
| Federation Metadata | XML document describing IdP endpoints and capabilities |
| Relying Party Trust | Configuration in AD FS for each SP (Azure AD) |
| Claims Rules | Transform AD attributes into SAML claims |
| Issuer URI | Unique identifier for the IdP (entity ID) |

## Implementation Steps

### Step 1: Prepare AD FS Infrastructure

```powershell
# Install AD FS role
Install-WindowsFeature ADFS-Federation -IncludeManagementTools

# Configure AD FS farm
Install-AdfsFarm `
    -CertificateThumbprint $certThumbprint `
    -FederationServiceDisplayName "Corp Federation Service" `
    -FederationServiceName "fs.corp.example.com" `
    -ServiceAccountCredential $gmsaCredential

# Verify AD FS is operational
Get-AdfsProperties | Select-Object HostName, Identifier, FederationPassiveAddress
```

### Step 2: Configure Azure AD Federated Domain

```powershell
# Install Microsoft Graph PowerShell module
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Domain.ReadWrite.All"

# Convert managed domain to federated
# Using AD FS federation metadata URL
$domainId = "corp.example.com"
$federationConfig = @{
    issuerUri = "http://fs.corp.example.com/adfs/services/trust"
    metadataExchangeUri = "https://fs.corp.example.com/adfs/services/trust/mex"
    passiveSignInUri = "https://fs.corp.example.com/adfs/ls/"
    signOutUri = "https://fs.corp.example.com/adfs/ls/?wa=wsignout1.0"
    signingCertificate = $base64Cert
    preferredAuthenticationProtocol = "saml"
}

# Apply federation settings to domain
New-MgDomainFederationConfiguration -DomainId $domainId -BodyParameter $federationConfig
```

### Step 3: Configure AD FS Claims Rules

```powershell
# Add Relying Party Trust for Azure AD
Add-AdfsRelyingPartyTrust `
    -Name "Microsoft Office 365 Identity Platform" `
    -MetadataUrl "https://nexus.microsoftonline-p.com/federationmetadata/2007-06/federationmetadata.xml"

# Configure claim rules
$rules = @"
@RuleTemplate = "LdapClaims"
@RuleName = "Extract AD Attributes"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
   Issuer == "AD AUTHORITY"]
=> issue(store = "Active Directory",
   types = ("http://schemas.xmlsoap.org/claims/UPN",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"),
   query = ";userPrincipalName,mail,givenName,sn;{0}",
   param = c.Value);

@RuleTemplate = "PassThroughClaims"
@RuleName = "Pass Through UPN as NameID"
c:[Type == "http://schemas.xmlsoap.org/claims/UPN"]
=> issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
   Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer,
   Value = c.Value,
   ValueType = c.ValueType,
   Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"]
       = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
"@

Set-AdfsRelyingPartyTrust `
    -TargetName "Microsoft Office 365 Identity Platform" `
    -IssuanceTransformRules $rules
```

### Step 4: Configure Third-Party SaaS Federation

For each SaaS application that supports SAML SSO via Azure AD:

1. Navigate to Microsoft Entra Admin Center > Enterprise Applications
2. Add the application from the gallery (or create custom SAML)
3. Configure Single Sign-On > SAML:
   - Identifier (Entity ID): Application's entity ID
   - Reply URL (ACS): Application's assertion consumer service URL
   - Sign-on URL: Application's login URL
4. Map user attributes/claims:
   - NameID: user.userprincipalname (email format)
   - Additional claims as required by the application
5. Download the Federation Metadata XML or certificate
6. Configure the SaaS app with Azure AD's federation details

### Step 5: Certificate Lifecycle Management

AD FS token-signing certificates expire and must be renewed:

```powershell
# Check current certificate expiration
Get-AdfsCertificate -CertificateType Token-Signing | Select-Object Thumbprint, NotAfter

# AD FS supports auto-rollover (enabled by default)
Get-AdfsProperties | Select-Object AutoCertificateRollover

# If manual rotation is needed:
# 1. Add new certificate as secondary
Set-AdfsCertificate -CertificateType Token-Signing -Thumbprint $newThumbprint -IsPrimary $false
# 2. Update Azure AD with new certificate
# 3. Promote to primary
Set-AdfsCertificate -CertificateType Token-Signing -Thumbprint $newThumbprint -IsPrimary $true
# 4. Remove old certificate
Remove-AdfsCertificate -CertificateType Token-Signing -Thumbprint $oldThumbprint
```

## Validation Checklist

- [ ] AD FS farm operational with valid TLS and token-signing certificates
- [ ] Azure AD domain configured as federated with correct metadata
- [ ] Claims rules properly transform AD attributes to SAML assertions
- [ ] Test user can authenticate through federation flow end-to-end
- [ ] MFA enforced at AD FS or Azure AD conditional access level
- [ ] Certificate auto-rollover enabled or manual rotation scheduled
- [ ] Federation metadata endpoint publicly accessible
- [ ] Smart lockout configured to prevent brute force
- [ ] Extranet lockout policies configured on AD FS
- [ ] Monitoring configured for AD FS health and certificate expiry
- [ ] Disaster recovery: managed authentication fallback documented

## References

- [Microsoft Entra Federation Documentation](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-fed)
- [AD FS Design Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/design/ad-fs-design-guide)
- [Configure AD FS for Azure AD Federation](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-management)
- [SAML 2.0 Authentication - OASIS](https://docs.oasis-open.org/security/saml/v2.0/)
