# Identity Federation with SAML Azure AD - Workflows

## Federation Setup Workflow

```
Phase 1: PREREQUISITES
    ├── Verify domain ownership in Azure AD
    ├── Install and configure Azure AD Connect for user sync
    ├── Deploy AD FS farm (if using on-premises federation)
    ├── Obtain public TLS certificate for federation endpoint
    └── Configure DNS for federation service name

Phase 2: FEDERATION CONFIGURATION
    ├── Configure AD FS relying party trust for Azure AD
    ├── Set up claims issuance rules (UPN, ImmutableID)
    ├── Convert Azure AD domain from managed to federated
    ├── Verify federation with Test-MgDomainFederationConfiguration
    └── Test user sign-in through federation flow

Phase 3: APPLICATION SSO
    ├── Add SaaS applications to Azure AD enterprise apps
    ├── Configure SAML SSO for each application
    ├── Map user attributes and claims
    ├── Test SSO for each application
    └── Assign users/groups to applications

Phase 4: SECURITY HARDENING
    ├── Enable conditional access policies
    ├── Configure MFA at AD FS or Azure AD level
    ├── Enable smart lockout and extranet lockout
    ├── Set up certificate auto-rollover
    └── Forward AD FS audit logs to SIEM
```

## SAML Authentication Flow (Federated Domain)

```
User accesses cloud application
    │
    ├── Application redirects to Azure AD
    │   (Azure AD acts as IdP for the application)
    │
    ├── Azure AD identifies user's domain as federated
    │
    ├── Azure AD redirects user to on-premises AD FS
    │   (AD FS is the IdP for the federated domain)
    │
    ├── AD FS authenticates user against Active Directory:
    │   ├── Kerberos (if on corporate network)
    │   ├── Forms-based authentication (if external)
    │   └── MFA challenge (if configured)
    │
    ├── AD FS issues SAML assertion with claims:
    │   ├── UPN (user principal name)
    │   ├── ImmutableID (objectGUID base64-encoded)
    │   ├── Email, display name, groups
    │   └── Signed with token-signing certificate
    │
    ├── SAML assertion posted to Azure AD
    │
    ├── Azure AD validates assertion:
    │   ├── Verify signature against known AD FS certificate
    │   ├── Match ImmutableID to synced user
    │   ├── Apply conditional access policies
    │   └── Issue Azure AD token for the application
    │
    └── User accesses the cloud application
```

## Failover Workflow (AD FS Outage)

```
AD FS becomes unavailable
    │
    ├── Users cannot authenticate through federation
    │
    ├── OPTION 1: Staged Rollout to Managed Authentication
    │   ├── Enable password hash sync as backup (should already be active)
    │   ├── Use Azure AD staged rollout to move groups to managed auth
    │   └── Users authenticate directly with Azure AD (password hash)
    │
    ├── OPTION 2: Convert Domain to Managed
    │   ├── Run: Convert-MgDomainToManaged (emergency procedure)
    │   ├── All users switch to Azure AD authentication
    │   └── Requires password hash sync to be active
    │
    └── After AD FS restored:
        ├── Re-establish federation trust
        ├── Convert domain back to federated
        └── Verify authentication flow
```

## Certificate Rotation Workflow

```
AD FS token-signing certificate approaching expiry
    │
    ├── Auto-Rollover Enabled (recommended):
    │   ├── AD FS generates new certificate 20 days before expiry
    │   ├── New cert is added as secondary
    │   ├── Azure AD automatically picks up via metadata refresh
    │   ├── New cert promoted to primary at expiry
    │   └── Old cert removed after grace period
    │
    └── Manual Rotation:
        ├── Generate new signing certificate in AD FS
        ├── Add as secondary: Set-AdfsCertificate ... -IsPrimary $false
        ├── Update Azure AD: Update-MgDomainFederationConfiguration
        ├── Wait for replication (allow 24-48 hours)
        ├── Promote to primary: Set-AdfsCertificate ... -IsPrimary $true
        └── Remove old certificate
```
