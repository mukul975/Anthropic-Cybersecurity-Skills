# Identity Federation Implementation Template

## Federation Details

| Setting | Value |
|---------|-------|
| Azure AD Tenant ID | |
| Federated Domain | |
| AD FS Farm Name | |
| AD FS Service URL | `https://fs.___/adfs/ls/` |
| Federation Protocol | SAML 2.0 / WS-Federation |
| Backup Auth | Password Hash Sync / Pass-Through Auth |

## AD FS Configuration

| Setting | Value |
|---------|-------|
| AD FS Version | |
| Service Account | gMSA recommended |
| Token-Signing Cert Expiry | |
| Auto-Rollover Enabled | Yes / No |
| WAP Deployed | Yes / No |

## Claims Rules

| Rule Name | Source Attribute | Claim Type | Description |
|-----------|-----------------|------------|-------------|
| UPN | userPrincipalName | NameID | Primary identifier |
| ImmutableID | objectGUID (base64) | ImmutableID | Azure AD anchor |
| Email | mail | emailaddress | User email |

## Validation Results

| Test | Status | Notes |
|------|--------|-------|
| AD FS metadata reachable | Pass/Fail | |
| Token-signing certificate valid | Pass/Fail | |
| Domain federation configured in Azure AD | Pass/Fail | |
| SP-initiated SSO flow | Pass/Fail | |
| IdP-initiated SSO flow | Pass/Fail | |
| MFA enforcement | Pass/Fail | |
| Smart lockout configured | Pass/Fail | |
| Sign-in logs showing federated auth | Pass/Fail | |

## Disaster Recovery

- [ ] Password hash sync enabled as backup
- [ ] Staged rollout to managed auth tested
- [ ] Break-glass cloud-only admin accounts created
- [ ] AD FS farm disaster recovery plan documented
- [ ] Secondary AD FS farm in DR site (if applicable)
