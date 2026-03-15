# Google Workspace SSO Implementation Template

## Configuration Details

| Setting | Value |
|---------|-------|
| Google Workspace Domain | |
| ACS URL | `https://www.google.com/a/{domain}/acs` |
| Entity ID | `google.com/a/{domain}` |
| IdP Name | Okta / Azure AD / ADFS / Other |
| IdP SSO URL | |
| IdP Sign-out URL | |
| Certificate Expiry | |

## Pre-Implementation Checklist

- [ ] Google Workspace Super Admin access confirmed
- [ ] IdP SAML application created for Google Workspace
- [ ] IdP signing certificate exported (X.509 PEM)
- [ ] User attributes mapped (NameID = email)
- [ ] Test users assigned in IdP
- [ ] Break-glass Super Admin account identified (bypasses SSO)

## Testing Results

| Test Case | Result | Notes |
|-----------|--------|-------|
| SP-initiated SSO (from Google login) | Pass/Fail | |
| IdP-initiated SSO (from IdP portal) | Pass/Fail | |
| User not in IdP (access denied) | Pass/Fail | |
| Sign-out flow | Pass/Fail | |
| Super Admin bypass | Pass/Fail | |
| MFA enforcement at IdP | Pass/Fail | |
| Clock skew tolerance | Pass/Fail | |

## Rollout Plan

- [ ] Phase 1: IT team pilot (1 week)
- [ ] Phase 2: Engineering department (1 week)
- [ ] Phase 3: All organizational units
- [ ] User communication sent
- [ ] Help desk trained
- [ ] Monitoring configured for auth failures
