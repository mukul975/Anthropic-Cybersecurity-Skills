# Google Workspace SSO - Workflows

## SSO Configuration Workflow

```
1. PREPARE IDP
   ├── Create Google Workspace SAML application in IdP
   ├── Configure ACS URL: https://www.google.com/a/{domain}/acs
   ├── Configure Entity ID: google.com/a/{domain}
   ├── Set NameID to user email address
   ├── Map required attributes (firstName, lastName)
   └── Download IdP metadata (SSO URL, certificate, entity ID)

2. CONFIGURE GOOGLE ADMIN CONSOLE
   ├── Navigate to Security > Authentication > SSO with third-party IdP
   ├── Enable third-party SSO
   ├── Enter Sign-in page URL from IdP
   ├── Enter Sign-out page URL from IdP
   ├── Upload IdP verification certificate
   ├── Enable domain-specific issuer
   └── Save configuration

3. ASSIGN SSO PROFILE
   ├── Apply to entire organization OR
   ├── Apply to specific organizational units OR
   └── Apply to specific groups

4. TEST
   ├── Test IdP-initiated SSO (login from IdP portal)
   ├── Test SP-initiated SSO (login from Google page)
   ├── Test sign-out flow
   ├── Test with user not in IdP (should fail)
   └── Test break-glass Super Admin access (should bypass SSO)

5. ROLLOUT
   ├── Communicate changes to users
   ├── Apply to all organizational units
   ├── Monitor for authentication failures
   └── Update help desk with troubleshooting guide
```

## User Authentication Flow (SP-Initiated)

```
User navigates to mail.google.com/a/{domain}
    │
    ├── Google identifies federated domain
    │
    ├── Redirect to IdP with SAML AuthnRequest
    │   URL: {IdP SSO URL}?SAMLRequest={base64encoded}
    │
    ├── User authenticates at IdP:
    │   ├── Enter credentials
    │   ├── Complete MFA challenge
    │   └── IdP validates against directory
    │
    ├── IdP generates SAML Response:
    │   ├── Assertion with NameID (email)
    │   ├── Authentication context (MFA)
    │   ├── Digitally signed with IdP certificate
    │   └── Optionally encrypted
    │
    ├── Browser POSTs Response to Google ACS URL
    │
    ├── Google validates:
    │   ├── Signature against uploaded certificate
    │   ├── Assertion not expired
    │   ├── Audience matches entity ID
    │   ├── NameID matches a Google Workspace user
    │   └── InResponseTo matches original request
    │
    └── User logged in to Google Workspace
```

## Certificate Renewal Workflow

```
IdP signing certificate approaching expiration (30 days before)
    │
    ├── Generate new signing certificate in IdP
    │
    ├── Upload new certificate to Google Admin Console
    │   (Google supports multiple verification certificates)
    │
    ├── Promote new certificate as primary in IdP
    │
    ├── Verify SSO still works with new certificate
    │
    └── Remove old certificate from Google Admin Console after confirmation
```

## Troubleshooting Workflow

```
User reports SSO failure
    │
    ├── Check 1: Is user assigned to the Google Workspace app in IdP?
    │   └── NO → Assign user in IdP
    │
    ├── Check 2: Does NameID match user's Google email exactly?
    │   └── NO → Fix attribute mapping in IdP
    │
    ├── Check 3: Is the IdP certificate expired?
    │   └── YES → Upload renewed certificate
    │
    ├── Check 4: Is there clock skew between IdP and Google?
    │   └── YES → Sync NTP on IdP server (max 5 min skew allowed)
    │
    ├── Check 5: Is the SAML assertion properly signed?
    │   └── NO → Verify IdP signing algorithm matches uploaded cert
    │
    └── Check 6: Check IdP SAML debug logs for detailed error
```
