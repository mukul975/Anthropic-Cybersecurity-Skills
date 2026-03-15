# SAML SSO Implementation Workflows

## Workflow 1: SP-Initiated SSO Flow

```
User -> Service Provider -> Okta IdP -> User Authenticates -> Okta -> Service Provider -> User
```

### Detailed Steps:
1. User accesses protected resource on Service Provider
2. SP checks for existing session - none found
3. SP generates SAML AuthnRequest with:
   - Issuer (SP Entity ID)
   - AssertionConsumerServiceURL
   - NameIDPolicy (email format)
   - RequestID (for InResponseTo validation)
4. SP redirects user to Okta SSO URL with base64-encoded AuthnRequest
5. Okta authenticates user (credentials, MFA if configured)
6. Okta generates SAML Response containing:
   - Signed assertion with SHA-256
   - Subject NameID (user identifier)
   - Conditions (NotBefore, NotOnOrAfter, AudienceRestriction)
   - AuthnStatement (authentication context)
   - AttributeStatement (mapped user attributes)
7. Okta POSTs SAML Response to SP ACS URL
8. SP validates SAML Response:
   - Verify XML signature against Okta certificate
   - Check InResponseTo matches original request ID
   - Validate time conditions (with clock skew tolerance)
   - Verify audience restriction matches SP Entity ID
   - Check authentication context class
9. SP extracts user identity and attributes
10. SP creates local session and grants access

## Workflow 2: IdP-Initiated SSO Flow

### Steps:
1. User logs into Okta dashboard
2. User clicks on application tile
3. Okta generates unsolicited SAML Response (no InResponseTo)
4. Okta POSTs to SP ACS URL
5. SP validates assertion (no InResponseTo check)
6. SP creates session

### Security Note:
IdP-initiated SSO is less secure because it cannot validate InResponseTo, making it more susceptible to replay attacks. Use SP-initiated flow when possible.

## Workflow 3: Certificate Rotation

### Steps:
1. Generate new X.509 certificate in Okta (Admin > Settings > Security)
2. Download new certificate (do not yet set as active)
3. Install new certificate on SP alongside existing certificate
4. Configure SP to accept assertions signed with either certificate
5. Activate new certificate in Okta
6. Monitor for authentication failures
7. After validation period, remove old certificate from SP
8. Update SAML metadata on both sides

### Timeline:
- Day 0: Generate new certificate and distribute to SP team
- Day 1-7: SP installs new certificate (dual-cert mode)
- Day 8: Activate new certificate in Okta
- Day 8-14: Monitor authentication logs for failures
- Day 15: Remove old certificate from SP

## Workflow 4: Single Logout (SLO)

### Steps:
1. User initiates logout at SP
2. SP generates SAML LogoutRequest
3. SP sends LogoutRequest to Okta SLO endpoint
4. Okta terminates IdP session
5. Okta sends LogoutRequest to all other SPs in session
6. Each SP terminates local session
7. Okta sends LogoutResponse to initiating SP
8. SP confirms logout to user

## Workflow 5: Troubleshooting Authentication Failures

### Diagnostic Steps:
1. Install SAML Tracer browser extension
2. Reproduce the failed SSO attempt
3. Capture the SAML AuthnRequest and Response
4. Check for common issues:
   - **Signature Invalid**: Certificate mismatch or SHA-1 vs SHA-256
   - **Audience Mismatch**: SP Entity ID doesn't match Okta config
   - **Time Condition Failed**: Clock skew > configured tolerance
   - **NameID Format Mismatch**: SP expects different format
   - **Missing Attributes**: Attribute mapping not configured
5. Review Okta System Log for error details
6. Verify SP metadata matches Okta configuration
