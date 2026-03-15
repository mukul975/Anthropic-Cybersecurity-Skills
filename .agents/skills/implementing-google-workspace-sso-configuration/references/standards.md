# Google Workspace SSO - Standards Reference

## SAML 2.0 Standard

### OASIS SAML 2.0 Core
- Assertions: Authentication statements, attribute statements
- Protocols: AuthnRequest, Response, LogoutRequest
- Bindings: HTTP Redirect, HTTP POST, Artifact
- Profiles: Web Browser SSO, Single Logout

### Google Workspace SAML Requirements
- SAML 2.0 compliant IdP
- HTTP POST binding for Assertion Consumer Service
- Signed SAML assertions (RSA-SHA256 recommended)
- NameID format: emailAddress (user's primary email)
- X.509 PEM certificate for signature verification

## Google Workspace SSO Parameters

| Parameter | Value |
|-----------|-------|
| ACS URL | `https://www.google.com/a/{domain}/acs` |
| Entity ID (domain-specific) | `google.com/a/{domain}` |
| Entity ID (generic) | `google.com` |
| NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| SAML Version | 2.0 |
| Binding | HTTP-POST |

## Compliance Mapping

### NIST SP 800-63-3 (Digital Identity Guidelines)
- AAL2: Multi-factor authentication (enforced at IdP)
- Federation assurance levels (FAL1-FAL3)
- Assertion protection requirements

### SOC 2 - CC6.1
- Single sign-on centralizes access control
- Audit trail of authentication events
- Timely deprovisioning via IdP user removal

### ISO 27001:2022 - A.8.5
- Secure authentication through centralized IdP
- MFA enforcement via SSO configuration
- Session management controls
